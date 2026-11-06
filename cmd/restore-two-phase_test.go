// Copyright (c) 2026 Feng Ruohang
//
// This file is part of Silo Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/config/storageclass"
	xhttp "github.com/minio/minio/internal/http"
)

// A native restore downloads its tier copy without the object lock: while
// the download of an old version is paused, the hot versions of the same key
// stay readable and writable. Only the short commit takes the object lock.
func TestRestoreDownloadKeepsKeyAvailable(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, multipart := range []bool{false, true} {
			t.Run(fmt.Sprintf("pools=%d/multipart=%v", pools, multipart), func(t *testing.T) {
				r := newRestoreSafetyTest(t, pools, versioning.Enabled)
				initConfigSubsystem(t.Context(), r.z)
				oi, body := nativeRestoreSeed(t, r, 0, false, multipart)
				hot := putConsistencyObject(t, r.z, r.bucket, r.object, 0, "hot latest", ObjectOptions{Versioned: true, MTime: oi.ModTime.Add(time.Hour)})
				putConsistencyObject(t, r.z, r.bucket, "unrelated", 0, "unrelated hot object", ObjectOptions{Versioned: true})
				gate := newRestoreIsolationGateTier(1, nil)
				globalTierConfigMgr.drivercache["WARM"] = gate
				defer gate.unblock()
				done := make(chan error, 1)
				go func() {
					done <- r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
				}()
				restoreIsolationEntered(t, gate)

				within := func(name string, fn func(ctx context.Context) error) {
					t.Helper()
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					start := time.Now()
					if err := fn(ctx); err != nil {
						t.Fatalf("%s during a paused restore download: %v after %s", name, err, time.Since(start))
					}
				}
				for _, key := range []string{"unrelated", r.object} {
					within("GET "+key, func(ctx context.Context) error {
						gr, err := r.z.GetObjectNInfo(ctx, r.bucket, key, nil, http.Header{}, ObjectOptions{})
						if err != nil {
							return err
						}
						defer gr.Close()
						_, err = io.ReadAll(gr)
						return err
					})
				}
				within("HEAD hot latest", func(ctx context.Context) error {
					got, err := r.z.GetObjectInfo(ctx, r.bucket, r.object, ObjectOptions{})
					if err == nil && got.VersionID != hot.VersionID {
						err = fmt.Errorf("latest is %s, want %s", got.VersionID, hot.VersionID)
					}
					return err
				})
				within("PutObjectTags hot latest", func(ctx context.Context) error {
					_, err := r.z.PutObjectTags(ctx, r.bucket, r.object, "during=restore", ObjectOptions{VersionID: hot.VersionID, Versioned: true})
					return err
				})
				// The download publishes nothing: no upload, public or not.
				if uploads := restoreIsolationUploads(t, r, 0); len(uploads) != 0 {
					t.Errorf("restore created uploads: %v", uploads)
				}
				within("PUT new version", func(ctx context.Context) error {
					data := []byte("written during restore")
					_, err := r.z.PutObject(ctx, r.bucket, r.object,
						mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{Versioned: true})
					return err
				})

				gate.unblock()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Minute):
					t.Fatal("restore did not complete after releasing the tier")
				}
				if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
					t.Fatalf("restored version mismatch: %v", err)
				}
			})
		}
	}
}

// restoreTwoPhaseStagedCommitFailure makes a multipart completion stage its
// object metadata in the upload and then fail before moving any data.
type restoreTwoPhaseStagedCommitFailure struct {
	StorageAPI
	bucket, object string
}

func (d restoreTwoPhaseStagedCommitFailure) RenameData(ctx context.Context, sv, sp string, fi FileInfo, dv, dp string, opts RenameOptions) (RenameDataResp, error) {
	if sv == minioMetaMultipartBucket && dv == d.bucket && dp == d.object {
		if err := d.WriteMetadata(ctx, "", sv, sp, fi); err != nil {
			return RenameDataResp{}, err
		}
		return RenameDataResp{}, errFaultyDisk
	}
	return d.StorageAPI.RenameData(ctx, sv, sp, fi, dv, dp, opts)
}

// An ordinary upload whose completion failed after staging stays usable as
// on main: the client re-uploads its parts and completes, or aborts.
func TestMultipartFailedCommitRetriesLikeMain(t *testing.T) {
	for _, abort := range []bool{false, true} {
		t.Run(fmt.Sprintf("abort=%v", abort), func(t *testing.T) {
			z, bucket := consistencyPools(t)
			initConfigSubsystem(t.Context(), z)
			const object = "public-upload"
			er := z.serverPools[0].getHashedSet(object)
			ctx := t.Context()
			mp, err := er.NewMultipartUpload(ctx, bucket, object, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			body := []byte("ordinary multipart data")
			putPart := func() (PartInfo, error) {
				return er.PutObjectPart(ctx, bucket, object, mp.UploadID, 1,
					mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), ObjectOptions{})
			}
			p, err := putPart()
			if err != nil {
				t.Fatal(err)
			}
			disks := er.getDisks()
			wrapped := make([]StorageAPI, len(disks))
			for i, d := range disks {
				wrapped[i] = restoreTwoPhaseStagedCommitFailure{d, bucket, object}
			}
			previous := er.getDisks
			er.getDisks = func() []StorageAPI { return wrapped }
			_, err = er.CompleteMultipartUpload(ctx, bucket, object, mp.UploadID, []CompletePart{{PartNumber: 1, ETag: p.ETag}}, ObjectOptions{})
			er.getDisks = previous
			if err == nil {
				t.Fatal("fault injection failed")
			}
			if _, err := er.GetMultipartInfo(ctx, bucket, object, mp.UploadID, ObjectOptions{}); err != nil {
				t.Fatalf("upload after a failed commit: %v", err)
			}
			if abort {
				if err := er.AbortMultipartUpload(ctx, bucket, object, mp.UploadID, ObjectOptions{}); err != nil {
					t.Fatalf("abort after a failed commit: %v", err)
				}
				if _, err := er.GetMultipartInfo(ctx, bucket, object, mp.UploadID, ObjectOptions{}); !errors.As(err, &InvalidUploadID{}) {
					t.Fatalf("aborted upload still answers: %v", err)
				}
				return
			}
			if p, err = putPart(); err != nil {
				t.Fatalf("re-upload a part after a failed commit: %v", err)
			}
			if _, err := er.CompleteMultipartUpload(ctx, bucket, object, mp.UploadID, []CompletePart{{PartNumber: 1, ETag: p.ETag}}, ObjectOptions{}); err != nil {
				t.Fatalf("complete after re-uploading: %v", err)
			}
			gr, err := er.GetObjectNInfo(ctx, bucket, object, nil, http.Header{}, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer gr.Close()
			if got, err := io.ReadAll(gr); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("completed object = %q, %v", got, err)
			}
		})
	}
}

// restoreTwoPhaseFaults are the faults restoreTwoPhaseDisk injects, shared by
// a test and its drives so that the test can turn them off.
type restoreTwoPhaseFaults struct {
	// rename: "" passes the publication through, "fail" fails it without
	// applying it, "apply-fail" applies it and then reports a failure.
	rename atomic.Value
	// oldDataDir, when set, replaces the old data directory a publication
	// reports.
	oldDataDir atomic.Pointer[string]
	// writeFails fails this many metadata writes of the object.
	writeFails atomic.Int32
	// writes counts the metadata writes of the object.
	writes atomic.Int32
	// recreateTmp drops the staging directory before the second part is
	// written, as a server restart moves the tmp volume away.
	recreateTmp atomic.Bool
}

func (f *restoreTwoPhaseFaults) renameMode() string {
	m, _ := f.rename.Load().(string)
	return m
}

type restoreTwoPhaseDisk struct {
	StorageAPI
	bucket, object string
	f              *restoreTwoPhaseFaults
}

func (d restoreTwoPhaseDisk) RenameData(ctx context.Context, sv, sp string, fi FileInfo, dv, dp string, opts RenameOptions) (RenameDataResp, error) {
	if sv != minioMetaTmpBucket || dv != d.bucket || dp != d.object {
		return d.StorageAPI.RenameData(ctx, sv, sp, fi, dv, dp, opts)
	}
	switch d.f.renameMode() {
	case "fail":
		return RenameDataResp{}, errFaultyDisk
	case "apply-fail":
		if _, err := d.StorageAPI.RenameData(ctx, sv, sp, fi, dv, dp, opts); err != nil {
			return RenameDataResp{}, err
		}
		return RenameDataResp{}, errFaultyDisk
	}
	resp, err := d.StorageAPI.RenameData(ctx, sv, sp, fi, dv, dp, opts)
	if old := d.f.oldDataDir.Load(); old != nil {
		resp.OldDataDir = *old
	}
	return resp, err
}

func (d restoreTwoPhaseDisk) WriteMetadata(ctx context.Context, orig, vol, path string, fi FileInfo) error {
	if vol == d.bucket && path == d.object {
		d.f.writes.Add(1)
		if d.f.writeFails.Load() > 0 {
			d.f.writeFails.Add(-1)
			return errFaultyDisk
		}
	}
	return d.StorageAPI.WriteMetadata(ctx, orig, vol, path, fi)
}

func (d restoreTwoPhaseDisk) CreateFile(ctx context.Context, origvolume, volume, path string, size int64, reader io.Reader) error {
	if volume == minioMetaTmpBucket && strings.HasSuffix(path, "/part.2") && d.f.recreateTmp.Load() {
		tmpID, _, _ := strings.Cut(path, "/")
		if err := os.RemoveAll(filepath.Join(d.Endpoint().Path, minioMetaTmpBucket, tmpID)); err != nil {
			return err
		}
	}
	return d.StorageAPI.CreateFile(ctx, origvolume, volume, path, size, reader)
}

// restoreTwoPhaseFaulty wraps the drives of the object's set in the first
// pool; faults[i] is nil for a drive left as it is. It returns the plain
// drives, for reads that see what is stored.
func restoreTwoPhaseFaulty(t *testing.T, r *restoreTest, faults ...*restoreTwoPhaseFaults) []StorageAPI {
	t.Helper()
	er := r.z.serverPools[0].getHashedSet(r.object)
	disks := er.getDisks()
	previous := er.getDisks
	t.Cleanup(func() { er.getDisks = previous })
	wrapped := append([]StorageAPI(nil), disks...)
	for i, f := range faults {
		if f != nil {
			wrapped[i] = restoreTwoPhaseDisk{StorageAPI: disks[i], bucket: r.bucket, object: r.object, f: f}
		}
	}
	er.getDisks = func() []StorageAPI { return wrapped }
	return disks
}

// restoreTwoPhaseEntries reads the version from each drive.
func restoreTwoPhaseEntries(t *testing.T, r *restoreTest, disks []StorageAPI, versionID string) []FileInfo {
	t.Helper()
	infos, errs := readAllFileInfo(t.Context(), disks, "", r.bucket, r.object, restoreTestVersionKey(versionID), false, false)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("drive %d: %v", i, err)
		}
	}
	return infos
}

func restoreTwoPhaseUnrestored(fi FileInfo) bool {
	return fi.Metadata[xhttp.AmzRestore] == "" && fi.Metadata[restoreAttemptKey] == "" && fi.IsRemote()
}

func restoreTwoPhaseRestored(fi FileInfo) bool {
	st, err := parseRestoreObjStatus(fi.Metadata[xhttp.AmzRestore])
	return err == nil && !st.Ongoing() && !fi.IsRemote() && fi.Metadata[restoreAttemptKey] == ""
}

// restoreTwoPhaseDelays shortens the convergence retries for a test.
func restoreTwoPhaseDelays(t *testing.T, delays ...time.Duration) {
	previous := restorePublicationDelays
	restorePublicationDelays = delays
	t.Cleanup(func() { restorePublicationDelays = previous })
}

// A publication that reaches fewer drives than the write quorum is brought
// back to the unrestored version on every drive, under the same lock hold.
// No directory is deleted: the staged one is left to abandoned-data cleanup.
// The version restores again once the drives work.
func TestRestorePublicationBelowQuorumReverts(t *testing.T) {
	for _, multipart := range []bool{false, true} {
		t.Run(fmt.Sprintf("multipart=%v", multipart), func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			oi, body := nativeRestoreSeed(t, r, 0, false, multipart)
			faults := &restoreTwoPhaseFaults{}
			faults.rename.Store("fail")
			disks := restoreTwoPhaseFaulty(t, r, faults, faults)
			before := restoreTwoPhaseEntries(t, r, disks, oi.VersionID)
			err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
			if err == nil {
				t.Fatal("a publication on two of four drives succeeded")
			}
			for i, fi := range restoreTwoPhaseEntries(t, r, disks, oi.VersionID) {
				if !restoreTwoPhaseUnrestored(fi) || fi.DataDir != before[i].DataDir {
					t.Errorf("drive %d after a failed publication: restore %q, remote %v, data dir %s (was %s)",
						i, fi.Metadata[xhttp.AmzRestore], fi.IsRemote(), fi.DataDir, before[i].DataDir)
				}
			}
			// The drives that published keep the staged directory.
			for i := 2; i < len(disks); i++ {
				entries, err := os.ReadDir(filepath.Join(disks[i].Endpoint().Path, r.bucket, r.object))
				if err != nil {
					t.Fatal(err)
				}
				dirs := 0
				for _, e := range entries {
					if e.IsDir() && e.Name() != before[i].DataDir {
						dirs++
					}
				}
				if dirs == 0 {
					t.Errorf("drive %d: the published data directory was deleted", i)
				}
			}
			faults.rename.Store("")
			if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err != nil {
				t.Fatalf("restore after the drives recovered: %v", err)
			}
			if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("restored contents: %v", err)
			}
		})
	}
}

// A publication whose drives applied it but did not answer is found on a
// write quorum when the worker reads the drives again: the restore stands.
func TestRestorePublicationUncertainCommits(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	oi, body := nativeRestoreSeed(t, r, 0, false, true)
	faults := &restoreTwoPhaseFaults{}
	faults.rename.Store("apply-fail")
	disks := restoreTwoPhaseFaulty(t, r, faults, faults)
	if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err != nil {
		t.Fatalf("restore whose answers were lost: %v", err)
	}
	for i, fi := range restoreTwoPhaseEntries(t, r, disks, oi.VersionID) {
		if !restoreTwoPhaseRestored(fi) {
			t.Errorf("drive %d: not restored: %q", i, fi.Metadata[xhttp.AmzRestore])
		}
	}
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("restored contents: %v", err)
	}
}

// A convergence that cannot write every drive under the commit's lock hold
// finishes in a background retry.
func TestRestoreConvergenceRetries(t *testing.T) {
	restoreTwoPhaseDelays(t, 50*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond)
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	oi, _ := nativeRestoreSeed(t, r, 0, false, false)
	failing, flaky := &restoreTwoPhaseFaults{}, &restoreTwoPhaseFaults{}
	failing.rename.Store("fail")
	flaky.writeFails.Store(1)
	disks := restoreTwoPhaseFaulty(t, r, failing, failing, flaky)
	if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err == nil {
		t.Fatal("a publication on two of four drives succeeded")
	}
	deadline := time.Now().Add(restoreTestWait)
	for {
		settled := true
		for _, fi := range restoreTwoPhaseEntries(t, r, disks, oi.VersionID) {
			settled = settled && restoreTwoPhaseUnrestored(fi)
		}
		if settled {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("background convergence did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A convergence retry never overwrites what someone else wrote between two
// lock holds: a metadata update or a newer attempt's marker stops it.
func TestRestoreConvergenceStopsOnOtherWrites(t *testing.T) {
	for _, other := range []string{"tags", "successor"} {
		t.Run(other, func(t *testing.T) {
			restoreTwoPhaseDelays(t, 300*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond)
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			initConfigSubsystem(t.Context(), r.z)
			oi, body := restoreIsolationSeed(t, r, 0, false, false)
			failing, stuck := &restoreTwoPhaseFaults{}, &restoreTwoPhaseFaults{}
			failing.rename.Store("fail")
			stuck.writeFails.Store(1 << 20)
			disks := restoreTwoPhaseFaulty(t, r, failing, failing, stuck)
			if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err == nil {
				t.Fatal("a publication on two of four drives succeeded")
			}
			var successor string
			release := make(chan struct{})
			layer := newRestoreIsolationLayer(r)
			switch other {
			case "tags":
				if _, err := r.z.PutObjectTags(t.Context(), r.bucket, r.object, "kept=yes", r.opts(oi.VersionID)); err != nil {
					t.Fatal(err)
				}
			case "successor":
				layer.restore = func(ctx context.Context, bucket, object string, opts ObjectOptions) error {
					<-release
					return r.z.RestoreTransitionedObject(ctx, bucket, object, opts)
				}
				if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
					close(release)
					t.Fatalf("successor POST: %d %s", rec.Code, rec.Body.String())
				}
				successor = restoreTwoPhaseEntries(t, r, disks, oi.VersionID)[0].Metadata[restoreAttemptKey]
				if successor == "" {
					close(release)
					t.Fatal("successor POST recorded no attempt")
				}
			}
			writes := stuck.writes.Load()
			time.Sleep(time.Second)
			if got := stuck.writes.Load(); got != writes {
				t.Errorf("a stopped convergence kept writing: %d -> %d writes", writes, got)
			}
			for i, fi := range restoreTwoPhaseEntries(t, r, disks, oi.VersionID) {
				if i == 2 {
					continue // the drive the convergence could not write
				}
				switch other {
				case "tags":
					if fi.Metadata[xhttp.AmzObjectTagging] != "kept=yes" {
						t.Errorf("drive %d: the tags written between retries were overwritten: %q", i, fi.Metadata[xhttp.AmzObjectTagging])
					}
				case "successor":
					if fi.Metadata[restoreAttemptKey] != successor {
						t.Errorf("drive %d: the successor's marker was overwritten: %q", i, fi.Metadata[restoreAttemptKey])
					}
				}
			}
			if other == "successor" {
				failing.rename.Store("")
				stuck.writeFails.Store(0)
				close(release)
				if err := layer.wait(t); err != nil {
					t.Fatalf("successor restore: %v", err)
				}
				if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
					t.Fatalf("restored contents: %v", err)
				}
			}
		})
	}
}

// The data directory of the replaced entry goes only where every drive that
// reports it agrees on it; a drive that does not report it, as when another
// version shares the directory, keeps the directory everywhere.
func TestRestoreRemovesOldDataDirOnlyWhenUnanimous(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixed=%v", mixed), func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			oi, body := nativeRestoreSeed(t, r, 0, false, true)
			old := r.fileInfo(oi.VersionID).DataDir
			if old == "" {
				t.Fatal("fixture: the transitioned version has no data directory")
			}
			faults := &restoreTwoPhaseFaults{}
			if mixed {
				none := ""
				faults.oldDataDir.Store(&none)
			}
			restoreTwoPhaseFaulty(t, r, faults)
			if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err != nil {
				t.Fatal(err)
			}
			if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("restored contents: %v", err)
			}
			n := r.dataDirs(old)
			if mixed && n != 4 {
				t.Errorf("drives disagreed on the old data directory, but %d of 4 kept it", n)
			}
			if !mixed && n != 0 {
				t.Errorf("the unanimous old data directory remained on %d drives", n)
			}
		})
	}
}

// An earlier restore of a small object may have inlined its data, and the
// expiry of that copy leaves the inline marker behind. A new restore writes
// a data directory and must not publish the marker with it.
func TestRestoreDropsStaleInlineMarker(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	oi, body := nativeRestoreSeed(t, r, 0, false, false)
	disks := r.z.serverPools[0].getHashedSet(r.object).getDisks()
	for i, fi := range restoreTwoPhaseEntries(t, r, disks, oi.VersionID) {
		fi.SetInlineData()
		if err := disks[i].WriteMetadata(t.Context(), "", r.bucket, r.object, fi); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err != nil {
		t.Fatal(err)
	}
	for i, fi := range restoreTwoPhaseEntries(t, r, disks, oi.VersionID) {
		if fi.InlineData() {
			t.Errorf("drive %d: the restored copy is marked inline", i)
		}
	}
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("restored contents: %v", err)
	}
}

// A drive whose staging directory was moved away and recreated by a later
// part misses the earlier parts: it is left out of the commit, and when too
// few drives are left nothing is published at all.
func TestRestoreStagingDropsRecreatedTmp(t *testing.T) {
	for _, recreated := range []int{1, 2} {
		t.Run(fmt.Sprintf("drives=%d", recreated), func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			oi, body := nativeRestoreSeed(t, r, 0, false, true)
			faults := &restoreTwoPhaseFaults{}
			faults.recreateTmp.Store(true)
			wrap := make([]*restoreTwoPhaseFaults, recreated)
			for i := range wrap {
				wrap[i] = faults
			}
			disks := restoreTwoPhaseFaulty(t, r, wrap...)
			err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
			entries := restoreTwoPhaseEntries(t, r, disks, oi.VersionID)
			if recreated == 2 {
				if err == nil {
					t.Fatal("a copy staged completely on two of four drives was published")
				}
				for i, fi := range entries {
					if !restoreTwoPhaseUnrestored(fi) {
						t.Errorf("drive %d after a failed staging: %q", i, fi.Metadata[xhttp.AmzRestore])
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if restoreTwoPhaseRestored(entries[0]) {
				t.Error("the drive with missing parts got the restored copy")
			}
			for i := 1; i < len(entries); i++ {
				if !restoreTwoPhaseRestored(entries[i]) {
					t.Errorf("drive %d: not restored", i)
				}
			}
			if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("restored contents: %v", err)
			}
		})
	}
}

// A POST while the worker of an earlier POST holds the restore lock answers
// that a restore is in progress; it starts no second worker.
func TestRestoreSecondPOSTWhileRunning(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	oi, body := restoreIsolationSeed(t, r, 0, false, true)
	release := make(chan struct{})
	layer := newRestoreIsolationLayer(r)
	layer.restore = func(ctx context.Context, bucket, object string, opts ObjectOptions) error {
		<-release
		return r.z.RestoreTransitionedObject(ctx, bucket, object, opts)
	}
	if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
		t.Fatalf("first POST: %d %s", rec.Code, rec.Body.String())
	}
	rec := restoreIsolationPOST(t, r, layer, oi.VersionID)
	close(release)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "RestoreAlreadyInProgress") {
		t.Errorf("second POST: %d %s", rec.Code, rec.Body.String())
	}
	if err := layer.wait(t); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-layer.done:
		t.Fatalf("a second restore ran: %v", err)
	default:
	}
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("restored contents: %v", err)
	}
}

// A version deleted while its tier copy downloads is not brought back.
func TestRestoreTargetDeletedDuringDownload(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	oi, _ := nativeRestoreSeed(t, r, 0, false, false)
	gate := newRestoreIsolationGateTier(1, nil)
	globalTierConfigMgr.drivercache["WARM"] = gate
	defer gate.unblock()
	done := make(chan error, 1)
	go func() {
		done <- r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
	}()
	restoreIsolationEntered(t, gate)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	_, err := r.z.DeleteObject(ctx, r.bucket, r.object, r.opts(oi.VersionID))
	cancel()
	if err != nil {
		t.Fatalf("delete during the download: %v", err)
	}
	gate.unblock()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the restore of a deleted version succeeded")
		}
	case <-time.After(restoreTestWait):
		t.Fatal("restore did not finish")
	}
	if _, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID)); !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
		t.Fatalf("deleted version after the restore: %v", err)
	}
}

// With several pools, abandoned-data cleanup takes the pools lock that every
// write of the object takes, also where a pool's sets have lockers of their
// own: while a writer holds it, cleanup removes nothing, such as a data
// directory that a commit moved in place and has not yet referenced.
func TestCheckAbandonedPartsTakesPoolsLock(t *testing.T) {
	r := newRestoreSafetyTest(t, 2, versioning.Enabled)
	nativeRestoreSeed(t, r, 1, false, false)
	for _, set := range r.z.serverPools[1].sets {
		previous := set.nsMutex
		set.nsMutex = newNSLock(false)
		t.Cleanup(func() { set.nsMutex = previous })
	}
	disks := r.z.serverPools[1].getHashedSet(r.object).getDisks()
	moved := mustGetUUID()
	for _, disk := range disks {
		dir := filepath.Join(disk.Endpoint().Path, r.bucket, r.object, moved)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "part.1"), []byte("staged"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	present := func() int {
		n := 0
		for _, disk := range disks {
			if _, err := os.Stat(filepath.Join(disk.Endpoint().Path, r.bucket, r.object, moved)); err == nil {
				n++
			}
		}
		return n
	}
	lk := r.z.NewObjectNSLock(r.bucket, r.object)
	lkctx, err := lk.GetLock(t.Context(), globalOperationTimeout)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	r.z.CheckAbandonedParts(ctx, r.bucket, r.object, madmin.HealOpts{Remove: true})
	cancel()
	held := present()
	lk.Unlock(lkctx)
	if held != len(disks) {
		t.Fatalf("abandoned-data cleanup removed a moved directory from %d drives while a writer held the object lock", len(disks)-held)
	}
	if err := r.z.CheckAbandonedParts(t.Context(), r.bucket, r.object, madmin.HealOpts{Remove: true}); err != nil {
		t.Fatalf("abandoned-data cleanup without a writer: %v", err)
	}
	if n := present(); n != 0 {
		t.Fatalf("abandoned-data cleanup left the unreferenced directory on %d drives", n)
	}
}

// The header flag that tells whether a transitioned version uses its data
// directory follows whether its restored copy has expired when a drive writes
// the entry. A publication's own entry is recognized with either value.
func TestRestorePublishedRevisionAcrossExpiry(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	oi, _ := nativeRestoreSeed(t, r, 0, false, false)
	fi := r.fileInfo(oi.VersionID)
	expiry := time.Now().Add(2 * time.Second).Truncate(time.Second).Add(time.Second)
	st := &restoreStage{dataDir: mustGetUUID(), expiry: expiry}
	published := restorePublished(fi, fi, st, 0)
	keys, err := fileInfoRevisions(published)
	if err != nil {
		t.Fatal(err)
	}
	stored := func() revisionKey {
		var x xlMetaV2
		if err := x.AddVersion(published); err != nil {
			t.Fatal(err)
		}
		buf, err := x.AppendTo(nil)
		if err != nil {
			t.Fatal(err)
		}
		var y xlMetaV2
		if err := y.Load(buf); err != nil {
			t.Fatal(err)
		}
		return versionRevision(y.versions[0], y.metaV)
	}
	before := stored()
	time.Sleep(time.Until(expiry) + 100*time.Millisecond)
	after := stored()
	if before == after {
		t.Fatal("fixture: the stored flag did not change at the expiry")
	}
	for _, got := range []revisionKey{before, after} {
		if got != keys[0] && got != keys[1] {
			t.Errorf("a publication's own entry is not recognized: %v not in %v", got, keys)
		}
	}
}

// A tier that lost the copy answers not found. That is no reason to keep the
// version's ongoing marker: the attempt clears it, and a later POST can
// restore the version again.
func TestRestoreTierNotFoundClearsMarker(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	oi, _ := restoreIsolationSeed(t, r, 0, false, false)
	tier := globalTierConfigMgr.drivercache["WARM"]
	globalTierConfigMgr.drivercache["WARM"] = nativeRestoreFailTier{tier, ObjectNotFound{Bucket: r.bucket, Object: r.object}}
	layer := newRestoreIsolationLayer(r)
	if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	if err := layer.wait(t); !isErrObjectNotFound(err) {
		t.Fatalf("restore from a tier without the copy: %v", err)
	}
	info, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
	if err != nil || info.RestoreOngoing || info.UserDefined[xhttp.AmzRestore] != "" {
		t.Fatalf("version after the failed restore: %q, %v", info.UserDefined[xhttp.AmzRestore], err)
	}
}

// newRestoreWideTest is newRestoreSafetyTest with one pool of twelve drives,
// whose default layout is eight data and four parity shards: a version's
// metadata reaches its read quorum on seven drives, one short of the write
// quorum of eight that its shards need.
func newRestoreWideTest(t *testing.T) *restoreTest {
	t.Helper()
	prevTier := globalTierConfigMgr
	t.Cleanup(func() { globalTierConfigMgr = prevTier })
	dirs, err := getRandomDisks(12)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeRoots(dirs) })
	obj, _, err := initObjectLayer(t.Context(), mustGetPoolEndpoints(0, dirs...))
	if err != nil {
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	t.Cleanup(func() { z.Shutdown(context.Background()) })
	// Other tests leave a storage class behind; fix the layout to 8+4.
	saved := globalStorageClass
	globalStorageClass.Update(storageclass.Config{Standard: storageclass.StorageClass{Parity: 4}})
	t.Cleanup(func() { globalStorageClass.Update(saved) })
	globalTierConfigMgr = NewTierConfigMgr()
	globalTierConfigMgr.drivercache["WARM"] = &restoreTestTier{tierExpiryTestBackend: &tierExpiryTestBackend{objects: map[string][]byte{}}}
	r := &restoreTest{t: t, z: z, bucket: getRandomBucketName(), object: "obj", labels: map[string]string{}, bodies: map[string][]byte{}}
	if err := z.MakeBucket(t.Context(), r.bucket, MakeBucketOptions{VersioningEnabled: true}); err != nil {
		t.Fatal(err)
	}
	meta, err := globalBucketMetadataSys.Get(r.bucket)
	if err != nil {
		t.Fatal(err)
	}
	meta.LifecycleConfigXML = []byte(restoreSafetyRules)
	if err := meta.Save(t.Context(), z); err != nil {
		t.Fatal(err)
	}
	globalBucketMetadataSys.Set(r.bucket, meta)
	return r
}

// On twelve drives with eight data shards, a publication that reached seven
// drives has the metadata read quorum but not the eight shards a read needs.
// It is not a restore: the worker brings every drive back to the unrestored
// version, and the version reads from its tier copy.
func TestRestorePublicationBelowWriteQuorumOnWideSet(t *testing.T) {
	r := newRestoreWideTest(t)
	oi, body := nativeRestoreSeed(t, r, 0, false, true)
	fi := r.fileInfo(oi.VersionID)
	if fi.Erasure.DataBlocks != 8 || fi.Erasure.ParityBlocks != 4 {
		t.Fatalf("fixture layout %d+%d, want 8+4", fi.Erasure.DataBlocks, fi.Erasure.ParityBlocks)
	}
	faults := &restoreTwoPhaseFaults{}
	faults.rename.Store("fail")
	disks := restoreTwoPhaseFaulty(t, r, faults, faults, faults, faults, faults)
	if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err == nil {
		t.Fatal("a publication on seven of twelve drives succeeded")
	}
	for i, e := range restoreTwoPhaseEntries(t, r, disks, oi.VersionID) {
		if !restoreTwoPhaseUnrestored(e) || e.DataDir != fi.DataDir {
			t.Errorf("drive %d after a publication on seven drives: restore %q, remote %v", i, e.Metadata[xhttp.AmzRestore], e.IsRemote())
		}
	}
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("the version no longer reads from its tier copy: %v", err)
	}
	faults.rename.Store("")
	if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err != nil {
		t.Fatalf("restore after the drives recovered: %v", err)
	}
	for i, e := range restoreTwoPhaseEntries(t, r, disks, oi.VersionID) {
		if !restoreTwoPhaseRestored(e) {
			t.Errorf("drive %d: not restored", i)
		}
	}
}

// A commit that reaches a write quorum but not every drive queues a heal of
// the version it restored: for the null version, the normalized null ID that
// the convergence path queues too. That heal repairs the null version on the
// drive that missed the commit, also where the null version is noncurrent.
func TestRestorePartialCommitQueuesNullVersionHeal(t *testing.T) {
	setTestStandardParity(t, 2)
	r := newRestoreSafetyTest(t, 1, versioning.Suspended)
	oi, body := nativeRestoreSeed(t, r, 0, true, false)
	// A version written while versioning was enabled makes the null version
	// noncurrent.
	newer := []byte("newer")
	if _, err := r.z.PutObject(t.Context(), r.bucket, r.object,
		mustGetPutObjReader(t, bytes.NewReader(newer), int64(len(newer)), "", ""), ObjectOptions{Versioned: true}); err != nil {
		t.Fatal(err)
	}

	failing := &restoreTwoPhaseFaults{}
	failing.rename.Store("fail")
	disks := restoreTwoPhaseFaulty(t, r, nil, nil, nil, failing)
	// Observe the MRF entries in place of the queue, which the heal routines
	// of the test servers consume.
	var mu sync.Mutex
	var queued []PartialOperation
	hook := func(op PartialOperation) {
		if op.Bucket == r.bucket && op.Object == r.object {
			mu.Lock()
			queued = append(queued, op)
			mu.Unlock()
		}
	}
	mrfPartialOpHook.Store(&hook)
	t.Cleanup(func() { mrfPartialOpHook.Store(nil) })
	err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
	mrfPartialOpHook.Store(nil)
	if err != nil {
		t.Fatalf("restore with one drive failing its commit: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(queued) != 1 || queued[0].VersionID != nullVersionID {
		t.Fatalf("queued heals %+v, want one of version %q", queued, nullVersionID)
	}
	if restoreTwoPhaseRestored(restoreTwoPhaseEntries(t, r, disks, oi.VersionID)[3]) {
		t.Fatal("the drive that failed the commit holds the restored copy")
	}

	failing.rename.Store("")
	if _, err := r.z.HealObject(t.Context(), r.bucket, r.object, queued[0].VersionID, madmin.HealOpts{ScanMode: madmin.HealNormalScan}); err != nil {
		t.Fatalf("heal of the queued version: %v", err)
	}
	for i, fi := range restoreTwoPhaseEntries(t, r, disks, oi.VersionID) {
		if !restoreTwoPhaseRestored(fi) {
			t.Errorf("drive %d: not restored after the heal: %q", i, fi.Metadata[xhttp.AmzRestore])
		}
	}
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("restored contents: %v", err)
	}
	if latest, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, ObjectOptions{}); err != nil || latest.VersionID == "" || latest.VersionID == nullVersionID {
		t.Fatalf("latest = %q, %v; want the newer version", latest.VersionID, err)
	}
}
