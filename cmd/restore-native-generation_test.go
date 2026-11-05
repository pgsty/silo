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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/config/drive"
	xhttp "github.com/minio/minio/internal/http"
)

// restoreGenerationDisk fails metadata writes or updates of the object, or
// metadata reads of uploads, while its toggles are set.
type restoreGenerationDisk struct {
	StorageAPI
	bucket, object            string
	write, update, uploadRead *atomic.Bool
}

func (d restoreGenerationDisk) WriteMetadata(ctx context.Context, orig, vol, path string, fi FileInfo) error {
	if d.write != nil && d.write.Load() && vol == d.bucket && path == d.object {
		return errFaultyDisk
	}
	return d.StorageAPI.WriteMetadata(ctx, orig, vol, path, fi)
}

func (d restoreGenerationDisk) UpdateMetadata(ctx context.Context, vol, path string, fi FileInfo, opts UpdateMetadataOpts) error {
	if d.update != nil && d.update.Load() && vol == d.bucket && path == d.object {
		return errFaultyDisk
	}
	return d.StorageAPI.UpdateMetadata(ctx, vol, path, fi, opts)
}

func (d restoreGenerationDisk) ReadVersion(ctx context.Context, orig, vol, path, version string, opts ReadOptions) (FileInfo, error) {
	if d.uploadRead != nil && d.uploadRead.Load() && vol == minioMetaMultipartBucket {
		return FileInfo{}, errFaultyDisk
	}
	return d.StorageAPI.ReadVersion(ctx, orig, vol, path, version, opts)
}

// restoreGenerationOffline makes a drive's object metadata unreadable and
// unwritable while set, its uploads still readable.
type restoreGenerationOffline struct {
	StorageAPI
	bucket, object string
	fail           *atomic.Bool
}

func (d restoreGenerationOffline) ReadXL(ctx context.Context, bucket, object string, data bool) (RawFileInfo, error) {
	if d.fail.Load() && bucket == d.bucket && object == d.object {
		return RawFileInfo{}, errFaultyDisk
	}
	return d.StorageAPI.ReadXL(ctx, bucket, object, data)
}

func (d restoreGenerationOffline) ReadVersion(ctx context.Context, orig, bucket, object, version string, opts ReadOptions) (FileInfo, error) {
	if d.fail.Load() && bucket == d.bucket && object == d.object {
		return FileInfo{}, errFaultyDisk
	}
	return d.StorageAPI.ReadVersion(ctx, orig, bucket, object, version, opts)
}

func (d restoreGenerationOffline) WriteMetadata(ctx context.Context, orig, bucket, object string, fi FileInfo) error {
	if d.fail.Load() && bucket == d.bucket && object == d.object {
		return errFaultyDisk
	}
	return d.StorageAPI.WriteMetadata(ctx, orig, bucket, object, fi)
}

// restoreGenerationMetadata returns the version's metadata on each drive.
func restoreGenerationMetadata(t *testing.T, disks []StorageAPI, r *restoreTest, versionID string) []map[string]string {
	t.Helper()
	metas := make([]map[string]string, len(disks))
	for i, d := range disks {
		fi, err := d.ReadVersion(t.Context(), "", r.bucket, r.object, versionID, ReadOptions{})
		if err != nil {
			t.Fatal(err)
		}
		metas[i] = fi.Metadata
	}
	return metas
}

// An Object Lock update acknowledged on a quorum, which one drive missed,
// survives POST restore: POST patches the restore fields onto the quorum's
// generation and never writes the stale drive's metadata anywhere.
func TestRestoreStatusUsesQuorumGeneration(t *testing.T) {
	for _, kind := range []string{"legal-hold", "retention"} {
		t.Run(kind, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			initConfigSubsystem(t.Context(), r.z)
			enableBucketObjectLock(t, r.bucket)
			oi, _ := nativeRestoreSeed(t, r, 0, false, false)
			if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err != nil {
				t.Fatal(err)
			}
			initial := []byte(`<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>OFF</Status></LegalHold>`)
			updated := []byte(`<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>ON</Status></LegalHold>`)
			key := strings.ToLower(xhttp.AmzObjectLockLegalHold)
			if kind == "retention" {
				initial = retentionBody("COMPLIANCE", UTCNow().Add(24*time.Hour))
				updated = retentionBody("COMPLIANCE", UTCNow().Add(48*time.Hour))
				key = strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)
			}
			if rec := nativeRestoreLockRequest(t.Context(), t, r, oi.VersionID, kind, initial); rec.Code != http.StatusOK {
				t.Fatal(rec.Body.String())
			}
			er := r.z.serverPools[0].getHashedSet(r.object)
			disks := er.getDisks()
			var fail atomic.Bool
			wrapped := append([]StorageAPI(nil), disks...)
			wrapped[0] = restoreGenerationDisk{StorageAPI: disks[0], bucket: r.bucket, object: r.object, update: &fail}
			er.getDisks = func() []StorageAPI { return wrapped }
			fail.Store(true)
			if rec := nativeRestoreLockRequest(t.Context(), t, r, oi.VersionID, kind, updated); rec.Code != http.StatusOK {
				t.Fatalf("protection update: %d %s", rec.Code, rec.Body.String())
			}
			fail.Store(false)
			before := restoreGenerationMetadata(t, disks, r, oi.VersionID)
			acknowledged := before[1][key]
			if before[0][key] == acknowledged {
				t.Fatal("fixture: drive 0 did not miss the update")
			}
			for i := 1; i < len(disks); i++ {
				if before[i][key] != acknowledged {
					t.Fatal("fixture: the update did not reach the other drives")
				}
			}
			if rec := restoreIsolationPOST(t, r, r.z, oi.VersionID); rec.Code != http.StatusOK {
				t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
			}
			after := restoreGenerationMetadata(t, disks, r, oi.VersionID)
			for i := 1; i < len(disks); i++ {
				if after[i][key] != acknowledged {
					t.Errorf("drive %d: POST wrote %q over the acknowledged %q", i, after[i][key], acknowledged)
				}
				if after[i][xhttp.AmzRestoreRequestDate] == before[i][xhttp.AmzRestoreRequestDate] {
					t.Errorf("drive %d: POST did not record its request", i)
				}
			}
			// The stale drive is left to heal; reads that pick it are not
			// changed here.
			if after[0][key] != before[0][key] || after[0][xhttp.AmzRestoreRequestDate] != before[0][xhttp.AmzRestoreRequestDate] {
				t.Error("POST wrote the stale drive instead of leaving it to heal")
			}
		})
	}
}

// The attempt is part of a version's metadata generation. A POST whose
// marker reached all drives but one is acknowledged: its restore owns the
// version, and the reset of an older attempt leaves the newer marker alone.
func TestRestoreAttemptGenerationFencing(t *testing.T) {
	for _, mode := range []string{"worker", "old-reset", "degraded-old-reset"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			initConfigSubsystem(t.Context(), r.z)
			oi, body := restoreIsolationSeed(t, r, 0, false, false)
			er := r.z.serverPools[0].getHashedSet(r.object)
			disks := er.getDisks()
			var fail, offline atomic.Bool
			wrapped := append([]StorageAPI(nil), disks...)
			wrapped[0] = restoreGenerationDisk{StorageAPI: disks[0], bucket: r.bucket, object: r.object, write: &fail}
			wrapped[1] = restoreGenerationOffline{StorageAPI: disks[1], bucket: r.bucket, object: r.object, fail: &offline}
			er.getDisks = func() []StorageAPI { return wrapped }
			captured := make(chan ObjectOptions, 2)
			layer := newRestoreIsolationLayer(r)
			layer.restore = func(_ context.Context, _, _ string, opts ObjectOptions) error {
				captured <- opts
				return nil
			}
			var older ObjectOptions
			if mode != "worker" {
				if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
					t.Fatal(rec.Body.String())
				}
				older = <-captured
				layer.wait(t)
			}
			fail.Store(true)
			rec := restoreIsolationPOST(t, r, layer, oi.VersionID)
			fail.Store(false)
			if rec.Code != http.StatusOK {
				t.Fatalf("POST on all drives but one: %d %s", rec.Code, rec.Body.String())
			}
			newer := <-captured
			layer.wait(t)
			id := newer.Transition.attempt.ID
			if mode == "worker" {
				if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, newer); err != nil {
					t.Fatalf("restore of the acknowledged attempt: %v", err)
				}
				if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
					t.Fatalf("restored contents: %v", err)
				}
				return
			}
			if mode == "degraded-old-reset" {
				// One drive of the newer attempt is unreadable: the drives
				// that answer no longer show which attempt is acknowledged.
				offline.Store(true)
			}
			if err := r.z.resetRestoreStatus(r.bucket, r.object, older); err != nil {
				t.Fatal(err)
			}
			offline.Store(false)
			after := restoreGenerationMetadata(t, disks, r, oi.VersionID)
			for i := 1; i < len(disks); i++ {
				if after[i][restoreAttemptKey] != id || !strings.Contains(after[i][xhttp.AmzRestore], "true") {
					t.Errorf("drive %d: the older attempt's reset cleared the newer marker: %q %q", i, after[i][restoreAttemptKey], after[i][xhttp.AmzRestore])
				}
			}
			if after[0][restoreAttemptKey] != older.Transition.attempt.ID {
				t.Error("the reset wrote the stale drive")
			}
			// The newer attempt still owns the version and restores it.
			if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, newer); err != nil {
				t.Fatalf("restore of the newer attempt after the older reset: %v", err)
			}
			if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("restored contents: %v", err)
			}
		})
	}
}

// restoreGenerationUploadPath is the stored path of an upload.
func restoreGenerationUploadPath(t *testing.T, r *restoreTest, id string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatal(err)
	}
	_, uploadUUID, ok := strings.Cut(string(b), ".")
	if !ok {
		t.Fatalf("upload ID without UUID: %q", id)
	}
	return pathJoin(r.z.serverPools[0].getHashedSet(r.object).getMultipartSHADir(r.bucket, r.object), uploadUUID)
}

// The restore marker is established on a majority of the drives. One drive
// whose copy of the upload lacks it does not open the upload to clients,
// and the restore still completes.
func TestRestoreUploadMarkerQuorum(t *testing.T) {
	r := newRestoreSafetyTest(t, 2, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	oi, body := restoreIsolationSeed(t, r, 0, false, true)
	tier := newRestoreIsolationGateTier(5<<20, nil)
	globalTierConfigMgr.drivercache["WARM"] = tier
	defer tier.unblock()
	layer := newRestoreIsolationLayer(r)
	if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	restoreIsolationEntered(t, tier)
	id, _ := restoreIsolationUpload(t, r, 0)
	disk := r.z.serverPools[0].getHashedSet(r.object).getDisks()[0]
	path := restoreGenerationUploadPath(t, r, id)
	fi, err := disk.ReadVersion(t.Context(), "", minioMetaMultipartBucket, path, "", ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	delete(fi.Metadata, restoreUploadKey)
	if err := disk.WriteMetadata(t.Context(), "", minioMetaMultipartBucket, path, fi); err != nil {
		t.Fatal(err)
	}
	poison := bytes.Repeat([]byte("p"), 5<<20)
	if _, err := r.z.PutObjectPart(t.Context(), r.bucket, r.object, id, 1,
		mustGetPutObjReader(t, bytes.NewReader(poison), int64(len(poison)), "", ""), ObjectOptions{}); !errors.As(err, &InvalidUploadID{}) {
		t.Errorf("public part with one unmarked copy of the upload: %v, want NoSuchUpload", err)
	}
	for _, op := range []func() error{
		func() error {
			_, err := r.z.ListObjectParts(t.Context(), r.bucket, r.object, id, 0, 10, ObjectOptions{})
			return err
		},
		func() error {
			_, err := r.z.GetMultipartInfo(t.Context(), r.bucket, r.object, id, ObjectOptions{})
			return err
		},
	} {
		if err := op(); !errors.As(err, &InvalidUploadID{}) {
			t.Errorf("public read with one unmarked copy of the upload: %v, want NoSuchUpload", err)
		}
	}
	if uploads, err := r.z.ListMultipartUploads(t.Context(), r.bucket, r.object, "", "", "", 10); err != nil || len(uploads.Uploads) != 0 {
		t.Errorf("listing with one unmarked copy of the upload: %+v, %v", uploads.Uploads, err)
	}
	tier.unblock()
	if err := layer.wait(t); err != nil {
		t.Fatal(err)
	}
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("restore contents: %v", err)
	}
}

// When the drives cannot tell an upload's marker, no client lists it, no
// abort removes it and stale cleanup keeps it; the restore completes once
// the drives answer again.
func TestRestoreUploadUnreadableFailsClosed(t *testing.T) {
	for _, mode := range []string{"list", "abort", "stale"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 2, versioning.Enabled)
			initConfigSubsystem(t.Context(), r.z)
			oi, body := restoreIsolationSeed(t, r, 0, false, true)
			er := r.z.serverPools[0].getHashedSet(r.object)
			disks := er.getDisks()
			var fail atomic.Bool
			// Stale cleanup with a short age also removes in-flight temporary
			// parts: hold that restore in completion, after its last part and
			// before its commit, and the others in their download, outside
			// the upload lock.
			gate := &restoreIsolationCompletionGate{entered: make(chan struct{}), release: make(chan struct{})}
			defer gate.unblock()
			tier := newRestoreIsolationGateTier(5<<20, nil)
			defer tier.unblock()
			wrapped := make([]StorageAPI, len(disks))
			for i, d := range disks {
				disk := d
				if mode == "stale" {
					disk = restoreIsolationValidationDisk{d, gate}
				}
				wrapped[i] = restoreGenerationDisk{StorageAPI: disk, uploadRead: &fail}
			}
			er.getDisks = func() []StorageAPI { return wrapped }
			if mode != "stale" {
				globalTierConfigMgr.drivercache["WARM"] = tier
			}
			layer := newRestoreIsolationLayer(r)
			if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
				t.Fatal(rec.Body.String())
			}
			if mode == "stale" {
				select {
				case <-gate.entered:
				case <-time.After(restoreTestWait):
					t.Fatal("restore never reached completion")
				}
			} else {
				restoreIsolationEntered(t, tier)
			}
			stored := restoreIsolationUploads(t, r, 0)
			if len(stored) != 1 {
				t.Fatalf("restore upload on disk: %v", stored)
			}
			var id string
			for uploadUUID := range stored {
				id = base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "%s.%s", globalDeploymentID(), uploadUUID))
			}
			fail.Store(true)
			switch mode {
			case "list":
				if uploads, err := r.z.ListMultipartUploads(t.Context(), r.bucket, r.object, "", "", "", 100); len(uploads.Uploads) != 0 {
					t.Errorf("an upload with an unknown marker is listed: %+v, %v", uploads.Uploads, err)
				}
			case "abort":
				if err := r.z.AbortMultipartUpload(t.Context(), r.bucket, r.object, id, ObjectOptions{}); err == nil {
					t.Error("abort of an upload with an unknown marker succeeded")
				}
			case "stale":
				globalAPIConfig.mu.Lock()
				prev := globalAPIConfig.staleUploadsExpiry
				globalAPIConfig.staleUploadsExpiry = time.Nanosecond
				globalAPIConfig.mu.Unlock()
				for _, disk := range wrapped {
					er.cleanupStaleUploadsOnDisk(t.Context(), disk)
				}
				globalAPIConfig.mu.Lock()
				globalAPIConfig.staleUploadsExpiry = prev
				globalAPIConfig.mu.Unlock()
			}
			fail.Store(false)
			if uploads := restoreIsolationUploads(t, r, 0); len(uploads) != 1 {
				t.Errorf("%s removed an upload with an unknown marker: %v", mode, uploads)
			}
			gate.unblock()
			tier.unblock()
			if err := layer.wait(t); err != nil {
				t.Fatalf("restore after %s: %v", mode, err)
			}
			if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("restore contents: %v", err)
			}
		})
	}
}

// POST restores the version it resolved with that version's identity. A
// replacement under the same version ID between its read and its status
// write is refused, and nothing restores it.
func TestRestorePOSTRejectsReplacedTarget(t *testing.T) {
	for _, state := range []versioning.State{"", versioning.Suspended} {
		t.Run(fmt.Sprintf("versioning=%q", state), func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, state)
			initConfigSubsystem(t.Context(), r.z)
			oi, _ := restoreIsolationSeed(t, r, 0, true, false)
			layer := newRestoreIsolationLayer(r)
			var replacement ObjectInfo
			layer.afterRead = func() {
				data := []byte("replacement after POST resolved its target")
				var err error
				replacement, err = r.z.PutObject(t.Context(), r.bucket, r.object,
					mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{VersionSuspended: state == versioning.Suspended})
				if err != nil {
					t.Fatal(err)
				}
				opts := r.opts(nullVersionID)
				opts.MTime = replacement.ModTime
				opts.Transition = TransitionOptions{Tier: "WARM", ETag: replacement.ETag}
				if err := r.z.serverPools[0].TransitionObject(t.Context(), r.bucket, r.object, opts); err != nil {
					t.Fatal(err)
				}
			}
			if rec := restoreIsolationPOST(t, r, layer, ""); rec.Code < 400 {
				layer.wait(t)
				t.Errorf("POST accepted a replacement of its target: %d", rec.Code)
			}
			after, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(nullVersionID))
			if err != nil {
				t.Fatal(err)
			}
			if after.ETag != replacement.ETag || after.UserDefined[xhttp.AmzRestore] != "" || after.ETag == oi.ETag {
				t.Errorf("replacement %q changed by POST: etag %q restore %q", replacement.ETag, after.ETag, after.UserDefined[xhttp.AmzRestore])
			}
		})
	}
}

// A POST on a version whose restore holds the object lock answers within
// the two-second takeover bound: its first read does not wait for the lock.
func TestRestorePOSTOngoingBound(t *testing.T) {
	for _, mode := range []string{"pools=1", "pools=2", "stale-minority", "failed-activity-read"} {
		t.Run(mode, func(t *testing.T) {
			pools := 1
			if mode == "pools=2" {
				pools = 2
			}
			r := newRestoreSafetyTest(t, pools, versioning.Enabled)
			initConfigSubsystem(t.Context(), r.z)
			oi, _ := restoreIsolationSeed(t, r, 0, false, false)
			tier := newRestoreIsolationGateTier(0, nil)
			globalTierConfigMgr.drivercache["WARM"] = tier
			defer tier.unblock()
			var fail atomic.Bool
			if mode == "stale-minority" {
				// The first read may pick a drive that missed the marker.
				er := r.z.serverPools[0].getHashedSet(r.object)
				disks := er.getDisks()
				wrapped := append([]StorageAPI(nil), disks...)
				wrapped[0] = restoreGenerationDisk{StorageAPI: disks[0], bucket: r.bucket, object: r.object, write: &fail}
				er.getDisks = func() []StorageAPI { return wrapped }
				fail.Store(true)
			}
			layer := newRestoreIsolationLayer(r)
			rec := restoreIsolationPOST(t, r, layer, oi.VersionID)
			fail.Store(false)
			if rec.Code != http.StatusOK {
				t.Fatal(rec.Body.String())
			}
			restoreIsolationEntered(t, tier)
			var unreadable atomic.Bool
			second := newRestoreIsolationLayer(r)
			if mode == "failed-activity-read" {
				// Once POST resolved its target, nothing tells whether it
				// is restoring.
				er := r.z.serverPools[0].getHashedSet(r.object)
				disks := er.getDisks()
				wrapped := make([]StorageAPI, len(disks))
				for i, d := range disks {
					wrapped[i] = restoreGenerationOffline{StorageAPI: d, bucket: r.bucket, object: r.object, fail: &unreadable}
				}
				er.getDisks = func() []StorageAPI { return wrapped }
				second.afterRead = func() { unreadable.Store(true) }
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			start := time.Now()
			go func() { done <- restoreIsolationPOST(t, r, second, oi.VersionID) }()
			select {
			case rec := <-done:
				want := rec.Code == http.StatusConflict
				if mode == "failed-activity-read" {
					want = rec.Code >= 500
				}
				if !want || time.Since(start) > restoreTakeoverWait+time.Second {
					t.Errorf("POST during a running restore: %d after %s, want a bounded refusal", rec.Code, time.Since(start))
				}
			case <-time.After(restoreTakeoverWait + 2*time.Second):
				t.Error("POST during a running restore waited for the object lock")
				unreadable.Store(false)
				tier.unblock()
				<-done
			}
			unreadable.Store(false)
			tier.unblock()
			if err := layer.wait(t); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A POST whose status write fails on drives that stay unwritten puts the
// generation it read back, and a split that a failed put-back leaves
// differs only in restore fields: the attempt's reset and a later POST both
// resolve it, while every other field still needs the quorum.
func TestRestorePOSTStatusWriteSplit(t *testing.T) {
	for _, mode := range []string{"put-back", "split-reset", "split-post"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			initConfigSubsystem(t.Context(), r.z)
			oi, body := restoreIsolationSeed(t, r, 0, false, false)
			er := r.z.serverPools[0].getHashedSet(r.object)
			disks := er.getDisks()
			var fail atomic.Bool
			wrapped := append([]StorageAPI(nil), disks...)
			for i := range 2 {
				wrapped[i] = restoreGenerationDisk{StorageAPI: disks[i], bucket: r.bucket, object: r.object, write: &fail}
			}
			er.getDisks = func() []StorageAPI { return wrapped }
			before := restoreGenerationMetadata(t, disks, r, oi.VersionID)
			var attempt *restoreAttempt
			if mode == "put-back" {
				fail.Store(true)
				rec := restoreIsolationPOST(t, r, r.z, oi.VersionID)
				fail.Store(false)
				if rec.Code < 400 {
					t.Fatalf("POST acknowledged a status write on two of four drives: %d", rec.Code)
				}
				if after := restoreGenerationMetadata(t, disks, r, oi.VersionID); !reflect.DeepEqual(before, after) {
					t.Error("failed status write was not put back")
				}
			} else {
				// A status write and its put-back both failed on two drives.
				attempt = newRestoreAttempt(oi)
				for _, d := range disks[2:] {
					fi, err := d.ReadVersion(t.Context(), "", r.bucket, r.object, oi.VersionID, ReadOptions{ReadData: true})
					if err != nil {
						t.Fatal(err)
					}
					fi.Metadata[xhttp.AmzRestore] = ongoingRestoreObj().String()
					fi.Metadata[restoreAttemptKey] = attempt.ID
					if err := d.WriteMetadata(t.Context(), "", r.bucket, r.object, fi); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := er.readRestoreGeneration(t.Context(), r.bucket, r.object, oi.VersionID); err != nil {
					t.Fatalf("a split in restore fields only has no generation: %v", err)
				}
			}
			if mode == "split-reset" {
				opts := nativeRestoreOptions(r, oi.VersionID)
				opts.Transition.attempt = attempt
				if err := r.z.resetRestoreStatus(r.bucket, r.object, opts); err != nil {
					t.Fatalf("reset of the split attempt: %v", err)
				}
				for i, meta := range restoreGenerationMetadata(t, disks, r, oi.VersionID) {
					if meta[xhttp.AmzRestore] != "" || meta[restoreAttemptKey] != "" {
						t.Errorf("drive %d keeps the split attempt: %q %q", i, meta[xhttp.AmzRestore], meta[restoreAttemptKey])
					}
				}
			}
			layer := newRestoreIsolationLayer(r)
			if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
				t.Fatalf("POST after the failed status write: %d %s", rec.Code, rec.Body.String())
			}
			if err := layer.wait(t); err != nil {
				t.Fatal(err)
			}
			if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("restore contents: %v", err)
			}
		})
	}
}

// A split in any other field is not resolved: the generation fails closed.
func TestRestoreGenerationSplitNeedsQuorum(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	oi, _ := restoreIsolationSeed(t, r, 0, false, false)
	er := r.z.serverPools[0].getHashedSet(r.object)
	for i, d := range er.getDisks()[2:] {
		fi, err := d.ReadVersion(t.Context(), "", r.bucket, r.object, oi.VersionID, ReadOptions{ReadData: true})
		if err != nil {
			t.Fatal(err)
		}
		fi.Metadata[xhttp.AmzRestore] = ongoingRestoreObj().String()
		fi.Metadata[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = fmt.Sprint("ON", i)
		if err := d.WriteMetadata(t.Context(), "", r.bucket, r.object, fi); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := er.readRestoreGeneration(t.Context(), r.bucket, r.object, oi.VersionID); !errors.Is(err, errErasureReadQuorum) {
		t.Fatalf("split outside the restore fields: %v, want read quorum", err)
	}
	if rec := restoreIsolationPOST(t, r, r.z, oi.VersionID); rec.Code < 400 {
		t.Errorf("POST over a split outside the restore fields: %d", rec.Code)
	}
}

// restoreGenerationStageDisk holds a completion that is staging: as
// xlStorage.RenameData does, a drive that stages writes the committed
// object metadata into the upload before it renames the upload into the
// object.
type restoreGenerationStageDisk struct {
	StorageAPI
	bucket, object string
	stage          bool
	arrived        *atomic.Int32
	entered        chan struct{}
	release        chan struct{}
	disks          int32
}

func (d restoreGenerationStageDisk) RenameData(ctx context.Context, srcVolume, srcPath string, fi FileInfo, dstVolume, dstPath string, opts RenameOptions) (RenameDataResp, error) {
	if srcVolume == minioMetaMultipartBucket && dstVolume == d.bucket && dstPath == d.object {
		if d.stage {
			if err := d.StorageAPI.WriteMetadata(ctx, "", srcVolume, srcPath, fi); err != nil {
				return RenameDataResp{}, err
			}
		}
		if d.arrived.Add(1) == d.disks {
			close(d.entered)
		}
		select {
		case <-d.release:
		case <-ctx.Done():
			return RenameDataResp{}, ctx.Err()
		}
	}
	return d.StorageAPI.RenameData(ctx, srcVolume, srcPath, fi, dstVolume, dstPath, opts)
}

// While a completion stages its commit, the upload holds object metadata
// without the marker on the drives that staged. Nobody lists, aborts or
// removes it then, also when the copies not staged yet are old.
func TestRestoreUploadStagingFailsClosed(t *testing.T) {
	for _, mode := range []string{"staged", "partly-staged", "stalled-commit"} {
		t.Run(mode, func(t *testing.T) { testRestoreUploadStaging(t, mode) })
	}
}

func testRestoreUploadStaging(t *testing.T, mode string) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	oi, body := restoreIsolationSeed(t, r, 0, false, true)
	er := r.z.serverPools[0].getHashedSet(r.object)
	disks := er.getDisks()
	var arrived atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	wrapped := make([]StorageAPI, len(disks))
	for i, d := range disks {
		wrapped[i] = restoreGenerationStageDisk{StorageAPI: d, bucket: r.bucket, object: r.object, stage: mode != "partly-staged" || i == 0,
			arrived: &arrived, entered: entered, release: release, disks: int32(len(disks))}
	}
	er.getDisks = func() []StorageAPI { return wrapped }
	layer := newRestoreIsolationLayer(r)
	if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	select {
	case <-entered:
	case <-time.After(restoreTestWait):
		t.Fatal("completion never staged its commit")
	}
	stored := restoreIsolationUploads(t, r, 0)
	var id string
	for uploadUUID := range stored {
		id = base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "%s.%s", globalDeploymentID(), uploadUUID))
		if mode != "staged" {
			// partly-staged: a long restore, the copies not staged yet are
			// old. stalled-commit: drives that stall the running commit
			// past the grace make its staged copies look abandoned.
			old := UTCNow().Add(-48 * time.Hour)
			for _, d := range disks[1:] {
				if err := os.Chtimes(pathJoin(d.Endpoint().Path, minioMetaMultipartBucket, er.getMultipartSHADir(r.bucket, r.object), uploadUUID, xlStorageFormatFile), old, old); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if uploads, err := r.z.ListMultipartUploads(t.Context(), r.bucket, r.object, "", "", "", 10); err != nil || len(uploads.Uploads) != 0 {
		t.Errorf("a staged restore upload is listed: %+v, %v", uploads.Uploads, err)
	}
	// The set's own abort: the pools layer would wait for the upload lock
	// the completion holds.
	if err := er.AbortMultipartUpload(t.Context(), r.bucket, r.object, id, ObjectOptions{}); err == nil {
		t.Error("abort of a staged restore upload succeeded")
	}
	globalAPIConfig.mu.Lock()
	prev := globalAPIConfig.staleUploadsExpiry
	globalAPIConfig.staleUploadsExpiry = time.Nanosecond
	globalAPIConfig.mu.Unlock()
	for _, disk := range wrapped {
		er.cleanupStaleUploadsOnDisk(t.Context(), disk)
	}
	globalAPIConfig.mu.Lock()
	globalAPIConfig.staleUploadsExpiry = prev
	globalAPIConfig.mu.Unlock()
	if after := restoreIsolationUploads(t, r, 0); !reflect.DeepEqual(after, stored) {
		t.Errorf("a staged restore upload was removed: %v -> %v", stored, after)
	}
	released = true
	close(release)
	if err := layer.wait(t); err != nil {
		t.Fatalf("restore after its staging was attacked: %v", err)
	}
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("restore contents: %v", err)
	}
}

// When a drive of an acknowledged attempt becomes unreadable, the drives that
// answer disagree on the restore status. That the attempt ended is then not
// established, and stale cleanup keeps its upload.
func TestRestoreSplitKeepsRunningUpload(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	oi, body := restoreIsolationSeed(t, r, 0, false, true)
	er := r.z.serverPools[0].getHashedSet(r.object)
	disks := er.getDisks()
	var missed, offline atomic.Bool
	gate := &restoreIsolationCompletionGate{entered: make(chan struct{}), release: make(chan struct{})}
	defer gate.unblock()
	wrapped := make([]StorageAPI, len(disks))
	for i, d := range disks {
		var disk StorageAPI = restoreIsolationValidationDisk{d, gate}
		switch i {
		case 0:
			disk = restoreGenerationDisk{StorageAPI: disk, bucket: r.bucket, object: r.object, write: &missed}
		case 1:
			disk = restoreGenerationOffline{StorageAPI: disk, bucket: r.bucket, object: r.object, fail: &offline}
		}
		wrapped[i] = disk
	}
	er.getDisks = func() []StorageAPI { return wrapped }
	layer := newRestoreIsolationLayer(r)
	missed.Store(true)
	rec := restoreIsolationPOST(t, r, layer, oi.VersionID)
	missed.Store(false)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	select {
	case <-gate.entered:
	case <-time.After(restoreTestWait):
		t.Fatal("restore never reached completion")
	}
	stored := restoreIsolationUploads(t, r, 0)
	offline.Store(true)
	if gen, err := er.readRestoreGeneration(t.Context(), r.bucket, r.object, oi.VersionID); err != nil || !gen.split {
		t.Fatalf("fixture: no split generation: %v", err)
	}
	globalAPIConfig.mu.Lock()
	prev := globalAPIConfig.staleUploadsExpiry
	globalAPIConfig.staleUploadsExpiry = time.Nanosecond
	globalAPIConfig.mu.Unlock()
	for _, disk := range wrapped {
		er.cleanupStaleUploadsOnDisk(t.Context(), disk)
	}
	globalAPIConfig.mu.Lock()
	globalAPIConfig.staleUploadsExpiry = prev
	globalAPIConfig.mu.Unlock()
	offline.Store(false)
	if after := restoreIsolationUploads(t, r, 0); !reflect.DeepEqual(after, stored) {
		t.Errorf("stale cleanup removed a running restore's upload: %v -> %v", stored, after)
	}
	gate.unblock()
	if err := layer.wait(t); err != nil {
		t.Fatalf("restore after the split: %v", err)
	}
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("restore contents: %v", err)
	}
}

// restoreGenerationCleanupDisk misses restored-copy cleanups and metadata
// writes of the object while its toggles are set.
type restoreGenerationCleanupDisk struct {
	StorageAPI
	bucket, object      string
	cleanup, metaWrites *atomic.Bool
}

func (d restoreGenerationCleanupDisk) DeleteVersion(ctx context.Context, bucket, object string, fi FileInfo, force bool, opts DeleteOptions) error {
	if bucket == d.bucket && object == d.object && fi.ExpireRestored && d.cleanup.Load() {
		return errFaultyDisk
	}
	return d.StorageAPI.DeleteVersion(ctx, bucket, object, fi, force, opts)
}

func (d restoreGenerationCleanupDisk) WriteMetadata(ctx context.Context, orig, bucket, object string, fi FileInfo) error {
	if bucket == d.bucket && object == d.object && d.metaWrites.Load() {
		return errFaultyDisk
	}
	return d.StorageAPI.WriteMetadata(ctx, orig, bucket, object, fi)
}

// Restored-copy expiry decides on the version's authoritative generation. A
// drive that missed a cleanup and the POST after it keeps an expired header,
// which must not clear the quorum's ongoing restore; drives split between
// an expired and a renewed header authorize nothing.
func TestExpireRestoredUsesQuorumGeneration(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, mode := range []string{"after-partial-cleanup", "split-renewal"} {
			t.Run(fmt.Sprintf("pools=%d/%s", pools, mode), func(t *testing.T) {
				r := newRestoreSafetyTest(t, pools, versioning.Enabled)
				initConfigSubsystem(t.Context(), r.z)
				oi := r.put("cache", false, true)
				r.restore(oi)
				stale, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
				if err != nil {
					t.Fatal(err)
				}
				er := r.z.serverPools[0].getHashedSet(r.object)
				disks := er.getDisks()
				expire := func() error {
					return expireTransitionedObject(t.Context(), r.z, &stale, lifecycle.Event{Action: lifecycle.DeleteRestoredAction}, lcEventSrc_Scanner)
				}
				if mode == "split-renewal" {
					// A renewal reached two drives; the other two keep the
					// expired header.
					dataDir := r.fileInfo(oi.VersionID).DataDir
					for _, d := range disks[2:] {
						fi, err := d.ReadVersion(t.Context(), "", r.bucket, r.object, oi.VersionID, ReadOptions{ReadData: true})
						if err != nil {
							t.Fatal(err)
						}
						fi.Metadata[xhttp.AmzRestore] = completedRestoreObj(UTCNow().Add(48 * time.Hour)).String()
						if err := d.WriteMetadata(t.Context(), "", r.bucket, r.object, fi); err != nil {
							t.Fatal(err)
						}
					}
					if err := expire(); err == nil || r.dataDirs(dataDir) != len(disks) {
						t.Errorf("expiry on drives split between expired and renewed: %v, %d/%d cache dirs", err, r.dataDirs(dataDir), len(disks))
					}
					return
				}
				var cleanup, metaWrites atomic.Bool
				wrapped := append([]StorageAPI(nil), disks...)
				wrapped[0] = restoreGenerationCleanupDisk{StorageAPI: disks[0], bucket: r.bucket, object: r.object, cleanup: &cleanup, metaWrites: &metaWrites}
				er.getDisks = func() []StorageAPI { return wrapped }
				cleanup.Store(true)
				err = expire()
				cleanup.Store(false)
				if err != nil {
					t.Fatalf("cleanup on all drives but one: %v", err)
				}
				captured := make(chan ObjectOptions, 1)
				layer := newRestoreIsolationLayer(r)
				layer.restore = func(_ context.Context, _, _ string, opts ObjectOptions) error {
					captured <- opts
					return nil
				}
				metaWrites.Store(true)
				rec := restoreIsolationPOST(t, r, layer, oi.VersionID)
				metaWrites.Store(false)
				if rec.Code != http.StatusOK {
					t.Fatalf("POST after the cleanup: %d %s", rec.Code, rec.Body.String())
				}
				opts := <-captured
				layer.wait(t)
				// The same cleanup, queued twice, runs again.
				if err := expire(); err == nil {
					t.Error("a drive's expired header cleared the quorum's ongoing restore")
				}
				if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, opts); err != nil {
					t.Fatalf("restore of the acknowledged attempt: %v", err)
				}
				if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, r.bodies["cache"]) {
					t.Fatalf("restored contents: %v", err)
				}
			})
		}
	}
}

// restoreGenerationHidden hides a drive's copy of the object version while
// set, as a drive that lost it and that heal writes again.
type restoreGenerationHidden struct {
	StorageAPI
	bucket, object string
	hidden         *atomic.Bool
}

func (d restoreGenerationHidden) ReadVersion(ctx context.Context, orig, bucket, object, version string, opts ReadOptions) (FileInfo, error) {
	if d.hidden.Load() && bucket == d.bucket && object == d.object {
		return FileInfo{}, errFileNotFound
	}
	return d.StorageAPI.ReadVersion(ctx, orig, bucket, object, version, opts)
}

// Heal copies the restore fields to a drive only as a quorum of the drives
// holds them. While they disagree, healing the version waits: it must not
// create a quorum for an expired header over a renewal, nor for a
// superseded attempt. Fields a quorum agrees on are copied.
func TestRestoreHealNeedsRestoreQuorum(t *testing.T) {
	for _, mode := range []string{"expired-over-renewal", "superseded-attempt", "agreed"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			initConfigSubsystem(t.Context(), r.z)
			er := r.z.serverPools[0].getHashedSet(r.object)
			disks := er.getDisks()
			setRestore := func(versionID string, drives []StorageAPI, fields map[string]string) {
				for _, d := range drives {
					fi, err := d.ReadVersion(t.Context(), "", r.bucket, r.object, versionID, ReadOptions{ReadData: true})
					if err != nil {
						t.Fatal(err)
					}
					maps.Copy(fi.Metadata, fields)
					if err := d.WriteMetadata(t.Context(), "", r.bucket, r.object, fi); err != nil {
						t.Fatal(err)
					}
				}
			}
			var versionID string
			var stale ObjectInfo
			var older ObjectOptions
			hide := 3
			switch mode {
			case "expired-over-renewal", "agreed":
				oi := r.put("cache", false, true)
				r.restore(oi)
				versionID = oi.VersionID
				var err error
				if stale, err = r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(versionID)); err != nil {
					t.Fatal(err)
				}
				renewed := map[string]string{xhttp.AmzRestore: completedRestoreObj(UTCNow().Add(48 * time.Hour)).String()}
				if mode == "agreed" {
					// Three drives renewed, the hidden one expired.
					setRestore(versionID, disks[:3], renewed)
				} else {
					// No quorum: two drives expired an hour ago, one renewed,
					// and the hidden one expired a day ago.
					setRestore(versionID, disks[:2], map[string]string{xhttp.AmzRestore: completedRestoreObj(UTCNow().Add(-time.Hour)).String()})
					setRestore(versionID, disks[2:3], renewed)
				}
			case "superseded-attempt":
				oi, _ := restoreIsolationSeed(t, r, 0, false, false)
				versionID = oi.VersionID
				captured := make(chan ObjectOptions, 1)
				layer := newRestoreIsolationLayer(r)
				layer.restore = func(_ context.Context, _, _ string, opts ObjectOptions) error {
					captured <- opts
					return nil
				}
				if rec := restoreIsolationPOST(t, r, layer, versionID); rec.Code != http.StatusOK {
					t.Fatal(rec.Body.String())
				}
				older = <-captured
				layer.wait(t)
				// A newer attempt reached two drives.
				setRestore(versionID, disks[2:], map[string]string{xhttp.AmzRestore: ongoingRestoreObj().String(), restoreAttemptKey: newRestoreAttempt(oi).ID})
				hide = 2
			}
			before := restoreGenerationMetadata(t, disks, r, versionID)
			var hidden atomic.Bool
			wrapped := append([]StorageAPI(nil), disks...)
			wrapped[hide] = restoreGenerationHidden{StorageAPI: disks[hide], bucket: r.bucket, object: r.object, hidden: &hidden}
			er.getDisks = func() []StorageAPI { return wrapped }
			hidden.Store(true)
			_, healErr := er.HealObject(t.Context(), r.bucket, r.object, versionID, madmin.HealOpts{ScanMode: madmin.HealNormalScan})
			hidden.Store(false)
			er.getDisks = func() []StorageAPI { return disks }
			after := restoreGenerationMetadata(t, disks, r, versionID)
			if mode == "agreed" {
				if healErr != nil || after[hide][xhttp.AmzRestore] != after[0][xhttp.AmzRestore] {
					t.Errorf("heal did not copy the restore fields a quorum holds: %v, %q", healErr, after[hide][xhttp.AmzRestore])
				}
				return
			}
			if healErr == nil {
				t.Error("heal proceeded on drives that disagree on the restore fields")
			}
			if after[hide][xhttp.AmzRestore] != before[hide][xhttp.AmzRestore] || after[hide][restoreAttemptKey] != before[hide][restoreAttemptKey] {
				t.Errorf("heal wrote a minority restore state: %q -> %q", before[hide][xhttp.AmzRestore], after[hide][xhttp.AmzRestore])
			}
			if mode == "expired-over-renewal" {
				dataDir := r.fileInfo(versionID).DataDir
				if err := expireTransitionedObject(t.Context(), r.z, &stale, lifecycle.Event{Action: lifecycle.DeleteRestoredAction}, lcEventSrc_Scanner); err == nil || r.dataDirs(dataDir) != len(disks) {
					t.Errorf("expiry after heal: %v, %d/%d cache dirs", err, r.dataDirs(dataDir), len(disks))
				}
				return
			}
			if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, older); !errors.Is(err, errRestoreSuperseded) {
				t.Errorf("superseded attempt after heal: %v", err)
			}
		})
	}
}

// restoreGenerationStageFails fails the commit before it stages.
type restoreGenerationStageFails struct {
	StorageAPI
	bucket, object string
}

func (d restoreGenerationStageFails) RenameData(ctx context.Context, srcVolume, srcPath string, fi FileInfo, dstVolume, dstPath string, opts RenameOptions) (RenameDataResp, error) {
	if srcVolume == minioMetaMultipartBucket && dstVolume == d.bucket && dstPath == d.object {
		return RenameDataResp{}, errFaultyDisk
	}
	return d.StorageAPI.RenameData(ctx, srcVolume, srcPath, fi, dstVolume, dstPath, opts)
}

// restoreGenerationFailedCommit stages the committed metadata into the
// upload, as RenameData does, and then fails the commit.
type restoreGenerationFailedCommit struct {
	StorageAPI
	bucket, object string
}

func (d restoreGenerationFailedCommit) RenameData(ctx context.Context, srcVolume, srcPath string, fi FileInfo, dstVolume, dstPath string, opts RenameOptions) (RenameDataResp, error) {
	if srcVolume == minioMetaMultipartBucket && dstVolume == d.bucket && dstPath == d.object {
		if err := d.StorageAPI.WriteMetadata(ctx, "", srcVolume, srcPath, fi); err != nil {
			return RenameDataResp{}, err
		}
		return RenameDataResp{}, errFaultyDisk
	}
	return d.StorageAPI.RenameData(ctx, srcVolume, srcPath, fi, dstVolume, dstPath, opts)
}

// restoreGenerationLeftover runs a restore whose commit fails after it
// staged on every drive, or on every drive but drive 0, which fails before
// it stages. It returns the upload left behind and its on-disk UUID.
func restoreGenerationLeftover(t *testing.T, r *restoreTest, unstaged bool) (map[string]int, string) {
	t.Helper()
	initConfigSubsystem(t.Context(), r.z)
	oi, _ := restoreIsolationSeed(t, r, 0, false, true)
	er := r.z.serverPools[0].getHashedSet(r.object)
	disks := er.getDisks()
	wrapped := make([]StorageAPI, len(disks))
	for i, d := range disks {
		if unstaged && i == 0 {
			wrapped[i] = restoreGenerationStageFails{StorageAPI: d, bucket: r.bucket, object: r.object}
			continue
		}
		wrapped[i] = restoreGenerationFailedCommit{StorageAPI: d, bucket: r.bucket, object: r.object}
	}
	er.getDisks = func() []StorageAPI { return wrapped }
	layer := newRestoreIsolationLayer(r)
	if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if err := layer.wait(t); err == nil {
		t.Fatal("fixture: the failed commit succeeded")
	}
	er.getDisks = func() []StorageAPI { return disks }
	stored := restoreIsolationUploads(t, r, 0)
	if len(stored) != 1 {
		t.Fatalf("fixture: no leftover of the failed commit: %v", stored)
	}
	for uploadUUID := range stored {
		return stored, uploadUUID
	}
	return nil, ""
}

// restoreGenerationAgeUpload makes every drive's copy of an upload's
// metadata look written d ago.
func restoreGenerationAgeUpload(t *testing.T, r *restoreTest, uploadUUID string, d time.Duration) {
	t.Helper()
	er := r.z.serverPools[0].getHashedSet(r.object)
	old := UTCNow().Add(-d)
	for _, disk := range er.getDisks() {
		if err := os.Chtimes(pathJoin(disk.Endpoint().Path, minioMetaMultipartBucket, er.getMultipartSHADir(r.bucket, r.object), uploadUUID, xlStorageFormatFile), old, old); err != nil {
			t.Fatal(err)
		}
	}
}

// What a failed commit leaves in an upload can always be removed once every
// copy is staged and older than the commit grace: abort removes it, also
// when stale cleanup could not. A recent staging, a copy that cannot be read
// and a copy not staged yet are refused, and nothing is removed then.
func TestRestoreAbandonedCommitAbort(t *testing.T) {
	for _, age := range []string{"recent", "abandoned", "unreadable-copy", "unstaged-copy"} {
		t.Run(age, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			stored, uploadUUID := restoreGenerationLeftover(t, r, age == "unstaged-copy")
			if age != "recent" {
				restoreGenerationAgeUpload(t, r, uploadUUID, 2*restoreCommitGrace)
			}
			id := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "%s.%s", globalDeploymentID(), uploadUUID))
			er := r.z.serverPools[0].getHashedSet(r.object)
			disks := er.getDisks()
			var unreadable atomic.Bool
			if age == "unreadable-copy" {
				wrapped := append([]StorageAPI(nil), disks...)
				wrapped[0] = restoreGenerationDisk{StorageAPI: disks[0], uploadRead: &unreadable}
				er.getDisks = func() []StorageAPI { return wrapped }
				unreadable.Store(true)
			}
			err := r.z.AbortMultipartUpload(t.Context(), r.bucket, r.object, id, ObjectOptions{})
			unreadable.Store(false)
			left := restoreIsolationUploads(t, r, 0)
			if age != "abandoned" {
				if err == nil || !reflect.DeepEqual(left, stored) {
					t.Errorf("abort of an upload that may still commit (%s): %v, left %v", age, err, left)
				}
				return
			}
			if err != nil || len(left) != 0 {
				t.Errorf("abort of an abandoned commit: %v, left %v", err, left)
			}
		})
	}
}

// With no commit running, stale cleanup removes what a failed commit left
// drive by drive: a staged copy older than the commit grace. A recent
// staging and a copy that never staged stay.
func TestRestoreFailedCommitStaleCleanup(t *testing.T) {
	for _, mode := range []string{"recent", "abandoned", "unstaged-copy"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			stored, uploadUUID := restoreGenerationLeftover(t, r, mode == "unstaged-copy")
			if mode != "recent" {
				// The copy that never staged is as old as the others.
				restoreGenerationAgeUpload(t, r, uploadUUID, 2*restoreCommitGrace)
			}
			er := r.z.serverPools[0].getHashedSet(r.object)
			globalAPIConfig.mu.Lock()
			prev := globalAPIConfig.staleUploadsExpiry
			globalAPIConfig.staleUploadsExpiry = time.Nanosecond
			globalAPIConfig.mu.Unlock()
			for _, disk := range er.getDisks() {
				er.cleanupStaleUploadsOnDisk(t.Context(), disk)
			}
			globalAPIConfig.mu.Lock()
			globalAPIConfig.staleUploadsExpiry = prev
			globalAPIConfig.mu.Unlock()
			want := map[string]int{}
			switch mode {
			case "recent":
				want = stored
			case "unstaged-copy":
				want = map[string]int{uploadUUID: 1}
			}
			if left := restoreIsolationUploads(t, r, 0); !reflect.DeepEqual(left, want) {
				t.Errorf("stale cleanup of a failed commit's leftover: %v -> %v, want %v", stored, left, want)
			}
		})
	}
}

// restoreGenerationSnapshotKey marks the context of a stale cleanup whose
// reads of upload metadata restoreGenerationSnapshotDisk holds.
type restoreGenerationSnapshotKey struct{}

// restoreGenerationSnapshotDisk reads upload metadata at once, and hands the
// reply to a marked stale cleanup only on release.
type restoreGenerationSnapshotDisk struct {
	StorageAPI
	reads   *atomic.Int32
	release chan struct{}
}

func (d restoreGenerationSnapshotDisk) ReadVersion(ctx context.Context, origvolume, volume, path, versionID string, opts ReadOptions) (FileInfo, error) {
	fi, err := d.StorageAPI.ReadVersion(ctx, origvolume, volume, path, versionID, opts)
	if volume == minioMetaMultipartBucket && ctx.Value(restoreGenerationSnapshotKey{}) != nil {
		d.reads.Add(1)
		select {
		case <-d.release:
		case <-ctx.Done():
			return FileInfo{}, ctx.Err()
		}
	}
	return fi, err
}

// Stale cleanup decides on a removal under the commit lock. A completion
// that starts while cleanup reads an upload past the stale age waits for
// it, and a cleanup that comes later skips the running commit: the upload,
// an ordinary one, still commits with its contents.
func TestCleanupStaleUploadsSkipsRunningCommit(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	er := r.z.serverPools[0].getHashedSet(r.object)
	mp, err := r.z.NewMultipartUpload(t.Context(), r.bucket, r.object, ObjectOptions{Versioned: true, MTime: UTCNow().Add(-48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("an ordinary upload past the stale age")
	part, err := r.z.PutObjectPart(t.Context(), r.bucket, r.object, mp.UploadID, 1, mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	disks := er.getDisks()
	var reads, staged atomic.Int32
	readRelease := make(chan struct{})
	stageEntered, stageRelease := make(chan struct{}), make(chan struct{})
	var readOnce, stageOnce sync.Once
	defer readOnce.Do(func() { close(readRelease) })
	defer stageOnce.Do(func() { close(stageRelease) })
	wrapped := make([]StorageAPI, len(disks))
	for i, d := range disks {
		stage := restoreGenerationStageDisk{StorageAPI: d, bucket: r.bucket, object: r.object, stage: true,
			arrived: &staged, entered: stageEntered, release: stageRelease, disks: int32(len(disks))}
		wrapped[i] = restoreGenerationSnapshotDisk{StorageAPI: stage, reads: &reads, release: readRelease}
	}
	er.getDisks = func() []StorageAPI { return wrapped }
	globalAPIConfig.mu.Lock()
	prev := globalAPIConfig.staleUploadsExpiry
	globalAPIConfig.staleUploadsExpiry = time.Nanosecond
	globalAPIConfig.mu.Unlock()
	defer func() {
		globalAPIConfig.mu.Lock()
		globalAPIConfig.staleUploadsExpiry = prev
		globalAPIConfig.mu.Unlock()
	}()
	// Every drive's cleanup at once, each reading the upload on every drive.
	ctx := context.WithValue(t.Context(), restoreGenerationSnapshotKey{}, true)
	var cleanups sync.WaitGroup
	for _, disk := range wrapped {
		cleanups.Go(func() { er.cleanupStaleUploadsOnDisk(ctx, disk) })
	}
	cleanupDone := make(chan struct{})
	go func() { cleanups.Wait(); close(cleanupDone) }()
	// The completion starts once every cleanup that may decide holds its
	// read of the upload from before the commit.
	for deadline := time.Now().Add(2 * time.Second); reads.Load() < int32(len(disks)*len(disks)) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	completion := make(chan ObjectInfo, 1)
	completionErr := make(chan error, 1)
	go func() {
		oi, err := r.z.CompleteMultipartUpload(t.Context(), r.bucket, r.object, mp.UploadID, []CompletePart{{PartNumber: 1, ETag: part.ETag}}, ObjectOptions{Versioned: true})
		completion <- oi
		completionErr <- err
	}()
	select {
	case <-stageEntered:
	case <-time.After(3 * time.Second):
	}
	readOnce.Do(func() { close(readRelease) })
	select {
	case <-cleanupDone:
	case <-time.After(restoreTestWait):
		t.Fatal("stale cleanup never returned")
	}
	stageOnce.Do(func() { close(stageRelease) })
	oi := <-completion
	if err := <-completionErr; err != nil {
		t.Fatalf("completion of an upload stale cleanup read: %v", err)
	}
	er.getDisks = func() []StorageAPI { return disks }
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("completed contents: %q, %v", got, err)
	}
}

// restoreGenerationRand draws UUIDs from crypto/rand for the whole test
// binary, installed before any goroutine runs. While a pause is set, it holds
// the UUID that stale cleanup draws in its deadline-bound worker, for the
// trash path right before its rename, until the pause is released.
var restoreGenerationRand = &restoreGenerationRandReader{}

func init() { uuid.SetRand(restoreGenerationRand) }

type restoreGenerationRandReader struct {
	pause atomic.Pointer[restoreGenerationPause]
}

type restoreGenerationPause struct {
	entered, release chan struct{}
}

func (r *restoreGenerationRandReader) Read(b []byte) (int, error) {
	if p := r.pause.Load(); p != nil && restoreGenerationInCleanupRename() && r.pause.CompareAndSwap(p, nil) {
		close(p.entered)
		<-p.release
	}
	return rand.Read(b)
}

// restoreGenerationInCleanupRename reports whether the caller runs in stale
// cleanup's deadline-bound worker.
func restoreGenerationInCleanupRename() bool {
	pcs := make([]uintptr, 32)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs)])
	cleanup, worker := false, false
	for {
		f, more := frames.Next()
		cleanup = cleanup || strings.Contains(f.Function, "cleanupStaleUploadsOnDisk")
		worker = worker || strings.Contains(f.Function, "ioutil.WithDeadline")
		if !more {
			return cleanup && worker
		}
	}
}

// Stale cleanup holds the commit lock until its rename ends, also when the
// rename outlives the drive deadline and cleanup has moved on: a completion
// does not stage while that rename can still remove its upload.
func TestCleanupStaleUploadsHoldsLockThroughRename(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	er := r.z.serverPools[0].getHashedSet(r.object)
	mp, err := r.z.NewMultipartUpload(t.Context(), r.bucket, r.object, ObjectOptions{Versioned: true, MTime: UTCNow().Add(-48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("an upload whose stale cleanup outlives the drive deadline")
	part, err := r.z.PutObjectPart(t.Context(), r.bucket, r.object, mp.UploadID, 1, mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	disks := er.getDisks()
	stored := restoreIsolationUploads(t, r, 0)
	prev := globalDriveConfig.GetMaxTimeout()
	// The shortest drive deadline the configuration takes.
	globalDriveConfig.Update(drive.Config{MaxTimeout: 1100 * time.Millisecond})
	defer globalDriveConfig.Update(drive.Config{MaxTimeout: prev})
	pause := &restoreGenerationPause{entered: make(chan struct{}), release: make(chan struct{})}
	var paused sync.Once
	defer paused.Do(func() { close(pause.release) })
	restoreGenerationRand.pause.Store(pause)
	defer restoreGenerationRand.pause.CompareAndSwap(pause, nil)

	cleanupDone := make(chan struct{})
	go func() {
		er.cleanupStaleUploadsOnDisk(t.Context(), disks[0])
		close(cleanupDone)
	}()
	select {
	case <-pause.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("stale cleanup never reached its rename")
	}
	select {
	case <-cleanupDone:
	case <-time.After(5 * time.Second):
		t.Fatal("stale cleanup did not move on after the drive deadline")
	}
	if left := restoreIsolationUploads(t, r, 0); !reflect.DeepEqual(left, stored) {
		t.Fatalf("fixture: the held rename already ran: %v -> %v", stored, left)
	}

	var staged atomic.Int32
	stageEntered, stageRelease := make(chan struct{}), make(chan struct{})
	var stageOnce sync.Once
	defer stageOnce.Do(func() { close(stageRelease) })
	wrapped := make([]StorageAPI, len(disks))
	for i, d := range disks {
		wrapped[i] = restoreGenerationStageDisk{StorageAPI: d, bucket: r.bucket, object: r.object, stage: true,
			arrived: &staged, entered: stageEntered, release: stageRelease, disks: int32(len(disks))}
	}
	er.getDisks = func() []StorageAPI { return wrapped }
	completion := make(chan ObjectInfo, 1)
	completionErr := make(chan error, 1)
	go func() {
		oi, err := r.z.CompleteMultipartUpload(t.Context(), r.bucket, r.object, mp.UploadID, []CompletePart{{PartNumber: 1, ETag: part.ETag}}, ObjectOptions{Versioned: true})
		completion <- oi
		completionErr <- err
	}()
	select {
	case <-stageEntered:
		t.Error("a completion staged while stale cleanup's rename could still run")
	case <-time.After(2 * time.Second):
	}
	paused.Do(func() { close(pause.release) })
	select {
	case <-stageEntered:
	case <-time.After(restoreTestWait):
		t.Fatal("completion never staged after the rename ended")
	}
	stageOnce.Do(func() { close(stageRelease) })
	oi := <-completion
	if err := <-completionErr; err != nil {
		t.Fatalf("completion after the rename ended: %v", err)
	}
	er.getDisks = func() []StorageAPI { return disks }
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("completed contents: %q, %v", got, err)
	}
}
