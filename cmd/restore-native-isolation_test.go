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
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/mux"
)

// The private attempt metadata of a native restore, as stored. A literal name
// keeps these regressions meaningful on a tree without the key.
const restoreIsolationAttemptKey = "x-minio-internal-restore-attempt"

// restoreIsolationLayer hooks the object layer a POST restore handler uses.
// afterRead runs once POST has read the version, before POST records its
// status. restore, when set, replaces the background restore; every
// background restore result is sent to done.
type restoreIsolationLayer struct {
	ObjectLayer
	afterRead func()
	once      sync.Once
	restore   func(ctx context.Context, bucket, object string, opts ObjectOptions) error
	done      chan error
}

func newRestoreIsolationLayer(r *restoreTest) *restoreIsolationLayer {
	return &restoreIsolationLayer{ObjectLayer: r.z, done: make(chan error, 4)}
}

func (l *restoreIsolationLayer) GetObjectInfo(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	oi, err := l.ObjectLayer.GetObjectInfo(ctx, bucket, object, opts)
	if err == nil && l.afterRead != nil {
		l.once.Do(l.afterRead)
	}
	return oi, err
}

func (l *restoreIsolationLayer) RestoreTransitionedObject(ctx context.Context, bucket, object string, opts ObjectOptions) error {
	var err error
	if l.restore != nil {
		err = l.restore(ctx, bucket, object, opts)
	} else {
		err = l.ObjectLayer.RestoreTransitionedObject(ctx, bucket, object, opts)
	}
	l.done <- err
	return err
}

// restoreTestWait bounds how long a restore test waits for a step that does
// real drive work: metadata writes with synchronous persistence and renames
// on every drive. It is a liveness bound, not a latency contract; a loaded
// machine has stalled such a step past ten seconds.
const restoreTestWait = time.Minute

// wait returns the result of the next background restore.
func (l *restoreIsolationLayer) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-l.done:
		return err
	case <-time.After(restoreTestWait):
		buf := make([]byte, 1<<20)
		t.Fatalf("background restore did not finish in %v; goroutines:\n%s", restoreTestWait, buf[:runtime.Stack(buf, true)])
		return nil
	}
}

func restoreIsolationPOST(t *testing.T, r *restoreTest, layer ObjectLayer, versionID string) *httptest.ResponseRecorder {
	t.Helper()
	body := []byte(`<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>1</Days></RestoreRequest>`)
	path := "/" + r.bucket + "/" + r.object + "?restore"
	if versionID != "" {
		path += "&versionId=" + url.QueryEscape(versionID)
	}
	req, err := newTestSignedRequestV4(http.MethodPost, path, int64(len(body)), bytes.NewReader(body), globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	req = mux.SetURLVars(req, map[string]string{"bucket": r.bucket, "object": r.object})
	rec := httptest.NewRecorder()
	api := objectAPIHandlers{ObjectAPI: func() ObjectLayer { return layer }}
	api.PostRestoreObjectHandler(rec, req)
	return rec
}

// restoreIsolationSeed is a transitioned version without the ongoing marker
// that nativeRestoreSeed leaves for direct restores: POST sets its own.
func restoreIsolationSeed(t *testing.T, r *restoreTest, pool int, null, multipart bool) (ObjectInfo, []byte) {
	t.Helper()
	oi, body := nativeRestoreSeed(t, r, pool, null, multipart)
	opts := r.opts(oi.VersionID)
	opts.MTime = oi.ModTime
	opts.EvalMetadataFn = func(o *ObjectInfo, _ error) (ReplicateDecision, error) {
		o.UserDefined[xhttp.AmzRestore] = ""
		return ReplicateDecision{}, nil
	}
	if _, err := r.z.PutObjectMetadata(t.Context(), r.bucket, r.object, opts); err != nil {
		t.Fatal(err)
	}
	return oi, body
}

// restoreIsolationSettled waits until the version is no longer ongoing.
func restoreIsolationSettled(t *testing.T, r *restoreTest, versionID string) ObjectInfo {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		oi, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(versionID))
		if err == nil && !oi.RestoreOngoing {
			return oi
		}
		if time.Now().After(deadline) {
			t.Fatalf("version stays ongoing, refusing every later POST: %q, %v", oi.UserDefined[xhttp.AmzRestore], err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// restoreIsolationUploads returns the upload directories of the object on
// each drive of a pool, as stored, whatever listings show.
func restoreIsolationUploads(t *testing.T, r *restoreTest, pool int) map[string]int {
	t.Helper()
	er := r.z.serverPools[pool].getHashedSet(r.object)
	found := make(map[string]int)
	for _, disk := range er.getDisks() {
		entries, err := disk.ListDir(t.Context(), r.bucket, minioMetaMultipartBucket, er.getMultipartSHADir(r.bucket, r.object), -1)
		if errors.Is(err, errFileNotFound) || errors.Is(err, errVolumeNotFound) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			found[strings.TrimSuffix(entry, SlashSeparator)]++
		}
	}
	return found
}

// restoreIsolationGateTier holds a download after its first bytes and can
// fail it once released.
type restoreIsolationGateTier struct {
	WarmBackend
	first   int
	entered chan struct{}
	release chan struct{}
	failure error
	enter   sync.Once
	open    sync.Once
}

func newRestoreIsolationGateTier(first int, failure error) *restoreIsolationGateTier {
	return &restoreIsolationGateTier{
		WarmBackend: globalTierConfigMgr.drivercache["WARM"],
		first:       first, failure: failure,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
}

func (b *restoreIsolationGateTier) unblock() { b.open.Do(func() { close(b.release) }) }

func (b *restoreIsolationGateTier) Get(ctx context.Context, object string, version remoteVersionID, opts WarmBackendGetOpts) (io.ReadCloser, error) {
	rd, err := b.WarmBackend.Get(ctx, object, version, opts)
	if err != nil {
		return nil, err
	}
	return &restoreIsolationGateReader{ReadCloser: rd, tier: b, ctx: ctx, remaining: b.first}, nil
}

type restoreIsolationGateReader struct {
	io.ReadCloser
	tier      *restoreIsolationGateTier
	ctx       context.Context
	remaining int
}

func (r *restoreIsolationGateReader) Read(p []byte) (int, error) {
	if r.remaining > 0 {
		if len(p) > r.remaining {
			p = p[:r.remaining]
		}
		n, err := r.ReadCloser.Read(p)
		r.remaining -= n
		return n, err
	}
	r.tier.enter.Do(func() { close(r.tier.entered) })
	select {
	case <-r.tier.release:
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}
	if r.tier.failure != nil {
		return 0, r.tier.failure
	}
	return r.ReadCloser.Read(p)
}

func restoreIsolationEntered(t *testing.T, tier *restoreIsolationGateTier) {
	t.Helper()
	select {
	case <-tier.entered:
	case <-time.After(restoreTestWait):
		t.Fatal("restore never reached its download gate")
	}
}

// restoreIsolationFaultDisk fails metadata reads of the object while
// failReads is set, and reports writes of its metadata as failed, after
// they were made, while failWrites is set. Toggles keep the wrapper in
// place, so no restore retry races a swap of the drives.
type restoreIsolationFaultDisk struct {
	StorageAPI
	bucket, object string
	failReads      *atomic.Bool
	failWrites     *atomic.Bool
}

func (d restoreIsolationFaultDisk) ReadVersion(ctx context.Context, origvolume, volume, path, version string, opts ReadOptions) (FileInfo, error) {
	if d.failReads.Load() && volume == d.bucket && path == d.object {
		return FileInfo{}, errDiskNotFound
	}
	return d.StorageAPI.ReadVersion(ctx, origvolume, volume, path, version, opts)
}

func (d restoreIsolationFaultDisk) ReadXL(ctx context.Context, volume, path string, readData bool) (RawFileInfo, error) {
	if d.failReads.Load() && volume == d.bucket && path == d.object {
		return RawFileInfo{}, errDiskNotFound
	}
	return d.StorageAPI.ReadXL(ctx, volume, path, readData)
}

func (d restoreIsolationFaultDisk) WriteMetadata(ctx context.Context, origvolume, volume, path string, fi FileInfo) error {
	err := d.StorageAPI.WriteMetadata(ctx, origvolume, volume, path, fi)
	if err == nil && d.failWrites != nil && d.failWrites.Load() && volume == d.bucket && path == d.object {
		return errFaultyDisk
	}
	return err
}

// installRestoreIsolationFaults wraps the drives of the object's set in a
// pool for the rest of the test; failing marks the drives whose writes fail.
func installRestoreIsolationFaults(r *restoreTest, pool int, failing int) (reads, writes *atomic.Bool) {
	reads, writes = new(atomic.Bool), new(atomic.Bool)
	er := r.z.serverPools[pool].getHashedSet(r.object)
	disks := er.getDisks()
	wrapped := make([]StorageAPI, len(disks))
	for i, disk := range disks {
		d := restoreIsolationFaultDisk{StorageAPI: disk, bucket: r.bucket, object: r.object, failReads: reads}
		if i < failing {
			d.failWrites = writes
		}
		wrapped[i] = d
	}
	er.getDisks = func() []StorageAPI { return wrapped }
	return reads, writes
}

// POST records its status on a fresh read under the object lock, so an
// Object Lock update it did not see survives.
func TestRestorePOSTKeepsConcurrentProtection(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, kind := range []string{"legal-hold", "retention"} {
			t.Run(fmt.Sprintf("pools=%d/%s", pools, kind), func(t *testing.T) {
				r := newRestoreSafetyTest(t, pools, versioning.Enabled)
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
					t.Fatalf("initial protection: %d %s", rec.Code, rec.Body.String())
				}
				var accepted ObjectInfo
				layer := newRestoreIsolationLayer(r)
				layer.afterRead = func() {
					if rec := nativeRestoreLockRequest(t.Context(), t, r, oi.VersionID, kind, updated); rec.Code != http.StatusOK {
						t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
					}
					var err error
					if accepted, err = r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID)); err != nil {
						t.Fatal(err)
					}
				}
				if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code >= 400 {
					t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
				}
				after, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
				if err != nil {
					t.Fatal(err)
				}
				if accepted.UserDefined[key] == "" || after.UserDefined[key] != accepted.UserDefined[key] {
					t.Errorf("POST restore overwrote acknowledged Object Lock metadata: %q -> %q", accepted.UserDefined[key], after.UserDefined[key])
				}
				if !after.ModTime.Equal(oi.ModTime) || after.ETag != oi.ETag {
					t.Error("POST restore changed the version identity")
				}
			})
		}
	}
}

// A restored copy removed between POST's read and its status write leads to
// a new restore, never to a completed header without the restored data.
func TestRestorePOSTRacesCacheExpiry(t *testing.T) {
	for _, pools := range []int{1, 2} {
		t.Run(fmt.Sprintf("pools=%d", pools), func(t *testing.T) {
			r := newRestoreSafetyTest(t, pools, versioning.Enabled)
			initConfigSubsystem(t.Context(), r.z)
			oi := r.put("restored", false, true)
			r.restore(oi)
			layer := newRestoreIsolationLayer(r)
			layer.afterRead = func() {
				if err := expireTransitionedObject(t.Context(), r.z, &oi, lifecycle.Event{Action: lifecycle.DeleteRestoredAction}, lcEventSrc_Scanner); err != nil {
					t.Fatal(err)
				}
			}
			if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code >= 400 {
				t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
			}
			select {
			case err := <-layer.done:
				if err != nil {
					t.Fatalf("rehydration: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("POST renewed a removed restored copy instead of restoring it")
			}
			_, body, err := r.read(oi.VersionID)
			if err != nil || !bytes.Equal(body, r.bodies["restored"]) {
				t.Errorf("version unreadable after POST raced cache expiry: %v", err)
			}
		})
	}
}

// A restore queued with the versioning POST captured writes back the null
// version it resolved, even after versioning was enabled in between.
func TestRestoreKeepsCapturedNullIdentity(t *testing.T) {
	enable := func(t *testing.T, r *restoreTest) {
		meta, err := globalBucketMetadataSys.Get(r.bucket)
		if err != nil {
			t.Fatal(err)
		}
		meta.VersioningConfigXML = []byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)
		if err := meta.Save(t.Context(), r.z); err != nil {
			t.Fatal(err)
		}
		globalBucketMetadataSys.Set(r.bucket, meta)
	}
	for _, mode := range []string{"direct", "post"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, "")
			initConfigSubsystem(t.Context(), r.z)
			var oi ObjectInfo
			var body []byte
			if mode == "direct" {
				oi, body = nativeRestoreSeed(t, r, 0, true, false)
				// These are the options that POST captured while versioning was off.
				queued := nativeRestoreOptions(r, "")
				enable(t, r)
				if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, queued); err != nil {
					t.Fatal(err)
				}
			} else {
				oi, body = restoreIsolationSeed(t, r, 0, true, false)
				release := make(chan struct{})
				layer := newRestoreIsolationLayer(r)
				layer.restore = func(ctx context.Context, bucket, object string, opts ObjectOptions) error {
					<-release
					return r.z.RestoreTransitionedObject(ctx, bucket, object, opts)
				}
				if rec := restoreIsolationPOST(t, r, layer, ""); rec.Code != http.StatusOK {
					t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
				}
				enable(t, r)
				close(release)
				if err := layer.wait(t); err != nil {
					t.Fatal(err)
				}
			}
			versions := nativeRestoreSnapshot(t, r)[0]
			if len(versions) != 1 || versions[0].VersionID != "" {
				t.Errorf("restore created a UUID alias of the queued null version: %d versions", len(versions))
			}
			_, got, err := r.read(oi.VersionID)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatalf("null original: %v", err)
			}
		})
	}
}

// A restore that fails before it reads the version, on its lock wait or on
// its first read, must not leave POST's ongoing marker for every later POST
// to refuse: bounded retries clear it once the version is readable again.
func TestRestoreRecoversStrandedMarker(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, stage := range []string{"lock-wait", "initial-read"} {
			t.Run(fmt.Sprintf("pools=%d/%s", pools, stage), func(t *testing.T) {
				r := newRestoreSafetyTest(t, pools, versioning.Enabled)
				oi, _ := nativeRestoreSeed(t, r, 0, false, false)
				var err error
				if stage == "lock-wait" {
					lk := r.z.NewNSLock(r.bucket, r.object)
					if pools == 1 {
						lk = r.z.serverPools[0].getHashedSet(r.object).NewNSLock(r.bucket, r.object)
					}
					lkctx, lerr := lk.GetLock(t.Context(), globalOperationTimeout)
					if lerr != nil {
						t.Fatal(lerr)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
					start := time.Now()
					err = r.z.RestoreTransitionedObject(ctx, r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
					// The canceled caller must not wait for the minute-long
					// background cleanup deadline before releasing its lock.
					if elapsed := time.Since(start); elapsed > 5*time.Second {
						t.Errorf("canceled restore blocked on marker cleanup for %s", elapsed)
					}
					cancel()
					lk.Unlock(lkctx)
				} else {
					reads, _ := installRestoreIsolationFaults(r, 0, 0)
					reads.Store(true)
					err = r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
					reads.Store(false)
				}
				if err == nil {
					t.Fatal("restore succeeded without its lock or its version")
				}
				after := restoreIsolationSettled(t, r, oi.VersionID)
				if !after.IsRemote() || !after.ModTime.Equal(oi.ModTime) {
					t.Error("recovery changed more than the restore status")
				}
			})
		}
	}
}

// A later POST takes over a marker that no running restore holds, and the
// superseded attempt then neither downloads nor clears the newer status,
// also when both POSTs share a second, the precision of the request date.
func TestRestoreSupersededAttempt(t *testing.T) {
	for _, mode := range []string{"newer-completes", "newer-fails"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			initConfigSubsystem(t.Context(), r.z)
			oi, body := restoreIsolationSeed(t, r, 0, false, false)
			tier := globalTierConfigMgr.drivercache["WARM"].(*restoreTestTier)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			older := newRestoreIsolationLayer(r)
			older.restore = func(ctx context.Context, bucket, object string, opts ObjectOptions) error {
				// The queued worker loses the restore lock POST handed it,
				// as when its refresh found it gone: the marker then belongs
				// to no running restore.
				opts.Transition.owner.release()
				<-release
				return r.z.RestoreTransitionedObject(ctx, bucket, object, opts)
			}
			newer := newRestoreIsolationLayer(r)
			time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 10*time.Millisecond)))
			if rec := restoreIsolationPOST(t, r, older, oi.VersionID); rec.Code != http.StatusOK {
				t.Fatalf("first POST: %d %s", rec.Code, rec.Body.String())
			}
			first := r.fileInfo(oi.VersionID).Metadata[xhttp.AmzRestoreRequestDate]
			if mode == "newer-fails" {
				globalTierConfigMgr.drivercache["WARM"] = nativeRestoreFailTier{tier, errors.New("injected remote failure")}
			}
			if rec := restoreIsolationPOST(t, r, newer, oi.VersionID); rec.Code != http.StatusOK {
				t.Fatalf("POST over a marker no restore holds: %d %s", rec.Code, rec.Body.String())
			}
			second := r.fileInfo(oi.VersionID).Metadata[xhttp.AmzRestoreRequestDate]
			t.Logf("request dates %q %q, same second: %v", first, second, first == second)
			newerErr := newer.wait(t)
			globalTierConfigMgr.drivercache["WARM"] = tier
			before := r.fileInfo(oi.VersionID)
			gets := tier.gets.Load()
			unblock()
			if err := older.wait(t); err == nil {
				t.Error("superseded restore reported success")
			}
			if tier.gets.Load() != gets {
				t.Error("superseded restore downloaded the version again")
			}
			after := r.fileInfo(oi.VersionID)
			if !reflect.DeepEqual(before.Metadata, after.Metadata) || before.DataDir != after.DataDir {
				t.Errorf("superseded restore changed the version: %q -> %q", before.Metadata[xhttp.AmzRestore], after.Metadata[xhttp.AmzRestore])
			}
			info, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
			if err != nil || info.RestoreOngoing {
				t.Fatalf("version left ongoing: %q, %v", info.UserDefined[xhttp.AmzRestore], err)
			}
			if mode == "newer-completes" {
				if newerErr != nil || info.IsRemote() {
					t.Fatalf("newer restore: %v remote=%v", newerErr, info.IsRemote())
				}
				if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) || tier.gets.Load() != gets {
					t.Errorf("restored contents: %v", err)
				}
				return
			}
			if newerErr == nil || !info.IsRemote() || info.UserDefined[xhttp.AmzRestore] != "" {
				t.Fatalf("failed newer restore is not retryable: %v %q", newerErr, info.UserDefined[xhttp.AmzRestore])
			}
			if rec := restoreIsolationPOST(t, r, newer, oi.VersionID); rec.Code != http.StatusOK {
				t.Fatalf("retry POST: %d %s", rec.Code, rec.Body.String())
			}
			if err := newer.wait(t); err != nil {
				t.Fatal(err)
			}
			if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
				t.Errorf("retried restore contents: %v", err)
			}
		})
	}
}

// A restart loses the restore that POST started; a POST to the restarted
// server takes the stranded marker over and restores the version.
func TestRestoreRestartTakeover(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	oi, body := restoreIsolationSeed(t, r, 0, false, true)
	lost := newRestoreIsolationLayer(r)
	lost.restore = func(context.Context, string, string, ObjectOptions) error { return nil }
	if rec := restoreIsolationPOST(t, r, lost, oi.VersionID); rec.Code != http.StatusOK {
		t.Fatalf("POST before restart: %d %s", rec.Code, rec.Body.String())
	}
	lost.wait(t)
	if info, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID)); err != nil || !info.RestoreOngoing {
		t.Fatalf("fixture: %q %v", info.UserDefined[xhttp.AmzRestore], err)
	}

	endpoints := make(EndpointServerPools, len(r.z.serverPools))
	for i, pool := range r.z.serverPools {
		endpoints[i] = pool.endpoints
	}
	obj, err := newErasureServerPools(t.Context(), endpoints)
	if err != nil {
		t.Fatal(err)
	}
	restarted := obj.(*erasureServerPools)
	t.Cleanup(func() { restarted.Shutdown(context.Background()) })
	r.z = restarted
	layer := newRestoreIsolationLayer(r)
	if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
		t.Fatalf("POST after restart: %d %s", rec.Code, rec.Body.String())
	}
	if err := layer.wait(t); err != nil {
		t.Fatal(err)
	}
	info := restoreIsolationSettled(t, r, oi.VersionID)
	if info.IsRemote() || info.UserDefined[restoreIsolationAttemptKey] != "" {
		t.Errorf("restore after restart incomplete: remote=%v attempt=%q", info.IsRemote(), info.UserDefined[restoreIsolationAttemptKey])
	}
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Errorf("contents after restart: %v", err)
	}
}

// A null version replaced while its restore was queued is another version:
// the restore must not rehydrate it, even if it is transitioned as well.
func TestRestoreReplacementNullObject(t *testing.T) {
	for _, state := range []versioning.State{"", versioning.Suspended} {
		t.Run(fmt.Sprintf("versioning=%q", state), func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, state)
			initConfigSubsystem(t.Context(), r.z)
			oi, _ := restoreIsolationSeed(t, r, 0, true, false)
			release := make(chan struct{})
			layer := newRestoreIsolationLayer(r)
			layer.restore = func(ctx context.Context, bucket, object string, opts ObjectOptions) error {
				<-release
				return r.z.RestoreTransitionedObject(ctx, bucket, object, opts)
			}
			if rec := restoreIsolationPOST(t, r, layer, ""); rec.Code != http.StatusOK {
				close(release)
				t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
			}
			replacement := []byte("replacement null object")
			repl, err := r.z.serverPools[0].PutObject(t.Context(), r.bucket, r.object,
				mustGetPutObjReader(t, bytes.NewReader(replacement), int64(len(replacement)), "", ""),
				ObjectOptions{VersionSuspended: state == versioning.Suspended})
			if err != nil {
				close(release)
				t.Fatal(err)
			}
			topts := r.opts(nullVersionID)
			topts.MTime = repl.ModTime
			topts.Transition = TransitionOptions{Tier: "WARM", ETag: repl.ETag}
			if err := r.z.serverPools[0].TransitionObject(t.Context(), r.bucket, r.object, topts); err != nil {
				close(release)
				t.Fatal(err)
			}
			tier := globalTierConfigMgr.drivercache["WARM"].(*restoreTestTier)
			before := r.fileInfo(nullVersionID)
			gets := tier.gets.Load()
			close(release)
			layer.wait(t)
			after := r.fileInfo(nullVersionID)
			if tier.gets.Load() != gets || after.Metadata[xhttp.AmzRestore] != "" || !reflect.DeepEqual(before.Metadata, after.Metadata) {
				t.Errorf("queued restore rehydrated the replacement null object: %q", after.Metadata[xhttp.AmzRestore])
			}
			if after.ModTime.Equal(oi.ModTime) || !after.ModTime.Equal(repl.ModTime) {
				t.Fatal("fixture did not replace the null version")
			}
			if _, got, err := r.read(nullVersionID); err != nil || !bytes.Equal(got, replacement) {
				t.Errorf("replacement contents: %v", err)
			}
		})
	}
}

// POST's own status write can fail after its ongoing marker reached the
// drives; the marker must not stay for every later POST to refuse.
func TestRestorePOSTStatusWritePartialFailure(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	oi, body := restoreIsolationSeed(t, r, 0, false, false)
	_, writes := installRestoreIsolationFaults(r, 0, 2)
	layer := newRestoreIsolationLayer(r)
	writes.Store(true)
	rec := restoreIsolationPOST(t, r, layer, oi.VersionID)
	writes.Store(false)
	if rec.Code < 400 {
		t.Fatalf("POST acknowledged a failed status write: %d %s", rec.Code, rec.Body.String())
	}
	if info, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID)); err == nil && !info.RestoreOngoing {
		t.Log("the failed status write left no marker in quorum")
	}
	restoreIsolationSettled(t, r, oi.VersionID)
	if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
		t.Fatalf("POST after a failed status write: %d %s", rec.Code, rec.Body.String())
	}
	if err := layer.wait(t); err != nil {
		t.Fatal(err)
	}
	if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
		t.Errorf("restore after a failed status write: %v", err)
	}
}

// Duplicate copies of a version in two pools can differ in whether they
// hold a restored copy. A completed restore header must never reach a copy
// without one; POST renews or restores only the copy that restores serve.
func TestRestoreDuplicatePoolCacheStates(t *testing.T) {
	for _, mode := range []string{"suspended-owner", "unrestored-first", "restored-first"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 2, versioning.Enabled)
			initConfigSubsystem(t.Context(), r.z)
			oi, body := restoreIsolationSeed(t, r, 0, false, false)
			// The duplicate is the same stored version, metadata only.
			src := r.z.serverPools[0].getHashedSet(r.object).getDisks()
			dst := r.z.serverPools[1].getHashedSet(r.object).getDisks()
			for i := range src {
				raw, err := src[i].ReadAll(t.Context(), r.bucket, pathJoin(r.object, xlStorageFormatFile))
				if err != nil {
					t.Fatal(err)
				}
				if err := dst[i].WriteAll(t.Context(), r.bucket, pathJoin(r.object, xlStorageFormatFile), raw); err != nil {
					t.Fatal(err)
				}
			}
			owner := 0
			if mode == "unrestored-first" {
				owner = 1
			}
			if err := r.z.serverPools[owner].RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err != nil {
				t.Fatal(err)
			}
			if mode == "suspended-owner" {
				r.z.poolMetaMutex.Lock()
				r.z.poolMeta.Pools[0].Decommission = &PoolDecommissionInfo{}
				r.z.poolMetaMutex.Unlock()
				t.Cleanup(func() {
					r.z.poolMetaMutex.Lock()
					r.z.poolMeta.Pools[0].Decommission = nil
					r.z.poolMetaMutex.Unlock()
				})
			}
			before := nativeRestoreSnapshot(t, r)
			layer := newRestoreIsolationLayer(r)
			if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
				t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
			}
			if mode != "restored-first" {
				select {
				case err := <-layer.done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("POST did not restore the copy without restored data")
				}
			}
			after := nativeRestoreSnapshot(t, r)
			for pool := range r.z.serverPools {
				gr, err := r.z.serverPools[pool].GetObjectNInfo(t.Context(), r.bucket, r.object, nil, nil, ObjectOptions{VersionID: oi.VersionID})
				if err != nil {
					t.Errorf("pool %d copy unreadable, header %q: %v", pool, after[pool][0].Metadata[xhttp.AmzRestore], err)
					continue
				}
				got, err := io.ReadAll(gr)
				gr.Close()
				if err != nil || !bytes.Equal(got, body) {
					t.Errorf("pool %d copy contents: %v", pool, err)
				}
			}
			// The copy that is neither renewed nor restored stays as it was.
			untouched := 1
			if mode == "suspended-owner" {
				untouched = 0
			}
			if !reflect.DeepEqual(before[untouched], after[untouched]) {
				t.Errorf("POST changed the pool %d copy: %q -> %q", untouched, before[untouched][0].Metadata[xhttp.AmzRestore], after[untouched][0].Metadata[xhttp.AmzRestore])
			}
		})
	}
}

// A restored copy expires only by its own reason, on a fresh read: its
// restore deadline passed and nothing else. A renewed deadline survives
// another rule falling due and an expiry checked across all pools.
func TestExpireRestoredNeedsOwnReason(t *testing.T) {
	for _, mode := range []string{"other-expiry-due", "checked-all-pools", "ongoing", "renewed", "expired"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			oi := r.put("restored", false, true)
			r.restore(oi)
			before := r.fileInfo(oi.VersionID)
			if mode == "other-expiry-due" {
				meta, err := globalBucketMetadataSys.Get(r.bucket)
				if err != nil {
					t.Fatal(err)
				}
				meta.LifecycleConfigXML = []byte(`<LifecycleConfiguration><Rule><ID>delete</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><Expiration><Date>2020-01-01T00:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>`)
				if err := meta.Save(t.Context(), r.z); err != nil {
					t.Fatal(err)
				}
				globalBucketMetadataSys.Set(r.bucket, meta)
			}
			header := completedRestoreObj(UTCNow().Add(48 * time.Hour)).String()
			switch mode {
			case "ongoing":
				header = ongoingRestoreObj().String()
			case "expired":
				header = ""
			}
			if header != "" {
				opts := r.opts(oi.VersionID)
				opts.MTime = oi.ModTime
				opts.EvalMetadataFn = func(o *ObjectInfo, _ error) (ReplicateDecision, error) {
					o.UserDefined[xhttp.AmzRestore] = header
					return ReplicateDecision{}, nil
				}
				if _, err := r.z.PutObjectMetadata(t.Context(), r.bucket, r.object, opts); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			if mode == "checked-all-pools" {
				opts := r.opts(oi.VersionID)
				opts.Expiration = ExpirationOptions{Expire: true, CheckedAllPools: true}
				opts.Transition.ExpireRestored = true
				_, err = r.z.serverPools[0].getHashedSet(r.object).DeleteObject(t.Context(), r.bucket, r.object, opts)
			} else {
				err = expireTransitionedObject(t.Context(), r.z, &oi, lifecycle.Event{Action: lifecycle.DeleteRestoredAction}, lcEventSrc_Scanner)
			}
			after := r.fileInfo(oi.VersionID)
			if mode == "expired" {
				// Control: an elapsed deadline is the reason itself.
				if err != nil || after.Metadata[xhttp.AmzRestore] != "" || r.dataDirs(before.DataDir) != 0 {
					t.Errorf("expired restored copy not removed: %v", err)
				}
				return
			}
			t.Logf("cleanup=%v header=%q", err, after.Metadata[xhttp.AmzRestore])
			if err == nil || after.Metadata[xhttp.AmzRestore] != header || r.dataDirs(before.DataDir) != len(r.z.serverPools[0].getHashedSet(r.object).getDisks()) {
				t.Error("cache cleanup removed a restored copy whose own deadline has not passed")
			}
		})
	}
}

// Controls: an ordinary POST restore, a renewal, and a client's multipart
// upload of the same key while a restore runs.
func TestRestorePOSTControls(t *testing.T) {
	t.Run("restore", func(t *testing.T) {
		r := newRestoreSafetyTest(t, 1, versioning.Enabled)
		initConfigSubsystem(t.Context(), r.z)
		oi, body := restoreIsolationSeed(t, r, 0, false, true)
		layer := newRestoreIsolationLayer(r)
		if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
			t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
		}
		if err := layer.wait(t); err != nil {
			t.Fatal(err)
		}
		info, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
		if err != nil || info.IsRemote() || info.RestoreOngoing || info.UserDefined[restoreIsolationAttemptKey] != "" {
			t.Fatalf("restored status: %q %q, %v", info.UserDefined[xhttp.AmzRestore], info.UserDefined[restoreIsolationAttemptKey], err)
		}
		if !info.ModTime.Equal(oi.ModTime) || info.ETag != oi.ETag || info.UserDefined["x-amz-meta-preserve"] != "keep-me" {
			t.Error("restore changed the version identity or metadata")
		}
		if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
			t.Errorf("restored contents: %v", err)
		}
		if uploads := restoreIsolationUploads(t, r, 0); len(uploads) != 0 {
			t.Errorf("completed restore left its upload: %v", uploads)
		}
	})
	t.Run("renewal", func(t *testing.T) {
		r := newRestoreSafetyTest(t, 1, versioning.Enabled)
		initConfigSubsystem(t.Context(), r.z)
		oi, body := nativeRestoreSeed(t, r, 0, false, false)
		if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err != nil {
			t.Fatal(err)
		}
		tier := globalTierConfigMgr.drivercache["WARM"].(*restoreTestTier)
		before := r.fileInfo(oi.VersionID)
		gets := tier.gets.Load()
		layer := newRestoreIsolationLayer(r)
		if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
			t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
		}
		select {
		case err := <-layer.done:
			t.Fatalf("renewal restored again: %v", err)
		case <-time.After(200 * time.Millisecond):
		}
		after := r.fileInfo(oi.VersionID)
		if after.DataDir != before.DataDir || !after.ModTime.Equal(before.ModTime) || after.Metadata[xhttp.AmzRestore] == "" {
			t.Error("renewal changed the restored copy")
		}
		if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) || tier.gets.Load() != gets {
			t.Errorf("renewed copy not served locally: %v", err)
		}
	})
	t.Run("public-multipart-same-key", func(t *testing.T) {
		r := newRestoreSafetyTest(t, 1, versioning.Enabled)
		initConfigSubsystem(t.Context(), r.z)
		oi, body := restoreIsolationSeed(t, r, 0, false, true)
		tier := newRestoreIsolationGateTier(5<<20, nil)
		globalTierConfigMgr.drivercache["WARM"] = tier
		defer tier.unblock()
		layer := newRestoreIsolationLayer(r)
		if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
			t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
		}
		restoreIsolationEntered(t, tier)
		upload, err := r.z.NewMultipartUpload(t.Context(), r.bucket, r.object, ObjectOptions{Versioned: true})
		if err != nil {
			t.Fatal(err)
		}
		uploads, err := r.z.ListMultipartUploads(t.Context(), r.bucket, r.object, "", "", "", 100)
		listed := false
		for _, u := range uploads.Uploads {
			listed = listed || u.UploadID == upload.UploadID
		}
		if err != nil || !listed {
			t.Fatalf("client upload not listed: %+v, %v", uploads.Uploads, err)
		}
		tier.unblock()
		if err := layer.wait(t); err != nil {
			t.Fatal(err)
		}
		// Single-pool part writes wait for the object lock of a running restore.
		data := []byte("client data")
		part, err := r.z.PutObjectPart(t.Context(), r.bucket, r.object, upload.UploadID, 1, mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		parts, err := r.z.ListObjectParts(t.Context(), r.bucket, r.object, upload.UploadID, 0, 10, ObjectOptions{})
		if err != nil || len(parts.Parts) != 1 {
			t.Fatalf("client parts: %+v, %v", parts, err)
		}
		newer, err := r.z.CompleteMultipartUpload(t.Context(), r.bucket, r.object, upload.UploadID, []CompletePart{{PartNumber: 1, ETag: part.ETag}}, ObjectOptions{Versioned: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, got, err := r.read(newer.VersionID); err != nil || !bytes.Equal(got, data) {
			t.Errorf("client version: %v", err)
		}
		if _, got, err := r.read(oi.VersionID); err != nil || !bytes.Equal(got, body) {
			t.Errorf("restored version: %v", err)
		}
	})
}
