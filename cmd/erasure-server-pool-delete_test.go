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
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	minio "github.com/minio/minio-go/v7"
)

func bulkDeletePools(t *testing.T, n int) (*erasureServerPools, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	dirs, err := getRandomDisks(4 * n)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var endpoints EndpointServerPools
	for i := range n {
		endpoints = append(endpoints, mustGetPoolEndpoints(i, dirs[4*i:4*i+4]...)...)
	}
	obj, _, err := initObjectLayer(ctx, endpoints)
	if err != nil {
		cancel()
		removeRoots(dirs)
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	t.Cleanup(func() { cancel(); z.Shutdown(context.Background()); removeRoots(dirs); setObjectLayer(previous) })
	bucket := "bulk-delete-consistency"
	if err := z.MakeBucket(ctx, bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	return z, bucket
}

func bulkDeleteBody(t *testing.T, z *erasureServerPools, bucket, object, version string) string {
	t.Helper()
	r, err := z.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{VersionID: version})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// All drives are online and all metadata reads succeed. Failure starts inside
// DeleteVersions, after any preflight. Count attempts to delete the latest copy
// instead of waiting for them: a safe implementation must never make that call.
type bulkDeleteFaultDisk struct {
	StorageAPI
	bucket, object, mode string
	fail, latest         bool
	failed, attempted    *atomic.Int32
}

func (d bulkDeleteFaultDisk) DeleteVersions(ctx context.Context, bucket string, versions []FileInfoVersions, opts DeleteOptions) []error {
	if bucket != d.bucket {
		return d.StorageAPI.DeleteVersions(ctx, bucket, versions, opts)
	}
	errs := make([]error, len(versions))
	for i, v := range versions {
		if v.Name != d.object {
			errs[i] = d.StorageAPI.DeleteVersions(ctx, bucket, []FileInfoVersions{v}, opts)[0]
			continue
		}
		if d.latest {
			d.attempted.Add(1)
		}
		if !d.fail {
			errs[i] = d.StorageAPI.DeleteVersions(ctx, bucket, []FileInfoVersions{v}, opts)[0]
			continue
		}
		d.failed.Add(1)
		switch d.mode {
		case "eio":
			errs[i] = syscall.EIO
		case "disconnect":
			errs[i] = errDiskNotFound
		case "permission":
			meta := filepath.Join(d.String(), bucket, v.Name, xlStorageFormatFile)
			info, err := os.Stat(meta)
			if err == nil {
				err = os.Chmod(meta, 0)
			}
			if err != nil {
				errs[i] = err
				continue
			}
			errs[i] = d.StorageAPI.DeleteVersions(ctx, bucket, []FileInfoVersions{v}, opts)[0]
			if err := os.Chmod(meta, info.Mode()); err != nil {
				panic(err)
			}
		}
	}
	return errs
}

func requireBulkDeletePermissionFailure(t *testing.T) {
	t.Helper()
	probe := filepath.Join(t.TempDir(), "permission-probe")
	if err := os.WriteFile(probe, []byte("metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(probe, 0); err != nil {
		t.Skipf("cannot inject filesystem permissions: %v", err)
	}
	_, err := os.ReadFile(probe)
	if restoreErr := os.Chmod(probe, 0o600); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if !os.IsPermission(err) {
		t.Skip("this user/filesystem can read mode-000 files")
	}
}

func TestPoolsBulkDeleteKeepsLatestOnIOFailure(t *testing.T) {
	for _, mode := range []string{"eio", "disconnect", "permission"} {
		for _, n := range []int{2, 3} {
			for primary := range n {
				for _, kind := range []string{"unversioned", "null", "uuid"} {
					t.Run(fmt.Sprintf("%s/pools=%d/primary=%d/%s", mode, n, primary, kind), func(t *testing.T) {
						if mode == "permission" {
							requireBulkDeletePermissionFailure(t)
						}
						z, bucket := bulkDeletePools(t, n)
						object, old := "target", (primary+1)%n
						opts := ObjectOptions{MTime: UTCNow().Add(-time.Hour), MaxParity: true}
						oldBody := "old"
						if kind == "uuid" {
							opts.Versioned, opts.VersionID, oldBody = true, mustGetUUID(), "latest"
						}
						putConsistencyObject(t, z, bucket, object, old, oldBody, opts)
						opts.MTime = opts.MTime.Add(time.Minute)
						latest := putConsistencyObject(t, z, bucket, object, primary, "latest", opts)
						version := opts.VersionID
						if kind == "null" {
							version = nullVersionID
						}
						for _, key := range []string{"before", "after"} {
							putConsistencyObject(t, z, bucket, key, primary, "unrelated", ObjectOptions{})
						}
						var failed, attempted atomic.Int32
						var restore []func()
						for _, p := range []int{old, primary} {
							set := z.serverPools[p].getHashedSet(object)
							original := set.getDisks
							disks := append([]StorageAPI(nil), original()...)
							for i, disk := range disks {
								disks[i] = bulkDeleteFaultDisk{StorageAPI: disk, bucket: bucket, object: object, mode: mode, fail: p == old, latest: p == primary, failed: &failed, attempted: &attempted}
							}
							set.getDisks = func() []StorageAPI { return disks }
							restore = append(restore, func() { set.getDisks = original })
						}
						defer func() {
							for _, f := range restore {
								f()
							}
						}()
						objects := []ObjectToDelete{{ObjectV: ObjectV{ObjectName: "before"}}, {ObjectV: ObjectV{ObjectName: object, VersionID: version}}, {ObjectV: ObjectV{ObjectName: "after"}}}
						deleted, errs := z.DeleteObjects(t.Context(), bucket, objects, ObjectOptions{})
						if failed.Load() != 4 || attempted.Load() != 0 {
							t.Errorf("cleanup failures=%d; latest deletion attempts=%d, want 4/0", failed.Load(), attempted.Load())
						}
						if errs[1] == nil {
							t.Error("cleanup failure was reported as success")
						}
						for _, i := range []int{0, 2} {
							if errs[i] != nil || deleted[i].ObjectName != objects[i].ObjectName {
								t.Errorf("unrelated item %d: %+v, %v", i, deleted[i], errs[i])
							}
						}
						if body := bulkDeleteBody(t, z, bucket, object, version); body != "latest" {
							t.Errorf("GET during failure=%q", body)
						}
						for _, f := range restore {
							f()
						}
						if body := bulkDeleteBody(t, z, bucket, object, version); body != "latest" {
							t.Errorf("GET after recovery=%q", body)
						}
						listed, err := z.ListObjectVersions(t.Context(), bucket, object, "", "", "", 100)
						if err != nil || len(listed.Objects) != 1 || listed.Objects[0].ETag != latest.ETag {
							t.Errorf("recovered versions=%+v, %v", listed.Objects, err)
						}
						_, retry := z.DeleteObjects(t.Context(), bucket, objects[1:2], ObjectOptions{})
						if retry[0] != nil {
							t.Fatal(retry[0])
						}
						_, err = z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: version})
						if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
							t.Errorf("retry retained the object: %v", err)
						}
					})
				}
			}
		}
	}
}

func TestPoolsBulkDeleteReplicationIdentity(t *testing.T) {
	z, _ := bulkDeletePools(t, 2)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bucket, router, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{VersioningEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected outbound replication for a failed deletion")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer remote.Close()
	client, err := minio.New(strings.TrimPrefix(remote.URL, "http://"), &minio.Options{Region: "us-east-1", MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, restoreReplication := r5ReplicationFixture(t, z, bucket, client)
	defer restoreReplication()
	versions := make(map[string]string)
	for _, key := range []string{"first", "second"} {
		v := putConsistencyObject(t, z, bucket, key, 0, "payload", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour)})
		putConsistencyObject(t, z, bucket, key, 1, "payload", ObjectOptions{Versioned: true, VersionID: v.VersionID, MTime: v.ModTime})
		versions[key] = v.VersionID
	}
	set := z.serverPools[0].getHashedSet("first")
	original := set.getDisks
	disks := append([]StorageAPI(nil), original()...)
	disks[0], disks[1] = nil, nil
	set.getDisks = func() []StorageAPI { return disks }
	defer func() { set.getDisks = original }()
	body := []byte(fmt.Sprintf("<Delete><Object><Key>first</Key><VersionId>%s</VersionId></Object><Object><Key>second</Key><VersionId>%s</VersionId></Object></Delete>", versions["first"], versions["second"]))
	req, err := newTestSignedRequestV4(http.MethodPost, getMultiDeleteObjectURL("", bucket), int64(len(body)), bytes.NewReader(body), globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var result struct {
		Errors []struct {
			Key, Code string
			VersionID string `xml:"VersionId"`
		} `xml:"Error"`
		Deleted []struct{ Key string } `xml:"Deleted"`
	}
	if err := xml.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || len(result.Errors) != 2 || len(result.Deleted) != 0 {
		t.Fatalf("lost response identity: HTTP %d %s", rec.Code, rec.Body.String())
	}
	for _, e := range result.Errors {
		if versions[e.Key] == "" || e.VersionID != versions[e.Key] || e.Code != "SlowDownWrite" {
			t.Errorf("incorrect error identity: %+v", e)
		}
		delete(versions, e.Key)
	}
	if len(versions) != 0 {
		t.Errorf("missing errors: %v", versions)
	}
}

func TestPoolsBulkDeleteNullBeforeMarker(t *testing.T) {
	for _, n := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("pools=%d", n), func(t *testing.T) {
			z, bucket := bulkDeletePools(t, n)
			object := "suspended"
			history := putConsistencyObject(t, z, bucket, object, 0, "history", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour)})
			for p := range n {
				putConsistencyObject(t, z, bucket, object, p, "null", ObjectOptions{MTime: UTCNow().Add(-time.Duration(p+1) * time.Minute)})
			}
			objects := []ObjectToDelete{{ObjectV: ObjectV{ObjectName: object}}, {ObjectV: ObjectV{ObjectName: object, VersionID: nullVersionID}}}
			deleted, errs := z.DeleteObjects(t.Context(), bucket, objects, ObjectOptions{VersionSuspended: true})
			if errs[0] != nil || errs[1] != nil || !deleted[0].DeleteMarker || deleted[1].VersionID != nullVersionID {
				t.Fatalf("results=%+v errors=%v", deleted, errs)
			}
			info, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{})
			if !info.DeleteMarker || !isErrObjectNotFound(err) {
				t.Errorf("replacement null marker lost: %+v, %v", info, err)
			}
			if body := bulkDeleteBody(t, z, bucket, object, history.VersionID); body != "history" {
				t.Errorf("UUID history changed: %q", body)
			}
		})
	}
}

func TestPoolsBulkDeletePartialCleanupRetry(t *testing.T) {
	for _, kind := range []string{"unversioned", "null", "uuid"} {
		t.Run(kind, func(t *testing.T) {
			z, bucket := bulkDeletePools(t, 2)
			object := "partial-cleanup"
			opts := ObjectOptions{MTime: UTCNow().Add(-time.Hour)}
			oldBody := "old"
			if kind == "uuid" {
				opts.Versioned, opts.VersionID, oldBody = true, mustGetUUID(), "latest"
			}
			putConsistencyObject(t, z, bucket, object, 0, oldBody, opts)
			opts.MTime = UTCNow()
			putConsistencyObject(t, z, bucket, object, 1, "latest", opts)
			version := opts.VersionID
			if kind == "null" {
				version = nullVersionID
			}
			set := z.serverPools[0].getHashedSet(object)
			original := set.getDisks
			disks := append([]StorageAPI(nil), original()...)
			var failed, attempted atomic.Int32
			for i := range 2 {
				disks[i] = bulkDeleteFaultDisk{StorageAPI: disks[i], bucket: bucket, object: object, mode: "eio", fail: true, failed: &failed, attempted: &attempted}
			}
			set.getDisks = func() []StorageAPI { return disks }
			defer func() { set.getDisks = original }()
			objects := []ObjectToDelete{{ObjectV: ObjectV{ObjectName: object, VersionID: version}}}
			_, errs := z.DeleteObjects(t.Context(), bucket, objects, ObjectOptions{})
			if errs[0] == nil || failed.Load() != 2 {
				t.Fatalf("did not partially fail cleanup: %v, failures=%d", errs, failed.Load())
			}
			set.getDisks = original
			if got := bulkDeleteBody(t, z, bucket, object, version); got != "latest" {
				t.Fatalf("latest lost after partial cleanup: %q", got)
			}
			_, errs = z.DeleteObjects(t.Context(), bucket, objects, ObjectOptions{})
			if errs[0] != nil {
				t.Fatalf("recovered retry must combine successful removals and already-absent replies: %v", errs[0])
			}
			_, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: version})
			if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
				t.Errorf("retry retained object: %v", err)
			}
		})
	}
}

func TestPoolsBulkDeleteDifferentPrimaries(t *testing.T) {
	for _, n := range []int{2, 3} {
		t.Run(fmt.Sprintf("pools=%d", n), func(t *testing.T) {
			z, bucket := bulkDeletePools(t, n)
			objects := make([]ObjectToDelete, n)
			for primary := range n {
				object := fmt.Sprintf("key-%d", primary)
				objects[primary].ObjectName = object
				putConsistencyObject(t, z, bucket, object, (primary+1)%n, "old", ObjectOptions{MTime: UTCNow().Add(-time.Hour)})
				putConsistencyObject(t, z, bucket, object, primary, "latest", ObjectOptions{})
			}
			set := z.serverPools[0].getHashedSet(objects[n-1].ObjectName)
			original := set.getDisks
			disks := append([]StorageAPI(nil), original()...)
			var failed, attempted atomic.Int32
			for i, disk := range disks {
				disks[i] = bulkDeleteFaultDisk{StorageAPI: disk, bucket: bucket, object: objects[n-1].ObjectName, mode: "eio", fail: true, failed: &failed, attempted: &attempted}
			}
			set.getDisks = func() []StorageAPI { return disks }
			defer func() { set.getDisks = original }()
			deleted, errs := z.DeleteObjects(t.Context(), bucket, objects, ObjectOptions{})
			for i := range objects {
				if deleted[i].ObjectName != objects[i].ObjectName {
					t.Errorf("wrong result index %d: %+v", i, deleted[i])
				}
				if i == n-1 {
					if errs[i] == nil || bulkDeleteBody(t, z, bucket, objects[i].ObjectName, "") != "latest" {
						t.Errorf("failed item lost latest: %v", errs[i])
					}
					continue
				}
				_, err := z.GetObjectInfo(t.Context(), bucket, objects[i].ObjectName, ObjectOptions{})
				if errs[i] != nil || !isErrObjectNotFound(err) {
					t.Errorf("healthy item %d: delete=%v GET=%v", i, errs[i], err)
				}
			}
		})
	}
}

func TestPoolsBulkDeleteTieAndUnreadable(t *testing.T) {
	for _, unreadable := range []bool{false, true} {
		t.Run(fmt.Sprintf("unreadable=%t", unreadable), func(t *testing.T) {
			z, bucket := bulkDeletePools(t, 3)
			object := "same-time"
			stamp := UTCNow().Add(-time.Hour)
			for p := range 3 {
				putConsistencyObject(t, z, bucket, object, p, fmt.Sprintf("pool-%d", p), ObjectOptions{MTime: stamp})
			}
			if got := bulkDeleteBody(t, z, bucket, object, ""); got != "pool-0" {
				t.Fatalf("unexpected read winner: %q", got)
			}
			set := z.serverPools[2].getHashedSet(object)
			original := set.getDisks
			disks := append([]StorageAPI(nil), original()...)
			var failed, attempted atomic.Int32
			for i, disk := range disks {
				if unreadable {
					disks[i] = consistencyReadFaultDisk{StorageAPI: disk, bucket: bucket, object: object}
				} else {
					disks[i] = bulkDeleteFaultDisk{StorageAPI: disk, bucket: bucket, object: object, mode: "eio", fail: true, failed: &failed, attempted: &attempted}
				}
			}
			set.getDisks = func() []StorageAPI { return disks }
			defer func() { set.getDisks = original }()
			_, errs := z.DeleteObjects(t.Context(), bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: object}}}, ObjectOptions{})
			set.getDisks = original
			if errs[0] == nil || bulkDeleteBody(t, z, bucket, object, "") != "pool-0" {
				t.Errorf("lost tie winner or unreadable-pool error: %v", errs[0])
			}
		})
	}
}

type bulkDeletePauseDisk struct {
	StorageAPI
	bucket, object string
	entered        chan<- struct{}
	release        <-chan struct{}
}

func (d bulkDeletePauseDisk) DeleteVersions(ctx context.Context, bucket string, versions []FileInfoVersions, opts DeleteOptions) []error {
	for _, v := range versions {
		if bucket != d.bucket || v.Name != d.object {
			continue
		}
		select {
		case d.entered <- struct{}{}:
		default:
		}
		select {
		case <-d.release:
		case <-ctx.Done():
		}
		errs := make([]error, len(versions))
		for i := range errs {
			errs[i] = syscall.EIO
		}
		return errs
	}
	return d.StorageAPI.DeleteVersions(ctx, bucket, versions, opts)
}

func TestPoolsBulkDeleteLockAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", canceled), func(t *testing.T) {
			z, bucket := bulkDeletePools(t, 2)
			object := "locked"
			putConsistencyObject(t, z, bucket, object, 0, "old", ObjectOptions{MTime: UTCNow().Add(-time.Hour)})
			putConsistencyObject(t, z, bucket, object, 1, "latest", ObjectOptions{})
			set := z.serverPools[0].getHashedSet(object)
			original := set.getDisks
			disks := append([]StorageAPI(nil), original()...)
			entered, release := make(chan struct{}, 4), make(chan struct{})
			for i, disk := range disks {
				disks[i] = bulkDeletePauseDisk{StorageAPI: disk, bucket: bucket, object: object, entered: entered, release: release}
			}
			set.getDisks = func() []StorageAPI { return disks }
			defer func() { set.getDisks = original }()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, errs := z.DeleteObjects(ctx, bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: object}}}, ObjectOptions{})
				done <- errs[0]
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("old-copy cleanup did not start")
			}
			if canceled {
				cancel()
				if err := <-done; err == nil {
					t.Fatal("canceled cleanup succeeded")
				}
				set.getDisks = original
				if got := bulkDeleteBody(t, z, bucket, object, ""); got != "latest" {
					t.Errorf("cancellation lost latest: %q", got)
				}
				return
			}
			putDone := make(chan error, 1)
			reader := mustGetPutObjReader(t, bytes.NewBufferString("after-put"), 9, "", "")
			go func() {
				_, err := z.PutObject(t.Context(), bucket, object, reader, ObjectOptions{})
				putDone <- err
			}()
			select {
			case err := <-putDone:
				t.Fatalf("PUT passed the held DELETE lock: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			if err := <-done; err == nil {
				t.Error("cleanup failure was lost")
			}
			if err := <-putDone; err != nil {
				t.Fatal(err)
			}
			if got := bulkDeleteBody(t, z, bucket, object, ""); got != "after-put" {
				t.Errorf("concurrent PUT lost: %q", got)
			}
		})
	}
}

type bulkDeleteReplyDisk struct {
	StorageAPI
	err error
}

func (d bulkDeleteReplyDisk) IsOnline() bool { return true }

func (d bulkDeleteReplyDisk) DeleteVersions(_ context.Context, _ string, versions []FileInfoVersions, _ DeleteOptions) []error {
	errs := make([]error, len(versions))
	for i := range errs {
		errs[i] = d.err
	}
	return errs
}

func TestBulkDeleteQuorumEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		obj  ObjectToDelete
		opts ObjectOptions
		ok   bool
	}{
		{name: "unversioned", ok: true},
		{name: "null", obj: ObjectToDelete{ObjectV: ObjectV{VersionID: nullVersionID}}, ok: true},
		{name: "uuid", obj: ObjectToDelete{ObjectV: ObjectV{VersionID: mustGetUUID()}}, ok: true},
		{name: "marker", opts: ObjectOptions{Versioned: true}},
		{name: "suspended-marker", opts: ObjectOptions{VersionSuspended: true}},
		{name: "pending-purge", obj: ObjectToDelete{ObjectV: ObjectV{VersionID: mustGetUUID()}, VersionPurgeStatuses: "target=PENDING;"}},
		{name: "replicated-marker", obj: ObjectToDelete{DeleteMarkerReplicationStatus: "target=PENDING;"}, opts: ObjectOptions{Versioned: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disks := []StorageAPI{
				bulkDeleteReplyDisk{},
				bulkDeleteReplyDisk{},
				bulkDeleteReplyDisk{err: errFileNotFound},
				bulkDeleteReplyDisk{err: errFileVersionNotFound},
			}
			er := erasureObjects{getDisks: func() []StorageAPI { return disks }}
			tc.obj.ObjectName, tc.opts.NoAuditLog = "object", true
			_, errs := er.DeleteObjects(t.Context(), "bucket", []ObjectToDelete{tc.obj}, tc.opts)
			if (errs[0] == nil) != tc.ok {
				t.Errorf("two writes + two absent replies: error=%v, want success=%t", errs[0], tc.ok)
			}
		})
	}
}
