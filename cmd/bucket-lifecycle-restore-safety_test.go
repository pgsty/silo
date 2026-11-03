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
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
	xhttp "github.com/minio/minio/internal/http"
)

const restoreSafetyRules = `<LifecycleConfiguration><Rule><ID>tier</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><Transition><Days>1000</Days><StorageClass>WARM</StorageClass></Transition></Rule></LifecycleConfiguration>`

// Reuse the original restore-copy fixture with a small, isolated real cluster.
func newRestoreSafetyTest(t *testing.T, pools int, state versioning.State) *restoreTest {
	t.Helper()
	prevTier := globalTierConfigMgr
	t.Cleanup(func() { globalTierConfigMgr = prevTier })
	dirs, err := getRandomDisks(4 * pools)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeRoots(dirs) })
	var endpoints EndpointServerPools
	for i := range pools {
		endpoints = append(endpoints, mustGetPoolEndpoints(i, dirs[4*i:4*i+4]...)...)
	}
	obj, _, err := initObjectLayer(t.Context(), endpoints)
	if err != nil {
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	t.Cleanup(func() { z.Shutdown(context.Background()) })
	globalTierConfigMgr = NewTierConfigMgr()
	globalTierConfigMgr.drivercache["WARM"] = &restoreTestTier{tierExpiryTestBackend: &tierExpiryTestBackend{objects: map[string][]byte{}}}
	r := &restoreTest{t: t, z: z, bucket: getRandomBucketName(), object: "obj", labels: map[string]string{}, bodies: map[string][]byte{}}
	if err := z.MakeBucket(t.Context(), r.bucket, MakeBucketOptions{VersioningEnabled: state != ""}); err != nil {
		t.Fatal(err)
	}
	meta, err := globalBucketMetadataSys.Get(r.bucket)
	if err != nil {
		t.Fatal(err)
	}
	if state == versioning.Suspended {
		meta.VersioningConfigXML = []byte(`<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`)
	}
	meta.LifecycleConfigXML = []byte(restoreSafetyRules)
	if err := meta.Save(t.Context(), z); err != nil {
		t.Fatal(err)
	}
	globalBucketMetadataSys.Set(r.bucket, meta)
	return r
}

type restoreCleanupFaultDisk struct {
	consistencyReadFaultDisk
	deletes *atomic.Int64
}

func (d restoreCleanupFaultDisk) DeleteVersion(ctx context.Context, bucket, object string, fi FileInfo, force bool, opts DeleteOptions) error {
	if bucket == d.bucket && object == d.object {
		d.deletes.Add(1)
	}
	return d.StorageAPI.DeleteVersion(ctx, bucket, object, fi, force, opts)
}

func TestExpireRestoredRequiresFreshMetadata(t *testing.T) {
	for _, restored := range []bool{true, false} {
		t.Run(fmt.Sprintf("expire-restored=%v", restored), func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, "")
			oi := r.put("v1", true, true)
			r.restore(oi)
			before := r.fileInfo(oi.VersionID)
			er := r.z.serverPools[0].getHashedSet(r.object)
			original := er.getDisks
			disks := original()
			var deletes atomic.Int64
			faulty := make([]StorageAPI, len(disks))
			for i, d := range disks {
				faulty[i] = restoreCleanupFaultDisk{consistencyReadFaultDisk{d, r.bucket, r.object}, &deletes}
			}
			er.getDisks = func() []StorageAPI { return faulty }
			// Restore the callback before any fixture reads and on a fatal assertion.
			defer func() { er.getDisks = original }()
			opts := ObjectOptions{VersionID: nullVersionID, Transition: TransitionOptions{ExpireRestored: restored}, Expiration: ExpirationOptions{Expire: restored}}
			_, err := er.DeleteObject(t.Context(), r.bucket, r.object, opts)
			er.getDisks = original
			if restored {
				var quorum InsufficientWriteQuorum
				if !errors.As(err, &quorum) {
					t.Errorf("cleanup without fresh metadata: got %v, want write-quorum error", err)
				}
				if n := deletes.Load(); n != 0 {
					t.Errorf("cleanup attempted %d blind disk deletes", n)
				}
				if after := r.fileInfo(oi.VersionID); !reflect.DeepEqual(before, after) {
					t.Error("failed metadata read changed the stored version")
				}
				if n := r.dataDirs(before.DataDir); n != len(disks) {
					t.Errorf("cleanup removed data: %d/%d directories remain", n, len(disks))
				}
			} else {
				// Ordinary unversioned DELETE retains the existing tryDel behavior.
				if err != nil || deletes.Load() != int64(len(disks)) {
					t.Fatalf("ordinary DELETE: err=%v, deletes=%d", err, deletes.Load())
				}
				if _, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, ObjectOptions{}); !isErrObjectNotFound(err) {
					t.Fatalf("ordinary DELETE left the object: %v", err)
				}
			}
		})
	}
}

func TestExpireRestoredRenewedOrMissing(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	oi := r.put("v1", false, true)
	r.restore(oi)
	stale, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
	if err != nil {
		t.Fatal(err)
	}
	before := r.fileInfo(oi.VersionID)
	renewed := completedRestoreObj(time.Now().Add(48 * time.Hour)).String()
	opts := r.opts(oi.VersionID)
	opts.EvalMetadataFn = func(o *ObjectInfo, _ error) (ReplicateDecision, error) {
		o.UserDefined[xhttp.AmzRestore] = renewed
		return ReplicateDecision{}, nil
	}
	if _, err := r.z.PutObjectMetadata(t.Context(), r.bucket, r.object, opts); err != nil {
		t.Fatal(err)
	}
	err = expireTransitionedObject(t.Context(), r.z, &stale, lifecycle.Event{Action: lifecycle.DeleteRestoredAction}, lcEventSrc_Scanner)
	if !isErrVersionNotFound(err) {
		t.Errorf("stale task should be rejected, got %v", err)
	}
	if got := r.fileInfo(oi.VersionID); got.Metadata[xhttp.AmzRestore] != renewed || got.DataDir != before.DataDir {
		t.Error("stale task changed renewed restore")
	}
	if n := r.dataDirs(before.DataDir); n != 4 {
		t.Errorf("renewed copy has %d directories, want 4", n)
	}
	if _, data, err := r.read(oi.VersionID); err != nil || !bytes.Equal(data, r.bodies["v1"]) {
		t.Fatalf("renewed copy not readable: %v", err)
	}

	for _, id := range []string{mustGetUUID(), nullVersionID} {
		opts := r.opts(id)
		opts.Expiration.Expire = true
		opts.Transition.ExpireRestored = true
		if _, err := r.z.DeleteObject(t.Context(), r.bucket, r.object, opts); !isErrVersionNotFound(err) {
			t.Errorf("missing version %s: %v", id, err)
		}
	}
	missing := r.opts(nullVersionID)
	missing.Expiration.Expire = true
	missing.Transition.ExpireRestored = true
	if _, err := r.z.DeleteObject(t.Context(), r.bucket, "missing-object", missing); !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
		t.Errorf("missing object: %v", err)
	}
	if got := r.fileInfo(oi.VersionID); got.Metadata[xhttp.AmzRestore] != renewed {
		t.Error("missing-target cleanup changed existing restore")
	}
}

func TestExpireRestoredStorageBoundary(t *testing.T) {
	for _, status := range []string{"", lifecycle.TransitionPending, lifecycle.TransitionComplete} {
		for _, inline := range []bool{false, true} {
			for _, requestStatus := range []string{"", lifecycle.TransitionComplete} {
				t.Run(fmt.Sprintf("stored=%s/inline=%v/request=%s", status, inline, requestStatus), func(t *testing.T) {
					disk, _, err := newXLStorageTestSetup(t)
					if err != nil {
						t.Fatal(err)
					}
					const bucket, object = "restore-storage", "obj"
					ctx := t.Context()
					if err := disk.MakeVol(ctx, bucket); err != nil {
						t.Fatal(err)
					}
					fi := newFileInfo(object, 2, 2)
					fi.VersionID, fi.DataDir = mustGetUUID(), mustGetUUID()
					fi.ModTime, fi.Size = time.Now().UTC(), 1024
					fi.TransitionStatus = status
					fi.AddObjectPart(1, "", fi.Size, fi.Size, fi.ModTime, nil, nil)
					fi.Metadata = map[string]string{xhttp.AmzRestore: completedRestoreObj(time.Now().Add(-time.Hour)).String(), "x-amz-meta-preserve": "keep"}
					payload := []byte("sole local contents")
					if inline {
						fi.Data = payload
						fi.SetInlineData()
					}
					if err := disk.WriteMetadata(ctx, "", bucket, object, fi); err != nil {
						t.Fatal(err)
					}
					dir := filepath.Join(disk.Endpoint().Path, bucket, object, fi.DataDir)
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "part.1"), payload, 0o600); err != nil {
						t.Fatal(err)
					}
					raw, err := disk.ReadXL(ctx, bucket, object, true)
					if err != nil {
						t.Fatal(err)
					}
					var xl xlMetaV2
					if err := xl.Load(raw.Buf); err != nil {
						t.Fatal(err)
					}
					del := FileInfo{VersionID: fi.VersionID, ExpireRestored: true, TransitionStatus: requestStatus}
					dataDir, err := xl.DeleteVersion(del)
					if err != nil {
						t.Fatal(err)
					}
					wantDir := ""
					if status == lifecycle.TransitionComplete {
						wantDir = fi.DataDir
					}
					if dataDir != wantDir {
						t.Errorf("format authorized directory %q, want %q", dataDir, wantDir)
					}
					before, err := getFileInfo(raw.Buf, bucket, object, fi.VersionID, fileInfoOpts{Data: true})
					if err != nil {
						t.Fatal(err)
					}
					if err := disk.DeleteVersion(ctx, bucket, object, del, false, DeleteOptions{}); err != nil {
						t.Fatal(err)
					}
					afterRaw, err := disk.ReadXL(ctx, bucket, object, true)
					if err != nil {
						t.Fatal(err)
					}
					after, err := getFileInfo(afterRaw.Buf, bucket, object, fi.VersionID, fileInfoOpts{Data: true})
					if err != nil {
						t.Fatal(err)
					}
					data, dirErr := os.ReadFile(filepath.Join(dir, "part.1"))
					if status != lifecycle.TransitionComplete {
						if !reflect.DeepEqual(before, after) {
							t.Error("non-complete cleanup changed metadata or inline data")
						}
						if dirErr != nil || !bytes.Equal(data, payload) {
							t.Errorf("sole local contents removed: %v", dirErr)
						}
					} else {
						if !os.IsNotExist(dirErr) {
							t.Errorf("completed restore directory still present: %v", dirErr)
						}
						if len(after.Data) != 0 || after.Metadata[xhttp.AmzRestore] != "" {
							t.Error("completed restore kept cached data or restore headers")
						}
						if after.TransitionStatus != status || after.VersionID != before.VersionID || after.Metadata["x-amz-meta-preserve"] != "keep" {
							t.Error("cleanup changed the transitioned version identity or user metadata")
						}
					}
				})
			}
		}
	}
}
