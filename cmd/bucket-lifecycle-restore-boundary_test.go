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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
)

// Read the actual metadata from every disk without object-layer read repair.
func restoreBoundarySnapshot(t *testing.T, r *restoreTest) [][]byte {
	t.Helper()
	var result [][]byte
	for _, pool := range r.z.serverPools {
		for _, disk := range pool.getHashedSet(r.object).getDisks() {
			raw, err := disk.ReadXL(t.Context(), r.bucket, r.object, true)
			if err != nil && err != errFileNotFound {
				t.Fatal(err)
			}
			result = append(result, bytes.Clone(raw.Buf))
		}
	}
	return result
}

func TestExpireRestoredKeepsReplacementDeleteMarker(t *testing.T) {
	for _, pools := range []int{1, 2} {
		t.Run(fmt.Sprintf("pools=%d", pools), func(t *testing.T) {
			r := newRestoreSafetyTest(t, pools, versioning.Suspended)
			r.put("old", false, false)
			oi := r.put("null", true, true)
			r.restore(oi)
			stale, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(nullVersionID))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.z.DeleteObject(t.Context(), r.bucket, r.object, r.opts("")); err != nil {
				t.Fatal(err)
			}
			if !r.fileInfo(nullVersionID).Deleted {
				t.Fatal("ordinary DELETE did not replace null with a delete marker")
			}
			before := restoreBoundarySnapshot(t, r)
			err = expireTransitionedObject(t.Context(), r.z, &stale, lifecycle.Event{Action: lifecycle.DeleteRestoredAction}, lcEventSrc_Scanner)
			if !isErrVersionNotFound(err) {
				t.Errorf("stale cleanup should reject the replacement marker: %v", err)
			}
			if !reflect.DeepEqual(before, restoreBoundarySnapshot(t, r)) {
				t.Error("stale cleanup changed stored versions or their data")
			}
			if _, _, err := r.read(""); !isErrObjectNotFound(err) {
				t.Errorf("stale cleanup exposed the old version: %v", err)
			}
			// An explicit user purge must still remove that same marker.
			if _, err := r.z.DeleteObject(t.Context(), r.bucket, r.object, r.opts(nullVersionID)); err != nil {
				t.Fatal(err)
			}
			if label, data, err := r.read(""); err != nil || label != "old" || !bytes.Equal(data, r.bodies["old"]) {
				t.Fatalf("ordinary marker purge: label=%s err=%v", label, err)
			}
		})
	}
}

func TestExpireRestoredMetadataReadKeepsMinorityVersion(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, operation := range []string{"cleanup", "restore", "restore-cleanup", "lookup-cleanup", "lookup-restore", "get", "delete"} {
			t.Run(fmt.Sprintf("pools=%d/%s", pools, operation), func(t *testing.T) {
				r := newRestoreSafetyTest(t, pools, versioning.Enabled)
				oi := r.put("target", false, true)
				r.restore(oi)
				fi := r.fileInfo(oi.VersionID)
				// A readable latest version lets pools lookup finish before the
				// set reads the specifically addressed, incomplete old version.
				r.put("newer", false, false)
				er := r.z.serverPools[0].getHashedSet(r.object)
				disks := er.getDisks()
				for _, disk := range disks[1:] {
					raw, err := disk.ReadXL(t.Context(), r.bucket, r.object, true)
					if err != nil {
						t.Fatal(err)
					}
					var meta xlMetaV2
					if err := meta.Load(raw.Buf); err != nil {
						t.Fatal(err)
					}
					del := FileInfo{VersionID: oi.VersionID}
					del.SetSkipTierFreeVersion()
					if _, err := meta.DeleteVersion(del); err != nil {
						t.Fatal(err)
					}
					buf, err := meta.AppendTo(nil)
					if err != nil {
						t.Fatal(err)
					}
					// Remove only this metadata entry; retain every real shard.
					if err := disk.WriteAll(t.Context(), r.bucket, pathJoin(r.object, xlStorageFormatFile), buf); err != nil {
						t.Fatal(err)
					}
				}
				before := restoreBoundarySnapshot(t, r)
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				opts := r.opts(oi.VersionID)
				var err error
				switch operation {
				case "cleanup":
					err = expireTransitionedObject(ctx, r.z, &oi, lifecycle.Event{Action: lifecycle.DeleteRestoredVersionAction}, lcEventSrc_Scanner)
				case "restore":
					opts.Transition.RestoreRequest = &RestoreObjectRequest{Days: 1}
					err = r.z.RestoreTransitionedObject(ctx, r.bucket, r.object, opts)
				case "restore-cleanup":
					// The initial read succeeded before remote download failed;
					// cleanup must not purge a now-incomplete target on reread.
					err = er.clearRestoreStatus(ctx, r.bucket, r.object, oi.VersionID, nil)
				case "lookup-cleanup", "lookup-restore":
					// Version-sensitive lookup also covers native restore routing.
					opts.MetadataChg = true
					if operation == "lookup-cleanup" {
						opts.Transition.ExpireRestored = true
					} else {
						opts.Transition.RestoreRequest = &RestoreObjectRequest{Days: 1}
					}
					_, _, err = r.z.getPoolInfoExistingWithOpts(ctx, r.bucket, r.object, opts)
				case "get":
					_, err = r.z.GetObjectInfo(ctx, r.bucket, r.object, opts)
				case "delete":
					_, err = r.z.DeleteObject(ctx, r.bucket, r.object, opts)
				}
				if ctx.Err() != nil {
					t.Fatalf("%s timed out instead of returning its read error: %v", operation, err)
				}
				if err == nil {
					t.Fatal("incomplete target unexpectedly readable")
				}
				if operation != "get" && operation != "delete" {
					if !reflect.DeepEqual(before, restoreBoundarySnapshot(t, r)) {
						t.Error("failed restore read changed metadata, inline data or free versions")
					}
					if n := r.dataDirs(fi.DataDir); n != len(disks) {
						t.Errorf("failed restore read removed shards: %d/%d directories remain", n, len(disks))
					}
					return
				}
				// Ordinary GET/DELETE retain their existing dangling cleanup.
				raw, err := disks[0].ReadXL(t.Context(), r.bucket, r.object, false)
				if err != nil {
					t.Fatal(err)
				}
				versions, err := getFileInfoVersions(raw.Buf, r.bucket, r.object, false)
				if err != nil {
					t.Fatal(err)
				}
				if len(versions.Versions) != 1 || len(versions.FreeVersions) != 1 || r.dataDirs(fi.DataDir) != len(disks)-1 {
					t.Fatal("ordinary dangling cleanup no longer removed the minority version")
				}
			})
		}
	}
}

func TestNativeRestoreInitialMissingReadDoesNotWrite(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	r.put("live", false, false)
	before := restoreBoundarySnapshot(t, r)
	opts := r.opts(mustGetUUID())
	opts.Transition.RestoreRequest = &RestoreObjectRequest{Days: 1}
	if err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, opts); !isErrVersionNotFound(err) {
		t.Fatalf("missing restore target: %v", err)
	}
	if !reflect.DeepEqual(before, restoreBoundarySnapshot(t, r)) {
		t.Fatal("initial restore failure wrote metadata without a resolved version")
	}
}

func TestExpireRestoredStorageRejectsOtherTypes(t *testing.T) {
	for _, kind := range []string{"null-marker", "uuid-marker", "legacy", "legacy-json"} {
		t.Run(kind, func(t *testing.T) {
			disk, _, err := newXLStorageTestSetup(t)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			const bucket, object = "restore-types", "obj"
			if err := disk.MakeVol(ctx, bucket); err != nil {
				t.Fatal(err)
			}
			var meta xlMetaV2
			versionID, metaName, dataDir := nullVersionID, xlStorageFormatFile, ""
			var buf []byte
			switch kind {
			case "null-marker", "uuid-marker":
				if kind == "uuid-marker" {
					versionID = mustGetUUID()
				}
				err = meta.AddVersion(FileInfo{VersionID: versionID, Deleted: true, ModTime: time.Now().UTC()})
			case "legacy", "legacy-json":
				legacy := getSampleXLMeta(1)
				legacy.DataDir, dataDir = "legacy", "legacy"
				if kind == "legacy-json" {
					metaName = xlStorageFormatFileV1
					buf, err = json.Marshal(legacy)
					disk.storage.Lock()
					disk.storage.formatLegacy = true
					disk.storage.Unlock()
				} else {
					err = meta.AddLegacy(&legacy)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if buf == nil {
				buf, err = meta.AppendTo(nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := disk.WriteAll(ctx, bucket, pathJoin(object, metaName), buf); err != nil {
				t.Fatal(err)
			}
			payload := []byte("sole legacy contents")
			dataPath := filepath.Join(disk.Endpoint().Path, bucket, object, dataDir, "part.1")
			if dataDir != "" {
				if err := os.MkdirAll(filepath.Dir(dataPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dataPath, payload, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := disk.DeleteVersion(ctx, bucket, object, FileInfo{VersionID: versionID, ExpireRestored: true, TransitionStatus: lifecycle.TransitionComplete}, false, DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			after, err := disk.ReadAll(ctx, bucket, pathJoin(object, metaName))
			if err != nil || !bytes.Equal(buf, after) {
				t.Errorf("restore cleanup changed %s metadata: %v", kind, err)
			}
			if dataDir != "" {
				if data, err := os.ReadFile(dataPath); err != nil || !bytes.Equal(data, payload) {
					t.Errorf("restore cleanup removed legacy contents: %v", err)
				}
			}
			if err := disk.DeleteVersion(ctx, bucket, object, FileInfo{VersionID: versionID}, false, DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := disk.ReadAll(ctx, bucket, pathJoin(object, metaName)); err != errFileNotFound {
				t.Errorf("ordinary purge left %s: %v", kind, err)
			}
		})
	}
}
