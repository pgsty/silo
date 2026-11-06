// Copyright (c) 2026 Feng Ruohang
//
// This file is part of Silo Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/replication"
	"github.com/minio/minio/internal/bucket/versioning"
	xhttp "github.com/minio/minio/internal/http"
)

// A partial metadata update can leave the newest lock/tag revision on a copy
// other than the one selected by content ModTime. Keep the data identity intact.
func setLifecycleCopyMetadata(t *testing.T, s *splitILM, key, id string, pool int, metadata map[string]string, advance bool) {
	t.Helper()
	oi, err := s.z.serverPools[pool].GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: id})
	if err != nil {
		t.Fatal(err)
	}
	opts := ObjectOptions{VersionID: id, Versioned: true, MTime: oi.ModTime}
	if advance {
		opts.MTime = opts.MTime.Add(time.Hour)
	}
	opts.EvalMetadataFn = func(oi *ObjectInfo, _ error) (ReplicateDecision, error) {
		maps.Copy(oi.UserDefined, metadata)
		return ReplicateDecision{}, nil
	}
	if _, err := s.z.serverPools[pool].PutObjectMetadata(t.Context(), s.bucket, key, opts); err != nil {
		t.Fatal(err)
	}
}

func TestPoolsLifecycleDuplicateLockMetadata(t *testing.T) {
	old := UTCNow().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	recent := UTCNow().Add(-time.Hour).Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name       string
		copies     [2]map[string]string
		mode, hold string
		delete     bool
		newerPool1 bool
	}{
		{name: "hold-on", copies: [2]map[string]string{poolLockMetadata("", "OFF", old, old), poolLockMetadata("", "ON", old, recent)}, hold: "ON"},
		{name: "held-earlier-pool", copies: [2]map[string]string{poolLockMetadata("", "ON", old, recent), poolLockMetadata("", "OFF", old, old)}, hold: "ON", newerPool1: true},
		{name: "retention-on", copies: [2]map[string]string{poolLockMetadata("", "OFF", old, old), poolLockMetadata("GOVERNANCE", "OFF", recent, old)}, mode: "GOVERNANCE", hold: "OFF"},
		{name: "independent-fields", copies: [2]map[string]string{poolLockMetadata("GOVERNANCE", "OFF", recent, old), poolLockMetadata("", "ON", old, recent)}, mode: "GOVERNANCE", hold: "ON"},
		{name: "hold-released", copies: [2]map[string]string{poolLockMetadata("", "ON", old, old), poolLockMetadata("", "OFF", old, recent)}, hold: "OFF", delete: true},
		{name: "retention-released", copies: [2]map[string]string{poolLockMetadata("GOVERNANCE", "OFF", old, old), poolLockMetadata("", "OFF", recent, old)}, hold: "OFF", delete: true},
	} {
		for _, batch := range []bool{false, true} {
			path := "single"
			if batch {
				path = "batch"
			}
			t.Run(tc.name+"/"+path, func(t *testing.T) {
				s := &splitILM{migrationILM: newMigrationILM(t, versioning.Enabled, true, splitILMRules), ids: map[string]string{}, bodies: map[string]string{}}
				const key = "ncv-copy-lock"
				v := splitAt("old", 5, 0, 1)
				v.tiered = batch
				s.write(key, v)
				s.write(key, splitAt("new", 3, 0, 1))
				id := s.ids[key+" old"]
				for pool, metadata := range tc.copies {
					metadata = maps.Clone(metadata)
					if metadata["x-amz-object-lock-mode"] != "" {
						metadata["x-amz-object-lock-retain-until-date"] = UTCNow().AddDate(1, 0, 0).Format(time.RFC3339)
					} else {
						metadata["x-amz-object-lock-retain-until-date"] = ""
					}
					setLifecycleCopyMetadata(t, s, key, id, pool, metadata, tc.newerPool1 && pool == 1)
				}
				versions, events, err := s.z.lifecycleEventsAllPools(t.Context(), s.bucket, key)
				switch {
				case tc.newerPool1:
					// Another ModTime makes the copies separate writes. The
					// held older one refuses the object instead of merging.
					if !errors.Is(err, errLifecycleNotApplicable) {
						t.Fatalf("held older write: %v", err)
					}
				case err != nil:
					t.Fatal(err)
				default:
					if len(versions) != 2 || versions[1].VersionID != id || versions[1].NumVersions != 2 {
						t.Fatalf("wrong version history: %+v", versions)
					}
					state := storedObjectLockState(versions[1].UserDefined)
					if state.mode != tc.mode || state.legalHold != tc.hold {
						t.Errorf("merged state=%+v, want mode=%s hold=%s", state, tc.mode, tc.hold)
					}
					want := lifecycle.NoneAction
					if tc.delete {
						want = lifecycle.DeleteVersionAction
					}
					// Read-side expiry rechecks consume the same event producer.
					if events[1].Action != want {
						t.Errorf("expiry event=%s want=%s", events[1].Action, want)
					}
				}
				opts := ObjectOptions{Versioned: true, Expiration: ExpirationOptions{Expire: true}}
				if batch {
					_, errs := s.z.DeleteObjects(t.Context(), s.bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: key, VersionID: id}}}, opts)
					err = errs[0]
				} else {
					opts.VersionID = id
					_, err = s.z.DeleteObject(t.Context(), s.bucket, key, opts)
				}
				if tc.delete && err != nil || !tc.delete && !errors.Is(err, errLifecycleNotApplicable) {
					t.Errorf("delete error=%v, wantDelete=%t", err, tc.delete)
				}
				for pool := range s.z.serverPools {
					_, err := s.z.serverPools[pool].GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: id})
					// An approved expiry removes the version from every pool,
					// in a batch and as a single delete.
					gone := tc.delete
					if gone && !isErrVersionNotFound(err) || !gone && err != nil {
						t.Errorf("pool=%d err=%v wantGone=%t", pool, err, gone)
					}
				}
			})
		}
	}
}

func TestPoolsLifecycleDuplicateTagMetadata(t *testing.T) {
	const rule = `<Rule><ID>tagged</ID><Status>Enabled</Status><Filter><Tag><Key>expire</Key><Value>yes</Value></Tag></Filter><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>`
	for _, tc := range []struct {
		name, stale, fresh string
		expire             bool
	}{
		{"removed", "expire=yes", "", false},
		{"changed", "expire=yes", "expire=no", false},
		{"enabled", "expire=no", "expire=yes", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, rule)
			const key = "tagged-copy"
			s.write(key, splitTiered("old", 5, 0, 1))
			s.write(key, splitAt("new", 3, 0, 1))
			id := s.ids[key+" old"]
			old := UTCNow().Add(-2 * time.Hour).Format(time.RFC3339Nano)
			recent := UTCNow().Add(-time.Hour).Format(time.RFC3339Nano)
			for pool, tags := range []string{tc.stale, tc.fresh} {
				stamp := old
				if pool == 1 {
					stamp = recent
				}
				setLifecycleCopyMetadata(t, s, key, id, pool, map[string]string{xhttp.AmzObjectTagging: tags, ReservedMetadataPrefixLower + TaggingTimestamp: stamp}, false)
			}
			versions, events, err := s.z.lifecycleEventsAllPools(t.Context(), s.bucket, key)
			if err != nil {
				t.Fatal(err)
			}
			if len(versions) != 2 || versions[1].UserTags != tc.fresh || versions[1].UserDefined[ReservedMetadataPrefixLower+TaggingTimestamp] != recent {
				t.Fatalf("lost newest tag revision: %+v", versions)
			}
			want := lifecycle.NoneAction
			if tc.expire {
				want = lifecycle.DeleteVersionAction
			}
			if events[1].Action != want {
				t.Errorf("shared read/delete expiry event=%s want=%s", events[1].Action, want)
			}
			_, errs := s.z.DeleteObjects(t.Context(), s.bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: key, VersionID: id}}}, ObjectOptions{Versioned: true, Expiration: ExpirationOptions{Expire: true}})
			if tc.expire && errs[0] != nil || !tc.expire && !errors.Is(errs[0], errLifecycleNotApplicable) {
				t.Errorf("delete error=%v", errs[0])
			}
			for pool := range s.z.serverPools {
				_, err := s.z.serverPools[pool].GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: id})
				if tc.expire && !isErrVersionNotFound(err) || !tc.expire && err != nil {
					t.Errorf("pool=%d err=%v wantGone=%t", pool, err, tc.expire)
				}
			}
		})
	}
}

// All-pool validation uses ReadXL. Run once at the first addressed read in
// batch dispatch, after validation and before the set's lifecycle check.
type lifecycleDispatchDisk struct {
	StorageAPI
	bucket, key string
	once        *sync.Once
	scans       *atomic.Int64
	beforeRead  func()
}

func (d lifecycleDispatchDisk) ReadXL(ctx context.Context, bucket, key string, data bool) (RawFileInfo, error) {
	if bucket == d.bucket && key == d.key {
		d.scans.Add(1)
	}
	return d.StorageAPI.ReadXL(ctx, bucket, key, data)
}

func (d lifecycleDispatchDisk) ReadVersion(ctx context.Context, orig, bucket, key, id string, opts ReadOptions) (FileInfo, error) {
	if bucket == d.bucket && key == d.key {
		d.once.Do(d.beforeRead)
	}
	return d.StorageAPI.ReadVersion(ctx, orig, bucket, key, id, opts)
}

func TestPoolsLifecycleBatchRejectionReplication(t *testing.T) {
	for _, mode := range []string{"withdraw-before-validation", "withdraw-after-validation", "already-absent", "normal"} {
		t.Run(mode, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			const key = "ncv-dispatch-recheck"
			s.write(key, splitTiered("old", 5, 0))
			s.write(key, splitAt("new", 3, 0))
			id := s.ids[key+" old"]
			target := newILMTestTarget(t)
			registerILMTestTarget(t, s.z, s.bucket, target, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Query().Get("versionId") != id {
					t.Errorf("unexpected purge: %s %s", r.Method, r.URL)
					w.WriteHeader(500)
					return
				}
				target.deletes.Add(1)
				opts := ObjectOptions{VersionID: r.URL.Query().Get("versionId"), Versioned: true, ReplicationRequest: true}
				opts.SetReplicaStatus(replication.Replica)
				if _, err := s.z.DeleteObject(r.Context(), target.bucket, key, opts); err != nil && !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})
			setILMTestReplicationConfig(t, s.bucket, target.arn, target.bucket)
			putConsistencyObject(t, s.z, target.bucket, key, 0, "replica", ObjectOptions{Versioned: true, VersionID: id})
			stats := NewReplicationStats(t.Context(), nil)
			previous := globalReplicationStats.Swap(stats)
			t.Cleanup(func() { globalReplicationStats.Store(previous) })
			restore, _ := newILMTestReplicationPool(t.Context(), s.z, stats)
			t.Cleanup(restore)
			oi, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: id})
			if err != nil {
				t.Fatal(err)
			}
			// As the scanner builds a noncurrent expiry entry: lifecycle
			// purges carry no replication decision.
			entry := ObjectToDelete{ObjectV: ObjectV{ObjectName: key, VersionID: oi.VersionID}}
			withdraw := func() {
				meta, err := globalBucketMetadataSys.Get(s.bucket)
				if err != nil {
					t.Error(err)
					return
				}
				meta.lifecycleConfig = nil
				meta.LifecycleConfigXML = nil
				globalBucketMetadataSys.Set(s.bucket, meta)
			}
			if mode == "withdraw-before-validation" {
				withdraw()
			}
			originals := s.z.serverPools[0].getHashedSet(key).getDisks()
			var once sync.Once
			var scans atomic.Int64
			var dispatched atomic.Bool
			for _, pool := range s.z.serverPools {
				pool.erasureDisksMu.Lock()
				prior := pool.erasureDisks
				wrapped := make([][]StorageAPI, len(prior))
				for i, disks := range prior {
					wrapped[i] = append([]StorageAPI(nil), disks...)
					for j, disk := range disks {
						wrapped[i][j] = lifecycleDispatchDisk{StorageAPI: disk, bucket: s.bucket, key: key, once: &once, scans: &scans, beforeRead: func() {
							dispatched.Store(true)
							if mode != "withdraw-before-validation" && scans.Load() == 0 {
								t.Error("dispatch injection ran before all-pool validation")
							}
							switch mode {
							case "withdraw-after-validation":
								withdraw()
							case "already-absent":
								fi := FileInfo{VersionID: id}
								fi.SetTierFreeVersionID(mustGetUUID())
								for _, disk := range originals {
									if err := disk.DeleteVersion(t.Context(), s.bucket, key, fi, false, DeleteOptions{}); err != nil {
										t.Error(err)
									}
								}
							}
						}}
					}
				}
				pool.erasureDisks = wrapped
				pool.erasureDisksMu.Unlock()
				t.Cleanup(func() { pool.erasureDisksMu.Lock(); pool.erasureDisks = prior; pool.erasureDisksMu.Unlock() })
			}
			result := &lifecycleBatchResult{ObjectLayer: s.z}
			deleteObjectVersions(t.Context(), result, s.bucket, []ObjectToDelete{entry}, []lifecycle.Event{{Action: lifecycle.DeleteVersionAction}})
			if mode != "withdraw-before-validation" && !dispatched.Load() {
				t.Fatal("dispatch injection did not run")
			}
			queue := globalReplicationPool.Get().workers[0]
			reject := mode == "withdraw-before-validation" || mode == "withdraw-after-validation"
			if reject {
				if !errors.Is(result.errs[0], errLifecycleNotApplicable) || result.deleted[0].found || result.deleted[0].VersionPurgeStatus() != "" || result.deleted[0].ReplicationState.ReplicateDecisionStr != "" {
					t.Errorf("rejection acknowledged a purge: %+v, %v", result.deleted[0], result.errs[0])
				}
				if len(queue) != 0 {
					t.Fatalf("rejected delete queued %d remote purges", len(queue))
				}
				for _, bucket := range []string{s.bucket, target.bucket} {
					oi, err := s.z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: id})
					if err != nil || oi.VersionPurgeStatus != "" {
						t.Errorf("rejection changed %s: purge=%s err=%v", bucket, oi.VersionPurgeStatus, err)
					}
				}
				if target.deletes.Load() != 0 {
					t.Fatal("rejected delete reached remote target")
				}
				return
			}
			if result.errs[0] != nil || len(queue) != 0 {
				t.Fatalf("valid/absent purge: error=%v queued=%d", result.errs[0], len(queue))
			}
			if _, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: id}); !isErrVersionNotFound(err) {
				t.Fatalf("source must be gone, not a purge tombstone: %v", err)
			}
			if target.deletes.Load() != 0 {
				t.Fatalf("remote deletes=%d", target.deletes.Load())
			}
			if _, err := s.z.GetObjectInfo(t.Context(), target.bucket, key, ObjectOptions{VersionID: id}); err != nil {
				t.Errorf("target copy changed: %v", err)
			}
		})
	}
}
