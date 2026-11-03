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
	"net/http"
	"testing"

	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/replication"
	"github.com/minio/minio/internal/bucket/versioning"
)

// Reuse the author's scanner/worker fixture. A second configured pool is
// sufficient to trigger the tiered NNV regression; no versions need move there.
func TestPoolsLifecycleTieredNoncurrentBatch(t *testing.T) {
	for _, tiered := range []bool{false, true} {
		name := "plain"
		if tiered {
			name = "tiered"
		}
		t.Run(name, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			old := func(label string, days float64) splitVersion {
				v := splitAt(label, days, 0)
				v.tiered = tiered
				return v
			}
			s.run([]splitKey{
				{"nnv-all-in-0", []splitVersion{old("v1", 5), old("v2", 4), splitAt("v3", 3, 0), splitAt("v4", 2, 0)}, "v4", "v4", [][]string{{"v4", "v3"}, nil}},
				{"ncv-all-in-0", []splitVersion{old("v1", 5), old("v2", 4), splitAt("v3", 0.01, 0)}, "v3", "v3", [][]string{{"v3", "v2"}, nil}},
			})
		})
	}
}

// Observe the actual pool results consumed by the expiry worker, without
// replacing the storage deletion or the replication enqueue path.
type lifecycleBatchResult struct {
	ObjectLayer
	deleted []DeletedObject
	errs    []error
}

func (o *lifecycleBatchResult) DeleteObjects(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions) ([]DeletedObject, []error) {
	o.deleted, o.errs = o.ObjectLayer.DeleteObjects(ctx, bucket, objects, opts)
	return o.deleted, o.errs
}

func TestPoolsLifecycleTieredBatchReplication(t *testing.T) {
	for _, identity := range []string{"uuid", "null"} {
		t.Run(identity, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			const key = "nnv-replicated"
			oldest := splitTiered("v1", 5, 0)
			oldest.null = identity == "null"
			for _, v := range []splitVersion{oldest, splitTiered("v2", 4, 0), splitTiered("v3", 3, 0), splitAt("v4", 2, 0)} {
				s.write(key, v)
			}
			target := newILMTestTarget(t)
			registerILMTestTarget(t, s.z, s.bucket, target, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("unexpected target method: %s", r.Method)
					w.WriteHeader(500)
					return
				}
				target.deletes.Add(1)
				opts := ObjectOptions{VersionID: r.URL.Query().Get("versionId"), Versioned: true, ReplicationRequest: true}
				opts.SetReplicaStatus(replication.Replica)
				if _, err := s.z.DeleteObject(r.Context(), target.bucket, key, opts); err != nil && !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
					t.Errorf("target purge: %v", err)
					w.WriteHeader(500)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})
			setILMTestReplicationConfig(t, s.bucket, target.arn, target.bucket)
			stats := NewReplicationStats(t.Context(), nil)
			previous := globalReplicationStats.Swap(stats)
			t.Cleanup(func() { globalReplicationStats.Store(previous) })
			restore, _ := newILMTestReplicationPool(t.Context(), s.z, stats)
			t.Cleanup(restore)
			var entries []ObjectToDelete
			for _, label := range []string{"v1", "v3"} {
				vid := s.ids[key+" "+label]
				if vid == "" {
					vid = nullVersionID
				}
				oi, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: vid, Versioned: true})
				if err != nil {
					t.Fatal(err)
				}
				entry := ilmPurgeToDelete(t.Context(), s.bucket, oi, true)
				if entry.VersionPurgeStatus != replication.VersionPurgePending {
					t.Fatalf("fixture lacks purge decision: %+v", entry)
				}
				entries = append(entries, entry)
				putConsistencyObject(t, s.z, target.bucket, key, 0, label, ObjectOptions{Versioned: identity != "null" || label != "v1", VersionID: vid})
			}
			result := &lifecycleBatchResult{ObjectLayer: s.z}
			deleteObjectVersions(t.Context(), result, s.bucket, entries, []lifecycle.Event{{Action: lifecycle.DeleteVersionAction}, {Action: lifecycle.DeleteVersionAction}})
			if result.errs[0] != nil {
				t.Errorf("eligible delete: %v", result.errs[0])
			}
			if !isErrVersionNotFound(result.errs[1]) {
				t.Errorf("retained version result: %v", result.errs[1])
			}
			if result.deleted[1].VersionPurgeStatus() != "" || result.deleted[1].ReplicationState.ReplicateDecisionStr != "" {
				t.Errorf("rejected entry retained replication state: %+v", result.deleted[1])
			}
			source, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: entries[0].VersionID, Versioned: true})
			if !isErrMethodNotAllowed(err) || source.VersionPurgeStatus != replication.VersionPurgePending {
				t.Errorf("source must be a pending purge tombstone before enqueue: status=%q err=%v", source.VersionPurgeStatus, err)
			}
			retained, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: entries[1].VersionID, Versioned: true})
			if err != nil || retained.VersionPurgeStatus != "" {
				t.Errorf("rejected source changed: %+v, %v", retained, err)
			}
			queue := globalReplicationPool.Get().workers[0]
			if len(queue) != 1 {
				t.Fatalf("queued %d purges, want only eligible v1", len(queue))
			}
			deletion, ok := (<-queue).(DeletedObjectReplicationInfo)
			if !ok || deletion.VersionID != entries[0].VersionID || deletion.EventType != ReplicateILMDelete || deletion.VersionPurgeStatus() != replication.VersionPurgePending {
				t.Fatalf("wrong purge queued: %+v", deletion)
			}
			if result := replicateDelete(t.Context(), deletion, s.z); result.VersionPurgeStatus() != replication.VersionPurgeComplete {
				t.Fatalf("replicate purge: %+v", result)
			}
			if target.deletes.Load() != 1 {
				t.Errorf("target delete count=%d", target.deletes.Load())
			}
			for _, bucket := range []string{s.bucket, target.bucket} {
				if _, err := s.z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: entries[0].VersionID}); !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
					t.Errorf("purged v1 remains in %s: %v", bucket, err)
				}
				if _, err := s.z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: entries[1].VersionID}); err != nil {
					t.Errorf("retained v3 missing from %s: %v", bucket, err)
				}
			}
		})
	}
}

func TestPoolsLifecycleTieredBatchIdentity(t *testing.T) {
	for _, tc := range []struct {
		name      string
		versioned bool
		id        string
		expire    bool
		wantGone  bool
	}{
		{"uuid-ilm", true, "uuid", true, true},
		{"null-ilm", true, "null", true, true},
		{"empty-unversioned-ilm", false, "", true, false},
		{"uuid-user-delete", true, "uuid", false, true},
		{"empty-user-delete", false, "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := versioning.State("")
			if tc.versioned {
				state = versioning.Enabled
			}
			s := newSplitILM(t, state, splitILMRules)
			const key = "nnv-identity"
			v := splitTiered("v1", 5, 0)
			v.null = tc.id != "uuid"
			s.write(key, v)
			if tc.versioned {
				s.write(key, splitAt("v2", 4, 0))
				s.write(key, splitAt("v3", 3, 0))
			}
			vid := tc.id
			if vid == "uuid" {
				vid = s.ids[key+" v1"]
			}
			vc, _ := globalBucketVersioningSys.Get(s.bucket)
			_, errs := s.z.DeleteObjects(t.Context(), s.bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: key, VersionID: vid}}}, ObjectOptions{PrefixEnabledFn: vc.PrefixEnabled, Expiration: ExpirationOptions{Expire: tc.expire}})
			if errs[0] != nil {
				t.Fatalf("delete: %v", errs[0])
			}
			query := vid
			if query == "" {
				query = nullVersionID
			}
			_, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: query})
			gone := isErrVersionNotFound(err) || isErrObjectNotFound(err)
			if gone != tc.wantGone || (!gone && err != nil) {
				t.Fatalf("gone=%t err=%v, want gone=%t", gone, err, tc.wantGone)
			}
		})
	}
}
