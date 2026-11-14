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
	"testing"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/pubsub"
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

// A batch of ILM version purges keeps the cross-pool refusal and does not
// replicate: the eligible version is gone from every pool, the refused one
// stays, and nothing reaches the replication target.
func TestPoolsLifecycleTieredBatchNotReplicated(t *testing.T) {
	for _, identity := range []string{"uuid", "null"} {
		t.Run(identity, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			const key = "nnv-replicated"
			oldest := splitTiered("v1", 5, 0)
			oldest.null = identity == "null"
			for _, v := range []splitVersion{oldest, splitTiered("v2", 4, 0), splitTiered("v3", 3, 0), splitAt("v4", 2, 0)} {
				s.write(key, v)
			}
			target, requests := ilmTestTarget(t, s.z, s.bucket, key, false)
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
				// As the scanner builds a noncurrent expiry entry.
				entries = append(entries, ObjectToDelete{ObjectV: ObjectV{ObjectName: key, VersionID: vid}})
				putConsistencyObject(t, s.z, target.bucket, key, 0, label, ObjectOptions{Versioned: identity != "null" || label != "v1", VersionID: vid})
			}
			result := &lifecycleBatchResult{ObjectLayer: s.z}
			deleteObjectVersions(t.Context(), result, s.bucket, entries, []lifecycle.Event{{Action: lifecycle.DeleteVersionAction}, {Action: lifecycle.DeleteVersionAction}})
			if result.errs[0] != nil {
				t.Errorf("eligible delete: %v", result.errs[0])
			}
			if !errors.Is(result.errs[1], errLifecycleNotApplicable) {
				t.Errorf("retained version result: %v", result.errs[1])
			}
			if result.deleted[1].VersionPurgeStatus() != "" || result.deleted[1].ReplicationState.ReplicateDecisionStr != "" {
				t.Errorf("rejected entry carries replication state: %+v", result.deleted[1])
			}
			for pool := range s.z.serverPools {
				if _, err := s.z.serverPools[pool].GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: entries[0].VersionID, Versioned: true}); !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
					t.Errorf("pool %d: purged v1 remains: %v", pool, err)
				}
			}
			retained, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: entries[1].VersionID, Versioned: true})
			if err != nil || retained.VersionPurgeStatus != "" {
				t.Errorf("rejected source changed: %+v, %v", retained, err)
			}
			if n := len(globalReplicationPool.Get().workers[0]); n != 0 {
				t.Fatalf("queued %d replication tasks", n)
			}
			if n := requests.Load(); n != 0 {
				t.Errorf("the target saw %d requests", n)
			}
			for _, e := range entries {
				if _, err := s.z.GetObjectInfo(t.Context(), target.bucket, key, ObjectOptions{VersionID: e.VersionID}); err != nil {
					t.Errorf("target copy %s changed: %v", e.VersionID, err)
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
			if tc.expire && !tc.wantGone {
				if !errors.Is(errs[0], errLifecycleNotApplicable) {
					t.Fatalf("ineligible expiry: %v", errs[0])
				}
			} else if errs[0] != nil {
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

// A batch entry whose expiry the all-pools recheck rejects is kept. The worker
// must not report it as removed, by event, ILM trace or audit, while eligible
// entries of the same batch are still reported.
func TestPoolsLifecycleBatchRejectionNotAnnounced(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	const key = "nnv-announce"
	for _, v := range []splitVersion{splitTiered("v1", 5, 0), splitTiered("v2", 4, 0), splitTiered("v3", 3, 0), splitAt("v4", 2, 0)} {
		s.write(key, v)
	}
	eligible, retained := s.ids[key+" v1"], s.ids[key+" v3"]
	done := make(chan struct{})
	defer close(done)
	events := make(chan event.Event, 8)
	if err := globalHTTPListen.Subscribe(pubsub.MaskFromMaskable(event.ObjectRemovedDelete), events, done, nil); err != nil {
		t.Fatal(err)
	}
	traces := make(chan madmin.TraceInfo, 8)
	if err := globalTrace.Subscribe(madmin.TraceILM, traces, done, nil); err != nil {
		t.Fatal(err)
	}
	result := &lifecycleBatchResult{ObjectLayer: s.z}
	deleteObjectVersions(t.Context(), result, s.bucket, []ObjectToDelete{
		{ObjectV: ObjectV{ObjectName: key, VersionID: eligible}},
		{ObjectV: ObjectV{ObjectName: key, VersionID: retained}},
	}, []lifecycle.Event{{Action: lifecycle.DeleteVersionAction}, {Action: lifecycle.DeleteVersionAction}})
	if result.errs[0] != nil || !errors.Is(result.errs[1], errLifecycleNotApplicable) {
		t.Fatalf("fixture results: eligible=%v retained=%v", result.errs[0], result.errs[1])
	}
	if _, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: retained, Versioned: true}); err != nil {
		t.Fatalf("rejected version must remain: %v", err)
	}
	// Both publishers deliver synchronously, so everything sent is buffered.
	var notified, traced []string
	refusedTraces := map[string]string{}
	for drained := false; !drained; {
		select {
		case ev := <-events:
			notified = append(notified, ev.S3.Object.VersionID)
		case tr := <-traces:
			if tr.FuncName == ILMExpiry {
				if r := tr.Custom["result"]; r != "" {
					// Not a removal: the expiry was refused or failed.
					refusedTraces[tr.Custom["version-id"]] = r
					continue
				}
				traced = append(traced, tr.Custom["version-id"])
			}
		default:
			drained = true
		}
	}
	if len(notified) != 1 || notified[0] != eligible {
		t.Errorf("removal events for %v, want only eligible %s (retained %s)", notified, eligible, retained)
	}
	if len(traced) != 1 || traced[0] != eligible {
		t.Errorf("ILM expiry traces for %v, want only eligible %s (retained %s)", traced, eligible, retained)
	}
	if refusedTraces[retained] != "refused" {
		t.Errorf("the retained version's refusal is not traced: %v", refusedTraces)
	}
}
