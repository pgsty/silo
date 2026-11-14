// Copyright (c) 2026 PGSTY
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
	"slices"
	"testing"

	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
)

// A version can have copies in two pools, for example after an interrupted
// decommission or rebalance. An ILM expiry of that version, approved with
// the versions in all pools, removes every copy, and the remote object of a
// tiered version only after every copy is gone.

// copyDeleteFailDisk fails the version deletes of object.
type copyDeleteFailDisk struct {
	StorageAPI
	object string
}

func (d copyDeleteFailDisk) DeleteVersion(ctx context.Context, volume, path string, fi FileInfo, forceDelMarker bool, opts DeleteOptions) error {
	if path == d.object {
		return errFaultyDisk
	}
	return d.StorageAPI.DeleteVersion(ctx, volume, path, fi, forceDelMarker, opts)
}

// failCopyDeletes makes every drive of pool fail the version deletes of
// object.
func failCopyDeletes(t *testing.T, z *erasureServerPools, pool int, object string) {
	t.Helper()
	p := z.serverPools[pool]
	p.erasureDisksMu.Lock()
	prior := p.erasureDisks
	wrapped := make([][]StorageAPI, len(prior))
	for i, disks := range prior {
		wrapped[i] = slices.Clone(disks)
		for j, d := range disks {
			if d != nil {
				wrapped[i][j] = copyDeleteFailDisk{StorageAPI: d, object: object}
			}
		}
	}
	p.erasureDisks = wrapped
	p.erasureDisksMu.Unlock()
	t.Cleanup(func() { p.erasureDisksMu.Lock(); p.erasureDisks = prior; p.erasureDisksMu.Unlock() })
}

// copiesOf reports, per pool, whether the pool holds versionID of object.
func (s *splitILM) copiesOf(object, versionID string) []bool {
	s.t.Helper()
	held := make([]bool, len(s.z.serverPools))
	for pool := range s.z.serverPools {
		_, err := s.z.serverPools[pool].GetObjectInfo(s.t.Context(), s.bucket, object, ObjectOptions{VersionID: versionID})
		switch {
		case err == nil:
			held[pool] = true
		case isErrVersionNotFound(err) || isErrObjectNotFound(err):
		default:
			s.t.Fatalf("pool %d: %v", pool, err)
		}
	}
	return held
}

func installExpiryTestTier(t *testing.T, objects map[string][]byte) *tierExpiryTestBackend {
	t.Helper()
	tier := &tierExpiryTestBackend{objects: objects}
	prev := globalTierConfigMgr
	globalTierConfigMgr = NewTierConfigMgr()
	globalTierConfigMgr.drivercache["WARM"] = tier
	t.Cleanup(func() { globalTierConfigMgr = prev })
	return tier
}

func TestPoolsLifecycleVersionExpiryDeletesEveryCopy(t *testing.T) {
	t.Run("hot", func(t *testing.T) {
		s := newSplitILM(t, versioning.Enabled, splitILMRules)
		const key = "ncv-copies-hot"
		s.write(key, splitAt("v1", 5, 0, 1))
		s.write(key, splitAt("v2", 3, 0))
		v1 := s.ids[key+" v1"]
		oi, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: v1})
		if err != nil {
			t.Fatal(err)
		}
		if !applyExpiryOnNonTransitionedObjects(t.Context(), s.z, oi, lifecycle.Event{Action: lifecycle.DeleteVersionAction}, lcEventSrc_Scanner) {
			t.Fatal("expiry did not apply")
		}
		if got := s.copiesOf(key, v1); slices.Contains(got, true) {
			t.Fatalf("copies left after the expiry: %v", got)
		}
	})

	tiered := func(t *testing.T, failSecondary, replicated bool) {
		s := newSplitILM(t, versioning.Enabled, splitILMRules)
		const key = "ncv-copies-tiered"
		tier := installExpiryTestTier(t, map[string][]byte{"remote-v1": []byte("v1")})
		s.write(key, splitTiered("v1", 5, 0, 1))
		s.write(key, splitAt("v2", 3, 0))
		v1 := s.ids[key+" v1"]
		var requests interface{ Load() int32 }
		if replicated {
			ctx := t.Context()
			stats := NewReplicationStats(ctx, nil)
			prev := globalReplicationStats.Swap(stats)
			t.Cleanup(func() { globalReplicationStats.Store(prev) })
			target, n := ilmTestTarget(t, s.z, s.bucket, key, false)
			putConsistencyObject(t, s.z, target.bucket, key, 0, "replica", ObjectOptions{Versioned: true, VersionID: v1})
			restore, _ := newILMTestReplicationPool(ctx, s.z, stats)
			t.Cleanup(restore)
			requests = n
		}
		if failSecondary {
			failCopyDeletes(t, s.z, 1, key)
		}
		oi, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: v1})
		if err != nil {
			t.Fatal(err)
		}
		err = expireTransitionedObject(t.Context(), s.z, &oi, lifecycle.Event{Action: lifecycle.DeleteVersionAction}, lcEventSrc_Scanner)
		got := s.copiesOf(key, v1)
		if failSecondary {
			if err == nil {
				t.Fatal("the expiry succeeded although a copy could not be deleted")
			}
			if !got[0] || !got[1] {
				t.Fatalf("copies after a failed expiry: %v, want both", got)
			}
			if len(tier.removed) != 0 {
				t.Fatalf("remote objects removed while a copy remains: %v", tier.removed)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(got, true) {
			t.Fatalf("copies left after the expiry: %v", got)
		}
		if !slices.Equal(tier.removed, []string{"remote-v1"}) {
			t.Fatalf("remote removals %v, want remote-v1 once", tier.removed)
		}
		if replicated {
			if n := len(globalReplicationPool.Get().workers[0]); n != 0 {
				t.Fatalf("queued %d replication tasks", n)
			}
			if n := requests.Load(); n != 0 {
				t.Fatalf("the target saw %d requests", n)
			}
		}
	}
	t.Run("tiered", func(t *testing.T) { tiered(t, false, false) })
	t.Run("tiered-secondary-fails", func(t *testing.T) { tiered(t, true, false) })
	t.Run("tiered-replicated", func(t *testing.T) { tiered(t, false, true) })

	t.Run("decommission-second-pool", func(t *testing.T) {
		s := newSplitILM(t, versioning.Enabled, splitILMRules)
		const key = "ncv-copies-decom"
		s.write(key, splitAt("v1", 5, 0, 1))
		s.write(key, splitAt("v2", 3, 1))
		v1, v2 := s.ids[key+" v1"], s.ids[key+" v2"]
		ctx := t.Context()
		if err := s.z.StartDecommission(ctx, 1); err != nil {
			t.Fatal(err)
		}
		s.z.doDecommissionInRoutine(ctx, 1)
		s.z.poolMetaMutex.RLock()
		info := *s.z.poolMeta.Pools[1].Decommission
		s.z.poolMetaMutex.RUnlock()
		if !info.Complete || info.Failed {
			t.Fatalf("decommission of pool 1: complete=%t failed=%t", info.Complete, info.Failed)
		}
		if got := s.copiesOf(key, v1); slices.Contains(got, true) {
			t.Errorf("the expired version is left: %v", got)
		}
		if got := s.copiesOf(key, v2); !got[0] || got[1] {
			t.Errorf("the latest version: %v, want only in pool 0", got)
		}
	})
}
