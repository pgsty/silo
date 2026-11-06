// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"errors"
	"slices"
	"testing"

	"github.com/minio/minio/internal/bucket/lifecycle"
)

func rewriteTierTestMeta(t *testing.T, disk StorageAPI, bucket, key string, change func(*xlMetaV2)) {
	t.Helper()
	raw, err := disk.ReadAll(t.Context(), bucket, pathJoin(key, xlStorageFormatFile))
	if err != nil {
		t.Fatal(err)
	}
	var xl xlMetaV2
	if err = xl.LoadOrConvert(raw); err != nil {
		t.Fatal(err)
	}
	change(&xl)
	raw, err = xl.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = disk.WriteAll(t.Context(), bucket, pathJoin(key, xlStorageFormatFile), raw); err != nil {
		t.Fatal(err)
	}
}

func TestTierCleanupRequiresDurableOwnership(t *testing.T) {
	for _, kind := range []string{"absent", "older-live", "minority-live", "unknown", "remote-failure", "same-id-other-tuple"} {
		t.Run(kind, func(t *testing.T) {
			f := newFreeVersionTest(t, "")
			const key = "shared"
			oi := f.tiered(key, "remote", daysAgo(4))
			tuple := tierRemoteTuple{Tier: "WARM", Object: f.remote(key, "remote")}
			live := slices.Clone(f.xlMeta(0, key))
			f.deleteVersion(oi)
			disks := f.z.serverPools[0].getHashedSet(key).getDisks()
			other := f.z.serverPools[1].getHashedSet(key).getDisks()
			switch kind {
			case "absent":
				// A stale task with a different remote identity has no owning free record.
				tuple.Object += "-stale"
				f.tier.objects[tuple.Object] = []byte("must survive")
			case "older-live", "minority-live":
				for i, disk := range other {
					if kind == "minority-live" && i > 0 {
						break
					}
					if err := disk.WriteAll(t.Context(), f.bucket, pathJoin(key, xlStorageFormatFile), live); err != nil {
						t.Fatal(err)
					}
				}
				// Hide the live remote reference beneath a newer hot version.
				putConsistencyObject(t, f.z, f.bucket, key, 1, "hot", ObjectOptions{Versioned: true})
			case "unknown":
				if err := other[0].WriteAll(t.Context(), f.bucket, pathJoin(key, xlStorageFormatFile), []byte("corrupt")); err != nil {
					t.Fatal(err)
				}
			case "remote-failure":
				f.tier.removeErr = errors.New("remote unavailable")
			case "same-id-other-tuple":
				rewriteTierTestMeta(t, disks[len(disks)-1], f.bucket, key, func(xl *xlMetaV2) {
					ver, err := xl.getIdx(0)
					if err != nil {
						t.Fatal(err)
					}
					ver.DeleteMarker.MetaSys[metaTierObjName] = []byte("another-remote")
					if err := xl.setIdx(0, *ver); err != nil {
						t.Fatal(err)
					}
				})
				f.tier.objects["another-remote"] = []byte("other")
			}
			err := f.z.deleteTierTuple(t.Context(), f.bucket, key, tuple)
			switch kind {
			case "older-live", "minority-live":
				if !errors.Is(err, errTierStillReferenced) {
					t.Fatalf("cleanup: %v", err)
				}
			case "unknown":
				if !errors.Is(err, errTierOwnershipUnavailable) {
					t.Fatalf("cleanup: %v", err)
				}
			case "remote-failure":
				if !errors.Is(err, f.tier.removeErr) {
					t.Fatalf("cleanup: %v", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
			}
			if kind != "same-id-other-tuple" {
				if len(f.tier.removed) != 0 {
					t.Fatalf("deleted without sole durable ownership: %v", f.tier.removed)
				}
				if got := f.stored(0, key); len(got) != 1 || got[0] != "free" {
					t.Fatalf("lost retry record: %v", got)
				}
			} else {
				raw, err := disks[len(disks)-1].ReadAll(t.Context(), f.bucket, pathJoin(key, xlStorageFormatFile))
				if err != nil {
					t.Fatal(err)
				}
				versions, err := getFileInfoVersions(raw, f.bucket, key, true)
				if err != nil {
					t.Fatal(err)
				}
				if len(versions.Versions) != 1 || versions.Versions[0].TransitionedObjName != "another-remote" {
					t.Fatalf("removed different tuple: %+v", versions)
				}
				if len(f.tier.removed) != 1 || f.tier.removed[0] != tuple.Object {
					t.Fatalf("remote deletions: %v", f.tier.removed)
				}
			}
			if kind == "remote-failure" {
				f.tier.removeErr = nil
				if err := f.z.deleteTierTuple(t.Context(), f.bucket, key, tuple); err != nil {
					t.Fatal(err)
				}
				if got := f.stored(0, key); len(got) != 0 {
					t.Fatalf("retry left %v", got)
				}
				if err := f.z.deleteTierTuple(t.Context(), f.bucket, key, tuple); err != nil {
					t.Fatal(err)
				}
				if len(f.tier.removed) != 1 {
					t.Fatalf("stale retry deleted again: %v", f.tier.removed)
				}
			}
		})
	}
}

func TestTierSweeperPreservesOtherPoolOwner(t *testing.T) {
	f := newFreeVersionTest(t, "")
	const key = "overwrite"
	oi := f.tiered(key, "remote", daysAgo(4))
	queue := f.expiryQueue()
	sweeper := newObjSweeper(f.bucket, key).WithVersion(oi.VersionID).WithVersioning(true, false)
	sweeper.SetTransitionState(TransitionedObject{Status: lifecycle.TransitionComplete, Tier: "WARM", Name: f.remote(key, "remote")})
	// Overwrite in the other pool while the draining pool retains its owner.
	putConsistencyObject(t, f.z, f.bucket, key, 1, "replacement", ObjectOptions{Versioned: true})
	sweeper.Sweep()
	close(queue)
	globalExpiryState.Worker(queue)
	if len(f.tier.removed) != 0 {
		t.Fatalf("sweeper deleted a live remote: %v", f.tier.removed)
	}
	if got := migrationTestBody(t, f.z.GetObjectNInfo, f.bucket, key, oi.VersionID); got != key+" remote" {
		t.Fatalf("old version body: %q", got)
	}
}

func TestDecommissionMovesTieredDeleteAll(t *testing.T) {
	for _, kind := range []string{"complete", "pending", "minority-other-pool"} {
		t.Run(kind, func(t *testing.T) {
			f := newFreeVersionTest(t, purgeRules)
			const key = "ea/tiered"
			oi := f.tiered(key, "v1", daysAgo(4))
			if kind == "pending" {
				for _, disk := range f.z.serverPools[0].getHashedSet(key).getDisks() {
					rewriteTierTestMeta(t, disk, f.bucket, key, func(xl *xlMetaV2) {
						i, ver, err := xl.findVersionStr(oi.VersionID)
						if err != nil {
							t.Fatal(err)
						}
						ver.ObjectV2.MetaSys[metaTierStatus] = []byte(lifecycle.TransitionPending)
						if err := xl.setIdx(i, *ver); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
			if kind == "minority-other-pool" {
				raw := slices.Clone(f.xlMeta(0, key))
				// A newer hot copy wins the logical merge, while one other-pool disk
				// still holds the older tier revision with the same version ID.
				putConsistencyObject(t, f.z, f.bucket, key, 0, "hot-v1", ObjectOptions{Versioned: true, VersionID: oi.VersionID, MTime: daysAgo(3)})
				disk := f.z.serverPools[1].getHashedSet(key).getDisks()[0]
				if err := disk.WriteAll(t.Context(), f.bucket, pathJoin(key, xlStorageFormatFile), raw); err != nil {
					t.Fatal(err)
				}
			}
			f.put(key, "v2", daysAgo(2))
			// Verify the precheck uses per-drive evidence, including minority data.
			var history migrationHistory
			latest, err := f.z.GetObjectInfo(t.Context(), f.bucket, key, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if f.z.migrationExpiryApplies(t.Context(), latest, lifecycle.Event{Action: lifecycle.DeleteAllVersionsAction}, &history) {
				t.Fatal("tiered purge selected instead of migration")
			}
			if kind == "pending" {
				return
			} // Pending data is tested at the precheck; a real transition owns its data move.
			if state := f.decommission(); !state.Complete || state.Failed {
				t.Fatalf("decommission: %+v", state)
			}
			if got := f.stored(0, key); len(got) != 0 {
				t.Fatalf("source retained %v", got)
			}
			if got := f.stored(1, key); len(got) < 2 || !slices.Equal(got[:2], []string{"v2", "v1"}) {
				t.Fatalf("destination versions: %v", got)
			}
			if slices.Contains(f.tier.removed, f.remote(key, "v1")) {
				t.Fatal("deleted live tier object during migration")
			}
		})
	}
}
