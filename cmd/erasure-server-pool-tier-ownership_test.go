// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/minio/minio/internal/bucket/lifecycle"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	xhttp "github.com/minio/minio/internal/http"
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

// expireRestoredFaultDisk fails the removal of the restored copy of one key,
// as a drive that refuses that write does. Every other operation passes.
type expireRestoredFaultDisk struct {
	StorageAPI
	bucket, object string
}

func (d expireRestoredFaultDisk) DeleteVersion(ctx context.Context, volume, path string, fi FileInfo, forceDelMarker bool, opts DeleteOptions) error {
	if volume == d.bucket && path == d.object && fi.ExpireRestored {
		return errDiskFull
	}
	return d.StorageAPI.DeleteVersion(ctx, volume, path, fi, forceDelMarker, opts)
}

// restoredPastDeadline turns the version oi of key in pool 0 into a tiered
// version with a restored copy whose restore deadline has passed: its data
// stays on the drives, its metadata records the completed transition and the
// deadline. Past the deadline the version reads as remote. It returns the
// name of the remote object.
func (f *freeVersionTest) restoredPastDeadline(key string, oi ObjectInfo) string {
	f.t.Helper()
	ctx := f.t.Context()
	label := f.labels[oi.VersionID]
	remote := f.remote(key, label)
	infos, errs := readAllFileInfo(ctx, f.z.serverPools[0].getHashedSet(key).getDisks(), "", f.bucket, key, oi.VersionID, false, false)
	if errs[0] != nil {
		f.t.Fatal(errs[0])
	}
	fi := infos[0]
	fi.TransitionStatus, fi.TransitionTier, fi.TransitionedObjName = lifecycle.TransitionComplete, "WARM", remote
	fi.Metadata[xhttp.AmzRestore] = completedRestoreObj(daysAgo(1)).String()
	f.tier.objects[remote] = []byte(key + " " + label)
	if err := f.z.serverPools[0].DecomTieredObject(ctx, f.bucket, key, fi, ObjectOptions{}); err != nil {
		f.t.Fatal(err)
	}
	cur, err := f.z.GetObjectInfo(ctx, f.bucket, key, ObjectOptions{VersionID: oi.VersionID})
	if err != nil || cur.RestoreExpires.IsZero() || !UTCNow().After(cur.RestoreExpires) {
		f.t.Fatalf("fixture: restore expires %v, %v", cur.RestoreExpires, err)
	}
	lc, err := globalLifecycleSys.Get(f.bucket)
	if err != nil {
		f.t.Fatal(err)
	}
	if evt := evalActionFromLifecycle(ctx, *lc, objectlock.Retention{}, nil, cur); !evt.Action.DeleteRestored() {
		f.t.Fatalf("fixture: lifecycle action %v, want the restored copy to expire", evt.Action)
	}
	return remote
}

// tieredVersion fails the test unless pool holds the version oi of key with
// its tier metadata of remote and its restore deadline, and returns it.
func (f *freeVersionTest) tieredVersion(pool int, key, remote string, oi ObjectInfo) ObjectInfo {
	f.t.Helper()
	got, err := f.z.serverPools[pool].GetObjectInfo(f.t.Context(), f.bucket, key, ObjectOptions{VersionID: oi.VersionID})
	if err != nil {
		f.t.Fatalf("pool %d: %v", pool, err)
	}
	if tr := got.TransitionedObject; tr.Status != lifecycle.TransitionComplete || tr.Tier != "WARM" || tr.Name != remote {
		f.t.Errorf("pool %d: the version lost its tier metadata: %+v", pool, tr)
	}
	if got.RestoreExpires.IsZero() || !UTCNow().After(got.RestoreExpires) {
		f.t.Errorf("pool %d: the version lost its restore deadline: %v", pool, got.RestoreExpires)
	}
	if slices.Contains(f.tier.removed, remote) {
		f.t.Errorf("remote object removed: %v", f.tier.removed)
	}
	return got
}

// expireRestoredCopy removes the restored copy of oi, as the scanner of the
// pool that holds the version does once its deadline has passed, and fails
// the test unless the version then reads as remote without a deadline and
// the remote object stays.
func (f *freeVersionTest) expireRestoredCopy(pool int, key, remote string, oi ObjectInfo) {
	f.t.Helper()
	ctx := f.t.Context()
	lc, err := globalLifecycleSys.Get(f.bucket)
	if err != nil {
		f.t.Fatal(err)
	}
	evt := evalActionFromLifecycle(ctx, *lc, objectlock.Retention{}, nil, oi)
	if !evt.Action.DeleteRestored() {
		f.t.Fatalf("lifecycle action in pool %d: %v", pool, evt.Action)
	}
	if !applyExpiryOnTransitionedObject(ctx, f.z, oi, evt, lcEventSrc_Scanner) {
		f.t.Fatalf("the restored copy did not expire in pool %d", pool)
	}
	after, err := f.z.serverPools[pool].GetObjectInfo(ctx, f.bucket, key, ObjectOptions{VersionID: oi.VersionID})
	if err != nil || !after.IsRemote() || !after.RestoreExpires.IsZero() || after.TransitionedObject.Name != remote {
		f.t.Fatalf("version after the restored copy expired: remote=%v expires=%v %+v, %v", after.IsRemote(), after.RestoreExpires, after.TransitionedObject, err)
	}
	if slices.Contains(f.tier.removed, remote) {
		f.t.Errorf("remote object removed with the restored copy: %v", f.tier.removed)
	}
}

// A decommission removes a restored copy that is past its deadline before it
// moves the version. When the drives refuse that removal, the version moves
// like any other tiered version, with its tier metadata and its deadline: the
// remote object stays, the source copy retires with the key, and the scanner
// of the pool that holds the version removes the copy by that deadline.
// Skipping the version instead leaves the key behind with a
// PreConditionFailed and fails the decommission on every retry.
func TestDecommissionMovesRestoredCopyPastDeadline(t *testing.T) {
	f := newFreeVersionTest(t, freeVersionNoncurrent)
	const key = "obj-restored"
	oi := f.put(key, "v1", daysAgo(4))
	remote := f.restoredPastDeadline(key, oi)

	set := f.z.serverPools[0].getHashedSet(key)
	getDisks := set.getDisks
	faulty := slices.Clone(getDisks())
	for i := range faulty {
		faulty[i] = expireRestoredFaultDisk{StorageAPI: faulty[i], bucket: f.bucket, object: key}
	}
	set.getDisks = func() []StorageAPI { return faulty }
	t.Cleanup(func() { set.getDisks = getDisks })

	info := f.decommission()
	if !info.Complete || info.Failed || info.ItemsDecommissionFailed != 0 {
		t.Fatalf("decommission with a refused restored-copy removal: complete=%v failed=%v items failed=%d, pool 0 holds %v, pool 1 holds %v",
			info.Complete, info.Failed, info.ItemsDecommissionFailed, f.stored(0, key), f.stored(1, key))
	}
	if got := f.stored(0, key); len(got) != 0 {
		t.Errorf("pool 0 still holds %v", got)
	}
	if got := f.stored(1, key); !slices.Equal(got, []string{"v1"}) {
		t.Fatalf("pool 1 holds %v, want [v1]", got)
	}
	moved := f.tieredVersion(1, key, remote, oi)
	t.Logf("the moved version reads as remote: %v", moved.IsRemote())
	f.expireRestoredCopy(1, key, remote, moved)
}

// Control: a rebalance moves no tiered version, and a restored copy past its
// deadline reads as remote. The walk leaves the version in the source pool
// without counting it as deleted, so the key is not retired, and the scanner
// of that pool removes the copy by its deadline.
func TestRebalanceLeavesRestoredCopyPastDeadline(t *testing.T) {
	f := newFreeVersionTest(t, freeVersionNoncurrent)
	const key = "obj-restored"
	oi := f.put(key, "v1", daysAgo(4))
	remote := f.restoredPastDeadline(key, oi)

	if failed := migrationTestWalk(t, f.z, f.bucket, 0, "rebalance"); failed != 0 {
		t.Fatalf("%d versions failed to move", failed)
	}
	if got := f.stored(0, key); !slices.Equal(got, []string{"v1"}) {
		t.Fatalf("pool 0 holds %v, want [v1]", got)
	}
	if got := f.stored(1, key); len(got) != 0 {
		t.Errorf("pool 1 holds %v", got)
	}
	left := f.tieredVersion(0, key, remote, oi)
	f.expireRestoredCopy(0, key, remote, left)
}
