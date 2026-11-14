// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later
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
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
)

// The walk has already captured the version when its data read reaches this
// hook. Metadata-only checks made by a concurrent DELETE do not reenter it.
type migrationProgressReadDisk struct {
	StorageAPI
	bucket, object, version string
	before                  func() error
}

func (d migrationProgressReadDisk) ReadVersion(ctx context.Context, orig, bucket, object, version string, opts ReadOptions) (FileInfo, error) {
	if opts.ReadData && bucket == d.bucket && object == d.object && version == d.version {
		if err := d.before(); err != nil {
			return FileInfo{}, err
		}
	}
	return d.StorageAPI.ReadVersion(ctx, orig, bucket, object, version, opts)
}

// Buffer every drive's first walk before publishing any entry. Thus deleting
// the parent cannot accidentally let this same walk discover the child.
type migrationSnapshotWalk struct {
	bucket string
	drives int32
	calls  atomic.Int32
	ready  chan struct{}
}

type migrationSnapshotWalkDisk struct {
	StorageAPI
	snapshot *migrationSnapshotWalk
}

func (d migrationSnapshotWalkDisk) WalkDir(ctx context.Context, opts WalkDirOptions, out io.Writer) error {
	if opts.Bucket != d.snapshot.bucket {
		return d.StorageAPI.WalkDir(ctx, opts, out)
	}
	var buf bytes.Buffer
	if err := d.StorageAPI.WalkDir(ctx, opts, &buf); err != nil {
		return err
	}
	if d.snapshot.calls.Add(1) == d.snapshot.drives {
		close(d.snapshot.ready)
	}
	select {
	case <-d.snapshot.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	_, err := io.Copy(out, &buf)
	return err
}

func migrationProgressSnapshot(t *testing.T, z *erasureServerPools, bucket, key string) *migrationSnapshotWalk {
	t.Helper()
	s := &migrationSnapshotWalk{bucket: bucket, drives: int32(len(z.serverPools[0].getHashedSet(key).getDisks())), ready: make(chan struct{})}
	t.Cleanup(conditionalPutSwapDisks(z.serverPools[0], key, func(d StorageAPI) StorageAPI {
		return migrationSnapshotWalkDisk{StorageAPI: d, snapshot: s}
	}))
	return s
}

func migrationProgressPrepare(t *testing.T, z *erasureServerPools, kind string) {
	t.Helper()
	migrationTestMover(t, z, 0, kind)
	z.poolMetaMutex.Lock()
	z.poolMeta.Pools[0].LastUpdate = UTCNow()
	z.poolMetaMutex.Unlock()
}

func TestDecommissionSplitMetadataDoesNotAdvance(t *testing.T) {
	m := newMigrationILM(t, "", false, migrationILMExpireCurrent())
	const key = "obj-01"
	m.put(key, "old", ObjectOptions{MTime: UTCNow().Add(-96 * time.Hour)})
	disks := m.z.serverPools[0].getHashedSet(key).getDisks()
	old := make([][]byte, len(disks)/2)
	for i := range old {
		var err error
		old[i], err = disks[i].ReadAll(t.Context(), m.bucket, pathJoin(key, xlStorageFormatFile))
		mustIAM(t, err)
	}
	m.put(key, "new-and-longer", ObjectOptions{MTime: UTCNow().Add(-72 * time.Hour)})
	for i := range old {
		mustIAM(t, disks[i].WriteAll(t.Context(), m.bucket, pathJoin(key, xlStorageFormatFile), old[i]))
	}
	if _, err := m.z.serverPools[0].GetObjectInfo(t.Context(), m.bucket, key, ObjectOptions{VersionID: nullVersionID}); !isErrVersionNotFound(err) {
		t.Fatalf("fixture must expose the ambiguous logical NotFound, got %v", err)
	}
	migrationProgressPrepare(t, m.z, "decommission")
	walk := migrationProgressSnapshot(t, m.z, m.bucket, key)
	bi := decomBucketInfo{Name: m.bucket}
	// Check a single pass first, so the unfixed implementation fails rather
	// than looping until the test timeout.
	removed, err := m.z.decommissionPoolWalk(t.Context(), 0, m.z.serverPools[0], bi)
	if err != nil || removed != 0 {
		t.Fatalf("split metadata reported progress: removed=%d err=%v", removed, err)
	}
	mustIAM(t, m.z.decommissionPool(t.Context(), 0, m.z.serverPools[0], bi))
	if got := walk.calls.Load(); got != 2*walk.drives {
		t.Fatalf("unchanged metadata repeated the walk: calls=%d", got)
	}
	if err := m.z.checkAfterDecomBucket(t.Context(), 0, bi); err == nil {
		t.Fatal("final verification accepted split metadata still on disk")
	}
	for _, disk := range disks {
		if _, err := disk.ReadVersion(t.Context(), "", m.bucket, key, nullVersionID, ReadOptions{}); err != nil {
			t.Fatalf("migration removed an ambiguous source revision: %v", err)
		}
	}
}

func TestPoolsMigrationConcurrentDeleteCleanup(t *testing.T) {
	for _, kind := range []string{"decommission", "rebalance"} {
		t.Run(kind, func(t *testing.T) {
			z, bucket := migrationTestPools(t)
			v1 := putConsistencyObject(t, z, bucket, "k", 0, "older", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour)})
			v2 := putConsistencyObject(t, z, bucket, "k", 0, "newer", ObjectOptions{Versioned: true})
			var once sync.Once
			var deleteErr error
			before := func() error {
				once.Do(func() {
					_, deleteErr = z.DeleteObject(t.Context(), bucket, "k", ObjectOptions{Versioned: true, VersionID: v2.VersionID})
				})
				return deleteErr
			}
			restore := conditionalPutSwapDisks(z.serverPools[0], "k", func(d StorageAPI) StorageAPI {
				return migrationProgressReadDisk{StorageAPI: d, bucket: bucket, object: "k", version: v2.VersionID, before: before}
			})
			defer restore()
			if failed := migrationTestWalk(t, z, bucket, 0, kind); failed != 0 {
				t.Fatalf("failed moves: %d", failed)
			}
			restore()
			for _, v := range []ObjectInfo{v1, v2} {
				for _, disk := range z.serverPools[0].getHashedSet("k").getDisks() {
					_, err := disk.ReadVersion(t.Context(), "", bucket, "k", v.VersionID, ReadOptions{})
					if !errors.Is(err, errFileVersionNotFound) && !errors.Is(err, errFileNotFound) {
						t.Fatalf("source version %s remained: %v", v.VersionID, err)
					}
				}
			}
			if body := migrationTestBody(t, z.GetObjectNInfo, bucket, "k", v1.VersionID); body != "older" {
				t.Fatalf("moved version reads %q", body)
			}
			if _, err := z.GetObjectInfo(t.Context(), bucket, "k", ObjectOptions{VersionID: v2.VersionID}); !isErrVersionNotFound(err) {
				t.Fatalf("concurrently deleted version resurrected: %v", err)
			}
		})
	}
}

func TestPoolsMigrationSiblingFailureCleanup(t *testing.T) {
	for _, kind := range []string{"decommission", "rebalance"} {
		for _, loseDestination := range []bool{false, true} {
			name := kind + "/destination-retained"
			if loseDestination {
				name = kind + "/destination-removed"
			}
			t.Run(name, func(t *testing.T) {
				z, bucket := migrationTestPools(t)
				v1 := putConsistencyObject(t, z, bucket, "k", 0, "older", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour)})
				v2 := putConsistencyObject(t, z, bucket, "k", 0, "newer", ObjectOptions{Versioned: true})
				var once sync.Once
				var deleteErr error
				before := func() error {
					once.Do(func() {
						if loseDestination {
							_, deleteErr = z.serverPools[1].DeleteObject(t.Context(), bucket, "k", ObjectOptions{VersionID: v1.VersionID})
						}
					})
					return errDiskNotFound // only the sibling's data read fails
				}
				restore := conditionalPutSwapDisks(z.serverPools[0], "k", func(d StorageAPI) StorageAPI {
					return migrationProgressReadDisk{StorageAPI: d, bucket: bucket, object: "k", version: v2.VersionID, before: before}
				})
				defer restore()
				migrationProgressPrepare(t, z, kind)
				if kind == "rebalance" {
					mustIAM(t, z.rebalanceBucket(t.Context(), bucket, 0))
				} else {
					_, err := z.decommissionPoolWalk(t.Context(), 0, z.serverPools[0], decomBucketInfo{Name: bucket})
					mustIAM(t, err)
					if err := z.checkAfterDecomBucket(t.Context(), 0, decomBucketInfo{Name: bucket}); err == nil {
						t.Fatal("failed sibling must block final decommission verification")
					}
				}
				restore()
				mustIAM(t, deleteErr)
				if body := migrationTestBody(t, z.GetObjectNInfo, bucket, "k", v2.VersionID); body != "newer" {
					t.Fatalf("failed sibling reads %q", body)
				}
				if body := migrationTestBody(t, z.GetObjectNInfo, bucket, "k", v1.VersionID); body != "older" {
					t.Fatalf("successful candidate lost: %q", body)
				}
				_, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, "k", ObjectOptions{VersionID: v1.VersionID})
				if loseDestination && err != nil || !loseDestination && !isErrVersionNotFound(err) {
					t.Fatalf("source cleanup ignored destination state: %v", err)
				}
			})
		}
	}
}

func TestDecommissionConcurrentParentDeleteRescansChildren(t *testing.T) {
	z, bucket := migrationTestPools(t)
	putConsistencyObject(t, z, bucket, "k", 0, "parent", ObjectOptions{})
	putConsistencyObject(t, z, bucket, "k/b", 0, "child", ObjectOptions{})
	migrationProgressSnapshot(t, z, bucket, "k")
	var once sync.Once
	var deleteErr error
	t.Cleanup(conditionalPutSwapDisks(z.serverPools[0], "k", func(d StorageAPI) StorageAPI {
		return migrationProgressReadDisk{StorageAPI: d, bucket: bucket, object: "k", version: nullVersionID, before: func() error {
			once.Do(func() {
				_, deleteErr = z.DeleteObject(t.Context(), bucket, "k", ObjectOptions{VersionID: nullVersionID})
			})
			return deleteErr
		}}
	}))
	if failed := migrationTestWalk(t, z, bucket, 0, "decommission"); failed != 0 {
		t.Fatalf("failed moves: %d", failed)
	}
	mustIAM(t, z.checkAfterDecomBucket(t.Context(), 0, decomBucketInfo{Name: bucket}))
	if body := migrationTestBody(t, z.GetObjectNInfo, bucket, "k/b", ""); body != "child" {
		t.Fatalf("child reads %q", body)
	}
}

func TestDecommissionDegradedPoolRescansChildren(t *testing.T) {
	z, bucket := migrationTestPools(t)
	putConsistencyObject(t, z, bucket, "k", 0, "parent", ObjectOptions{})
	putConsistencyObject(t, z, bucket, "k/b", 0, "child", ObjectOptions{})
	var wrapped int
	t.Cleanup(conditionalPutSwapDisks(z.serverPools[0], "k", func(d StorageAPI) StorageAPI {
		wrapped++
		if wrapped == 1 {
			return nil
		}
		return d
	}))
	if failed := migrationTestWalk(t, z, bucket, 0, "decommission"); failed != 0 {
		t.Fatalf("failed moves: %d", failed)
	}
	mustIAM(t, z.checkAfterDecomBucket(t.Context(), 0, decomBucketInfo{Name: bucket}))
	if body := migrationTestBody(t, z.GetObjectNInfo, bucket, "k/b", ""); body != "child" {
		t.Fatalf("child reads %q", body)
	}
}

func TestFreeVersionDecommissionRescansChildren(t *testing.T) {
	f := newFreeVersionTest(t, "")
	f.bucket = "free-parent"
	mustIAM(t, f.z.MakeBucket(t.Context(), f.bucket, MakeBucketOptions{VersioningEnabled: true}))
	f.deleteVersion(f.tiered("k", "parent", UTCNow().Add(-time.Hour)))
	f.put("k/b", "child", UTCNow())
	migrationProgressSnapshot(t, f.z, f.bucket, "k")
	migrationProgressPrepare(t, f.z, "decommission")
	bi := decomBucketInfo{Name: f.bucket}
	removed, err := f.z.decommissionPoolWalk(t.Context(), 0, f.z.serverPools[0], bi)
	if err != nil || removed != 1 {
		t.Fatalf("free-only parent removal: removed=%d err=%v", removed, err)
	}
	if err := f.z.checkAfterDecomBucket(t.Context(), 0, bi); err == nil {
		t.Fatal("the newly exposed child must still block completion")
	}
	mustIAM(t, f.z.decommissionPool(t.Context(), 0, f.z.serverPools[0], bi))
	mustIAM(t, f.z.checkAfterDecomBucket(t.Context(), 0, bi))
	if body := migrationTestBody(t, f.z.GetObjectNInfo, f.bucket, "k/b", ""); body != "k/b child" {
		t.Fatalf("child reads %q", body)
	}
	if !slices.Contains(f.tier.removed, f.remote("k", "parent")) {
		t.Fatal("free version cleanup did not delete its remote object")
	}
}

func TestPoolsMigrationCancellation(t *testing.T) {
	for _, kind := range []string{"decommission", "rebalance"} {
		for _, phase := range []string{"before-walk", "during-read", "deadline"} {
			name := kind + "/" + phase
			t.Run(name, func(t *testing.T) {
				z, bucket := migrationTestPools(t)
				oi := putConsistencyObject(t, z, bucket, "k", 0, "source", ObjectOptions{Versioned: true})
				migrationProgressPrepare(t, z, kind)
				ctx, cancel := context.WithCancel(t.Context())
				wantErr := context.Canceled
				if phase == "deadline" {
					cancel()
					ctx, cancel = context.WithDeadline(t.Context(), time.Time{})
					wantErr = context.DeadlineExceeded
				}
				defer cancel()
				if phase == "during-read" {
					t.Cleanup(conditionalPutSwapDisks(z.serverPools[0], "k", func(d StorageAPI) StorageAPI {
						return migrationProgressReadDisk{StorageAPI: d, bucket: bucket, object: "k", version: oi.VersionID, before: func() error { cancel(); return ctx.Err() }}
					}))
				} else {
					cancel()
				}
				var err error
				if kind == "decommission" {
					err = z.decommissionPool(ctx, 0, z.serverPools[0], decomBucketInfo{Name: bucket})
				} else {
					err = z.rebalanceBucket(ctx, bucket, 0)
				}
				if !errors.Is(err, wantErr) {
					t.Fatalf("cancellation returned %v", err)
				}
				if err := z.decommissionInBackground(ctx, 0); !errors.Is(err, wantErr) {
					t.Fatalf("canceled background migration returned %v", err)
				}
				if err := z.rebalanceBuckets(ctx, 0); !errors.Is(err, wantErr) {
					t.Fatalf("canceled background rebalance returned %v", err)
				}
				if n, err := z.countAbsentMigrationVersions(ctx, bucket, "k", 0, []FileInfo{{VersionID: oi.VersionID}}); n != 0 || !errors.Is(err, wantErr) {
					t.Fatalf("canceled progress verification: removed=%d err=%v", n, err)
				}
				if _, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, "k", ObjectOptions{VersionID: oi.VersionID}); err != nil {
					t.Fatalf("canceled migration lost source: %v", err)
				}
				if err := z.checkAfterDecomBucket(ctx, 0, decomBucketInfo{Name: bucket}); !errors.Is(err, wantErr) {
					t.Fatalf("canceled verification returned %v", err)
				}
			})
		}
	}
}

type migrationProgressRawDisk struct {
	StorageAPI
	buf   []byte
	err   error
	reads *atomic.Int32
}

func (d migrationProgressRawDisk) ReadXL(ctx context.Context, bucket, object string, data bool) (RawFileInfo, error) {
	d.reads.Add(1)
	if data {
		return RawFileInfo{}, errors.New("progress check requested object data")
	}
	return RawFileInfo{Buf: d.buf}, d.err
}

func (d migrationProgressRawDisk) ListDir(context.Context, string, string, string, int) ([]string, error) {
	return nil, errFileNotFound
}

func TestPoolsMigrationPhysicalProgress(t *testing.T) {
	f := newFreeVersionTest(t, "")
	buf := f.xlMeta(0, "obj-01")
	versions, err := getFileInfoVersions(buf, f.bucket, "obj-01", true)
	mustIAM(t, err)
	if len(versions.Versions) != 3 || !versions.Versions[0].TierFreeVersion() {
		t.Fatal("fixture must contain two live versions and one free version")
	}
	missing := FileInfo{VersionID: mustGetUUID()}
	snapshot := append(slices.Clone(versions.Versions), missing)
	for _, tc := range []struct {
		name    string
		buf     []byte
		err     error
		want    int
		wantErr bool
	}{
		{name: "all-absent", err: errFileNotFound, want: 4},
		{name: "missing-volume", err: errVolumeNotFound, want: 4},
		{name: "minority-live-and-free", buf: buf, want: 1},
		{name: "unavailable", err: errDiskNotFound, wantErr: true},
		{name: "read-quorum", err: errErasureReadQuorum, wantErr: true},
		{name: "corrupt-read", err: errFileCorrupt, wantErr: true},
		{name: "corrupt-metadata", buf: []byte("broken xl.meta"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads atomic.Int32
			disks := make([]StorageAPI, 4)
			for i := range disks {
				disks[i] = migrationProgressRawDisk{err: errFileNotFound, reads: &reads}
			}
			disks[3] = migrationProgressRawDisk{buf: tc.buf, err: tc.err, reads: &reads}
			er := erasureObjects{getDisks: func() []StorageAPI { return disks }}
			n, err := er.countAbsentMigrationVersions(t.Context(), f.bucket, "obj-01", snapshot)
			if n != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("removed=%d err=%v, want %d / error=%t", n, err, tc.want, tc.wantErr)
			}
			if reads.Load() != int32(len(disks)) {
				t.Fatalf("read count %d must not depend on version count", reads.Load())
			}
		})
	}
	putConsistencyObject(t, f.z, f.bucket, "null", 0, "null-data", ObjectOptions{})
	nullBuf := f.xlMeta(0, "null")
	var reads atomic.Int32
	er := erasureObjects{getDisks: func() []StorageAPI {
		return []StorageAPI{migrationProgressRawDisk{buf: nullBuf, reads: &reads}}
	}}
	if n, err := er.countAbsentMigrationVersions(t.Context(), f.bucket, "null", []FileInfo{{VersionID: nullVersionID}, {VersionID: ""}}); n != 0 || err != nil {
		t.Fatalf("null version normalization: removed=%d err=%v", n, err)
	}
}

func TestCountAbsentMigrationVersionsToleratesConfiguredOfflineDrives(t *testing.T) {
	makeDisks := func(offlineCount int, asError bool) []StorageAPI {
		disks := make([]StorageAPI, 4)
		for i := range disks {
			disks[i] = migrationProgressRawDisk{err: errFileNotFound, reads: &atomic.Int32{}}
		}
		for i := range offlineCount {
			if asError {
				disks[i] = migrationProgressRawDisk{err: errDiskNotFound, reads: &atomic.Int32{}}
			} else {
				disks[i] = nil
			}
		}
		return disks
	}
	snapshot := []FileInfo{{VersionID: mustGetUUID()}}
	for _, tc := range []struct {
		name      string
		offline   int
		parity    int
		asError   bool
		wantCount int
		wantErr   bool
	}{
		{name: "nil-drive-within-parity", offline: 1, parity: 1, wantCount: 1},
		{name: "read-error-within-parity", offline: 1, parity: 1, asError: true, wantCount: 1},
		{name: "half-offline-within-parity", offline: 2, parity: 2, wantCount: 1},
		{name: "offline-beyond-parity", offline: 2, parity: 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disks := makeDisks(tc.offline, tc.asError)
			er := erasureObjects{
				setDriveCount:      len(disks),
				defaultParityCount: tc.parity,
				getDisks:           func() []StorageAPI { return disks },
			}
			got, err := er.countAbsentMigrationVersions(t.Context(), "bucket", "object", snapshot)
			if got != tc.wantCount || (err != nil) != tc.wantErr {
				t.Fatalf("removed=%d err=%v, want %d / error=%t", got, err, tc.wantCount, tc.wantErr)
			}
		})
	}
}

// A successful quorum deletion can leave one source drive behind. It must not
// count as physical removal or pass the final check, nor cause a retry loop.
func TestDecommissionQuorumDeletionIsNotPhysicalProgress(t *testing.T) {
	z, bucket := migrationTestPools(t)
	oi := putConsistencyObject(t, z, bucket, "k", 0, "payload", ObjectOptions{Versioned: true})
	move := migrationTestMover(t, z, 0, "decommission")
	mustIAM(t, move(t.Context(), 0, bucket, migrationTestReader(t, z, 0, oi)))
	first := true
	restore := conditionalPutSwapDisks(z.serverPools[0], "k", func(d StorageAPI) StorageAPI {
		if first {
			first = false
			return consistencyDeleteFaultDisk{StorageAPI: d, bucket: bucket, object: "k", version: oi.VersionID}
		}
		return d
	})
	defer restore()
	snapshot := []FileInfo{{VersionID: oi.VersionID, ModTime: oi.ModTime}}
	for range 2 {
		n, err := z.removeMovedVersions(t.Context(), bucket, "k", 0, snapshot, nil)
		if err != nil || n != 0 {
			t.Fatalf("partial deletion reported progress: removed=%d err=%v", n, err)
		}
	}
	if err := z.checkAfterDecomBucket(t.Context(), 0, decomBucketInfo{Name: bucket}); err == nil {
		t.Fatal("final verification accepted a minority-drive source copy")
	}
	if body := migrationTestBody(t, z.GetObjectNInfo, bucket, "k", oi.VersionID); body != "payload" {
		t.Fatalf("destination copy lost: %q", body)
	}
}

func TestDecommissionProgressReadFailureStopsWalk(t *testing.T) {
	z, bucket := migrationTestPools(t)
	putConsistencyObject(t, z, bucket, "k", 0, "payload", ObjectOptions{Versioned: true})
	migrationProgressPrepare(t, z, "decommission")
	walk := migrationProgressSnapshot(t, z, bucket, "k")
	restore := conditionalPutSwapDisks(z.serverPools[0], "k", func(d StorageAPI) StorageAPI {
		return tierReadFaultDisk{StorageAPI: d, bucket: bucket, object: "k", err: errDiskNotFound}
	})
	defer restore()
	if err := z.decommissionPool(t.Context(), 0, z.serverPools[0], decomBucketInfo{Name: bucket}); err == nil {
		t.Fatal("unreadable source progress check reported success")
	}
	if got := walk.calls.Load(); got != walk.drives {
		t.Fatalf("verification failure repeated the walk: calls=%d", got)
	}
	restore()
	if body := migrationTestBody(t, z.GetObjectNInfo, bucket, "k", ""); body != "payload" {
		t.Fatalf("quorum move lost destination: %q", body)
	}
}

type migrationProgressListFaultDisk struct {
	StorageAPI
}

func (d migrationProgressListFaultDisk) ListDir(context.Context, string, string, string, int) ([]string, error) {
	return nil, errDiskAccessDenied
}

func TestDecommissionFinalVerificationFailsClosed(t *testing.T) {
	for _, state := range []string{"offline-drive", "directory-error", "corrupt-metadata", "truncated-metadata", "legacy-metadata"} {
		t.Run(state, func(t *testing.T) {
			z, bucket := migrationTestPools(t)
			switch state {
			case "offline-drive":
				set := z.serverPools[0].getHashedSet("k")
				maxOffline := set.defaultParityCount + 1
				wrapped := 0
				t.Cleanup(conditionalPutSwapDisks(z.serverPools[0], "k", func(d StorageAPI) StorageAPI {
					wrapped++
					if wrapped <= maxOffline {
						return nil
					}
					return d
				}))
			case "directory-error":
				t.Cleanup(conditionalPutSwapDisks(z.serverPools[0], "k", func(d StorageAPI) StorageAPI {
					return migrationProgressListFaultDisk{StorageAPI: d}
				}))
			default:
				// Real metadata on only one drive, without a readable quorum.
				// This also covers errors that WalkDir deliberately skips.
				disk := z.serverPools[0].getHashedSet("k").getDisks()[0]
				file, data := xlStorageFormatFile, []byte("broken xl.meta")
				if state == "truncated-metadata" {
					data = nil
				}
				if state == "legacy-metadata" {
					file = xlStorageFormatFileV1
				}
				mustIAM(t, disk.WriteAll(t.Context(), bucket, pathJoin("k", file), data))
			}
			if err := z.checkAfterDecomBucket(t.Context(), 0, decomBucketInfo{Name: bucket}); err == nil {
				t.Fatal("unreadable storage was accepted as physically empty")
			}
			if n, err := z.countAbsentMigrationVersions(t.Context(), bucket, "k", 0, []FileInfo{{VersionID: mustGetUUID()}}); n != 0 || err == nil {
				t.Fatalf("unreadable storage was counted as progress: removed=%d err=%v", n, err)
			}
		})
	}
}

func TestFreeVersionDecommissionPreservesLiveRemoteOwner(t *testing.T) {
	f := newFreeVersionTest(t, "")
	const key = "obj-02"
	fv, tuple := f.freeRecord(0, key)
	owner := putConsistencyObject(t, f.z, f.bucket, key, 1, "live-owner", ObjectOptions{Versioned: true})
	infos, errs := readAllFileInfo(t.Context(), f.z.serverPools[1].getHashedSet(key).getDisks(), "", f.bucket, key, owner.VersionID, false, false)
	mustIAM(t, errs[0])
	fi := infos[0]
	fi.TransitionStatus, fi.TransitionTier = lifecycle.TransitionComplete, tuple.Tier
	fi.TransitionedObjName, fi.TransitionVersionID = tuple.Object, tuple.VersionID
	mustIAM(t, f.z.serverPools[1].DecomTieredObject(t.Context(), f.bucket, key, fi, ObjectOptions{}))
	if err := f.z.removeFreeVersions(t.Context(), f.bucket, key, 0, []FileInfo{fv}); !errors.Is(err, errTierStillReferenced) {
		t.Fatalf("cleanup with a live remote owner: %v", err)
	}
	if n, err := f.z.countAbsentMigrationVersions(t.Context(), f.bucket, key, 0, []FileInfo{fv}); err != nil || n != 0 {
		t.Fatalf("retained free record reported progress: removed=%d err=%v", n, err)
	}
	if slices.Contains(f.tier.removed, tuple.Object) {
		t.Fatal("cleanup deleted a live remote object")
	}
	if err := f.z.checkAfterDecomBucket(t.Context(), 0, decomBucketInfo{Name: f.bucket}); err == nil {
		t.Fatal("retained free record must block final decommission verification")
	}
}
