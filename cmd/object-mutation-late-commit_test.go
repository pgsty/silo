//go:build consistency_strict

// Preserved diagnostic for the deferred strict-read policy. This is not a
// maintenance release gate; failures record intentionally unresolved risks.

// Copyright (c) 2026 Feng Ruohang
//
// This file is part of Silo Object Storage.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/dsync"
)

func lateCommitPools(t *testing.T) (*erasureServerPools, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dirs, err := getRandomDisks(16)
	if err != nil {
		t.Fatal(err)
	}
	obj, _, err := initObjectLayer(ctx, mustGetPoolEndpoints(0, dirs...))
	if err != nil {
		cancel()
		removeRoots(dirs)
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	t.Cleanup(func() { cancel(); z.Shutdown(context.Background()); removeRoots(dirs); setObjectLayer(previous) })
	bucket := "late-commit-regression"
	if err := z.MakeBucket(ctx, bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	return z, bucket
}

func lateCommitSwitch(set *erasureObjects) ([]StorageAPI, func([]StorageAPI)) {
	original := set.getDisks()
	var active atomic.Value
	active.Store(original)
	set.getDisks = func() []StorageAPI { return active.Load().([]StorageAPI) }
	return original, func(disks []StorageAPI) { active.Store(disks) }
}

type lateCommitDisk struct {
	StorageAPI
	index         int
	earlyDone     chan<- struct{}
	releaseRename <-chan struct{}
	renameReady   chan<- struct{}
	releaseUndo   <-chan struct{}
}

func (d lateCommitDisk) RenameData(ctx context.Context, sv, sp string, fi FileInfo, dv, dp string, opts RenameOptions) (RenameDataResp, error) {
	defer func() { d.renameReady <- struct{}{} }()
	if d.index >= 1 {
		<-d.releaseRename
	}
	result, err := d.StorageAPI.RenameData(ctx, sv, sp, fi, dv, dp, opts)
	if err != nil {
		return result, err
	}
	if d.index < 1 {
		d.earlyDone <- struct{}{}
		<-d.releaseRename
	}
	// Model a lost successful response. Real disk commit has already happened.
	if d.index < 1 || d.index >= 12 {
		return RenameDataResp{}, errDiskNotFound
	}
	return result, nil
}

func (d lateCommitDisk) DeleteVersion(ctx context.Context, volume, path string, fi FileInfo, force bool, opts DeleteOptions) error {
	if opts.UndoWrite {
		<-d.releaseUndo
	}
	return d.StorageAPI.DeleteVersion(ctx, volume, path, fi, force, opts)
}

// All metadata changes use production PutObject/RenameData/UndoWrite on real disks.
// Fault injection only controls timing, namespace lease age, and transport results.
func TestMutationReadDuringLateCommitAndUndo(t *testing.T) {
	z, bucket := lateCommitPools(t)
	object := "late-undo-16"
	bodyA, bodyB := strings.Repeat("writer-A", 262144), strings.Repeat("writer-B", 262144)
	label := func(s string) string {
		if s == bodyA {
			return "A (2 MiB, exact payload match)"
		}
		if s == bodyB {
			return "B (2 MiB, exact payload match)"
		}
		if s == "" {
			return "empty"
		}
		return "UNEXPECTED PAYLOAD"
	}
	set := z.serverPools[0].getHashedSet(object)
	put := func(ctx context.Context, body string) (ObjectInfo, error) {
		return set.PutObject(ctx, bucket, object, mustGetPutObjReader(t, strings.NewReader(body), int64(len(body)), "", ""), ObjectOptions{NoLock: true})
	}
	if _, err := put(t.Context(), "seed"); err != nil {
		t.Fatal(err)
	}
	lockers := make([]*localLocker, 4)
	clients := make([]dsync.NetLocker, 4)
	for i := range lockers {
		lockers[i] = newLocker()
		clients[i] = lockers[i]
	}
	newLock := func() *distLockInstance {
		return &distLockInstance{rwMutex: dsync.NewDRWMutex(&dsync.Dsync{GetLockers: func() ([]dsync.NetLocker, string) { return clients, "late-commit" }, Timeouts: dsync.DefaultTimeouts}, bucket+"/"+object), opsID: mustGetUUID()}
	}
	oldLock := newLock()
	oldCtx, err := oldLock.GetLock(t.Context(), newDynamicTimeout(time.Second, time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer oldLock.Unlock(oldCtx)
	disks, swap := lateCommitSwitch(set)
	defer swap(disks)
	earlyDone, renameReady := make(chan struct{}, 16), make(chan struct{}, 16)
	releaseRename, releaseUndo := make(chan struct{}), make(chan struct{})
	var renameOnce, undoOnce sync.Once
	unblockRename := func() { renameOnce.Do(func() { close(releaseRename) }) }
	unblockUndo := func() { undoOnce.Do(func() { close(releaseUndo) }) }
	defer unblockUndo()
	defer unblockRename()
	wrapped := append([]StorageAPI(nil), disks...)
	for i, d := range disks {
		wrapped[i] = lateCommitDisk{d, i, earlyDone, releaseRename, renameReady, releaseUndo}
	}
	swap(wrapped)
	aDone := make(chan error, 1)
	go func() { _, e := put(oldCtx.Context(), bodyA); aDone <- e }()
	for range 1 {
		select {
		case <-earlyDone:
		case <-time.After(5 * time.Second):
			t.Fatal("A early commit barrier")
		}
	}
	// Expire actual dsync lease records, allowing another holder to take over.
	for _, l := range lockers {
		l.mutex.Lock()
		for key, entries := range l.lockMap {
			for i := range entries {
				entries[i].TimeLastRefresh = time.Now().Add(-lockValidityDuration - time.Second).UnixNano()
			}
			l.lockMap[key] = entries
		}
		l.mutex.Unlock()
		l.expireOldLocks(lockValidityDuration)
	}
	newHolder := newLock()
	newCtx, err := newHolder.GetLock(t.Context(), newDynamicTimeout(time.Second, time.Second))
	if err != nil {
		t.Fatal(err)
	}
	swap(disks)
	b, err := put(newCtx.Context(), bodyB)
	newHolder.Unlock(newCtx)
	if err != nil {
		t.Fatalf("B must acknowledge success: %v", err)
	}
	counts := func() (older, newer, unknown int) {
		for _, d := range disks {
			fi, e := d.ReadVersion(t.Context(), "", bucket, object, "", ReadOptions{})
			if e != nil {
				unknown++
				continue
			}
			switch {
			case fi.ModTime.Equal(b.ModTime):
				newer++
			case fi.ModTime.Before(b.ModTime):
				older++
			default:
				t.Fatalf("unexpected generation %v", fi.ModTime)
			}
		}
		return
	}
	o, n, u := counts()
	if o != 0 || n != 16 || u != 0 {
		t.Fatalf("B ACK evidence: %d %d %d", o, n, u)
	}
	t.Logf("B successfully committed; observed B=16/16, all disks online; ModTime=%s", b.ModTime)
	unblockRename()
	for range len(disks) {
		select {
		case <-renameReady:
		case <-time.After(5 * time.Second):
			t.Fatal("rename completion barrier")
		}
	}
	o, n, u = counts()

	fi, e := disks[0].ReadVersion(t.Context(), "", bucket, object, "", ReadOptions{})
	if e != nil {
		t.Fatal(e)
	}
	qr, qw := fi.Erasure.DataBlocks, fi.Erasure.DataBlocks
	if fi.Erasure.DataBlocks == fi.Erasure.ParityBlocks {
		qw++
	}
	if qr != 12 || qw != 12 {
		t.Fatalf("unexpected quorum %d/%d", qr, qw)
	}
	t.Logf("Before A undo: old A=%d, newer acknowledged B=%d, U=%d, Qr=%d, Qw=%d", o, n, u, qr, qw)
	get := func() (string, error) {
		rd, e := z.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{})
		if e != nil {
			return "", e
		}
		defer rd.Close()
		body, e := io.ReadAll(rd)
		return string(body), e
	}
	first, firstErr := get()
	t.Logf("R1 after B ACK and before A undo: body=%q error=%v", label(first), firstErr)
	if firstErr != nil && !isErrReadQuorum(firstErr) {
		t.Errorf("unexpected first read error: %v", firstErr)
	}
	unblockUndo()
	select {
	case e := <-aDone:
		if e == nil {
			t.Fatal("A unexpectedly succeeded")
		}
		t.Logf("A failed after completing UndoWrite: %v", e)
	case <-time.After(5 * time.Second):
		t.Fatal("A undo did not finish")
	}
	second, secondErr := get()
	if secondErr != nil || second != bodyB {
		t.Fatalf("B must remain after A fails: %q %v", label(second), secondErr)
	}
	o, n, u = counts()
	t.Logf("R2 after A failure, with no new PUT: body=%q; old A=%d, B=%d, U=%d", label(second), o, n, u)
	if first == bodyA {
		t.Error("NON-LINEARIZABLE: R1 exposed A, then R2 returned B with no second B PUT; B completed before R1, and R1 completed before R2. Current fragment counts do not prove B was never committed.")
	}
}
