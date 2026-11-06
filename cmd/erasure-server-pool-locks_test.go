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
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/dsync"
)

// ldTry reports whether lk can be taken now, and releases it again.
func ldTry(t *testing.T, lk RWLocker, write bool) bool {
	t.Helper()
	dt := newDynamicTimeout(100*time.Millisecond, 100*time.Millisecond)
	if write {
		lc, err := lk.GetLock(t.Context(), dt)
		if err == nil {
			lk.Unlock(lc)
		}
		return err == nil
	}
	lc, err := lk.GetRLock(t.Context(), dt)
	if err == nil {
		lk.RUnlock(lc)
	}
	return err == nil
}

// ldFree reports whether lk can be taken within a few seconds: a distributed
// unlock completes in the background.
func ldFree(t *testing.T, lk RWLocker, write bool) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ldTry(t, lk, write) {
		if time.Now().After(deadline) {
			return false
		}
	}
	return true
}

// ldTaken waits until someone else holds lk.
func ldTaken(t *testing.T, lk RWLocker) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for ldTry(t, lk, false) {
		if time.Now().After(deadline) {
			t.Fatal("lock never taken")
		}
		time.Sleep(time.Millisecond)
	}
}

func ldHoldLock(t *testing.T, lk RWLocker) func() {
	t.Helper()
	lc, err := lk.GetLock(t.Context(), globalOperationTimeout)
	if err != nil {
		t.Fatal(err)
	}
	done := false
	return func() {
		if !done {
			done = true
			lk.Unlock(lc)
		}
	}
}

// Object locks, and upload guards by their object, are in the set the
// object's writes lock in; with several pools they stay the pools lock.
func TestObjectNSLockRouting(t *testing.T) {
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket := ldPool(t, mode)
			pool := z.serverPools[0]
			key := ldKey(t, z, "route", 1)
			dir := ldKey(t, z, "route-dir", 0) + "/"
			for _, name := range []string{key, dir} {
				release := ldHoldLock(t, z.NewObjectNSLock(bucket, name))
				encoded := encodeDirObject(name)
				if ldTry(t, pool.getHashedSet(encoded).NewNSLock(bucket, encoded), false) {
					t.Errorf("%s: a writer of the object's set ignores the object lock", name)
				}
				release()
			}
			id := mustGetUUID()
			release := ldHoldLock(t, z.uploadIDNSLock(bucket, key, id))
			if ldTry(t, pool.getHashedSet(key).NewNSLock(bucket, pathJoin(key, id)), false) {
				t.Error("PutObjectPart's guard ignores the upload guard")
			}
			release()
			if mode != ldShared && pool.sharesLocalNSLock() {
				t.Error("split sets reported as one local table")
			}
			if mode == ldShared && !pool.sharesLocalNSLock() {
				t.Error("one local table not recognized")
			}
		})
	}
	t.Run("pools", func(t *testing.T) {
		z, bucket := bulkDeletePools(t, 2)
		release := ldHoldLock(t, z.NewNSLock(bucket, "pooled"))
		defer release()
		if ldTry(t, z.NewObjectNSLock(bucket, "pooled"), false) || ldTry(t, z.uploadIDNSLock(bucket, "pooled", ""), false) {
			t.Error("multi-pool object locks left the pools lock")
		}
	})
}

// lockObjects merges a name asked twice into one write lock and takes source
// and destination in their own sets.
func TestLockObjects(t *testing.T) {
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket := ldPool(t, mode)
			pool := z.serverPools[0]
			src, dst := ldKey(t, z, "lock-src", 1), ldKey(t, z, "lock-dst", 0)
			lkctx, unlock, err := z.lockObjects(t.Context(), objectLockRequest{bucket: bucket, object: src}, objectLockRequest{bucket: bucket, object: dst, write: true})
			if err != nil {
				t.Fatal(err)
			}
			if lkctx.Context().Err() != nil {
				t.Fatal("lock context ended")
			}
			if !ldTry(t, pool.getHashedSet(src).NewNSLock(bucket, src), false) {
				t.Error("source not shared with readers")
			}
			if ldTry(t, pool.getHashedSet(src).NewNSLock(bucket, src), true) {
				t.Error("source not locked against writers")
			}
			if ldTry(t, pool.getHashedSet(dst).NewNSLock(bucket, dst), false) {
				t.Error("destination not locked")
			}
			unlock()
			if !ldFree(t, pool.getHashedSet(dst).NewNSLock(bucket, dst), true) || !ldFree(t, pool.getHashedSet(src).NewNSLock(bucket, src), true) {
				t.Error("locks left behind")
			}

			// A copy onto itself takes one write lock; a directory object is
			// locked by its stored name.
			self := ldKey(t, z, "lock-self", 1) + "/"
			_, unlock, err = z.lockObjects(t.Context(), objectLockRequest{bucket: bucket, object: self}, objectLockRequest{bucket: bucket, object: self, write: true})
			if err != nil {
				t.Fatal(err)
			}
			encoded := encodeDirObject(self)
			if ldTry(t, pool.getHashedSet(encoded).NewNSLock(bucket, encoded), false) {
				t.Error("self copy not write locked")
			}
			unlock()
		})
	}
}

// ldLeaseLock is a lock whose lease the test ends.
type ldLeaseLock struct {
	RWLocker
	lost chan context.CancelFunc
}

func (l ldLeaseLock) GetLock(ctx context.Context, timeout *dynamicTimeout) (LockContext, error) {
	lc, err := l.RWLocker.GetLock(ctx, timeout)
	if err != nil {
		return lc, err
	}
	lease, cancel := context.WithCancel(lc.Context())
	select {
	case l.lost <- cancel:
	default:
		panic("too many lock attempts")
	}
	return LockContext{ctx: lease, cancel: cancel}, nil
}

// getNSLocks never holds one lock while it waits for another for long: it
// releases what it holds and retries, also after a lost lease, until its
// timeout or the request ends, and leaves nothing behind.
func TestGetNSLocksTransactional(t *testing.T) {
	ns := newNSLock(false)
	lock := func(name string) RWLocker { return ns.NewNSLock(nil, "bucket", name) }
	newLock := func(name string) func() RWLocker { return func() RWLocker { return lock(name) } }
	reqs := func() []nsLockRequest {
		return []nsLockRequest{{newLock: newLock("a"), write: true, atomic: true}, {newLock: newLock("b"), write: true, atomic: true}}
	}

	t.Run("partial", func(t *testing.T) {
		releaseB := ldHoldLock(t, lock("b"))
		defer releaseB()
		type result struct {
			unlock func()
			err    error
		}
		done := make(chan result, 1)
		go func() {
			_, unlock, err := getNSLocks(t.Context(), reqs(), globalOperationTimeout)
			done <- result{unlock, err}
		}()
		// "a" is taken while "b" is waited for, and free again between
		// attempts.
		ldTaken(t, lock("a"))
		deadline := time.Now().Add(3 * nsLockTryTimeout)
		for !ldTry(t, lock("a"), true) {
			if time.Now().After(deadline) {
				t.Fatal("a stays held while b is waited for")
			}
		}
		releaseB()
		res := <-done
		if res.err != nil {
			t.Fatal(res.err)
		}
		if ldTry(t, lock("a"), false) || ldTry(t, lock("b"), false) {
			t.Error("not both locks held")
		}
		res.unlock()
		if !ldTry(t, lock("a"), true) || !ldTry(t, lock("b"), true) {
			t.Error("locks left behind")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		releaseB := ldHoldLock(t, lock("b"))
		defer releaseB()
		start := time.Now()
		_, _, err := getNSLocks(t.Context(), reqs(), newDynamicTimeout(3*time.Second, 3*time.Second))
		if !errors.As(err, &OperationTimedOut{}) {
			t.Fatalf("got %v, want a timeout", err)
		}
		if took := time.Since(start); took > 6*time.Second {
			t.Errorf("timed out after %v", took)
		}
		if !ldTry(t, lock("a"), true) {
			t.Error("a left behind")
		}
	})

	t.Run("cancel", func(t *testing.T) {
		releaseB := ldHoldLock(t, lock("b"))
		defer releaseB()
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(300*time.Millisecond, cancel)
		_, _, err := getNSLocks(ctx, reqs(), globalOperationTimeout)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want canceled", err)
		}
		if !ldTry(t, lock("a"), true) {
			t.Error("a left behind")
		}
	})

	t.Run("lease", func(t *testing.T) {
		lost := make(chan context.CancelFunc, 64)
		leased := []nsLockRequest{{newLock: func() RWLocker { return ldLeaseLock{lock("a"), lost} }, write: true, atomic: true}, {newLock: newLock("b"), write: true, atomic: true}}
		// Losing the first lease while the second is waited for retries
		// with a fresh context.
		releaseB := ldHoldLock(t, lock("b"))
		type result struct {
			lkctx  LockContext
			unlock func()
			err    error
		}
		done := make(chan result, 1)
		go func() {
			lkctx, unlock, err := getNSLocks(t.Context(), leased, globalOperationTimeout)
			done <- result{lkctx, unlock, err}
		}()
		(<-lost)()
		releaseB()
		res := <-done
		if res.err != nil {
			t.Fatal(res.err)
		}
		if res.lkctx.Context().Err() != nil {
			t.Fatal("returned context ended before any lease was lost")
		}
		// Losing a held lease ends the returned context.
		var cancel context.CancelFunc
		for len(lost) > 0 {
			cancel = <-lost
		}
		cancel()
		select {
		case <-res.lkctx.Context().Done():
		case <-time.After(time.Second):
			t.Error("lost lease did not end the locks' context")
		}
		res.unlock()
		if !ldTry(t, lock("a"), true) || !ldTry(t, lock("b"), true) {
			t.Error("locks left behind")
		}
	})
}

// A group whose lock times out fails alone and the later groups still run.
func TestDeleteObjectsInSetsLaterGroupsRun(t *testing.T) {
	for _, mode := range ldModes[1:] {
		t.Run(mode, func(t *testing.T) {
			z, bucket := ldPool(t, mode)
			k0, k1 := ldKey(t, z, "later", 0), ldKey(t, z, "later", 1)
			ldMustPut(t, z, bucket, k0, "zero")
			ldMustPut(t, z, bucket, k1, "one")
			release := ldHoldLock(t, z.serverPools[0].getHashedSet(k0).NewNSLock(bucket, k0))
			defer release()
			objects := []ObjectToDelete{{ObjectV: ObjectV{ObjectName: k0}}, {ObjectV: ObjectV{ObjectName: k1}}}
			dobjects := []DeletedObject{{ObjectName: k0}, {ObjectName: k1}}
			derrs := make([]error, 2)
			z.deleteObjectsInSets(t.Context(), bucket, objects, ObjectOptions{}, dobjects, derrs, newDynamicTimeout(time.Second, time.Second))
			if !errors.As(derrs[0], &OperationTimedOut{}) || derrs[1] != nil {
				t.Fatalf("results %v, want a timeout for k0 only", derrs)
			}
			release()
			if body, _ := ldBody(t, z, bucket, k0); body != "zero" {
				t.Errorf("k0 = %q", body)
			}
			ldAbsent(t, z, bucket, k1)
		})
	}
}

// The local lock takes the names of a group one by one. A group that waits
// for a name must not keep the names it holds: a part upload holds its part
// lock and then reads its upload ID, which the batch names too.
func TestDeleteObjectsInSetsLocalGroupReleases(t *testing.T) {
	z, bucket := ldPool(t, ldLocal)
	pool := z.serverPools[0]
	var upload, part string
	for i := range 1000 {
		upload = ldKey(t, z, "local-upload", 1) + fmt.Sprintf("/u%d", i)
		part = upload + "/1"
		if pool.getHashedSetIndex(upload) == 1 && pool.getHashedSetIndex(part) == 1 {
			break
		}
	}
	er := pool.getHashedSet(upload)
	releasePart := ldHoldLock(t, er.NewNSLock(bucket, part))
	defer releasePart()
	done := make(chan []error, 1)
	go func() {
		_, errs := z.DeleteObjects(t.Context(), bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: upload}}, {ObjectV: ObjectV{ObjectName: part}}}, ObjectOptions{})
		done <- errs
	}()
	// The batch takes the upload name, waits for the part, and lets the
	// part upload's read of its upload ID through.
	ldTaken(t, er.NewNSLock(bucket, upload))
	read := er.NewNSLock(bucket, upload)
	rctx, err := read.GetRLock(t.Context(), newDynamicTimeout(4*nsLockTryTimeout, 4*nsLockTryTimeout))
	if err != nil {
		t.Fatalf("batch kept a name while waiting: %v", err)
	}
	read.RUnlock(rctx)
	releasePart()
	select {
	case errs := <-done:
		if errors.Join(errs...) != nil {
			t.Fatal(errs)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("bulk delete did not finish")
	}
}

// ldLostUnlockReply applies its first unlock but loses the reply until gate
// opens, so dsync retries that unlock in the background.
type ldLostUnlockReply struct {
	dsync.NetLocker
	gate             <-chan struct{}
	applied, retried chan<- struct{}
	calls            atomic.Int32
}

func (l *ldLostUnlockReply) Unlock(ctx context.Context, args dsync.LockArgs) (bool, error) {
	n := l.calls.Add(1)
	ok, err := l.NetLocker.Unlock(ctx, args)
	switch n {
	case 1:
		l.applied <- struct{}{}
		<-l.gate
		return false, errors.New("unlock reply lost")
	case 2:
		l.retried <- struct{}{}
	}
	return ok, err
}

// ldFailFirst fails the first acquisition of any of its instances.
type ldFailFirst struct {
	RWLocker
	calls *atomic.Int32
}

func (l ldFailFirst) GetLock(ctx context.Context, timeout *dynamicTimeout) (LockContext, error) {
	if l.calls.Add(1) == 1 {
		return LockContext{}, OperationTimedOut{}
	}
	return l.RWLocker.GetLock(ctx, timeout)
}

// A distributed unlock of a failed attempt that is retried late must not
// release the lock the next attempt took.
func TestGetNSLocksFreshLockPerAttempt(t *testing.T) {
	gate := make(chan struct{})
	applied, retried := make(chan struct{}, 3), make(chan struct{}, 3)
	lockers := make([]dsync.NetLocker, 3)
	for i := range lockers {
		lockers[i] = &ldLostUnlockReply{NetLocker: newLocker(), gate: gate, applied: applied, retried: retried}
	}
	ns := newNSLock(true)
	dst := func() RWLocker {
		return ns.NewNSLock(func() ([]dsync.NetLocker, string) { return lockers, "test" }, "bucket", "destination")
	}
	local := newNSLock(false)
	var calls atomic.Int32
	src := func() RWLocker { return ldFailFirst{local.NewNSLock(nil, "bucket", "source"), &calls} }
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	opened := false
	open := func() {
		if !opened {
			opened = true
			close(gate)
		}
	}
	defer open()
	_, unlock, err := getNSLocks(ctx, []nsLockRequest{{newLock: dst, write: true, atomic: true}, {newLock: src, write: true, atomic: true}}, newDynamicTimeout(10*time.Second, 10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	for range lockers {
		select {
		case <-applied:
		case <-ctx.Done():
			t.Fatal("the first attempt's unlock never reached the lockers")
		}
	}
	open()
	for range lockers {
		select {
		case <-retried:
		case <-ctx.Done():
			t.Fatal("the lost unlock was not retried")
		}
	}
	competitor := dst()
	lc, err := competitor.GetLock(ctx, newDynamicTimeout(300*time.Millisecond, 300*time.Millisecond))
	if err == nil {
		competitor.Unlock(lc)
		t.Fatal("a late unlock retry released the held lock")
	}
}

// One attempt at a local lock over several names is bounded as a whole, and so
// is the acquisition.
func TestGetNSLocksLocalAttemptBound(t *testing.T) {
	ns := newNSLock(false)
	a, b := ns.NewNSLock(nil, "bucket", "a"), ns.NewNSLock(nil, "bucket", "b")
	releaseA, releaseB := ldHoldLock(t, a), ldHoldLock(t, b)
	defer releaseA()
	defer releaseB()
	time.AfterFunc(900*time.Millisecond, releaseA)
	time.AfterFunc(1800*time.Millisecond, releaseB)
	start := time.Now()
	_, unlock, err := getNSLocks(t.Context(), []nsLockRequest{{
		newLock: func() RWLocker { return ns.NewNSLock(nil, "bucket", "a", "b") }, write: true,
	}}, newDynamicTimeout(1500*time.Millisecond, 1500*time.Millisecond))
	if err == nil {
		unlock()
		t.Fatalf("acquired after %v with a deadline of 1.5s", time.Since(start))
	}
	if !errors.As(err, &OperationTimedOut{}) {
		t.Fatalf("got %v, want a timeout", err)
	}
}

// ldLeaseLayer gives the COPY handler locks whose lease the test ends, and
// holds its destination lookup until the lookup's context ends.
type ldLeaseLayer struct {
	ObjectLayer
	destination string
	lost        chan context.CancelFunc
	lookup      chan context.Context
}

func (l *ldLeaseLayer) lockObjects(ctx context.Context, reqs ...objectLockRequest) (LockContext, func(), error) {
	lc, unlock, err := l.ObjectLayer.lockObjects(ctx, reqs...)
	if err != nil {
		return lc, unlock, err
	}
	lease, cancel := context.WithCancel(lc.Context())
	l.lost <- cancel
	return LockContext{ctx: lease, cancel: cancel}, func() { cancel(); unlock() }, nil
}

func (l *ldLeaseLayer) GetObjectInfo(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	if object == l.destination && opts.NoLock {
		l.lookup <- ctx
		<-ctx.Done()
		return ObjectInfo{}, ctx.Err()
	}
	return l.ObjectLayer.GetObjectInfo(ctx, bucket, object, opts)
}

// The COPY handler's work under its locks ends when a lease is lost, the
// destination lookups included.
func TestLockDomainCopyLookupEndsWithLease(t *testing.T) {
	z, bucket, _ := ldAPI(t, ldShared)
	ldMustPut(t, z, bucket, "source", "")
	prevTier := globalTierConfigMgr
	t.Cleanup(func() { globalTierConfigMgr = prevTier })
	globalTierConfigMgr = NewTierConfigMgr()
	globalTierConfigMgr.Tiers["WARM"] = madmin.TierConfig{Version: madmin.TierConfigVer, Type: madmin.S3, Name: "WARM", S3: &madmin.TierS3{Bucket: "warm"}}
	layer := &ldLeaseLayer{ObjectLayer: z, destination: "destination", lost: make(chan context.CancelFunc, 1), lookup: make(chan context.Context, 1)}
	router := initTestAPIEndPoints(layer, []string{"CopyObject"})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	code := make(chan int, 1)
	go func() { code <- ldCopyRequest(ctx, t, router, bucket, "source", "destination", nil).Code }()
	var lookup context.Context
	select {
	case lookup = <-layer.lookup:
	case <-ctx.Done():
		t.Fatal("COPY did not look up its destination")
	}
	(<-layer.lost)()
	select {
	case <-lookup.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the destination lookup outlived the lost lease")
	}
	if c := <-code; c == http.StatusOK {
		t.Error("COPY succeeded after losing its lock")
	}
}
