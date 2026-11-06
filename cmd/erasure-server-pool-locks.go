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
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	"github.com/minio/minio-go/v7/pkg/set"
)

// Object lock domains.
//
// Every erasure set has its own lockers, one per host among its drives, and a
// distributed lock is granted by a majority of them. Two locks of one name
// exclude each other only when they ask the same lockers. In a single pool the
// writers (PutObject, multipart commit, PutObjectPart, tags, retention, legal
// hold, metadata, restore, transition, heal) lock in the set an object hashes
// to. The pools layer locks an object, and its upload IDs, in the same set, so
// that a pool whose sets use different hosts still has one lock per object.
// With several pools every object write takes the pools lock instead, which
// these helpers then return unchanged.
//
// Generic NewNSLock keeps one stable domain for names that are not objects:
// bucket and IAM metadata locks, format and leader coordination, and the
// /[replicate]/ serializer.

// NewObjectNSLock returns the lock of one object in the lock domain that its
// writes use: in a single pool the object's own erasure set, otherwise the
// pools lock. Directory objects are named as storage names them.
func (z *erasureServerPools) NewObjectNSLock(bucket, object string) RWLocker {
	if z.SinglePool() {
		object = encodeDirObject(object)
	}
	return z.objectNSLock(bucket, object, object)
}

// uploadIDNSLock returns the guard of one upload ID. It is chosen by the
// upload's object, as PutObjectPart locks it in that object's set; the name
// locked stays object/uploadID.
func (z *erasureServerPools) uploadIDNSLock(bucket, object, uploadID string) RWLocker {
	return z.objectNSLock(bucket, object, pathJoin(object, uploadID))
}

// objectNSLock returns the lock of resource, a name owned by object, in the
// lock domain of object.
func (z *erasureServerPools) objectNSLock(bucket, object, resource string) RWLocker {
	if z.SinglePool() {
		return z.serverPools[0].getHashedSet(encodeDirObject(object)).NewNSLock(bucket, resource)
	}
	return z.NewNSLock(bucket, resource)
}

// objectLockRequest is one object lock that lockObjects takes.
type objectLockRequest struct {
	bucket, object string
	write          bool
}

// lockObjects takes the locks of several objects, such as the source and
// destination of a copy, before any of them is read. A name that appears twice
// gets one lock, a write lock if either asks for one. The locks are taken in
// one order, by lock domain and then by bucket and object, and transactionally
// (see getNSLocks), so that two copies in opposite directions, or an operation
// that orders its locks differently, cannot hold each other forever. The
// returned context ends when any of the locks is lost; the returned function
// releases them all.
func (z *erasureServerPools) lockObjects(ctx context.Context, reqs ...objectLockRequest) (LockContext, func(), error) {
	type entry struct {
		objectLockRequest
		domain   int
		resource string
	}
	// A lock is one resource in one lock table. The resource is the cleaned
	// name the lockers see; the domain is the set whose lockers grant it,
	// or 0 where every set shares one local table or the pools lock
	// applies.
	splitDomains := z.SinglePool() && !z.serverPools[0].sharesLocalNSLock()
	locks := make([]entry, 0, len(reqs))
	for _, r := range reqs {
		r.object = encodeDirObject(r.object)
		domain := 0
		if splitDomains {
			domain = z.serverPools[0].getHashedSetIndex(r.object)
		}
		resource := pathJoin(r.bucket, r.object)
		i := slices.IndexFunc(locks, func(e entry) bool { return e.domain == domain && e.resource == resource })
		if i >= 0 {
			locks[i].write = locks[i].write || r.write
			continue
		}
		locks = append(locks, entry{objectLockRequest: r, domain: domain, resource: resource})
	}
	slices.SortFunc(locks, func(a, b entry) int {
		if a.domain != b.domain {
			return a.domain - b.domain
		}
		return strings.Compare(a.resource, b.resource)
	})
	nsLocks := make([]nsLockRequest, len(locks))
	for i, l := range locks {
		nsLocks[i] = nsLockRequest{
			newLock: func() RWLocker { return z.NewObjectNSLock(l.bucket, l.object) },
			write:   l.write,
			atomic:  true,
		}
	}
	return getNSLocks(ctx, nsLocks, globalOperationTimeout)
}

// nsLockRequest is one lock of a transactional acquisition.
type nsLockRequest struct {
	// newLock returns a new instance of the lock for each attempt. An
	// instance names its holder, and a distributed unlock retries in the
	// background; a later attempt with the same instance could be released
	// by such a retry of the attempt before.
	newLock func() RWLocker
	write   bool
	// atomic: the lock is granted as a whole or not at all. A distributed
	// lock is, also over several names. The local backend takes several
	// names one at a time, holding the first while it waits for the next;
	// its lock context is the context it was given.
	atomic bool
}

const (
	// nsLockTryTimeout bounds each wait for a lock while holding another.
	nsLockTryTimeout = 2 * time.Second
	// nsLockRetryWait is the longest random pause before a new attempt.
	nsLockRetryWait = 250 * time.Millisecond
)

// getNSLocks acquires every lock of locks, in their order, or none. While it
// holds a lock it waits for the next one only up to nsLockTryTimeout; then it
// releases what it holds in reverse order, pauses, and tries again with a
// fresh context, until the timeout of all attempts. A wait that holds nothing
// can last for the rest of the timeout. Each lock is taken in the context of
// the one before, so the returned context ends when any lease is lost.
func getNSLocks(ctx context.Context, locks []nsLockRequest, timeout *dynamicTimeout) (LockContext, func(), error) {
	type held struct {
		lock  RWLocker
		write bool
		lkctx LockContext
	}
	release := func(hs []held) {
		for i := len(hs) - 1; i >= 0; i-- {
			if hs[i].write {
				hs[i].lock.Unlock(hs[i].lkctx)
			} else {
				hs[i].lock.RUnlock(hs[i].lkctx)
			}
		}
	}
	// Fail as a single lock does: a canceled request with its own error,
	// anything else as a timeout.
	failed := func() error {
		if err := ctx.Err(); errors.Is(err, context.Canceled) {
			return err
		}
		return OperationTimedOut{}
	}
	start := time.Now()
	deadline := start.Add(timeout.Timeout())
	for {
		hs := make([]held, 0, len(locks))
		lctx := ctx
		var err error
		for _, l := range locks {
			wait := time.Until(deadline)
			if len(hs) > 0 || !l.atomic {
				wait = min(wait, nsLockTryTimeout)
			}
			if wait <= 0 {
				err = OperationTimedOut{}
				break
			}
			lk := l.newLock()
			try := newDynamicTimeout(wait, wait)
			// The local backend waits up to the timeout for each name: bound
			// the whole attempt by its context instead.
			tctx, cancel := lctx, context.CancelFunc(func() {})
			if !l.atomic {
				tctx, cancel = context.WithTimeout(lctx, wait)
			}
			var lkctx LockContext
			if l.write {
				lkctx, err = lk.GetLock(tctx, try)
			} else {
				lkctx, err = lk.GetRLock(tctx, try)
			}
			cancel()
			if err != nil {
				break
			}
			if !l.atomic {
				lkctx.ctx = lctx
			}
			hs = append(hs, held{lock: lk, write: l.write, lkctx: lkctx})
			lctx = lkctx.Context()
		}
		if err == nil {
			timeout.LogSuccess(time.Since(start))
			if len(hs) == 0 {
				return LockContext{ctx: ctx, cancel: func() {}}, func() {}, nil
			}
			return LockContext{ctx: lctx, cancel: func() {}}, func() { release(hs) }, nil
		}
		release(hs)
		// A lost lease cancels the context of a later wait; only the
		// request's own context ends the attempts.
		if ctx.Err() != nil || (!errors.As(err, &OperationTimedOut{}) && !errors.Is(err, context.Canceled)) {
			return LockContext{}, nil, err
		}
		pause := rand.N(nsLockRetryWait) + time.Millisecond
		if time.Until(deadline) <= pause {
			timeout.LogFailure()
			return LockContext{}, nil, OperationTimedOut{}
		}
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return LockContext{}, nil, failed()
		case <-t.C:
		}
	}
}

// sharesLocalNSLock reports whether every set of the pool uses one local lock
// table, as a single node does: there all sets are one lock domain.
func (s *erasureSets) sharesLocalNSLock() bool {
	first := s.sets[0].nsMutex
	if first.isDistErasure {
		return false
	}
	for _, set := range s.sets[1:] {
		if set.nsMutex != first {
			return false
		}
	}
	return true
}

// deleteObjectsInSets is the bulk delete of a single pool whose sets do not
// share one lock table. The names are grouped by the set they hash to, the
// lock domain of their writers. The groups run one after another in ascending
// set index; each takes its set's lock over all of its names in one
// acquisition, deletes its sub-batch, and releases the lock before the next
// group starts. No two sets' locks are held at once.
//
// Each group's lock is taken in the request's context. A group whose lock
// cannot be taken fails as a whole and the next group still runs; once the
// request is canceled the remaining groups fail without being attempted. The
// results keep their positions in objects. Replication, events and auditing
// stay with the callers, on the merged results.
func (z *erasureServerPools) deleteObjectsInSets(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions, dobjects []DeletedObject, derrs []error, timeout *dynamicTimeout) {
	pool := z.serverPools[0]
	groups := make(map[int][]int)
	for i, obj := range objects {
		idx := pool.getHashedSetIndex(obj.ObjectName)
		groups[idx] = append(groups[idx], i)
	}
	order := make([]int, 0, len(groups))
	for idx := range groups {
		order = append(order, idx)
	}
	slices.Sort(order)

	for _, idx := range order {
		members := groups[idx]
		fail := func(err error) {
			for _, i := range members {
				derrs[i] = err
			}
		}
		if err := ctx.Err(); err != nil {
			fail(err)
			continue
		}
		er := pool.sets[idx]
		names := set.NewStringSet()
		batch := make([]ObjectToDelete, len(members))
		for j, i := range members {
			names.Add(objects[i].ObjectName)
			batch[j] = objects[i]
		}
		resources := names.ToSlice()
		lkctx, unlock, err := getNSLocks(ctx, []nsLockRequest{{
			newLock: func() RWLocker { return er.NewNSLock(bucket, resources...) },
			write:   true,
			atomic:  er.nsMutex.isDistErasure || len(resources) == 1,
		}}, timeout)
		if err != nil {
			fail(err)
			continue
		}
		deleted, errs := er.DeleteObjects(lkctx.Context(), bucket, batch, opts)
		unlock()
		// Merge as the pools loop of DeleteObjects does for one pool.
		for j, i := range members {
			if errs[j] == nil && deleted[j].found {
				dobjects[i], derrs[i] = deleted[j], nil
				continue
			}
			if derrs[i] == nil {
				dobjects[i], derrs[i] = deleted[j], errs[j]
			}
		}
	}
}
