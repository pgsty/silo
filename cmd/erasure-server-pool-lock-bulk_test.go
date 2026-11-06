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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A bulk delete of a single pool whose sets have their own lockers deletes
// the groups of different sets concurrently, as the sets of one bulk delete
// did before the lock-domain change.

// bulkGateDisk calls enter before the bulk deletes of its set and counts
// them.
type bulkGateDisk struct {
	StorageAPI
	enter func(ctx context.Context) error
	calls *atomic.Int32
}

func (d bulkGateDisk) DeleteVersions(ctx context.Context, volume string, versions []FileInfoVersions, opts DeleteOptions) []error {
	d.calls.Add(1)
	if err := d.enter(ctx); err != nil {
		errs := make([]error, len(versions))
		for i := range errs {
			errs[i] = err
		}
		return errs
	}
	return d.StorageAPI.DeleteVersions(ctx, volume, versions, opts)
}

// bulkSplit makes the single pool of z n sets with their own local lock
// tables that share its drives. enter(set) runs before each bulk delete on a
// drive of that set; calls counts them per set.
func bulkSplit(t *testing.T, z *erasureServerPools, n int, enter func(ctx context.Context, set int) error) []*atomic.Int32 {
	t.Helper()
	pool := z.serverPools[0]
	sets, count := pool.sets, pool.setCount
	t.Cleanup(func() { pool.sets, pool.setCount = sets, count })
	disks := sets[0].getDisks
	calls := make([]*atomic.Int32, n)
	split := make([]*erasureObjects, n)
	for i := range n {
		set := *sets[0]
		set.setIndex = i
		set.nsMutex = newNSLock(false)
		calls[i] = &atomic.Int32{}
		set.getDisks = func() []StorageAPI {
			ds := disks()
			for j, d := range ds {
				if d != nil {
					ds[j] = bulkGateDisk{StorageAPI: d, enter: func(ctx context.Context) error { return enter(ctx, i) }, calls: calls[i]}
				}
			}
			return ds
		}
		split[i] = &set
	}
	pool.sets, pool.setCount = split, n
	return calls
}

func TestDeleteObjectsInSetsRunsGroupsConcurrently(t *testing.T) {
	z, bucket := bulkDeletePools(t, 1)
	// The first bulk delete of each set waits until the other set's first
	// one has started too: run one after the other, they cannot meet.
	var arrived sync.WaitGroup
	arrived.Add(2)
	once := []sync.Once{{}, {}}
	var missed atomic.Bool
	bulkSplit(t, z, 2, func(ctx context.Context, set int) error {
		once[set].Do(func() {
			arrived.Done()
			met := make(chan struct{})
			go func() { arrived.Wait(); close(met) }()
			select {
			case <-met:
			case <-time.After(5 * time.Second):
				missed.Store(true)
			}
		})
		return nil
	})
	k0, k1 := ldKey(t, z, "concurrent", 0), ldKey(t, z, "concurrent", 1)
	ldMustPut(t, z, bucket, k0, "zero")
	ldMustPut(t, z, bucket, k1, "one")
	_, errs := z.DeleteObjects(t.Context(), bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: k0}}, {ObjectV: ObjectV{ObjectName: k1}}}, ObjectOptions{})
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	if missed.Load() {
		t.Fatal("the groups of the two sets ran one after the other")
	}
	ldAbsent(t, z, bucket, k0)
	ldAbsent(t, z, bucket, k1)
}

// With fewer workers than groups, a group that is admitted after the request
// was canceled does no storage work. A group in flight at the cancel keeps
// the result its own delete reports, and a group that completed before keeps
// its success.
func TestDeleteObjectsInSetsQueuedGroupsCancel(t *testing.T) {
	prev := deleteSetGroupsLimit
	deleteSetGroupsLimit = 1
	t.Cleanup(func() { deleteSetGroupsLimit = prev })
	for _, blocked := range []int{0, 1} {
		t.Run(fmt.Sprintf("blocked=%d", blocked), func(t *testing.T) {
			z, bucket := bulkDeletePools(t, 1)
			entered, gate := make(chan struct{}, 1), make(chan struct{})
			var once sync.Once
			calls := bulkSplit(t, z, 3, func(ctx context.Context, set int) error {
				if set == blocked {
					once.Do(func() { entered <- struct{}{} })
					<-gate
				}
				return nil
			})
			keys := make([]string, 3)
			objects := make([]ObjectToDelete, 3)
			for set := range keys {
				keys[set] = ldKey(t, z, fmt.Sprintf("queued-%d", blocked), set)
				ldMustPut(t, z, bucket, keys[set], "body")
				objects[set] = ObjectToDelete{ObjectV: ObjectV{ObjectName: keys[set]}}
			}
			for _, c := range calls {
				c.Store(0)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			dobjects := make([]DeletedObject, 3)
			for i := range dobjects {
				dobjects[i].ObjectName = keys[i]
			}
			derrs := make([]error, 3)
			done := make(chan struct{})
			go func() {
				defer close(done)
				z.deleteObjectsInSets(ctx, bucket, objects, ObjectOptions{}, dobjects, derrs, newDynamicTimeout(10*time.Second, 10*time.Second))
			}()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("the blocked group did not start")
			}
			cancel()
			close(gate)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("deleteObjectsInSets did not return")
			}
			for set := range keys {
				switch {
				case set < blocked:
					if derrs[set] != nil || !dobjects[set].found {
						t.Errorf("set %d completed before the cancel: %v found=%v", set, derrs[set], dobjects[set].found)
					}
				case set == blocked:
					if !errors.Is(derrs[set], context.Canceled) {
						t.Errorf("set %d in flight: %v, want context.Canceled", set, derrs[set])
					}
				default:
					if !errors.Is(derrs[set], context.Canceled) {
						t.Errorf("queued set %d: %v, want context.Canceled", set, derrs[set])
					}
					if n := calls[set].Load(); n != 0 {
						t.Errorf("queued set %d made %d drive calls", set, n)
					}
				}
			}
		})
	}
}
