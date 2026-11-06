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
	"net/http"
	"strings"
	"testing"
	"time"
)

// getNSLocks waits for a lock that it could not get within its bounded wait
// alone, holding nothing: the locks before it in the order are free for
// others for as long as it waits.

// nsLocksEvents records the events of getNSLocks for the test.
func nsLocksEvents(t *testing.T) chan string {
	t.Helper()
	events := make(chan string, 256)
	getNSLocksEvent = func(event string, index int) {
		select {
		case events <- fmt.Sprintf("%s:%d", event, index):
		default:
		}
	}
	t.Cleanup(func() { getNSLocksEvent = nil })
	return events
}

// waitNSLocksEvent waits for want, bounded, skipping other events.
func waitNSLocksEvent(t *testing.T, events chan string, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev == want {
				return
			}
		case <-deadline:
			t.Fatalf("no %q event", want)
		}
	}
}

type nsLocksResult struct {
	unlock func()
	err    error
}

// nsLockFactories are the lock backends the tests run with: one local table,
// and in-process dsync lockers of two sets that share no locker.
func nsLockFactories(t *testing.T) map[string]func(name string) RWLocker {
	ns := newNSLock(false)
	z, bucket := ldPool(t, ldDsync)
	pool := z.serverPools[0]
	return map[string]func(string) RWLocker{
		"local": func(name string) RWLocker { return ns.NewNSLock(nil, "bucket", name) },
		"dsync": func(name string) RWLocker {
			// "a" names a key of set 0, anything else a key of set 1.
			set := 1
			if strings.HasPrefix(name, "a") {
				set = 0
			}
			return pool.sets[set].NewNSLock(bucket, name)
		},
	}
}

func nsLockPair(lock func(string) RWLocker) []nsLockRequest {
	newLock := func(name string) func() RWLocker { return func() RWLocker { return lock(name) } }
	return []nsLockRequest{{newLock: newLock("a"), write: true, atomic: true}, {newLock: newLock("b"), write: true, atomic: true}}
}

func TestGetNSLocksWaitsHoldingNothing(t *testing.T) {
	for name, lock := range nsLockFactories(t) {
		t.Run(name, func(t *testing.T) {
			events := nsLocksEvents(t)
			releaseB := ldHoldLock(t, lock("b"))
			defer releaseB()
			done := make(chan nsLocksResult, 1)
			go func() {
				_, unlock, err := getNSLocks(t.Context(), nsLockPair(lock), newDynamicTimeout(30*time.Second, 30*time.Second))
				done <- nsLocksResult{unlock, err}
			}()
			waitNSLocksEvent(t, events, "idle-wait:1")
			// The event says that a was released; a distributed unlock may
			// still be on its way.
			if !ldFree(t, lock("a"), true) {
				t.Fatal("a is not released while b is waited for")
			}
			releaseA := ldHoldLock(t, lock("a"))
			hold := time.After(3 * (nsLockTryTimeout + nsLockRetryWait))
		holding:
			for {
				select {
				case ev := <-events:
					if strings.HasPrefix(ev, "bounded-timeout") {
						t.Fatalf("%s while a was free for others", ev)
					}
				case res := <-done:
					t.Fatalf("returned while a was held by the test: %v", res.err)
				case <-hold:
					break holding
				}
			}
			releaseB()
			releaseA()
			var res nsLocksResult
			select {
			case res = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("getNSLocks did not return after both locks were released")
			}
			if res.err != nil {
				t.Fatal(res.err)
			}
			if ldTry(t, lock("a"), false) || ldTry(t, lock("b"), false) {
				t.Error("not both locks held")
			}
			res.unlock()
			if !ldFree(t, lock("a"), true) || !ldFree(t, lock("b"), true) {
				t.Error("locks left behind")
			}
		})
	}
}

func TestGetNSLocksIdleWaitCancel(t *testing.T) {
	for name, lock := range nsLockFactories(t) {
		t.Run(name, func(t *testing.T) {
			events := nsLocksEvents(t)
			releaseB := ldHoldLock(t, lock("b"))
			defer releaseB()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan nsLocksResult, 1)
			go func() {
				_, unlock, err := getNSLocks(ctx, nsLockPair(lock), newDynamicTimeout(30*time.Second, 30*time.Second))
				done <- nsLocksResult{unlock, err}
			}()
			waitNSLocksEvent(t, events, "idle-wait:1")
			cancel()
			select {
			case res := <-done:
				if !errors.Is(res.err, context.Canceled) {
					t.Fatalf("err = %v, want context.Canceled", res.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("a canceled idle wait did not return")
			}
			if !ldFree(t, lock("a"), true) {
				t.Error("a left behind")
			}
		})
	}
}

func TestGetNSLocksIdleWaitDeadline(t *testing.T) {
	for name, lock := range nsLockFactories(t) {
		t.Run(name, func(t *testing.T) {
			events := nsLocksEvents(t)
			releaseB := ldHoldLock(t, lock("b"))
			defer releaseB()
			const timeout = 4 * time.Second
			start := time.Now()
			done := make(chan nsLocksResult, 1)
			go func() {
				_, unlock, err := getNSLocks(t.Context(), nsLockPair(lock), newDynamicTimeout(timeout, timeout))
				done <- nsLocksResult{unlock, err}
			}()
			waitNSLocksEvent(t, events, "idle-wait:1")
			select {
			case res := <-done:
				if !errors.As(res.err, &OperationTimedOut{}) {
					t.Fatalf("err = %v, want OperationTimedOut", res.err)
				}
				if took := time.Since(start); took > timeout+2*time.Second {
					t.Errorf("returned after %v", took)
				}
			case <-time.After(timeout + 5*time.Second):
				t.Fatal("the idle wait outlived the deadline")
			}
			if !ldFree(t, lock("a"), true) {
				t.Error("a left behind")
			}
		})
	}
}

// A non-atomic request may hold some of its names while it waits for the
// next, so it is never waited for alone; it keeps the bounded retries.
func TestGetNSLocksNonAtomicKeepsBoundedRetry(t *testing.T) {
	ns := newNSLock(false)
	lock := func(name string) RWLocker { return ns.NewNSLock(nil, "bucket", name) }
	events := nsLocksEvents(t)
	releaseB := ldHoldLock(t, lock("b"))
	reqs := []nsLockRequest{
		{newLock: func() RWLocker { return lock("a") }, write: true, atomic: true},
		{newLock: func() RWLocker { return lock("b") }, write: true},
	}
	done := make(chan nsLocksResult, 1)
	go func() {
		_, unlock, err := getNSLocks(t.Context(), reqs, newDynamicTimeout(30*time.Second, 30*time.Second))
		done <- nsLocksResult{unlock, err}
	}()
	wait := time.After(2 * (nsLockTryTimeout + nsLockRetryWait))
watch:
	for {
		select {
		case ev := <-events:
			t.Fatalf("event %s for a non-atomic lock", ev)
		case <-wait:
			break watch
		}
	}
	releaseB()
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatal(res.err)
		}
		res.unlock()
	case <-time.After(10 * time.Second):
		t.Fatal("getNSLocks did not return")
	}
}

// A copy whose destination sorts first in the lock order no longer keeps
// its destination locked while its source is held by another writer.
func TestLockDomainCopyDoesNotStarveDestination(t *testing.T) {
	for _, mode := range []string{ldShared, ldDsync} {
		t.Run(mode, func(t *testing.T) {
			z, bucket, router := ldAPI(t, mode)
			dst, src := "a-dst", "b-src" // the shared table orders by name
			if mode != ldShared {
				dst, src = ldKey(t, z, "starve-dst", 0), ldKey(t, z, "starve-src", 1)
			}
			ldMustPut(t, z, bucket, dst, "destination")
			ldMustPut(t, z, bucket, src, "source")
			events := nsLocksEvents(t)
			releaseSrc := ldHoldLock(t, z.NewObjectNSLock(bucket, src))
			defer releaseSrc()
			done := make(chan int, 1)
			go func() {
				done <- ldCopyRequest(t.Context(), t, router, bucket, src, dst, nil).Code
			}()
			waitNSLocksEvent(t, events, "idle-wait:1")
			if !ldFree(t, z.NewObjectNSLock(bucket, dst), true) {
				t.Fatal("the destination is not released while the source is waited for")
			}
			for range 3 {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				_, err := z.GetObjectInfo(ctx, bucket, dst, ObjectOptions{})
				cancel()
				if err != nil {
					t.Fatalf("HEAD of the destination while the copy waits: %v", err)
				}
				if body, _ := ldBody(t, z, bucket, dst); body != "destination" {
					t.Fatalf("destination = %q", body)
				}
			}
			releaseSrc()
			select {
			case code := <-done:
				if code != http.StatusOK {
					t.Fatalf("copy: %d", code)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("the copy did not complete")
			}
			if body, _ := ldBody(t, z, bucket, dst); body != "source" {
				t.Errorf("after the copy: %q", body)
			}
		})
	}
}
