// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later
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
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
)

type iamPolicyReloadStore struct {
	IAMStorageAPI
	policies func(context.Context, map[string]PolicyDoc) error
	users    func(context.Context, IAMUserType, map[string]UserIdentity) error
}

func (s *iamPolicyReloadStore) loadPolicyDocs(ctx context.Context, m map[string]PolicyDoc) error {
	return s.policies(ctx, m)
}

func (s *iamPolicyReloadStore) loadUsers(ctx context.Context, typ IAMUserType, m map[string]UserIdentity) error {
	if s.users != nil {
		return s.users(ctx, typ, m)
	}
	return s.IAMStorageAPI.loadUsers(ctx, typ, m)
}

func iamPolicyReloadCall(ctx context.Context, store *IAMStoreSys, docs bool) error {
	if docs {
		_, err := store.ListPolicyDocs(ctx, "")
		return err
	}
	_, err := store.ListPolicies(ctx, "")
	return err
}

func awaitIAMPolicyReload(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("IAM operation did not reach the controlled barrier")
	}
}

// Both list entry points must allow cached readers while preserving the writer
// ordering used by policy edits, peer notifications and credential revocation.
// A refresh that captured the old state must not publish after those writes.
func TestIAMPolicyReloadConcurrentChanges(t *testing.T) {
	for _, backend := range []string{"object", "etcd"} {
		for _, docs := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/docs=%t", backend, docs), func(t *testing.T) {
				ctx, sys, obj := prepareIAMRevisionFixture(t, backend)
				store := sys.store
				original := store.IAMStorageAPI
				rw, err := store.GetPolicy("readwrite")
				mustIAM(t, err)
				ro, err := store.GetPolicy("readonly")
				mustIAM(t, err)
				for _, name := range []string{"reload-edit", "reload-delete", "reload-peer"} {
					_, err := store.SetPolicy(ctx, name, rw)
					mustIAM(t, err)
				}
				const parent = "reload-parent"
				_, err = sys.CreateUser(ctx, parent, madmin.AddOrUpdateUserReq{SecretKey: "synthetic-reload-password", Status: madmin.AccountEnabled})
				mustIAM(t, err)
				secret, err := getTokenSigningKey()
				mustIAM(t, err)
				issue := func(typ string) auth.Credentials {
					c, err := auth.GetNewCredentialsWithMetadata(map[string]any{"exp": UTCNow().Add(time.Hour).Unix(), parentClaim: parent, tokenRevokeTypeClaim: typ}, secret)
					mustIAM(t, err)
					c.ParentUser = parent
					_, err = store.SetTempUser(ctx, c.AccessKey, c, "")
					mustIAM(t, err)
					return c
				}
				revoked, retained := issue("selected"), issue("other")
				peer := &IAMStoreSys{IAMStorageAPI: newIAMObjectStore(obj, MinIOUsersSysType)}
				if backend == "etcd" {
					peer.IAMStorageAPI = newIAMEtcdStore(original.(*IAMEtcdStore).client, MinIOUsersSysType)
				}
				mustIAM(t, peer.LoadIAMCache(ctx, true))

				type refreshKey struct{}
				loading, releaseLoad := make(chan struct{}), make(chan struct{})
				refreshing, releaseRefresh := make(chan struct{}), make(chan struct{})
				unblockLoad := sync.OnceFunc(func() { close(releaseLoad) })
				unblockRefresh := sync.OnceFunc(func() { close(releaseRefresh) })
				var wg sync.WaitGroup
				t.Cleanup(func() { unblockLoad(); unblockRefresh(); wg.Wait() })
				store.IAMStorageAPI = &iamPolicyReloadStore{
					IAMStorageAPI: original,
					policies: func(ctx context.Context, m map[string]PolicyDoc) error {
						if err := original.loadPolicyDocs(ctx, m); err != nil {
							return err
						}
						if ctx.Value(refreshKey{}) == nil {
							close(loading)
							select {
							case <-releaseLoad:
							case <-ctx.Done():
								return ctx.Err()
							}
						}
						return nil
					},
					users: func(ctx context.Context, typ IAMUserType, m map[string]UserIdentity) error {
						if err := original.loadUsers(ctx, typ, m); err != nil {
							return err
						}
						if typ == stsUser && ctx.Value(refreshKey{}) != nil {
							close(refreshing)
							<-releaseRefresh
						}
						return nil
					},
				}
				start := func(fn func() error) <-chan error {
					out := make(chan error, 1)
					wg.Go(func() { out <- fn() })
					return out
				}
				refreshDone := start(func() error { return store.LoadIAMCache(context.WithValue(ctx, refreshKey{}, true), false) })
				awaitIAMPolicyReload(t, refreshing)
				listDone := start(func() error { return iamPolicyReloadCall(ctx, store, docs) })
				awaitIAMPolicyReload(t, loading)
				reader := start(func() error {
					if _, ok := store.GetUser(parent); !ok {
						return errors.New("committed user disappeared during policy loading")
					}
					_, err := store.GetPolicy("reload-edit")
					return err
				})
				select {
				case err := <-reader:
					mustIAM(t, err)
				case <-time.After(time.Second):
					t.Fatal("policy loading blocked cached authentication")
				}

				// The peer commits independently; its notification waits alongside
				// local changes while the older list snapshot remains in flight.
				_, err = peer.SetPolicy(ctx, "reload-peer", ro)
				mustIAM(t, err)
				writersStarted := make(chan struct{}, 4)
				startWrite := func(fn func() error) <-chan error {
					return start(func() error { writersStarted <- struct{}{}; return fn() })
				}
				writes := []<-chan error{
					startWrite(func() error { _, err := store.SetPolicy(ctx, "reload-edit", ro); return err }),
					startWrite(func() error { return store.DeletePolicy(ctx, "reload-delete", false) }),
					startWrite(func() error { _, err := store.RevokeTokens(ctx, parent, "selected"); return err }),
					startWrite(func() error { return store.PolicyNotificationHandler(ctx, "reload-peer") }),
				}
				for range writes {
					<-writersStarted
				}
				select {
				case err := <-writes[0]:
					t.Fatalf("policy write overtook the pending reload: %v", err)
				case <-time.After(25 * time.Millisecond):
				}
				for _, done := range writes[1:] {
					select {
					case err := <-done:
						t.Fatalf("IAM mutation overtook the pending reload: %v", err)
					default:
					}
				}
				unblockLoad()
				mustIAM(t, <-listDone)
				for _, done := range writes {
					mustIAM(t, <-done)
				}
				unblockRefresh()
				mustIAM(t, <-refreshDone)
				for _, name := range []string{"reload-edit", "reload-peer"} {
					p, err := store.GetPolicy(name)
					mustIAM(t, err)
					if p.IsAllowed(policy.Args{Action: policy.PutObjectAction, BucketName: "bucket", ObjectName: "object"}) {
						t.Fatalf("stale list/refresh restored the old grant: %s", name)
					}
					if !p.IsAllowed(policy.Args{Action: policy.GetObjectAction, BucketName: "bucket", ObjectName: "object"}) {
						t.Fatalf("reload lost the committed read grant: %s", name)
					}
				}
				if _, err := store.GetPolicy("reload-delete"); !errors.Is(err, errNoSuchPolicy) {
					t.Fatalf("deleted policy returned: %v", err)
				}
				if _, ok := store.GetUser(revoked.AccessKey); ok {
					t.Fatal("stale list/refresh restored a revoked token")
				}
				for _, key := range []string{retained.AccessKey, parent} {
					if _, ok := store.GetUser(key); !ok {
						t.Fatal("reload removed an unrelated credential")
					}
				}
			})
		}
	}
}

func TestIAMPolicyReloadFailurePreservesCache(t *testing.T) {
	for _, docs := range []bool{false, true} {
		for _, failure := range []string{"storage", "cancel_partial", "caller_deadline_partial"} {
			t.Run(fmt.Sprintf("docs=%t/%s", docs, failure), func(t *testing.T) {
				ctx, sys, _ := prepareIAMRevisionFixture(t)
				var cancel context.CancelFunc
				if failure == "caller_deadline_partial" {
					ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				} else {
					ctx, cancel = context.WithCancel(ctx)
				}
				defer cancel()
				store := sys.store
				cache := store.rlock()
				updated := cache.updatedAt
				store.runlock()
				injected := errors.New("policy read failed")
				entered := make(chan struct{})
				original := store.IAMStorageAPI
				store.IAMStorageAPI = &iamPolicyReloadStore{IAMStorageAPI: original, policies: func(ctx context.Context, m map[string]PolicyDoc) error {
					m["partial-result"] = PolicyDoc{}
					close(entered)
					if failure == "storage" {
						return injected
					}
					<-ctx.Done()
					// A canceled enumeration can close without yielding an error.
					return nil
				}}
				done := make(chan error, 1)
				go func() { done <- iamPolicyReloadCall(ctx, store, docs) }()
				awaitIAMPolicyReload(t, entered)
				want := injected
				switch failure {
				case "cancel_partial":
					cancel()
					want = context.Canceled
				case "caller_deadline_partial":
					want = context.DeadlineExceeded
				}
				select {
				case err := <-done:
					if !errors.Is(err, want) {
						t.Fatalf("got %v, want %v", err, want)
					}
				case <-time.After(time.Second):
					cancel()
					<-done
					t.Fatal("reload did not honor caller cancellation")
				}
				cache = store.rlock()
				_, partial := cache.iamPolicyDocsMap["partial-result"]
				unchanged := cache.updatedAt.Equal(updated)
				store.runlock()
				if partial || !unchanged {
					t.Fatal("failed/canceled reload published a partial policy map")
				}
				store.IAMStorageAPI = original
				// Cancellation must release both locks so the next operation works.
				mustIAM(t, iamPolicyReloadCall(context.Background(), store, docs))
				if _, err := store.GetPolicy("readwrite"); err != nil {
					t.Fatal("reload lost default policies")
				}
			})
		}
	}
}

type iamPolicyRelockObserver struct {
	IAMStorageAPI
	calls       atomic.Int32
	reacquiring chan struct{}
}

func (s *iamPolicyRelockObserver) lock() *iamCache {
	if s.calls.Add(1) == 2 {
		close(s.reacquiring)
	}
	return s.IAMStorageAPI.lock()
}

func TestIAMPolicyReloadCallerBudgetPreserved(t *testing.T) {
	for _, docs := range []bool{false, true} {
		t.Run(fmt.Sprintf("docs=%t", docs), func(t *testing.T) {
			_, sys, _ := prepareIAMRevisionFixture(t)
			original := sys.store.IAMStorageAPI
			prior := defaultContextTimeout
			defaultContextTimeout = 50 * time.Millisecond
			t.Cleanup(func() { defaultContextTimeout = prior })
			sys.store.IAMStorageAPI = &iamPolicyReloadStore{IAMStorageAPI: original, policies: func(ctx context.Context, m map[string]PolicyDoc) error {
				select {
				case <-time.After(120 * time.Millisecond):
					return original.loadPolicyDocs(ctx, m)
				case <-ctx.Done():
					return ctx.Err()
				}
			}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := iamPolicyReloadCall(ctx, sys.store, docs)
			if err != nil {
				t.Fatalf("reload cut off a still-valid caller budget: err=%v callerErr=%v", err, ctx.Err())
			}
		})
	}
}

func TestIAMPolicyReloadCancelWhileReacquiringCache(t *testing.T) {
	for _, docs := range []bool{false, true} {
		t.Run(fmt.Sprintf("docs=%t", docs), func(t *testing.T) {
			_, sys, _ := prepareIAMRevisionFixture(t)
			store := sys.store
			original := store.IAMStorageAPI
			observer := &iamPolicyRelockObserver{IAMStorageAPI: original, reacquiring: make(chan struct{})}
			entered, release := make(chan struct{}), make(chan struct{})
			store.IAMStorageAPI = &iamPolicyReloadStore{IAMStorageAPI: observer, policies: func(ctx context.Context, m map[string]PolicyDoc) error {
				m["partial-reload"] = PolicyDoc{}
				close(entered)
				<-release
				return nil
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- iamPolicyReloadCall(ctx, store, docs) }()
			awaitIAMPolicyReload(t, entered)
			cache := store.rlock()
			before := cache.updatedAt
			count := len(cache.iamPolicyDocsMap)
			close(release)
			awaitIAMPolicyReload(t, observer.reacquiring)
			// This reader forces the reload to wait before its commit step.
			// The request is canceled after I/O completed, before publishing.
			cancel()
			store.runlock()
			err := <-done
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel before publish lost: %v", err)
			}
			cache = store.rlock()
			_, partial := cache.iamPolicyDocsMap["partial-reload"]
			unchanged := cache.updatedAt.Equal(before) && len(cache.iamPolicyDocsMap) == count
			store.runlock()
			if partial || !unchanged {
				t.Fatal("canceled complete load still published")
			}
		})
	}
}
