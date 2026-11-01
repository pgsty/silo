// Copyright (c) 2026 PGSTY
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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/grid"
	"github.com/pgsty/silo-pkg/v3/policy"
)

func newIAMPolicyResetSibling(ctx context.Context, t *testing.T, source *IAMSys, obj ObjectLayer) *IAMSys {
	t.Helper()
	store := &IAMStoreSys{IAMStorageAPI: newIAMObjectStore(obj, MinIOUsersSysType)}
	if original, ok := source.store.IAMStorageAPI.(*IAMEtcdStore); ok {
		store.IAMStorageAPI = newIAMEtcdStore(original.client, MinIOUsersSysType)
	}
	mustIAM(t, store.LoadIAMCache(ctx, true))
	return &IAMSys{store: store, usersSysType: MinIOUsersSysType}
}

func assertIAMPolicyResetInfo(t *testing.T, sys *IAMSys, name string, want *madmin.PolicyInfo) {
	t.Helper()
	got, err := sys.InfoPolicy(name)
	mustIAM(t, err)
	var gotPolicy, wantPolicy policy.Policy
	mustIAM(t, json.Unmarshal(got.Policy, &gotPolicy))
	mustIAM(t, json.Unmarshal(want.Policy, &wantPolicy))
	// Actions and resources are sets, whose JSON array order is not stable.
	// Compare their exact contents while retaining all native metadata checks.
	gotMetadata, wantMetadata := *got, *want
	gotMetadata.Policy, wantMetadata.Policy = nil, nil
	if !gotPolicy.Equals(wantPolicy) || !reflect.DeepEqual(gotMetadata, wantMetadata) {
		t.Fatalf("policy definition or native metadata changed: got %+v, want %+v", got, want)
	}
}

// The first InfoPolicy call after Reset must work without any inventory read,
// refresh, or retry. The durable tombstone belongs to the removed override;
// it must still reject stale overrides without suppressing the native policy.
func TestIAMBuiltinPolicyResetRestoresNativePolicy(t *testing.T) {
	for _, backend := range []string{"object", "etcd"} {
		t.Run(backend, func(t *testing.T) {
			ctx, sys, obj := prepareIAMRevisionFixture(t, backend)
			for _, builtin := range policy.DefaultPolicies {
				t.Run(builtin.Name, func(t *testing.T) {
					name := builtin.Name
					native, err := sys.InfoPolicy(name)
					mustIAM(t, err)
					override := builtin.Definition
					override.ID = "reset-override"
					written, err := sys.SetPolicy(ctx, name, override)
					mustIAM(t, err)
					mustIAM(t, sys.DeletePolicy(ctx, name, true))
					assertIAMPolicyResetInfo(t, sys, name, native)

					path := getPolicyDocPath(name)
					deleted, err := loadIAMRevision(ctx, sys.store, path)
					mustIAM(t, err)
					if !deleted.Deleted || !deleted.timestamp().After(written) {
						t.Fatalf("Reset lost the override deletion revision: %+v", deleted)
					}
					for _, at := range []time.Time{written, deleted.timestamp()} {
						_, err = sys.SetPolicy(withIAMReplicationTime(ctx, at), name, override)
						if !errors.Is(err, errIAMStaleUpdate) {
							t.Fatalf("Reset accepted a stale override at %s: %v", at, err)
						}
						assertIAMPolicyResetInfo(t, sys, name, native)
					}
					mustIAM(t, sys.store.LoadIAMCache(ctx, false))
					assertIAMPolicyResetInfo(t, sys, name, native)
					fresh := newIAMPolicyResetSibling(ctx, t, sys, obj)
					assertIAMPolicyResetInfo(t, fresh, name, native)
					for _, docs := range []bool{false, true} {
						mustIAM(t, iamPolicyReloadCall(ctx, fresh.store, docs))
						assertIAMPolicyResetInfo(t, fresh, name, native)
					}
					after, err := loadIAMRevision(ctx, fresh.store, path)
					mustIAM(t, err)
					if !reflect.DeepEqual(after, deleted) || !fresh.store.revisionIndex().get(path).Deleted {
						t.Fatal("default restoration changed the durable deletion or revision index")
					}
					// A deliberate new edit remains possible after Reset.
					_, err = sys.SetPolicy(ctx, name, override)
					mustIAM(t, err)
					current, err := sys.store.GetPolicyDoc(name)
					mustIAM(t, err)
					if current.Policy.ID != override.ID || current.UpdateDate.IsZero() {
						t.Fatal("Reset prevented a subsequent explicit override")
					}
					mustIAM(t, sys.DeletePolicy(ctx, name, true))
				})
			}
		})
	}
}

// Peer and watch notifications carry a name, not a version. Reload committed
// storage so delayed deletion events cannot erase a recreated policy. Built-in
// defaults retain mappings; a genuinely deleted custom policy does not.
func TestIAMPolicyResetNotificationLoadsCommittedState(t *testing.T) {
	for _, backend := range []string{"object", "etcd"} {
		for _, delivery := range []string{"peer", "watch"} {
			for _, recreate := range []bool{false, true} {
				for _, name := range []string{"writeonly", "reset-custom"} {
					t.Run(fmt.Sprintf("%s/%s/recreate=%t/%s", backend, delivery, recreate, name), func(t *testing.T) {
						ctx, source, obj := prepareIAMRevisionFixture(t, backend)
						globalObjLayerMutex.Lock()
						globalObjectAPI = obj
						globalObjLayerMutex.Unlock()
						builtin := name == "writeonly"
						var want *madmin.PolicyInfo
						if builtin {
							var err error
							want, err = source.InfoPolicy(name)
							mustIAM(t, err)
						}
						p, err := source.store.GetPolicy("readwrite")
						mustIAM(t, err)
						p.ID = "reset-original-override"
						_, err = source.SetPolicy(ctx, name, p)
						mustIAM(t, err)
						_, err = source.CreateUser(ctx, "reset-user", madmin.AddOrUpdateUserReq{SecretKey: "synthetic-reset-password", Status: madmin.AccountEnabled})
						mustIAM(t, err)
						_, err = source.AddUsersToGroup(ctx, "reset-group", []string{"reset-user"})
						mustIAM(t, err)
						for _, group := range []bool{false, true} {
							entity := "reset-user"
							if group {
								entity = "reset-group"
							}
							_, err = source.PolicyDBSet(ctx, entity, "readonly,"+name, regUser, group)
							mustIAM(t, err)
						}
						if err := source.DeletePolicy(ctx, name, true); !errors.Is(err, errPolicyInUse) {
							t.Fatalf("Reset bypassed policy-in-use protection: %v", err)
						}
						sibling := newIAMPolicyResetSibling(ctx, t, source, obj)
						mappings := make(map[bool]MappedPolicy)
						mappings[false], _ = sibling.store.GetMappedPolicy("reset-user", false)
						mappings[true], _ = sibling.store.GetMappedPolicy("reset-group", true)
						// A remote site may delete before this node has received the
						// corresponding mapping changes. Local deletion stays guarded.
						mustIAM(t, source.DeletePolicy(withIAMReplicationTime(ctx, UTCNow()), name, true))
						if recreate {
							p.ID = "reset-recreated-override"
							_, err = source.SetPolicy(ctx, name, p)
							mustIAM(t, err)
							want, err = source.InfoPolicy(name)
							mustIAM(t, err)
						}
						before, err := loadIAMRevision(ctx, source.store, getPolicyDocPath(name))
						mustIAM(t, err)
						globalIAMSys = sibling
						defer func() { globalIAMSys = source }()
						for range 2 {
							if delivery == "peer" {
								_, remoteErr := (&peerRESTServer{}).DeletePolicyHandler(grid.NewMSSWith(map[string]string{peerRESTPolicy: name}))
								if remoteErr != nil {
									t.Fatal(remoteErr)
								}
							} else {
								mustIAM(t, sibling.loadWatchedEvent(ctx, iamWatchEvent{keyPath: getPolicyDocPath(name)}))
							}
							if builtin || recreate {
								assertIAMPolicyResetInfo(t, sibling, name, want)
							} else if _, err := sibling.InfoPolicy(name); !errors.Is(err, errNoSuchPolicy) {
								t.Fatalf("deleted custom policy returned: %v", err)
							}
							for group, original := range mappings {
								entity := "reset-user"
								if group {
									entity = "reset-group"
								}
								got, _ := sibling.store.GetMappedPolicy(entity, group)
								if builtin || recreate {
									if !reflect.DeepEqual(got, original) {
										t.Fatalf("notification changed surviving mappings: %+v", got)
									}
								} else if got.Policies != "readonly" {
									t.Fatalf("custom deletion did not retain only the unrelated mapping: %+v", got)
								}
							}
						}
						after, err := loadIAMRevision(ctx, source.store, getPolicyDocPath(name))
						mustIAM(t, err)
						if !reflect.DeepEqual(after, before) {
							t.Fatal("notification changed durable policy storage")
						}
					})
				}
			}
		}
	}
}

func TestIAMPolicyResetNotificationSurvivesOlderRefresh(t *testing.T) {
	ctx, source, obj := prepareIAMRevisionFixture(t)
	p, err := source.store.GetPolicy("readwrite")
	mustIAM(t, err)
	p.ID = "old-override"
	_, err = source.SetPolicy(ctx, "writeonly", p)
	mustIAM(t, err)
	sibling := newIAMPolicyResetSibling(ctx, t, source, obj)
	original := sibling.store.IAMStorageAPI
	loading, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	var wg sync.WaitGroup
	t.Cleanup(func() { unblock(); wg.Wait() })
	sibling.store.IAMStorageAPI = &iamPolicyReloadStore{
		IAMStorageAPI: original,
		policies:      original.loadPolicyDocs,
		users: func(ctx context.Context, typ IAMUserType, m map[string]UserIdentity) error {
			if typ == regUser {
				close(loading)
				<-release
			}
			return original.loadUsers(ctx, typ, m)
		},
	}
	done := make(chan error, 1)
	wg.Go(func() { done <- sibling.store.LoadIAMCache(ctx, false) })
	awaitIAMPolicyReload(t, loading)
	mustIAM(t, source.DeletePolicy(ctx, "writeonly", true))
	p.ID = "newer-override"
	_, err = source.SetPolicy(ctx, "writeonly", p)
	mustIAM(t, err)
	want, err := source.InfoPolicy("writeonly")
	mustIAM(t, err)
	// The delayed deletion notification must observe the newer edit, and
	// prevent a refresh that captured the old override from replacing it.
	mustIAM(t, sibling.DeletePolicy(ctx, "writeonly", false))
	unblock()
	mustIAM(t, <-done)
	assertIAMPolicyResetInfo(t, sibling, "writeonly", want)
}

type iamPolicyResetFailureStore struct {
	IAMStorageAPI
	err error
}

func (s *iamPolicyResetFailureStore) saveIAMConfig(context.Context, any, string, ...options) error {
	return s.err
}

func (s *iamPolicyResetFailureStore) loadPolicyDoc(context.Context, string, map[string]PolicyDoc) error {
	return s.err
}

func TestIAMBuiltinPolicyResetStorageFailurePreservesOverride(t *testing.T) {
	for _, backend := range []string{"object", "etcd"} {
		t.Run(backend, func(t *testing.T) {
			ctx, sys, _ := prepareIAMRevisionFixture(t, backend)
			p, err := sys.store.GetPolicy("readonly")
			mustIAM(t, err)
			_, err = sys.SetPolicy(ctx, "writeonly", p)
			mustIAM(t, err)
			before, err := sys.InfoPolicy("writeonly")
			mustIAM(t, err)
			stored, err := loadIAMRevision(ctx, sys.store, getPolicyDocPath("writeonly"))
			mustIAM(t, err)
			original := sys.store.IAMStorageAPI
			injected := errors.New("injected policy storage failure")
			sys.store.IAMStorageAPI = &iamPolicyResetFailureStore{IAMStorageAPI: original, err: injected}
			for _, notify := range []bool{true, false} {
				if err := sys.DeletePolicy(ctx, "writeonly", notify); !errors.Is(err, injected) {
					t.Fatalf("storage failure became a successful Reset, notify=%t: %v", notify, err)
				}
				assertIAMPolicyResetInfo(t, sys, "writeonly", before)
			}
			if err := sys.loadWatchedEvent(ctx, iamWatchEvent{keyPath: getPolicyDocPath("writeonly")}); !errors.Is(err, injected) {
				t.Fatalf("watch storage failure became a default policy: %v", err)
			}
			assertIAMPolicyResetInfo(t, sys, "writeonly", before)
			after, err := loadIAMRevision(ctx, original, getPolicyDocPath("writeonly"))
			mustIAM(t, err)
			if !reflect.DeepEqual(after, stored) {
				t.Fatal("failed Reset changed the durable override")
			}
		})
	}
}
