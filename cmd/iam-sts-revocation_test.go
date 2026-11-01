// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/grid"
	xnet "github.com/pgsty/silo-pkg/v3/net"
)

func TestIAMSTSRevocationDurableScope(t *testing.T) {
	for _, backend := range []string{"object", "etcd"} {
		for _, notify := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/notify=%t", backend, notify), func(t *testing.T) {
				ctx, sys, obj := prepareIAMRevisionFixture(t, backend)
				for _, parent := range []string{"sts-parent", "other-parent"} {
					_, err := sys.CreateUser(ctx, parent, madmin.AddOrUpdateUserReq{SecretKey: "synthetic-parent-password", Status: madmin.AccountEnabled})
					mustIAM(t, err)
				}
				sibling := &IAMStoreSys{IAMStorageAPI: newIAMObjectStore(obj, MinIOUsersSysType)}
				if backend == "etcd" {
					sibling.IAMStorageAPI = newIAMEtcdStore(sys.store.IAMStorageAPI.(*IAMEtcdStore).client, MinIOUsersSysType)
				}
				mustIAM(t, sibling.LoadIAMCache(ctx, false))
				secret, err := getTokenSigningKey()
				mustIAM(t, err)
				issue := func(store *IAMStoreSys, parent, typ string) auth.Credentials {
					cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{"exp": UTCNow().Add(time.Hour).Unix(), parentClaim: parent, tokenRevokeTypeClaim: typ}, secret)
					mustIAM(t, err)
					cred.ParentUser = parent
					_, err = store.SetTempUser(ctx, cred.AccessKey, cred, "")
					mustIAM(t, err)
					return cred
				}
				first := issue(sys.store, "sts-parent", "selected")
				uncached := issue(sibling, "sts-parent", "selected")
				otherType := issue(sys.store, "sts-parent", "other-type")
				otherUser := issue(sys.store, "other-parent", "selected")
				if _, ok := sys.store.GetUser(uncached.AccessKey); ok {
					t.Fatal("fixture cached the remote token")
				}
				for _, c := range []auth.Credentials{first, otherType, otherUser} {
					mustIAM(t, sibling.UserNotificationHandler(ctx, c.AccessKey, stsUser))
				}
				prior := globalNotificationSys
				globalNotificationSys = &NotificationSys{}
				t.Cleanup(func() { globalNotificationSys = prior })
				if notify {
					tg, err := grid.SetupTestGrid(2)
					mustIAM(t, err)
					t.Cleanup(tg.Cleanup)
					mustIAM(t, loadUserRPC.Register(tg.Managers[1], func(r *grid.MSS) (grid.NoPayload, *grid.RemoteErr) {
						if err := sibling.UserNotificationHandler(ctx, r.Get(peerRESTUser), stsUser); err != nil {
							return grid.NoPayload{}, grid.NewRemoteErr(err)
						}
						return grid.NoPayload{}, nil
					}))
					host, err := xnet.ParseHost(strings.TrimPrefix(tg.Hosts[1], "http://"))
					mustIAM(t, err)
					globalNotificationSys = &NotificationSys{peerClients: []*peerRESTClient{{host: host, gridConn: func() *grid.Connection { return tg.Managers[0].Connection(tg.Hosts[1]) }}}}
				}
				mustIAM(t, sys.RevokeTokens(ctx, "sts-parent", "selected"))
				for _, c := range []auth.Credentials{first, uncached} {
					r, err := loadIAMRevision(ctx, sys.store, getUserIdentityPath(c.AccessKey, stsUser))
					mustIAM(t, err)
					if !r.Deleted {
						t.Errorf("durable token was omitted: %s", c.AccessKey)
					}
					if _, ok := iamDeletionItem(getUserIdentityPath(c.AccessKey, stsUser), r); !ok {
						t.Error("STS revocation cannot be replayed")
					}
					if notify && backend == "object" {
						if _, ok := sibling.GetUser(c.AccessKey); ok {
							t.Error("notified sibling accepted revoked token")
						}
					}
				}
				fresh := issue(sibling, "sts-parent", "selected")
				// A missed notification must converge through the normal cache refresh.
				mustIAM(t, sibling.LoadIAMCache(ctx, false))
				for _, c := range []auth.Credentials{first, uncached} {
					if _, ok := sibling.GetUser(c.AccessKey); ok {
						t.Error("refresh retained revoked token")
					}
				}
				for _, c := range []auth.Credentials{otherType, otherUser, fresh} {
					mustIAM(t, sibling.UserNotificationHandler(ctx, c.AccessKey, stsUser))
					if _, ok := sibling.GetUser(c.AccessKey); !ok {
						t.Error("revocation removed an out-of-scope or new token")
					}
				}
				if _, ok := sibling.GetUser("sts-parent"); !ok {
					t.Error("revocation removed parent")
				}
			})
		}
	}
}

// Deletion is keyed by the immutable STS access key, so delayed delivery cannot
// affect a newly issued token and a delayed creation cannot undo revocation.
func TestIAMSTSRevocationReorderedReplay(t *testing.T) {
	for _, backend := range []string{"object", "etcd"} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/missing=%t", backend, missing), func(t *testing.T) {
				ctx, sys, _ := prepareIAMRevisionFixture(t, backend)
				const parent = "sts-replay-parent"
				_, err := sys.CreateUser(ctx, parent, madmin.AddOrUpdateUserReq{SecretKey: "synthetic-parent-password", Status: madmin.AccountEnabled})
				mustIAM(t, err)
				secret, err := getTokenSigningKey()
				mustIAM(t, err)
				cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{"exp": UTCNow().Add(time.Hour).Unix(), parentClaim: parent}, secret)
				mustIAM(t, err)
				cred.ParentUser = parent
				created := UTCNow().Add(-time.Minute)
				peer := madmin.SRSTSCredential{AccessKey: cred.AccessKey, SecretKey: cred.SecretKey, SessionToken: cred.SessionToken, ParentUser: parent}
				if !missing {
					mustIAM(t, globalSiteReplicationSys.PeerSTSAccHandler(ctx, &peer, created))
				}
				fresh, err := auth.GetNewCredentialsWithMetadata(map[string]any{"exp": UTCNow().Add(time.Hour).Unix(), parentClaim: parent}, secret)
				mustIAM(t, err)
				fresh.ParentUser = parent
				_, err = sys.SetTempUser(ctx, fresh.AccessKey, fresh, "")
				mustIAM(t, err)
				// Older than the live record on this peer: deletion must still win.
				item := iamReplicationItem{SRIAMItem: madmin.SRIAMItem{Type: iamSTSDeleteType, Name: cred.AccessKey, UpdatedAt: created.Add(-time.Second)}, STSExpiresAt: cred.Expiration.Add(globalMaxSkewTime)}
				for range 2 {
					mustIAM(t, applyIAMReplicationItem(ctx, item))
					mustIAM(t, globalSiteReplicationSys.PeerSTSAccHandler(ctx, &peer, UTCNow()))
					mustIAM(t, sys.store.LoadIAMCache(ctx, false))
					if _, ok := sys.GetUser(ctx, cred.AccessKey); ok {
						t.Fatal("delayed STS creation undid revocation")
					}
					if _, ok := sys.GetUser(ctx, fresh.AccessKey); !ok {
						t.Fatal("delayed revocation removed new token")
					}
				}
				r, err := loadIAMRevision(ctx, sys.store, getUserIdentityPath(cred.AccessKey, stsUser))
				mustIAM(t, err)
				if !r.Deleted || !r.ExpiresAt.Equal(item.STSExpiresAt) || r.Credentials.SessionToken != "" || r.Credentials.SecretKey != "" {
					t.Fatal("revocation lost expiry or retained secret material")
				}
				for _, status := range []madmin.AccountStatus{madmin.AccountDisabled, madmin.AccountEnabled} {
					_, err = sys.SetUserStatus(ctx, parent, status)
					mustIAM(t, err)
				}
				if _, ok := sys.GetUser(ctx, cred.AccessKey); ok {
					t.Fatal("parent re-enable revived revoked token")
				}
			})
		}
	}
}

// Pause the durable scan while another node persists a new credential. The
// revocation's original cutoff must survive the scan and leave that token live.
type iamSTSScanGateStore struct {
	IAMStorageAPI
	entered chan struct{}
	resume  chan struct{}
}

func (s *iamSTSScanGateStore) loadUsers(ctx context.Context, typ IAMUserType, users map[string]UserIdentity) error {
	close(s.entered)
	select {
	case <-s.resume:
	case <-ctx.Done():
		return ctx.Err()
	}
	return s.IAMStorageAPI.loadUsers(ctx, typ, users)
}

func TestIAMSTSRevocationConcurrentIssuance(t *testing.T) {
	ctx, sys, obj := prepareIAMRevisionFixture(t)
	_, err := sys.CreateUser(ctx, "sts-race-parent", madmin.AddOrUpdateUserReq{SecretKey: "synthetic-parent-password", Status: madmin.AccountEnabled})
	mustIAM(t, err)
	sibling := &IAMStoreSys{IAMStorageAPI: newIAMObjectStore(obj, MinIOUsersSysType)}
	secret, err := getTokenSigningKey()
	mustIAM(t, err)
	issue := func() auth.Credentials {
		c, err := auth.GetNewCredentialsWithMetadata(map[string]any{"exp": UTCNow().Add(time.Hour).Unix(), parentClaim: "sts-race-parent"}, secret)
		mustIAM(t, err)
		c.ParentUser = "sts-race-parent"
		_, err = sibling.SetTempUser(ctx, c.AccessKey, c, "")
		mustIAM(t, err)
		return c
	}
	old := issue()
	gate := &iamSTSScanGateStore{IAMStorageAPI: sys.store.IAMStorageAPI, entered: make(chan struct{}), resume: make(chan struct{})}
	sys.store.IAMStorageAPI = gate
	done := make(chan error, 1)
	go func() { done <- sys.RevokeTokens(ctx, "sts-race-parent", "") }()
	<-gate.entered
	fresh := issue()
	close(gate.resume)
	mustIAM(t, <-done)
	mustIAM(t, sibling.UserNotificationHandler(ctx, old.AccessKey, stsUser))
	if _, ok := sibling.GetUser(old.AccessKey); ok {
		t.Fatal("old uncached token survived")
	}
	mustIAM(t, sibling.UserNotificationHandler(ctx, fresh.AccessKey, stsUser))
	if _, ok := sibling.GetUser(fresh.AccessKey); !ok {
		t.Fatal("new token was included in earlier revocation")
	}
}

type iamSTSFailureStore struct {
	IAMStorageAPI
	failedPath string
}

func (s *iamSTSFailureStore) saveIAMConfig(ctx context.Context, item any, path string, opts ...options) error {
	if path == s.failedPath {
		return errIAMInjectedWrite
	}
	return s.IAMStorageAPI.saveIAMConfig(ctx, item, path, opts...)
}

func TestIAMSTSRevocationPartialFailure(t *testing.T) {
	ctx, sys, _ := prepareIAMRevisionFixture(t)
	_, err := sys.CreateUser(ctx, "sts-partial-parent", madmin.AddOrUpdateUserReq{SecretKey: "synthetic-parent-password", Status: madmin.AccountEnabled})
	mustIAM(t, err)
	secret, err := getTokenSigningKey()
	mustIAM(t, err)
	var keys []string
	for range 2 {
		c, err := auth.GetNewCredentialsWithMetadata(map[string]any{"exp": UTCNow().Add(time.Hour).Unix(), parentClaim: "sts-partial-parent"}, secret)
		mustIAM(t, err)
		c.ParentUser = "sts-partial-parent"
		_, err = sys.SetTempUser(ctx, c.AccessKey, c, "")
		mustIAM(t, err)
		keys = append(keys, c.AccessKey)
	}
	sys.store.IAMStorageAPI = &iamSTSFailureStore{IAMStorageAPI: sys.store.IAMStorageAPI, failedPath: getUserIdentityPath(keys[0], stsUser)}
	revoked, err := sys.store.RevokeTokens(ctx, "sts-partial-parent", "")
	if !errors.Is(err, errIAMInjectedWrite) || len(revoked) != 1 || revoked[0] != keys[1] {
		t.Fatalf("committed keys or failure lost: %v %v", revoked, err)
	}
	if _, ok := sys.store.GetUser(keys[1]); ok {
		t.Fatal("committed revocation retained cache entry")
	}
	if _, ok := sys.store.GetUser(keys[0]); !ok {
		t.Fatal("failed revocation claimed cache success")
	}
}
