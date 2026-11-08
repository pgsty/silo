// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// An administrator edits an identity through a server whose cache missed
// a rotation or a deletion made through another. The edit applies to what
// is stored and must not write the stale copy back.

func TestIAMStaleServiceAccountEdit(t *testing.T) {
	t.Run("rotated", func(t *testing.T) {
		f := newGroupRefreshFixture(t)
		snapshot := f.service(t, "edit-rotated")
		other := f.sibling(t)
		_, err := f.sys.UpdateServiceAccount(f.ctx, snapshot.AccessKey, updateServiceAccountOpts{secretKey: "edit-rotated-secret"})
		mustIAM(t, err)
		if cached, _ := other.GetUser(snapshot.AccessKey); cached.Credentials.SecretKey != snapshot.SecretKey {
			t.Fatal("control: the stale server must not have heard of the rotation")
		}
		_, err = other.UpdateServiceAccount(f.ctx, snapshot.AccessKey, updateServiceAccountOpts{description: "edited on a stale server"})
		mustIAM(t, err)
		for where, get := range map[string]func() (UserIdentity, bool){
			"storage":      func() (UserIdentity, bool) { return f.stored(t, snapshot.AccessKey) },
			"stale server": func() (UserIdentity, bool) { return other.GetUser(snapshot.AccessKey) },
		} {
			u, ok := get()
			if !ok || u.Credentials.SecretKey != "edit-rotated-secret" || u.Credentials.Description != "edited on a stale server" {
				t.Errorf("%s: present=%v rotated=%v description=%q: the edit must apply to the rotated credential",
					where, ok, u.Credentials.SecretKey == "edit-rotated-secret", u.Credentials.Description)
			}
		}
	})
	t.Run("deleted", func(t *testing.T) {
		f := newGroupRefreshFixture(t)
		snapshot := f.service(t, "edit-deleted")
		other := f.sibling(t)
		mustIAM(t, f.sys.DeleteServiceAccount(f.ctx, snapshot.AccessKey, false))
		_, err := other.UpdateServiceAccount(f.ctx, snapshot.AccessKey, updateServiceAccountOpts{description: "edited on a stale server"})
		if !errors.Is(err, errNoSuchServiceAccount) {
			t.Errorf("an edit of a deleted account must fail with no such service account, got %v", err)
		}
		if _, ok := f.stored(t, snapshot.AccessKey); ok {
			t.Error("an edit on a stale server brought a deleted account back")
		}
		if _, ok := other.GetUser(snapshot.AccessKey); ok {
			t.Error("the stale server still caches the deleted account")
		}
	})
}

// A session policy edit stores the claims of the token it signs.
func TestIAMServiceAccountEditStoresNewClaims(t *testing.T) {
	f := newGroupRefreshFixture(t)
	snapshot := f.service(t, "edit-claims")
	sp, err := policy.ParseConfig(strings.NewReader(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::edit/*"]}]}`))
	mustIAM(t, err)
	_, err = f.sys.UpdateServiceAccount(f.ctx, snapshot.AccessKey, updateServiceAccountOpts{sessionPolicy: sp})
	mustIAM(t, err)
	var raw UserIdentity
	mustIAM(t, f.sys.store.loadIAMConfig(f.ctx, &raw, getUserIdentityPath(snapshot.AccessKey, svcUser)))
	claims, err := getClaimsFromTokenWithSecret(raw.Credentials.SessionToken, raw.Credentials.SecretKey)
	mustIAM(t, err)
	if raw.Credentials.Claims[iamPolicyClaimNameSA()] != embeddedPolicyType || claims.MapClaims[iamPolicyClaimNameSA()] != embeddedPolicyType {
		t.Errorf("stored claims %v, token claims %v: both must name the embedded policy", raw.Credentials.Claims[iamPolicyClaimNameSA()], claims.MapClaims[iamPolicyClaimNameSA()])
	}
}

func TestIAMStaleUserEdit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *groupRefreshFixture, user auth.Credentials)
		edit   func(s *IAMStoreSys, f *groupRefreshFixture, user auth.Credentials) error
		check  func(t *testing.T, u UserIdentity, ok bool, err error)
	}{
		{"status-after-delete", func(t *testing.T, f *groupRefreshFixture, user auth.Credentials) {
			mustIAM(t, f.sys.DeleteUser(f.ctx, user.AccessKey, false))
		}, func(s *IAMStoreSys, f *groupRefreshFixture, user auth.Credentials) error {
			_, err := s.SetUserStatus(f.ctx, user.AccessKey, madmin.AccountEnabled)
			return err
		}, func(t *testing.T, u UserIdentity, ok bool, err error) {
			if !errors.Is(err, errNoSuchUser) || ok {
				t.Errorf("err=%v present=%v: a status change on a stale server must not bring a deleted user back", err, ok)
			}
		}},
		{"status-after-rotation", func(t *testing.T, f *groupRefreshFixture, user auth.Credentials) {
			mustIAM(t, f.sys.SetUserSecretKey(f.ctx, user.AccessKey, "edit-user-rotated"))
		}, func(s *IAMStoreSys, f *groupRefreshFixture, user auth.Credentials) error {
			_, err := s.SetUserStatus(f.ctx, user.AccessKey, madmin.AccountDisabled)
			return err
		}, func(t *testing.T, u UserIdentity, ok bool, err error) {
			if err != nil || !ok || u.Credentials.SecretKey != "edit-user-rotated" || u.Credentials.Status != auth.AccountOff {
				t.Errorf("err=%v present=%v rotated=%v status=%q: the status change must apply to the rotated user",
					err, ok, u.Credentials.SecretKey == "edit-user-rotated", u.Credentials.Status)
			}
		}},
		{"secret-after-delete", func(t *testing.T, f *groupRefreshFixture, user auth.Credentials) {
			mustIAM(t, f.sys.DeleteUser(f.ctx, user.AccessKey, false))
		}, func(s *IAMStoreSys, f *groupRefreshFixture, user auth.Credentials) error {
			return s.UpdateUserSecretKey(f.ctx, user.AccessKey, "edit-user-new-secret")
		}, func(t *testing.T, u UserIdentity, ok bool, err error) {
			if !errors.Is(err, errNoSuchUser) || ok {
				t.Errorf("err=%v present=%v: a secret change on a stale server must not bring a deleted user back", err, ok)
			}
		}},
		{"secret-after-disable", func(t *testing.T, f *groupRefreshFixture, user auth.Credentials) {
			_, err := f.sys.SetUserStatus(f.ctx, user.AccessKey, madmin.AccountDisabled)
			mustIAM(t, err)
		}, func(s *IAMStoreSys, f *groupRefreshFixture, user auth.Credentials) error {
			return s.UpdateUserSecretKey(f.ctx, user.AccessKey, "edit-user-new-secret")
		}, func(t *testing.T, u UserIdentity, ok bool, err error) {
			if err != nil || !ok || u.Credentials.SecretKey != "edit-user-new-secret" || u.Credentials.Status != auth.AccountOff {
				t.Errorf("err=%v present=%v status=%q: a secret change on a stale server must keep the user disabled", err, ok, u.Credentials.Status)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGroupRefreshFixture(t)
			user := iamAdminUser(f.ctx, t, f.sys, "edit-user", "refresh-parent")
			other := f.sibling(t)
			tc.change(t, f, user)
			if cached, ok := other.GetUser(user.AccessKey); !ok || cached.Credentials.SecretKey != user.SecretKey {
				t.Fatal("control: the stale server must not have heard of the change")
			}
			err := tc.edit(other, f, user)
			u, ok := f.stored(t, user.AccessKey)
			tc.check(t, u, ok, err)
		})
	}
}

// An edit that the caller was authorized for under one parent does not
// apply to an account stored under another parent: the account was deleted
// and created again for it meanwhile.
func TestIAMServiceAccountEditKeepsAuthorizedParent(t *testing.T) {
	f := newGroupRefreshFixture(t)
	snapshot := f.service(t, "edit-parent")
	other := iamAdminUser(f.ctx, t, f.sys, "edit-other-parent", "refresh-parent")
	mustIAM(t, f.sys.DeleteServiceAccount(f.ctx, snapshot.AccessKey, false))
	_, _, err := f.sys.NewServiceAccount(f.ctx, other.AccessKey, nil, newServiceAccountOpts{accessKey: snapshot.AccessKey, secretKey: "edit-other-secret"})
	mustIAM(t, err)
	_, err = f.sys.store.UpdateServiceAccount(f.ctx, snapshot.AccessKey, updateServiceAccountOpts{secretKey: "edit-chosen-secret", parentUser: snapshot.ParentUser})
	if !errors.Is(err, errNoSuchServiceAccount) {
		t.Errorf("an edit authorized for another parent must fail, got %v", err)
	}
	if u, ok := f.stored(t, snapshot.AccessKey); !ok || u.Credentials.SecretKey != "edit-other-secret" {
		t.Errorf("present=%v: the account of the other parent must keep its secret", ok)
	}
	// Without a bound parent (replication), the edit applies.
	_, err = f.sys.store.UpdateServiceAccount(f.ctx, snapshot.AccessKey, updateServiceAccountOpts{description: "replicated"})
	mustIAM(t, err)
}

// A record stored without claims, or with only a deprecated comment, is
// edited as the loaders present it.
func TestIAMServiceAccountEditLegacyRecord(t *testing.T) {
	f := newGroupRefreshFixture(t)
	snapshot := f.service(t, "edit-legacy")
	path := getUserIdentityPath(snapshot.AccessKey, svcUser)
	var raw UserIdentity
	mustIAM(t, f.sys.store.loadIAMConfig(f.ctx, &raw, path))
	raw.Credentials.Claims = nil
	raw.Credentials.Description, raw.Credentials.Comment = "", "legacy comment"
	mustIAM(t, f.sys.store.saveIAMConfig(f.ctx, &raw, path))
	_, err := f.sys.store.UpdateServiceAccount(f.ctx, snapshot.AccessKey, updateServiceAccountOpts{status: string(madmin.AccountDisabled)})
	mustIAM(t, err)
	for where, get := range map[string]func() (UserIdentity, bool){
		"storage": func() (UserIdentity, bool) { return f.stored(t, snapshot.AccessKey) },
		"cache":   func() (UserIdentity, bool) { return f.sys.store.GetUser(snapshot.AccessKey) },
	} {
		u, ok := get()
		if !ok || u.Credentials.Status != auth.AccountOff || u.Credentials.Description != "legacy comment" {
			t.Errorf("%s: present=%v status=%q description=%q", where, ok, u.Credentials.Status, u.Credentials.Description)
		}
	}
}

// A peer's edit from before a deletion this site applied is acknowledged as
// stale; one from after it is not found.
func TestIAMReplicatedEditAfterDeletion(t *testing.T) {
	f := newGroupRefreshFixture(t)
	snapshot := f.service(t, "edit-repl")
	user := iamAdminUser(f.ctx, t, f.sys, "edit-repl-user", "refresh-parent")
	before := UTCNow()
	mustIAM(t, f.sys.DeleteServiceAccount(f.ctx, snapshot.AccessKey, false))
	mustIAM(t, f.sys.DeleteUser(f.ctx, user.AccessKey, false))
	after := UTCNow().Add(time.Second)

	_, err := f.sys.store.UpdateServiceAccount(withIAMReplicationTime(f.ctx, before), snapshot.AccessKey, updateServiceAccountOpts{description: "late"})
	if iamReplicationError(err) != nil {
		t.Errorf("an older service-account edit must be acknowledged, got %v", err)
	}
	_, err = f.sys.store.SetUserStatus(withIAMReplicationTime(f.ctx, before), user.AccessKey, madmin.AccountDisabled)
	if iamReplicationError(err) != nil {
		t.Errorf("an older status edit must be acknowledged, got %v", err)
	}
	if _, err = f.sys.store.UpdateServiceAccount(withIAMReplicationTime(f.ctx, after), snapshot.AccessKey, updateServiceAccountOpts{description: "late"}); !errors.Is(err, errNoSuchServiceAccount) {
		t.Errorf("a newer edit of a deleted account must not be acknowledged as stale, got %v", err)
	}
	if _, ok := f.stored(t, snapshot.AccessKey); ok {
		t.Error("a replicated edit brought a deleted account back")
	}
}

// A status change addressed to a service account is refused as before, and
// the account stays cached.
func TestIAMUserStatusOnServiceAccount(t *testing.T) {
	f := newGroupRefreshFixture(t)
	snapshot := f.service(t, "edit-sa-status")
	_, err := f.sys.store.SetUserStatus(f.ctx, snapshot.AccessKey, madmin.AccountDisabled)
	if !errors.Is(err, errIAMActionNotAllowed) {
		t.Errorf("got %v, want errIAMActionNotAllowed", err)
	}
	if _, ok := f.sys.store.GetUser(snapshot.AccessKey); !ok {
		t.Error("a refused status change dropped the service account from the cache")
	}
	if err := f.sys.store.UpdateUserSecretKey(f.ctx, snapshot.AccessKey, "edit-not-a-user"); !errors.Is(err, errNoSuchUser) {
		t.Errorf("a user secret change of a service account must find no user, got %v", err)
	}
	if u, ok := f.sys.store.GetUser(snapshot.AccessKey); !ok || u.Credentials.SecretKey != snapshot.SecretKey {
		t.Error("a user secret change of a service account touched the account")
	}
}
