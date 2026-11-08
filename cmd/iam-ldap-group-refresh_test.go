// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"slices"
	"testing"

	"github.com/minio/minio/internal/auth"
)

// The LDAP group refresh computes groups from a snapshot of a server's cache
// taken before a slow directory lookup, then writes them. These tests take
// such a snapshot, change the credential the way an administrator would on
// this or another server, and run the write: it must change only the
// groups of what is stored now, and never undo the change.

type groupRefreshFixture struct {
	ctx    context.Context
	sys    *IAMSys
	obj    ObjectLayer
	parent auth.Credentials
}

func newGroupRefreshFixture(t *testing.T) *groupRefreshFixture {
	t.Helper()
	ctx, sys, obj := prepareIAMRevisionFixture(t)
	batchAuthzPolicy(ctx, t, sys, "refresh-parent", batchAuthzFullAccess)
	parent := iamAdminUser(ctx, t, sys, "refresh-parent", "refresh-parent")
	return &groupRefreshFixture{ctx: ctx, sys: sys, obj: obj, parent: parent}
}

// service creates a service account of the fixture's parent and returns
// its stored credential, the snapshot a refresh would take.
func (f *groupRefreshFixture) service(t *testing.T, accessKey string) auth.Credentials {
	t.Helper()
	_, _, err := f.sys.NewServiceAccount(f.ctx, f.parent.AccessKey, nil, newServiceAccountOpts{accessKey: accessKey, secretKey: "refresh-original-secret"})
	mustIAM(t, err)
	u, ok := f.sys.store.GetUser(accessKey)
	if !ok {
		t.Fatal("service account missing")
	}
	return u.Credentials
}

// sibling is another server: the same storage, its own cache.
func (f *groupRefreshFixture) sibling(t *testing.T) *IAMStoreSys {
	t.Helper()
	s := &IAMStoreSys{IAMStorageAPI: newIAMObjectStore(f.obj, f.sys.usersSysType)}
	mustIAM(t, s.LoadIAMCache(f.ctx, false))
	return s
}

// stored is the record as a server that starts now loads it.
func (f *groupRefreshFixture) stored(t *testing.T, accessKey string) (UserIdentity, bool) {
	t.Helper()
	return f.sibling(t).GetUser(accessKey)
}

func TestIAMGroupRefreshKeepsRotation(t *testing.T) {
	f := newGroupRefreshFixture(t)
	snapshot := f.service(t, "refresh-rotate")
	_, err := f.sys.UpdateServiceAccount(f.ctx, snapshot.AccessKey, updateServiceAccountOpts{secretKey: "refresh-rotated-secret", description: "rotated"})
	mustIAM(t, err)

	wrote, err := f.sys.store.RefreshUserGroups(f.ctx, snapshot, []string{"g1"})
	mustIAM(t, err)
	if !wrote {
		t.Fatal("a refresh of a live credential must write its new groups")
	}
	check := func(where string, u UserIdentity, ok bool) {
		t.Helper()
		switch {
		case !ok:
			t.Fatalf("%s: credential missing", where)
		case u.Credentials.SecretKey != "refresh-rotated-secret":
			t.Errorf("%s: the refresh undid the rotation", where)
		case u.Credentials.Description != "rotated":
			t.Errorf("%s: the refresh undid an edit", where)
		case !slices.Equal(u.Credentials.Groups, []string{"g1"}):
			t.Errorf("%s: groups %v, want [g1]", where, u.Credentials.Groups)
		}
	}
	u, ok := f.sys.store.GetUser(snapshot.AccessKey)
	check("cache", u, ok)
	u, ok = f.stored(t, snapshot.AccessKey)
	check("storage", u, ok)
	if _, valid, _ := f.sys.CheckKey(f.ctx, snapshot.AccessKey); !valid {
		t.Error("the rotated credential must stay valid")
	}
}

func TestIAMGroupRefreshKeepsDeletion(t *testing.T) {
	f := newGroupRefreshFixture(t)
	snapshot := f.service(t, "refresh-delete")
	mustIAM(t, f.sys.DeleteServiceAccount(f.ctx, snapshot.AccessKey, false))

	wrote, err := f.sys.store.RefreshUserGroups(f.ctx, snapshot, []string{"g1"})
	mustIAM(t, err)
	if wrote {
		t.Error("a refresh wrote a deleted credential")
	}
	if _, ok := f.sys.store.GetUser(snapshot.AccessKey); ok {
		t.Error("a refresh brought a deleted credential back into the cache")
	}
	if _, ok := f.stored(t, snapshot.AccessKey); ok {
		t.Error("a refresh brought a deleted credential back in storage")
	}
}

// Another server changed the credential and this server's cache has not
// heard of it: its snapshot and its cache are both stale.
func TestIAMGroupRefreshStaleSiblingCache(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *groupRefreshFixture, accessKey string)
		check  func(t *testing.T, u UserIdentity, ok bool)
	}{
		{"rotated", func(t *testing.T, f *groupRefreshFixture, accessKey string) {
			_, err := f.sys.UpdateServiceAccount(f.ctx, accessKey, updateServiceAccountOpts{secretKey: "refresh-rotated-secret"})
			mustIAM(t, err)
		}, func(t *testing.T, u UserIdentity, ok bool) {
			if !ok || u.Credentials.SecretKey != "refresh-rotated-secret" {
				t.Errorf("a stale server undid the rotation of another (present=%v)", ok)
			}
		}},
		{"deleted", func(t *testing.T, f *groupRefreshFixture, accessKey string) {
			mustIAM(t, f.sys.DeleteServiceAccount(f.ctx, accessKey, false))
		}, func(t *testing.T, u UserIdentity, ok bool) {
			if ok {
				t.Error("a stale server brought back a credential another deleted")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGroupRefreshFixture(t)
			snapshot := f.service(t, "refresh-sib-"+tc.name)
			other := f.sibling(t)
			stale, ok := other.GetUser(snapshot.AccessKey)
			if !ok {
				t.Fatal("sibling fixture did not load the credential")
			}
			tc.change(t, f, snapshot.AccessKey)
			if cached, _ := other.GetUser(snapshot.AccessKey); cached.Credentials.SecretKey != stale.Credentials.SecretKey {
				t.Fatal("control: the sibling cache must not have heard of the change")
			}
			_, err := other.RefreshUserGroups(f.ctx, stale.Credentials, []string{"g1"})
			mustIAM(t, err)
			u, ok := f.stored(t, snapshot.AccessKey)
			tc.check(t, u, ok)
			// The refreshing server's own cache follows storage too: it holds
			// the stored record, or nothing, so a lookup loads it.
			u, ok = other.GetUser(snapshot.AccessKey)
			tc.check(t, u, ok)
		})
	}
}

// A stored record may lack its access key; the loaders take it from the
// path, and so does the refresh. Such a credential still gets its groups,
// including a removal.
func TestIAMGroupRefreshRecordWithoutAccessKey(t *testing.T) {
	f := newGroupRefreshFixture(t)
	snapshot := f.service(t, "refresh-nokey")
	path := getUserIdentityPath(snapshot.AccessKey, svcUser)
	var u UserIdentity
	mustIAM(t, f.sys.store.loadIAMConfig(f.ctx, &u, path))
	u.Credentials.AccessKey = ""
	u.Credentials.Groups = []string{"admins"}
	mustIAM(t, f.sys.store.saveIAMConfig(f.ctx, &u, path))
	loaded, ok := f.stored(t, snapshot.AccessKey)
	if !ok || loaded.Credentials.AccessKey != snapshot.AccessKey {
		t.Fatal("control: the loaders must take the access key from the path")
	}
	wrote, err := f.sys.store.RefreshUserGroups(f.ctx, loaded.Credentials, []string{"users"})
	mustIAM(t, err)
	after, ok := f.stored(t, snapshot.AccessKey)
	if !wrote || !ok || !slices.Equal(after.Credentials.Groups, []string{"users"}) {
		t.Errorf("wrote=%v present=%v groups=%v: a record without its access key must still lose a group", wrote, ok, after.Credentials.Groups)
	}
}

// The access key was deleted and created again. Under the same parent the
// groups the lookup computed are that parent's, and the new record gets
// them with everything else it has; under another parent it is left alone.
func TestIAMGroupRefreshRecreated(t *testing.T) {
	f := newGroupRefreshFixture(t)
	snapshot := f.service(t, "refresh-recreate")
	mustIAM(t, f.sys.DeleteServiceAccount(f.ctx, snapshot.AccessKey, false))
	_, _, err := f.sys.NewServiceAccount(f.ctx, f.parent.AccessKey, nil, newServiceAccountOpts{accessKey: snapshot.AccessKey, secretKey: "refresh-original-secret", description: "recreated"})
	mustIAM(t, err)
	_, err = f.sys.store.RefreshUserGroups(f.ctx, snapshot, []string{"g1"})
	mustIAM(t, err)
	u, ok := f.stored(t, snapshot.AccessKey)
	if !ok || u.Credentials.Description != "recreated" || !slices.Equal(u.Credentials.Groups, []string{"g1"}) {
		t.Errorf("same parent: present=%v description=%q groups=%v, want the recreated record with [g1]", ok, u.Credentials.Description, u.Credentials.Groups)
	}

	other := iamAdminUser(f.ctx, t, f.sys, "refresh-other-parent", "refresh-parent")
	mustIAM(t, f.sys.DeleteServiceAccount(f.ctx, snapshot.AccessKey, false))
	_, _, err = f.sys.NewServiceAccount(f.ctx, other.AccessKey, nil, newServiceAccountOpts{accessKey: snapshot.AccessKey, secretKey: "refresh-other-secret"})
	mustIAM(t, err)
	wrote, err := f.sys.store.RefreshUserGroups(f.ctx, snapshot, []string{"g2"})
	mustIAM(t, err)
	u, ok = f.stored(t, snapshot.AccessKey)
	if wrote || !ok || u.Credentials.ParentUser != other.AccessKey || slices.Contains(u.Credentials.Groups, "g2") {
		t.Errorf("another parent: wrote=%v present=%v parent=%q groups=%v, want it left alone", wrote, ok, u.Credentials.ParentUser, u.Credentials.Groups)
	}
}

// Groups the record already has are not written again.
func TestIAMGroupRefreshUnchanged(t *testing.T) {
	f := newGroupRefreshFixture(t)
	snapshot := f.service(t, "refresh-unchanged")
	_, err := f.sys.store.RefreshUserGroups(f.ctx, snapshot, []string{"g1"})
	mustIAM(t, err)
	before, _ := f.stored(t, snapshot.AccessKey)
	wrote, err := f.sys.store.RefreshUserGroups(f.ctx, snapshot, []string{"g1"})
	mustIAM(t, err)
	after, _ := f.stored(t, snapshot.AccessKey)
	if wrote || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Errorf("wrote=%v, revision %s -> %s: unchanged groups must not be written", wrote, before.UpdatedAt, after.UpdatedAt)
	}
}
