// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
)

// Edits that keep the credential keep a job running; edits of the
// credential itself, and its status, still end it.
func TestBatchSubmitterCredentialEdits(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "edit-parent", batchAuthzFullAccess)
	parent := iamAdminUser(f.ctx, t, f.sys, "edit-parent", "edit-parent")
	soon := UTCNow().Add(time.Hour)
	later := UTCNow().Add(24 * time.Hour)
	newService := func(t *testing.T, expiring bool) (auth.Credentials, *batchJobSubmitter) {
		t.Helper()
		var opts newServiceAccountOpts
		if expiring {
			opts.expiration = &soon
		}
		created, _, err := f.sys.NewServiceAccount(f.ctx, parent.AccessKey, nil, opts)
		mustIAM(t, err)
		stored, ok := f.sys.GetUser(f.ctx, created.AccessKey)
		if !ok {
			t.Fatal("service account missing")
		}
		sub, err := newBatchJobSubmitter(stored.Credentials)
		mustIAM(t, err)
		mustIAM(t, sub.authorize(f.ctx, batchContextRead(f)))
		return stored.Credentials, sub
	}
	for _, tc := range []struct {
		name     string
		expiring bool
		edit     func(t *testing.T, cred auth.Credentials)
		keep     bool
	}{
		{"description", false, func(t *testing.T, cred auth.Credentials) {
			_, err := f.sys.UpdateServiceAccount(f.ctx, cred.AccessKey, updateServiceAccountOpts{description: "cosmetic"})
			mustIAM(t, err)
		}, true},
		{"name", false, func(t *testing.T, cred auth.Credentials) {
			_, err := f.sys.UpdateServiceAccount(f.ctx, cred.AccessKey, updateServiceAccountOpts{name: "renamed"})
			mustIAM(t, err)
		}, true},
		{"expiry-extended", true, func(t *testing.T, cred auth.Credentials) {
			_, err := f.sys.UpdateServiceAccount(f.ctx, cred.AccessKey, updateServiceAccountOpts{expiration: &later})
			mustIAM(t, err)
		}, true},
		// An expiry makes a service account a temporary credential, which
		// IsAllowed evaluates differently.
		{"expiry-added", false, func(t *testing.T, cred auth.Credentials) {
			_, err := f.sys.UpdateServiceAccount(f.ctx, cred.AccessKey, updateServiceAccountOpts{expiration: &later})
			mustIAM(t, err)
		}, false},
		{"groups-refreshed", false, func(t *testing.T, cred auth.Credentials) {
			// As the LDAP group refresh rewrites a derived credential.
			u, ok := f.sys.GetUser(f.ctx, cred.AccessKey)
			if !ok {
				t.Fatal("service account missing")
			}
			wrote, err := f.sys.store.RefreshUserGroups(f.ctx, u.Credentials, append(u.Credentials.Groups, "refreshed-group"))
			mustIAM(t, err)
			if !wrote {
				t.Fatal("control: the refresh did not write")
			}
		}, true},
		{"secret-rotated", false, func(t *testing.T, cred auth.Credentials) {
			_, err := f.sys.UpdateServiceAccount(f.ctx, cred.AccessKey, updateServiceAccountOpts{secretKey: "edit-rotated-secret-key"})
			mustIAM(t, err)
		}, false},
		{"disabled", false, func(t *testing.T, cred auth.Credentials) {
			_, err := f.sys.UpdateServiceAccount(f.ctx, cred.AccessKey, updateServiceAccountOpts{status: string(madmin.AccountDisabled)})
			mustIAM(t, err)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred, sub := newService(t, tc.expiring)
			before, _ := f.sys.GetUser(f.ctx, cred.AccessKey)
			time.Sleep(2 * time.Millisecond) // a distinct UpdatedAt
			tc.edit(t, cred)
			after, _ := f.sys.GetUser(f.ctx, cred.AccessKey)
			if after.UpdatedAt.Equal(before.UpdatedAt) {
				t.Fatal("control: the edit did not change the identity record")
			}
			err := sub.authorize(f.ctx, batchContextRead(f))
			if tc.keep && err != nil {
				t.Errorf("an edit that keeps the credential ended the job: %v", err)
			}
			if !tc.keep && !isBatchJobAuthzError(err) {
				t.Errorf("an edit of the credential must end the job, got %v", err)
			}
		})
	}
}

// A user deleted and created again under its access key, with the same
// secret, is not the credential that submitted the job.
func TestBatchSubmitterRecreatedSameSecret(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "recreate-full", batchAuthzFullAccess)
	cred := iamAdminUser(f.ctx, t, f.sys, "recreate-user", "recreate-full")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	mustIAM(t, sub.authorize(f.ctx, batchContextRead(f)))
	mustIAM(t, f.sys.DeleteUser(f.ctx, cred.AccessKey, false))
	time.Sleep(10 * time.Millisecond)
	again := iamAdminUser(f.ctx, t, f.sys, cred.AccessKey, "recreate-full")
	if again.SecretKey != cred.SecretKey {
		t.Fatal("control: the user must be created again with the same secret")
	}
	err = sub.authorize(f.ctx, batchContextRead(f))
	t.Logf("recreated: %v", err)
	if !isBatchJobAuthzError(err) {
		t.Errorf("a recreated user must not run the job of the deleted one: %v", err)
	}
}
