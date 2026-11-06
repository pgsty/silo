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
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/pgsty/silo-pkg/v3/policy"
)

func TestIAMPolicyMergeFailureDeniesAuthorization(t *testing.T) {
	ctx, sys, _ := prepareIAMRevisionFixture(t)
	const names = "merge-allow,merge-deny"
	batchAuthzPolicy(ctx, t, sys, "merge-allow", `{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::merge-bucket/*"]}`)
	batchAuthzPolicy(ctx, t, sys, "merge-deny", `{"Effect":"Deny","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::merge-bucket/protected"]},
{"Effect":"Deny","Action":["admin:ListServiceAccounts"]}`)
	cred := iamAdminUser(ctx, t, sys, "merge-user", names)
	store := sys.store
	original := store.IAMStorageAPI
	t.Cleanup(func() { store.IAMStorageAPI = original })
	evict := func() {
		cache := store.lock()
		delete(cache.iamPolicyDocsMap, "merge-deny")
		store.unlock()
	}
	args := policy.Args{AccountName: cred.AccessKey, Action: policy.GetObjectAction, BucketName: "merge-bucket", ObjectName: "protected"}
	checks := []struct {
		name    string
		allowed func() bool
	}{
		{"regular", func() bool { return sys.IsAllowed(args) }},
		{"sts", func() bool { return sys.IsAllowedSTS(args, cred.AccessKey) }},
		{"service-account", func() bool {
			saArgs := args
			saArgs.Claims = map[string]any{parentClaim: cred.AccessKey, iamPolicyClaimNameSA(): inheritedPolicyType}
			return sys.IsAllowedServiceAccount(saArgs, cred.AccessKey)
		}},
		{"deny-only", func() bool {
			return sys.doesPolicyAllow(names, policy.Args{DenyOnly: true, Action: policy.ListServiceAccountsAdminAction})
		}},
		{"self-service", func() bool {
			return isAllowedServiceAccountAction(cred, policy.Args{AccountName: cred.AccessKey, DenyOnly: true, Action: policy.ListServiceAccountsAdminAction})
		}},
	}
	for _, fault := range []struct {
		name string
		err  error
	}{
		{"quorum", errErasureReadQuorum},
		{"timeout", context.DeadlineExceeded},
		{"malformed", errors.New("invalid policy document")},
	} {
		t.Run(fault.name, func(t *testing.T) {
			evict()
			store.IAMStorageAPI = &batchPolicyOutage{IAMStorageAPI: original, failed: "merge-deny", err: fault.err}
			for _, check := range checks {
				t.Run(check.name, func(t *testing.T) {
					if check.allowed() {
						t.Fatal("policy load failure discarded Deny and granted authorization")
					}
				})
			}
		})
	}
	// A successful retry must enforce the loaded Deny and keep its unaffected
	// Allow. Neither an outage nor a deny may permanently poison the cache.
	store.IAMStorageAPI = original
	for _, check := range checks {
		if check.allowed() {
			t.Errorf("%s discarded Deny after recovery", check.name)
		}
	}
	args.ObjectName = "unprotected"
	if !sys.IsAllowed(args) {
		t.Fatal("unaffected permission did not recover")
	}
}

func TestIAMPolicyMergeLoadResult(t *testing.T) {
	ctx, sys, _ := prepareIAMRevisionFixture(t)
	batchAuthzPolicy(ctx, t, sys, "merge-allow", `{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::merge-bucket/*"]}`)
	store := sys.store
	original := store.IAMStorageAPI
	t.Cleanup(func() { store.IAMStorageAPI = original })
	for _, tc := range []struct {
		name    string
		loadErr error
		wantErr bool
	}{
		{"confirmed-absent", errNoSuchPolicy, false},
		{"unavailable", errErasureReadQuorum, true},
		{"empty-success", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store.IAMStorageAPI = &batchPolicyOutage{IAMStorageAPI: original, failed: "merge-missing", err: tc.loadErr}
			names, combined, err := store.MergePolicies("merge-allow,merge-missing")
			if tc.wantErr {
				if err == nil || names != "" || len(combined.Statements) != 0 {
					t.Fatalf("incomplete policy selection returned a usable result: names=%q statements=%d err=%v", names, len(combined.Statements), err)
				}
				if tc.loadErr != nil && !errors.Is(err, tc.loadErr) {
					t.Fatalf("lost policy load error: %v", err)
				}
				if _, err := sys.CurrentPolicies("merge-allow,merge-missing"); err == nil {
					t.Fatal("STS policy selection hid a load failure")
				}
				if _, err := sys.GetCombinedPolicy("merge-allow", "merge-missing"); err == nil {
					t.Fatal("combined policy hid a load failure")
				}
			} else {
				mustIAM(t, err)
				if names != "merge-allow" || !combined.IsAllowed(policy.Args{Action: policy.GetObjectAction, BucketName: "merge-bucket", ObjectName: "object"}) {
					t.Fatal("confirmed absence changed the remaining policy")
				}
			}
		})
	}
	store.IAMStorageAPI = original
	// A regular user's self inspection without any policy must still work.
	cred := iamAdminUser(ctx, t, sys, "merge-no-policy", "")
	if !isAllowedServiceAccountAction(cred, policy.Args{AccountName: cred.AccessKey, DenyOnly: true, Action: policy.ListServiceAccountsAdminAction}) {
		t.Fatal("a valid empty policy set was mistaken for an unavailable policy")
	}
}

func TestIAMPolicyMergeInfoFailure(t *testing.T) {
	ctx, sys := iamAdminFixture(t)
	batchAuthzPolicy(ctx, t, sys, "merge-info-allow", `{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::merge-bucket/*"]}`)
	batchAuthzPolicy(ctx, t, sys, "merge-info-deny", `{"Effect":"Deny","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::merge-bucket/protected"]}`)
	parent := iamAdminUser(ctx, t, sys, "merge-info-user", "merge-info-allow,merge-info-deny")
	svc := iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "merge-info-service", "")
	store := sys.store
	original := store.IAMStorageAPI
	t.Cleanup(func() { store.IAMStorageAPI = original })
	cache := store.lock()
	delete(cache.iamPolicyDocsMap, "merge-info-deny")
	store.unlock()
	store.IAMStorageAPI = &batchPolicyOutage{IAMStorageAPI: original, failed: "merge-info-deny", err: errErasureReadQuorum}
	api := adminAPIHandlers{}
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"info-service-account", api.InfoServiceAccount},
		{"info-access-key", api.InfoAccessKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := iamAdminCall(t, globalActiveCred, http.MethodGet, "/minio/admin/v3/"+tc.name+"?accessKey="+svc.AccessKey, nil, map[string]string{"accessKey": svc.AccessKey}, tc.handler)
			if rec.Code < http.StatusInternalServerError {
				t.Fatalf("incomplete effective policy returned as success: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

type iamPolicyMergeBlockedStore struct {
	IAMStorageAPI
	started chan struct{}
	release chan struct{}
}

func (s *iamPolicyMergeBlockedStore) loadPolicyDoc(ctx context.Context, name string, out map[string]PolicyDoc) error {
	if name == "merge-slow" {
		close(s.started)
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.IAMStorageAPI.loadPolicyDoc(ctx, name, out)
}

func TestIAMPolicyMergeSlowLoadKeepsCachedAuthorizationAvailable(t *testing.T) {
	ctx, sys, _ := prepareIAMRevisionFixture(t)
	const statement = `{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::merge-bucket/*"]}`
	batchAuthzPolicy(ctx, t, sys, "merge-cached", statement)
	batchAuthzPolicy(ctx, t, sys, "merge-slow", statement)
	cached := iamAdminUser(ctx, t, sys, "merge-cached-user", "merge-cached")
	slow := iamAdminUser(ctx, t, sys, "merge-slow-user", "merge-slow")
	store := sys.store
	original := store.IAMStorageAPI
	blocked := &iamPolicyMergeBlockedStore{IAMStorageAPI: original, started: make(chan struct{}), release: make(chan struct{})}
	cache := store.lock()
	delete(cache.iamPolicyDocsMap, "merge-slow")
	store.unlock()
	store.IAMStorageAPI = blocked
	var wg sync.WaitGroup
	var once sync.Once
	unblock := func() { once.Do(func() { close(blocked.release) }) }
	t.Cleanup(func() { unblock(); wg.Wait(); store.IAMStorageAPI = original })
	args := policy.Args{AccountName: slow.AccessKey, Action: policy.GetObjectAction, BucketName: "merge-bucket", ObjectName: "object"}
	slowDone := make(chan bool, 1)
	wg.Go(func() { slowDone <- sys.IsAllowed(args) })
	select {
	case <-blocked.started:
	case <-time.After(5 * time.Second):
		t.Fatal("missing policy load did not start")
	}
	cachedDone := make(chan bool, 1)
	wg.Go(func() {
		cachedArgs := args
		cachedArgs.AccountName = cached.AccessKey
		cachedDone <- sys.IsAllowed(cachedArgs)
	})
	select {
	case allowed := <-cachedDone:
		if !allowed {
			t.Fatal("unrelated cached policy was rejected")
		}
	case <-time.After(time.Second):
		t.Fatal("a slow policy load blocked unrelated cached authorization")
	}
	unblock()
	if !<-slowDone {
		t.Fatal("slow policy did not load after recovery")
	}
}
