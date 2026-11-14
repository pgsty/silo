// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	polplugin "github.com/minio/minio/internal/config/policy/plugin"
	"github.com/minio/mux"
	xnet "github.com/pgsty/silo-pkg/v3/net"
	"github.com/pgsty/silo-pkg/v3/policy"
)

func iamAdminFixture(t *testing.T) (context.Context, *IAMSys) {
	t.Helper()
	ctx, sys, obj := prepareIAMRevisionFixture(t)
	globalObjLayerMutex.Lock()
	globalObjectAPI = obj
	globalObjLayerMutex.Unlock()
	return ctx, sys
}

func iamAdminUser(ctx context.Context, t *testing.T, sys *IAMSys, name, policyName string) auth.Credentials {
	t.Helper()
	cred := auth.Credentials{AccessKey: name, SecretKey: "review-user-valid-secret"}
	_, err := sys.CreateUser(ctx, name, madmin.AddOrUpdateUserReq{SecretKey: cred.SecretKey, Status: madmin.AccountEnabled})
	mustIAM(t, err)
	if policyName != "" {
		_, err = sys.PolicyDBSet(ctx, name, policyName, regUser, false)
		mustIAM(t, err)
	}
	return cred
}

func iamAdminServiceAccount(ctx context.Context, t *testing.T, sys *IAMSys, parent, key, document string) auth.Credentials {
	t.Helper()
	var sp *policy.Policy
	var err error
	if document != "" {
		sp, err = policy.ParseConfig(strings.NewReader(document))
		mustIAM(t, err)
	}
	cred, _, err := sys.NewServiceAccount(ctx, parent, nil, newServiceAccountOpts{accessKey: key, secretKey: "review-service-valid-secret", sessionPolicy: sp})
	mustIAM(t, err)
	return cred
}

func iamAdminRequest(t *testing.T, cred auth.Credentials, method, target string, payload any) *http.Request {
	t.Helper()
	var body []byte
	if payload != nil {
		raw, err := json.Marshal(payload)
		mustIAM(t, err)
		body, err = madmin.EncryptData(cred.SecretKey, raw)
		mustIAM(t, err)
	}
	headers := map[string]string{}
	if cred.IsTemp() && !cred.IsServiceAccount() {
		headers["X-Amz-Security-Token"] = cred.SessionToken
	}
	req, err := newTestSignedRequestV4(method, "http://localhost"+target, int64(len(body)), bytes.NewReader(body), cred.AccessKey, cred.SecretKey, headers)
	mustIAM(t, err)
	mustIAM(t, req.ParseForm())
	return req
}

func iamAdminCall(t *testing.T, cred auth.Credentials, method, target string, payload any, vars map[string]string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := iamAdminRequest(t, cred, method, target, payload)
	req = mux.SetURLVars(req, vars)
	rec := httptest.NewRecorder()
	req = req.WithContext(newContext(req, rec, "IAMAdminAuthorization"))
	handler(rec, req)
	return rec
}

func assertIAMAdminStatus(t *testing.T, operation string, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s status=%d want=%d body=%s", operation, rec.Code, want, rec.Body.String())
		return
	}
	if want == http.StatusForbidden || want == http.StatusNotFound {
		var response APIErrorResponse
		mustIAM(t, json.Unmarshal(rec.Body.Bytes(), &response))
		wantCode := errorCodes.ToAPIErr(ErrAccessDenied).Code
		if want == http.StatusNotFound {
			wantCode = errorCodes.ToAPIErr(ErrAdminServiceAccountNotFound).Code
		}
		if response.Code != wantCode {
			t.Errorf("%s error code=%s want=%s", operation, response.Code, wantCode)
		}
	}
}

func iamAdminPlugin(t *testing.T, allow bool) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"result": allow})
	}))
	t.Cleanup(server.Close)
	u, err := xnet.ParseHTTPURL(server.URL)
	mustIAM(t, err)
	previous := newGlobalAuthZPluginFn()
	setGlobalAuthZPlugin(polplugin.New(polplugin.Args{URL: u, CloseRespFn: func(r io.ReadCloser) { r.Close() }}))
	t.Cleanup(func() { setGlobalAuthZPlugin(previous) })
}

func TestIAMAdminRootEmptyPolicy(t *testing.T) {
	for _, doc := range []string{"", "null", "{}", `{"Statement":null}`} {
		t.Run("policy="+doc, func(t *testing.T) {
			ctx, sys := iamAdminFixture(t)
			caller := iamAdminServiceAccount(ctx, t, sys, globalActiveCred.AccessKey, "review-root-empty", doc)
			sibling := iamAdminServiceAccount(ctx, t, sys, globalActiveCred.AccessKey, "review-root-sibling", "")
			req := iamAdminRequest(t, caller, "GET", "/minio/admin/v3/list-service-accounts", nil)
			checked, owner, code := checkKeyValid(req, caller.AccessKey)
			if code != ErrNone {
				t.Fatalf("checkKeyValid: %v", code)
			}
			active, _ := isAllowedBySessionPolicyForServiceAccount(policy.Args{Claims: checked.Claims})
			t.Logf("owner=%v parsed_active_session_policy=%v", owner, active)
			api := adminAPIHandlers{}
			assertIAMAdminStatus(t, "create", iamAdminCall(t, caller, "PUT", "/minio/admin/v3/add-service-account", madmin.AddServiceAccountReq{AccessKey: "review-root-new", SecretKey: "review-service-valid-secret"}, nil, api.AddServiceAccount), 200)
			assertIAMAdminStatus(t, "update", iamAdminCall(t, caller, "POST", "/minio/admin/v3/update-service-account?accessKey="+sibling.AccessKey, madmin.UpdateServiceAccountReq{NewName: "review"}, map[string]string{"accessKey": sibling.AccessKey}, api.UpdateServiceAccount), 204)
			assertIAMAdminStatus(t, "delete", iamAdminCall(t, caller, "DELETE", "/minio/admin/v3/delete-service-account?accessKey="+sibling.AccessKey, nil, map[string]string{"accessKey": sibling.AccessKey}, api.DeleteServiceAccount), 204)
			assertIAMAdminStatus(t, "revoke", iamAdminCall(t, caller, "POST", "/minio/admin/v3/revoke-tokens/builtin?fullRevoke=true", nil, map[string]string{"userProvider": madmin.BuiltinProvider}, api.RevokeTokens), 204)
		})
	}
}

func TestIAMAdminEmptyPolicyDelegation(t *testing.T) {
	for _, parentType := range []string{"root", "user"} {
		for _, document := range []string{"null", "{}", `{"Statement":null}`} {
			t.Run(parentType+"/"+document, func(t *testing.T) {
				ctx, sys := iamAdminFixture(t)
				parent := globalActiveCred
				if parentType == "user" {
					parent = iamAdminUser(ctx, t, sys, "empty-policy-parent", "readwrite")
				}
				sp, err := policy.ParseConfig(strings.NewReader(document))
				mustIAM(t, err)
				caller, _, err := sys.NewServiceAccount(ctx, parent.AccessKey, nil, newServiceAccountOpts{
					accessKey: "empty-policy-caller", secretKey: "empty-policy-caller-secret", sessionPolicy: sp,
					claims: map[string]any{"identity-attribute": "preserved"},
				})
				mustIAM(t, err)
				const limitedPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:ListServiceAccounts"]}]}`
				for _, tc := range []struct {
					policy      string
					listStatus  int
					allowObject bool
				}{
					{"", http.StatusOK, true},
					{"null", http.StatusOK, true},
					{"{}", http.StatusOK, true},
					{`{"Statement":null}`, http.StatusOK, true},
					{limitedPolicy, http.StatusOK, false},
					{`{"Version":"2012-10-17"}`, http.StatusOK, true},
					{`{"Statement":[]}`, http.StatusOK, true},
					{`{"Version":"2012-10-17","Statement":[]}`, http.StatusOK, true},
				} {
					expires := UTCNow().Add(time.Hour)
					req := madmin.AddServiceAccountReq{Expiration: &expires}
					if tc.policy != "" {
						req.Policy = json.RawMessage(tc.policy)
					}
					api := adminAPIHandlers{}
					rec := iamAdminCall(t, caller, "PUT", "/minio/admin/v3/add-service-account", req, nil, api.AddServiceAccount)
					assertIAMAdminStatus(t, "create expiring child", rec, http.StatusOK)
					data, err := madmin.DecryptData(caller.SecretKey, rec.Body)
					mustIAM(t, err)
					var response madmin.AddServiceAccountResp
					mustIAM(t, json.Unmarshal(data, &response))
					child, ok := sys.store.GetUser(response.Credentials.AccessKey)
					if !ok {
						t.Fatal("new service account missing")
					}
					// Exercise the issued key through authentication and authorization.
					assertIAMAdminStatus(t, "use expiring child policy="+tc.policy, iamAdminCall(t, child.Credentials, "GET", "/minio/admin/v3/list-service-accounts", nil, nil, api.ListServiceAccounts), tc.listStatus)
					signed := iamAdminRequest(t, child.Credentials, "GET", "/example/object", nil)
					checked, owner, code := checkKeyValid(signed, child.Credentials.AccessKey)
					if code != ErrNone {
						t.Fatalf("child authentication: %v", code)
					}
					if checked.Claims["identity-attribute"] != "preserved" {
						t.Fatal("creation lost the caller's identity context")
					}
					allowed := sys.IsAllowed(policy.Args{AccountName: checked.AccessKey, Claims: checked.Claims, IsOwner: owner, Action: policy.GetObjectAction, BucketName: "example", ObjectName: "object"})
					if allowed != tc.allowObject {
						t.Errorf("GetObject allowed=%v with requested policy=%s", allowed, tc.policy)
					}
				}
			})
		}
	}
}

func TestIAMAdminCorruptServiceCleanup(t *testing.T) {
	for _, status := range []string{auth.AccountOn, auth.AccountOff, "expired"} {
		t.Run(status, func(t *testing.T) {
			ctx, sys := iamAdminFixture(t)
			caller := iamAdminUser(ctx, t, sys, "review-admin", "consoleAdmin")
			parent := iamAdminUser(ctx, t, sys, "review-parent", "readwrite")
			svc := iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "rv-corrupt", "")
			if status == auth.AccountOff {
				_, err := sys.UpdateServiceAccount(ctx, svc.AccessKey, updateServiceAccountOpts{status: status})
				mustIAM(t, err)
			}
			cache := sys.store.lock()
			u := cache.iamUsersMap[svc.AccessKey]
			u.Credentials.SessionToken = "broken-session-token"
			if status == "expired" {
				u.Credentials.Expiration = UTCNow().Add(-time.Minute)
			}
			cache.iamUsersMap[svc.AccessKey] = u
			sys.store.unlock()
			_, _, err := sys.GetServiceAccount(ctx, svc.AccessKey)
			if err == nil {
				t.Fatal("fault injection failed")
			}
			raw, exists := sys.store.GetUser(svc.AccessKey)
			_, loginOK := sys.GetUser(ctx, svc.AccessKey)
			t.Logf("metadata_exists=%v parent_known=%v GetUser_ok=%v", exists, raw.Credentials.ParentUser == parent.AccessKey, loginOK)
			api := adminAPIHandlers{}
			outsider := iamAdminUser(ctx, t, sys, "cleanup-outsider", "readwrite")
			assertIAMAdminStatus(t, "unauthorized cleanup", iamAdminCall(t, outsider, "DELETE", "/minio/admin/v3/delete-service-account?accessKey="+svc.AccessKey, nil, map[string]string{"accessKey": svc.AccessKey}, api.DeleteServiceAccount), 404)
			assertIAMAdminStatus(t, "admin cleanup", iamAdminCall(t, caller, "DELETE", "/minio/admin/v3/delete-service-account?accessKey="+svc.AccessKey, nil, map[string]string{"accessKey": svc.AccessKey}, api.DeleteServiceAccount), 204)
			if _, ok := sys.store.GetUser(svc.AccessKey); ok {
				t.Fatal("deleted service account remains in the IAM cache")
			}
		})
	}
}

func TestIAMAdminPolicylessSelf(t *testing.T) {
	ctx, sys := iamAdminFixture(t)
	caller := iamAdminUser(ctx, t, sys, "review-policyless", "")
	svc := iamAdminServiceAccount(ctx, t, sys, caller.AccessKey, "rv-policyless-child", "")
	other := iamAdminUser(ctx, t, sys, "bulk-other", "readwrite")
	_ = iamAdminServiceAccount(ctx, t, sys, other.AccessKey, "bulk-other-child", "")
	api := adminAPIHandlers{}
	assertIAMAdminStatus(t, "list", iamAdminCall(t, caller, "GET", "/minio/admin/v3/list-service-accounts", nil, nil, api.ListServiceAccounts), 200)
	rec := iamAdminCall(t, caller, "GET", "/minio/admin/v3/list-access-keys-bulk?listType=all", nil, nil, api.ListAccessKeysBulk)
	assertIAMAdminStatus(t, "list bulk self", rec, 200)
	data, err := madmin.DecryptData(caller.SecretKey, rec.Body)
	mustIAM(t, err)
	var listed map[string]madmin.ListAccessKeysResp
	mustIAM(t, json.Unmarshal(data, &listed))
	entry, ok := listed[caller.AccessKey]
	if len(listed) != 1 || !ok || len(entry.ServiceAccounts) != 1 || entry.ServiceAccounts[0].AccessKey != svc.AccessKey || len(entry.STSKeys) != 0 {
		t.Fatalf("policyless bulk self returned unexpected identities: %+v", listed)
	}
	assertIAMAdminStatus(t, "info service", iamAdminCall(t, caller, "GET", "/minio/admin/v3/info-service-account?accessKey="+svc.AccessKey, nil, map[string]string{"accessKey": svc.AccessKey}, api.InfoServiceAccount), 200)
	assertIAMAdminStatus(t, "info access key", iamAdminCall(t, caller, "GET", "/minio/admin/v3/info-access-key?accessKey="+svc.AccessKey, nil, map[string]string{"accessKey": svc.AccessKey}, api.InfoAccessKey), 200)
	assertIAMAdminStatus(t, "delete", iamAdminCall(t, caller, "DELETE", "/minio/admin/v3/delete-service-account?accessKey="+svc.AccessKey, nil, map[string]string{"accessKey": svc.AccessKey}, api.DeleteServiceAccount), 204)
	assertIAMAdminStatus(t, "revoke", iamAdminCall(t, caller, "POST", "/minio/admin/v3/revoke-tokens/builtin?fullRevoke=true", nil, map[string]string{"userProvider": madmin.BuiltinProvider}, api.RevokeTokens), 204)
	assertIAMAdminStatus(t, "list another user", iamAdminCall(t, caller, "GET", "/minio/admin/v3/list-service-accounts?user="+globalActiveCred.AccessKey, nil, nil, api.ListServiceAccounts), 403)
	assertIAMAdminStatus(t, "revoke another user", iamAdminCall(t, caller, "POST", "/minio/admin/v3/revoke-tokens/builtin?fullRevoke=true&user="+globalActiveCred.AccessKey, nil, map[string]string{"userProvider": madmin.BuiltinProvider}, api.RevokeTokens), 403)
}

func TestIAMAdminExpiringInheritedPolicy(t *testing.T) {
	ctx, sys := iamAdminFixture(t)
	parent := iamAdminUser(ctx, t, sys, "review-legacy-parent", "consoleAdmin")
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:CreateServiceAccount","admin:UpdateServiceAccount"]}]}`
	// Model a credential persisted by the old handler: it copied its caller's
	// policy claims but set the newly created service's type to inherited.
	expires := UTCNow().Add(time.Hour)
	caller, _, err := sys.NewServiceAccount(ctx, parent.AccessKey, nil, newServiceAccountOpts{
		accessKey: "rv-exp-inherited", secretKey: "review-service-valid-secret", expiration: &expires,
		claims: map[string]any{policy.SessionPolicyName: base64.StdEncoding.EncodeToString([]byte(document))},
	})
	mustIAM(t, err)
	req := iamAdminRequest(t, caller, "GET", "/minio/admin/v3/list-service-accounts", nil)
	checked, owner, code := checkKeyValid(req, caller.AccessKey)
	if code != ErrNone {
		t.Fatalf("checkKeyValid: %v", code)
	}
	args := policy.Args{AccountName: caller.AccessKey, Claims: checked.Claims, IsOwner: owner, Action: policy.CreateServiceAccountAdminAction, DenyOnly: true}
	if !sys.IsAllowed(args) {
		t.Fatal("fixture cannot create")
	}
	args.Action = policy.CreateUserAdminAction
	args.DenyOnly = false
	if sys.IsAllowed(args) {
		t.Fatal("fixture not constrained")
	}
	t.Logf("service=%v temp=%v inherited=%v; create allowed, create-user denied", checked.IsServiceAccount(), checked.IsTemp(), checked.Claims[iamPolicyClaimNameSA()] == inheritedPolicyType)
	api := adminAPIHandlers{}
	rec := iamAdminCall(t, caller, "PUT", "/minio/admin/v3/add-service-account", madmin.AddServiceAccountReq{AccessKey: "review-escaped", SecretKey: "review-service-valid-secret"}, nil, api.AddServiceAccount)
	if rec.Code == 200 {
		child, ok := sys.GetUser(ctx, "review-escaped")
		if !ok {
			t.Fatal("new key missing")
		}
		childReq := iamAdminRequest(t, child.Credentials, "GET", "/minio/admin/v3/list-service-accounts", nil)
		childChecked, childOwner, childCode := checkKeyValid(childReq, child.Credentials.AccessKey)
		if childCode != ErrNone {
			t.Fatalf("child auth=%v", childCode)
		}
		allowed := sys.IsAllowed(policy.Args{AccountName: childChecked.AccessKey, Claims: childChecked.Claims, IsOwner: childOwner, Action: policy.CreateUserAdminAction})
		t.Errorf("constrained inherited service created a new key; new key CreateUser allowed=%v", allowed)
	} else {
		assertIAMAdminStatus(t, "reject derived creation", rec, 403)
	}
	updated := iamAdminCall(t, caller, "POST", "/minio/admin/v3/update-service-account?accessKey="+caller.AccessKey, madmin.UpdateServiceAccountReq{NewName: "metadata-only"}, map[string]string{"accessKey": caller.AccessKey}, api.UpdateServiceAccount)
	if updated.Code == 204 {
		after, ok := sys.GetUser(ctx, caller.AccessKey)
		if !ok {
			t.Fatal("updated key missing")
		}
		afterReq := iamAdminRequest(t, after.Credentials, "GET", "/minio/admin/v3/list-service-accounts", nil)
		afterChecked, afterOwner, afterCode := checkKeyValid(afterReq, caller.AccessKey)
		if afterCode != ErrNone {
			t.Fatalf("updated auth=%v", afterCode)
		}
		allowed := sys.IsAllowed(policy.Args{AccountName: caller.AccessKey, Claims: afterChecked.Claims, IsOwner: afterOwner, Action: policy.CreateUserAdminAction})
		t.Errorf("constrained inherited service updated itself; CreateUser allowed after update=%v", allowed)
	} else {
		assertIAMAdminStatus(t, "reject inherited self update", updated, 403)
	}
}

func TestIAMAdminSessionPolicyCannotDelegate(t *testing.T) {
	for _, temp := range []bool{false, true} {
		t.Run(map[bool]string{false: "service", true: "sts"}[temp], func(t *testing.T) {
			ctx, sys := iamAdminFixture(t)
			parent := iamAdminUser(ctx, t, sys, "rv-parent", "consoleAdmin")
			doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:CreateServiceAccount","admin:UpdateServiceAccount"]}]}`
			var caller auth.Credentials
			if !temp {
				caller = iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "review-restricted", doc)
			} else {
				var err error
				caller, err = auth.GetNewCredentialsWithMetadata(map[string]any{parentClaim: parent.AccessKey, "exp": UTCNow().Add(time.Hour).Unix(), policy.SessionPolicyName: base64.StdEncoding.EncodeToString([]byte(doc))}, globalActiveCred.SecretKey)
				mustIAM(t, err)
				caller.ParentUser = parent.AccessKey
				_, err = sys.SetTempUser(ctx, caller.AccessKey, caller, "")
				mustIAM(t, err)
			}
			sibling := iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "rv-sibling", "")
			api := adminAPIHandlers{}
			assertIAMAdminStatus(t, "restrict create", iamAdminCall(t, caller, "PUT", "/minio/admin/v3/add-service-account", madmin.AddServiceAccountReq{AccessKey: "review-bad-new", SecretKey: "review-service-valid-secret"}, nil, api.AddServiceAccount), 403)
			assertIAMAdminStatus(t, "restrict LDAP create", iamAdminCall(t, caller, "PUT", "/minio/admin/v3/idp/ldap/add-service-account", madmin.AddServiceAccountReq{AccessKey: "review-bad-new", SecretKey: "review-service-valid-secret"}, nil, api.AddServiceAccountLDAP), 403)
			assertIAMAdminStatus(t, "restrict update", iamAdminCall(t, caller, "POST", "/minio/admin/v3/update-service-account?accessKey="+sibling.AccessKey, madmin.UpdateServiceAccountReq{NewSecretKey: "review-known-new-secret"}, map[string]string{"accessKey": sibling.AccessKey}, api.UpdateServiceAccount), 403)
			if _, ok := sys.store.GetUser("review-bad-new"); ok {
				t.Fatal("denied creation persisted a credential")
			}
			u, ok := sys.store.GetUser(sibling.AccessKey)
			if !ok || u.Credentials.SecretKey != sibling.SecretKey {
				t.Fatal("denied update changed the target credential")
			}
		})
	}
}

func TestIAMAdminSelfDenials(t *testing.T) {
	for _, mode := range []string{"parent_deny", "group_deny", "session_implicit_deny", "session_explicit_deny", "plugin_deny"} {
		t.Run(mode, func(t *testing.T) {
			ctx, sys := iamAdminFixture(t)
			parent := iamAdminUser(ctx, t, sys, "rv-self-parent", "readwrite")
			target := iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "rv-self-target", "")
			caller := parent
			doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["admin:ListServiceAccounts","admin:RemoveServiceAccount"]}]}`
			switch mode {
			case "parent_deny", "group_deny":
				p, err := policy.ParseConfig(strings.NewReader(doc))
				mustIAM(t, err)
				_, err = sys.SetPolicy(ctx, "review-self-deny", *p)
				mustIAM(t, err)
				if mode == "group_deny" {
					_, err = sys.AddUsersToGroup(ctx, "self-deny-group", []string{parent.AccessKey})
					mustIAM(t, err)
					_, err = sys.PolicyDBSet(ctx, "self-deny-group", "review-self-deny", regUser, true)
				} else {
					_, err = sys.PolicyDBSet(ctx, parent.AccessKey, "readwrite,review-self-deny", regUser, false)
				}
				mustIAM(t, err)
			case "session_implicit_deny":
				caller = iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "rv-self-caller", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::example/*"]}]}`)
			case "session_explicit_deny":
				caller = iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "rv-self-caller", doc)
			case "plugin_deny":
				iamAdminPlugin(t, false)
			}
			api := adminAPIHandlers{}
			assertIAMAdminStatus(t, "list", iamAdminCall(t, caller, "GET", "/minio/admin/v3/list-service-accounts", nil, nil, api.ListServiceAccounts), 403)
			assertIAMAdminStatus(t, "list bulk self", iamAdminCall(t, caller, "GET", "/minio/admin/v3/list-access-keys-bulk?listType=all", nil, nil, api.ListAccessKeysBulk), 403)
			assertIAMAdminStatus(t, "info service", iamAdminCall(t, caller, "GET", "/minio/admin/v3/info-service-account?accessKey="+target.AccessKey, nil, map[string]string{"accessKey": target.AccessKey}, api.InfoServiceAccount), 403)
			assertIAMAdminStatus(t, "info access key", iamAdminCall(t, caller, "GET", "/minio/admin/v3/info-access-key?accessKey="+target.AccessKey, nil, map[string]string{"accessKey": target.AccessKey}, api.InfoAccessKey), 403)
			assertIAMAdminStatus(t, "delete", iamAdminCall(t, caller, "DELETE", "/minio/admin/v3/delete-service-account?accessKey="+target.AccessKey, nil, map[string]string{"accessKey": target.AccessKey}, api.DeleteServiceAccount), 403)
			assertIAMAdminStatus(t, "revoke", iamAdminCall(t, caller, "POST", "/minio/admin/v3/revoke-tokens/builtin?fullRevoke=true", nil, map[string]string{"userProvider": madmin.BuiltinProvider}, api.RevokeTokens), 403)
		})
	}
}

func TestIAMAdminNonRootCannotManageRoot(t *testing.T) {
	ctx, sys := iamAdminFixture(t)
	caller := iamAdminUser(ctx, t, sys, "rv-console-admin", "consoleAdmin")
	target := iamAdminServiceAccount(ctx, t, sys, globalActiveCred.AccessKey, "rv-root-target", "")
	api := adminAPIHandlers{}
	assertIAMAdminStatus(t, "create root", iamAdminCall(t, caller, "PUT", "/minio/admin/v3/add-service-account", madmin.AddServiceAccountReq{AccessKey: "rv-new-root", SecretKey: "review-service-valid-secret", TargetUser: globalActiveCred.AccessKey}, nil, api.AddServiceAccount), 403)
	assertIAMAdminStatus(t, "update root", iamAdminCall(t, caller, "POST", "/minio/admin/v3/update-service-account?accessKey="+target.AccessKey, madmin.UpdateServiceAccountReq{NewSecretKey: "review-known-new-secret"}, map[string]string{"accessKey": target.AccessKey}, api.UpdateServiceAccount), 403)
	assertIAMAdminStatus(t, "delete root", iamAdminCall(t, caller, "DELETE", "/minio/admin/v3/delete-service-account?accessKey="+target.AccessKey, nil, map[string]string{"accessKey": target.AccessKey}, api.DeleteServiceAccount), 404)
	assertIAMAdminStatus(t, "revoke root", iamAdminCall(t, caller, "POST", "/minio/admin/v3/revoke-tokens/builtin?fullRevoke=true&user="+globalActiveCred.AccessKey, nil, map[string]string{"userProvider": madmin.BuiltinProvider}, api.RevokeTokens), 403)
	// Restricted root-derived credentials and the site replicator are not root
	// administrators, even when their effective policy allows these actions.
	limited := iamAdminServiceAccount(ctx, t, sys, globalActiveCred.AccessKey, "limited-root", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:*"]}]}`)
	assertIAMAdminStatus(t, "limited root delete", iamAdminCall(t, limited, "DELETE", "/minio/admin/v3/delete-service-account?accessKey="+target.AccessKey, nil, map[string]string{"accessKey": target.AccessKey}, api.DeleteServiceAccount), 404)
	assertIAMAdminStatus(t, "limited root revoke", iamAdminCall(t, limited, "POST", "/minio/admin/v3/revoke-tokens/builtin?fullRevoke=true", nil, map[string]string{"userProvider": madmin.BuiltinProvider}, api.RevokeTokens), 403)
	replicator, _, err := sys.NewServiceAccount(ctx, globalActiveCred.AccessKey, nil, newServiceAccountOpts{accessKey: siteReplicatorSvcAcc, secretKey: "replicator-valid-secret", allowSiteReplicatorAccount: true})
	mustIAM(t, err)
	assertIAMAdminStatus(t, "replicator create root", iamAdminCall(t, replicator, "PUT", "/minio/admin/v3/add-service-account", madmin.AddServiceAccountReq{}, nil, api.AddServiceAccount), 403)

	// An external plugin remains authoritative, including for root targets.
	iamAdminPlugin(t, true)
	assertIAMAdminStatus(t, "plugin update root", iamAdminCall(t, limited, "POST", "/minio/admin/v3/update-service-account?accessKey="+target.AccessKey, madmin.UpdateServiceAccountReq{NewName: "plugin-authorized"}, map[string]string{"accessKey": target.AccessKey}, api.UpdateServiceAccount), 204)
	assertIAMAdminStatus(t, "plugin create root", iamAdminCall(t, limited, "PUT", "/minio/admin/v3/add-service-account", madmin.AddServiceAccountReq{}, nil, api.AddServiceAccount), 200)
}

func TestIAMAdminDeleteCorruptServiceReplicates(t *testing.T) {
	ctx, sys := iamAdminFixture(t)
	caller := iamAdminUser(ctx, t, sys, "cleanup-admin", "consoleAdmin")
	parent := iamAdminUser(ctx, t, sys, "cleanup-parent", "readwrite")
	target := iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "cleanup-target", "")
	cache := sys.store.lock()
	u := cache.iamUsersMap[target.AccessKey]
	u.Credentials.SessionToken = "broken-session-token"
	u.Credentials.Status = auth.AccountOff
	cache.iamUsersMap[target.AccessKey] = u
	sys.store.unlock()

	var deletions atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/minio/health/live" {
			return
		}
		var batch iamRevisionBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(batch.Items) != 1 || batch.Items[0].SvcAccChange == nil || batch.Items[0].SvcAccChange.Delete == nil || batch.Items[0].SvcAccChange.Delete.AccessKey != target.AccessKey {
			t.Error("replication did not carry the service account deletion")
		} else {
			deletions.Add(1)
		}
		_ = json.NewEncoder(w).Encode(iamRevisionResponse{iamRevisionStatus: iamRevisionStatus{Version: iamRevisionProtocol, Node: "peer", Instance: "peer-boot", Digest: "deleted"}})
	}))
	t.Cleanup(peer.Close)
	globalSiteReplicatorCred.RLock()
	previousSecret := globalSiteReplicatorCred.secretKey
	globalSiteReplicatorCred.RUnlock()
	globalSiteReplicatorCred.Set(caller.SecretKey)
	t.Cleanup(func() { globalSiteReplicatorCred.Set(previousSecret) })
	globalSiteReplicationSys.Lock()
	globalSiteReplicationSys.enabled = true
	globalSiteReplicationSys.state = srState{ServiceAccountAccessKey: caller.AccessKey, Peers: map[string]madmin.PeerInfo{
		globalDeploymentID(): {DeploymentID: globalDeploymentID(), Name: "local"},
		"peer":               {DeploymentID: "peer", Name: "peer", Endpoint: peer.URL},
	}}
	globalSiteReplicationSys.Unlock()
	t.Cleanup(func() {
		globalSiteReplicationSys.Lock()
		globalSiteReplicationSys.enabled = false
		globalSiteReplicationSys.Unlock()
	})
	api := adminAPIHandlers{}
	assertIAMAdminStatus(t, "replicated cleanup", iamAdminCall(t, caller, "DELETE", "/minio/admin/v3/delete-service-account?accessKey="+target.AccessKey, nil, map[string]string{"accessKey": target.AccessKey}, api.DeleteServiceAccount), 204)
	if deletions.Load() != 1 {
		t.Fatalf("expected one immediate deletion notification, got %d", deletions.Load())
	}
}

func TestIAMAdminListSelfAliases(t *testing.T) {
	for _, kind := range []string{"service", "sts"} {
		t.Run(kind, func(t *testing.T) {
			ctx, sys := iamAdminFixture(t)
			parent := iamAdminUser(ctx, t, sys, "alias-parent", "readwrite")
			target := iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "alias-target", "")
			serviceCaller := iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "alias-caller", "")
			caller := serviceCaller
			other := iamAdminUser(ctx, t, sys, "alias-other", "readwrite")
			_ = iamAdminServiceAccount(ctx, t, sys, other.AccessKey, "alias-other-child", "")
			if kind == "sts" {
				var err error
				caller, err = auth.GetNewCredentialsWithMetadata(map[string]any{parentClaim: parent.AccessKey, "exp": UTCNow().Add(time.Hour).Unix()}, globalActiveCred.SecretKey)
				mustIAM(t, err)
				caller.ParentUser = parent.AccessKey
				_, err = sys.SetTempUser(ctx, caller.AccessKey, caller, "")
				mustIAM(t, err)
			}
			api := adminAPIHandlers{}
			for _, alias := range []string{"", caller.AccessKey, parent.AccessKey} {
				rec := iamAdminCall(t, caller, "GET", "/minio/admin/v3/list-service-accounts?user="+alias, nil, nil, api.ListServiceAccounts)
				assertIAMAdminStatus(t, "list self alias", rec, 200)
				data, err := madmin.DecryptData(caller.SecretKey, rec.Body)
				mustIAM(t, err)
				var response madmin.ListServiceAccountsResp
				mustIAM(t, json.Unmarshal(data, &response))
				found := false
				for _, account := range response.Accounts {
					found = found || account.AccessKey == target.AccessKey
				}
				if !found {
					t.Fatalf("self alias %q did not list the parent's service accounts", alias)
				}

				query := url.Values{"listType": {madmin.AccessKeyListAll}}
				if alias != "" {
					query.Set("users", alias)
				}
				bulk := iamAdminCall(t, caller, "GET", "/minio/admin/v3/list-access-keys-bulk?"+query.Encode(), nil, nil, api.ListAccessKeysBulk)
				assertIAMAdminStatus(t, "list bulk self alias", bulk, 200)
				data, err = madmin.DecryptData(caller.SecretKey, bulk.Body)
				mustIAM(t, err)
				var listed map[string]madmin.ListAccessKeysResp
				mustIAM(t, json.Unmarshal(data, &listed))
				entry, ok := listed[parent.AccessKey]
				if len(listed) != 1 || !ok || len(entry.ServiceAccounts) != 2 {
					t.Fatalf("bulk self alias %q returned unexpected identities: %+v", alias, listed)
				}
				want := map[string]bool{target.AccessKey: true, serviceCaller.AccessKey: true}
				for _, account := range entry.ServiceAccounts {
					if !want[account.AccessKey] {
						t.Fatalf("bulk self alias %q returned unexpected or duplicate service account %s", alias, account.AccessKey)
					}
					delete(want, account.AccessKey)
				}
				if kind == "sts" {
					if len(entry.STSKeys) != 1 || entry.STSKeys[0].AccessKey != caller.AccessKey {
						t.Fatalf("bulk self alias %q returned unexpected STS accounts: %+v", alias, entry.STSKeys)
					}
				} else if len(entry.STSKeys) != 0 {
					t.Fatalf("service caller returned unexpected STS accounts: %+v", entry.STSKeys)
				}
				if bytes.Contains(data, []byte(serviceCaller.SecretKey)) || bytes.Contains(data, []byte(`"secretKey"`)) || bytes.Contains(data, []byte(`"sessionToken"`)) {
					t.Fatal("bulk listing returned credential secrets")
				}
			}
		})
	}
}
