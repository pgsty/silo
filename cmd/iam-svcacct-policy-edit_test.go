// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// An edit of a service account that names no policy keeps the embedded
// policy: the account must not come out of a status change, a key rotation
// or a rename with all its parent is allowed. Only a policy that is given
// and empty removes the embedded one.

const svcAccEditPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::edit/*"]}]}`

func TestIAMServiceAccountPolicySemantics(t *testing.T) {
	for _, expiring := range []bool{false, true} {
		t.Run(fmt.Sprintf("expiring=%v", expiring), func(t *testing.T) {
			f := newGroupRefreshFixture(t)
			readPolicy, err := policy.ParseConfig(strings.NewReader(svcAccEditPolicy))
			mustIAM(t, err)
			writePolicy, err := policy.ParseConfig(strings.NewReader(strings.ReplaceAll(svcAccEditPolicy, "s3:GetObject", "s3:PutObject")))
			mustIAM(t, err)
			_, err = f.sys.PolicyDBSet(f.ctx, f.parent.AccessKey, "readwrite", regUser, false)
			mustIAM(t, err)
			for _, action := range []policy.Action{policy.GetObjectAction, policy.PutObjectAction} {
				if !f.sys.IsAllowed(policy.Args{AccountName: f.parent.AccessKey, Action: action, BucketName: "edit", ObjectName: "object"}) {
					t.Fatal("control: the parent must allow reads and writes to the test object")
				}
			}
			noVersion, invalidVersion, oversized := *writePolicy, *writePolicy, *writePolicy
			noVersion.Version = ""
			invalidVersion.Version = "2008-10-17"
			oversized.ID = policy.ID(strings.Repeat("x", maxSVCSessionPolicySize))
			var expiration *time.Time
			if expiring {
				later := UTCNow().Add(time.Hour)
				expiration = &later
			}
			for i, tc := range []struct {
				name    string
				input   *policy.Policy
				invalid bool
			}{
				{"nil", nil, false},
				{"empty", &policy.Policy{}, false},
				{"empty-statements", &policy.Policy{Statements: []policy.Statement{}}, false},
				{"empty-with-version", &policy.Policy{Version: policy.DefaultVersion, Statements: []policy.Statement{}}, false},
				{"missing-version", &noVersion, false},
				{"version", writePolicy, false},
				{"invalid-version", &invalidVersion, true},
				{"empty-invalid-version", &policy.Policy{Version: "2008-10-17"}, true},
				{"invalid-statement", &policy.Policy{Statements: []policy.Statement{{}}}, true},
				{"oversized", &oversized, true},
			} {
				for _, edit := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/edit=%v", tc.name, edit), func(t *testing.T) {
						key := fmt.Sprintf("policy-%d-%v", i, edit)
						inputBefore, err := json.Marshal(tc.input)
						mustIAM(t, err)
						var before UserIdentity
						if edit {
							_, _, err = f.sys.NewServiceAccount(f.ctx, f.parent.AccessKey, nil, newServiceAccountOpts{
								accessKey: key, secretKey: "policy-valid-secret", sessionPolicy: readPolicy, expiration: expiration,
							})
							mustIAM(t, err)
							mustIAM(t, f.sys.store.loadIAMConfig(f.ctx, &before, getUserIdentityPath(key, svcUser)))
							_, err = f.sys.UpdateServiceAccount(f.ctx, key, updateServiceAccountOpts{sessionPolicy: tc.input, description: "edited"})
						} else {
							// Snapshots can carry a stale copy of the policy in claims.
							var claims map[string]any
							if tc.input != nil {
								claims = map[string]any{policy.SessionPolicyName: base64.StdEncoding.EncodeToString([]byte(svcAccEditPolicy))}
							}
							_, _, err = f.sys.NewServiceAccount(f.ctx, f.parent.AccessKey, nil, newServiceAccountOpts{
								accessKey: key, secretKey: "policy-valid-secret", sessionPolicy: tc.input, expiration: expiration,
								claims: claims,
							})
						}
						if (err != nil) != tc.invalid {
							t.Fatalf("operation error = %v, want rejected=%v", err, tc.invalid)
						}
						inputAfter, err := json.Marshal(tc.input)
						mustIAM(t, err)
						if !bytes.Equal(inputBefore, inputAfter) {
							t.Fatal("operation changed the caller's policy")
						}
						var stored UserIdentity
						loadErr := f.sys.store.loadIAMConfig(f.ctx, &stored, getUserIdentityPath(key, svcUser))
						if tc.invalid {
							if edit {
								mustIAM(t, loadErr)
								if !reflect.DeepEqual(stored, before) {
									t.Fatal("rejected edit changed the stored account")
								}
							} else if loadErr != errConfigNotFound {
								t.Fatalf("rejected create left an account: %v", loadErr)
							}
							return
						}
						mustIAM(t, loadErr)
						claims, err := auth.ExtractClaims(stored.Credentials.SessionToken, stored.Credentials.SecretKey)
						mustIAM(t, err)
						if _, ok := claims.Map()[sessionPolicyNameExtracted]; ok {
							t.Fatal("raw JWT contains the derived policy claim")
						}
						var want *policy.Policy
						if tc.input != nil && !tc.input.IsEmpty() {
							want = writePolicy
						} else if tc.input == nil && edit {
							want = readPolicy
						}
						got, err := embeddedServiceAccountPolicy(claims)
						mustIAM(t, err)
						if (got == nil) != (want == nil) || (got != nil && !got.Equals(*want)) {
							t.Fatalf("stored policy = %+v, want %+v", got, want)
						}
						if want == nil {
							if _, ok := claims.Lookup(policy.SessionPolicyName); ok || claims.Map()[iamPolicyClaimNameSA()] != inheritedPolicyType {
								t.Fatal("inheritance must remove the embedded policy claim")
							}
						}
						mustIAM(t, f.sys.store.LoadIAMCache(f.ctx, false))
						u, valid, err := f.sys.CheckKey(f.ctx, key)
						mustIAM(t, err)
						if !valid || u.Credentials.IsTemp() != expiring {
							t.Fatal("credential validity or expiration changed")
						}
						for _, action := range []policy.Action{policy.GetObjectAction, policy.PutObjectAction} {
							allowed := f.sys.IsAllowed(policy.Args{AccountName: key, Claims: u.Credentials.Claims, Action: action, BucketName: "edit", ObjectName: "object"})
							wantAllowed := want == nil || (want == readPolicy && action == policy.GetObjectAction) || (want == writePolicy && action == policy.PutObjectAction)
							if allowed != wantAllowed {
								t.Errorf("%s allowed=%v, want %v", action, allowed, wantAllowed)
							}
						}
					})
				}
			}
		})
	}
}

func TestIAMServiceAccountEditKeepsPolicy(t *testing.T) {
	f := newGroupRefreshFixture(t)
	want, err := policy.ParseConfig(strings.NewReader(svcAccEditPolicy))
	mustIAM(t, err)

	// restricted creates a service account with the embedded policy.
	restricted := func(t *testing.T, key, status string) {
		t.Helper()
		_, _, err := f.sys.NewServiceAccount(f.ctx, f.parent.AccessKey, nil, newServiceAccountOpts{accessKey: key, secretKey: "edit-original-secret", status: status, sessionPolicy: want})
		mustIAM(t, err)
	}
	// embedded reports whether this server and storage have the policy, and
	// returns the stored credential.
	embedded := func(t *testing.T, key string) (cached, stored bool, cr auth.Credentials) {
		t.Helper()
		_, got, err := f.sys.GetServiceAccount(f.ctx, key)
		mustIAM(t, err)
		if got != nil && !got.Equals(*want) {
			t.Fatalf("the embedded policy changed: %+v", got)
		}
		u, ok := f.stored(t, key)
		if !ok {
			t.Fatal("service account missing in storage")
		}
		claims, err := getClaimsFromTokenWithSecret(u.Credentials.SessionToken, u.Credentials.SecretKey)
		mustIAM(t, err)
		_, hasPolicy := claims.Lookup(policy.SessionPolicyName)
		return got != nil, hasPolicy && claims.MapClaims[iamPolicyClaimNameSA()] == embeddedPolicyType, u.Credentials
	}
	// check wants the edit applied, and the policy kept or removed.
	check := func(t *testing.T, key string, keep bool, took func(auth.Credentials) bool) {
		t.Helper()
		cached, stored, cr := embedded(t, key)
		if cached != keep || stored != keep {
			t.Errorf("embedded policy: cached=%v stored=%v, want %v", cached, stored, keep)
		}
		if took != nil && !took(cr) {
			t.Errorf("the edit did not apply: status=%q name=%q description=%q expiration=%v", cr.Status, cr.Name, cr.Description, cr.Expiration)
		}
	}

	later := UTCNow().Add(time.Hour)
	for _, edit := range []struct {
		name, start string
		opts        updateServiceAccountOpts
		took        func(auth.Credentials) bool
	}{
		{"disable", auth.AccountOn, updateServiceAccountOpts{status: string(madmin.AccountDisabled)}, func(c auth.Credentials) bool { return c.Status == auth.AccountOff }},
		{"enable", auth.AccountOff, updateServiceAccountOpts{status: string(madmin.AccountEnabled)}, func(c auth.Credentials) bool { return c.Status == auth.AccountOn }},
		{"status-off", auth.AccountOn, updateServiceAccountOpts{status: auth.AccountOff}, func(c auth.Credentials) bool { return c.Status == auth.AccountOff }},
		{"status-on", auth.AccountOff, updateServiceAccountOpts{status: auth.AccountOn}, func(c auth.Credentials) bool { return c.Status == auth.AccountOn }},
		{"secret-key", auth.AccountOn, updateServiceAccountOpts{secretKey: "edit-rotated-secret"}, func(c auth.Credentials) bool { return c.SecretKey == "edit-rotated-secret" }},
		{"name", auth.AccountOn, updateServiceAccountOpts{name: "renamed"}, func(c auth.Credentials) bool { return c.Name == "renamed" }},
		{"description", auth.AccountOn, updateServiceAccountOpts{description: "described"}, func(c auth.Credentials) bool { return c.Description == "described" }},
		{"expiration", auth.AccountOn, updateServiceAccountOpts{expiration: &later}, func(c auth.Credentials) bool { return c.Expiration.Equal(later) }},
	} {
		t.Run(edit.name, func(t *testing.T) {
			key := "edit-" + edit.name
			restricted(t, key, edit.start)
			_, err := f.sys.UpdateServiceAccount(f.ctx, key, edit.opts)
			mustIAM(t, err)
			check(t, key, true, edit.took)
		})
	}

	t.Run("empty-policy", func(t *testing.T) {
		const key = "edit-empty-policy"
		restricted(t, key, auth.AccountOn)
		_, err := f.sys.UpdateServiceAccount(f.ctx, key, updateServiceAccountOpts{sessionPolicy: &policy.Policy{}})
		mustIAM(t, err)
		check(t, key, false, nil)
	})

	// A peer applies the edit as the site that took it did. The edit goes
	// through the encoding of the wire, which is where no policy and a null
	// one become the same.
	for _, edit := range []struct {
		name   string
		update madmin.SRSvcAccUpdate
		keep   bool
		took   func(auth.Credentials) bool
	}{
		{"peer-status", madmin.SRSvcAccUpdate{Status: auth.AccountOff}, true, func(c auth.Credentials) bool { return c.Status == auth.AccountOff }},
		{"peer-null", madmin.SRSvcAccUpdate{Description: "described", SessionPolicy: madmin.SRSessionPolicy("null")}, true, func(c auth.Credentials) bool { return c.Description == "described" }},
		{"peer-empty", madmin.SRSvcAccUpdate{SessionPolicy: madmin.SRSessionPolicy(`{"Statement":[]}`)}, false, nil},
		{"peer-empty-v", madmin.SRSvcAccUpdate{SessionPolicy: madmin.SRSessionPolicy(`{"Version":"2012-10-17","Statement":[]}`)}, false, nil},
	} {
		t.Run(edit.name, func(t *testing.T) {
			key := "edit-" + edit.name
			restricted(t, key, auth.AccountOn)
			edit.update.AccessKey = key
			sent, err := json.Marshal(iamReplicationItem{SRIAMItem: madmin.SRIAMItem{
				Type:         madmin.SRIAMItemSvcAcc,
				SvcAccChange: &madmin.SRSvcAccChange{Update: &edit.update},
				UpdatedAt:    UTCNow(),
			}})
			mustIAM(t, err)
			var got iamReplicationItem
			mustIAM(t, json.Unmarshal(sent, &got))
			mustIAM(t, applyIAMReplicationItem(f.ctx, got))
			check(t, key, edit.keep, edit.took)
		})
	}
}

// The same over the admin API, with what a client can send for no policy.
func TestServiceAccountUpdateKeepsPolicy(t *testing.T) {
	if runtime.GOOS == globalWindowsOSName {
		t.Skip("IAM integration harness is disabled on Windows")
	}
	s := newTestSuiteIAM(TestSuiteCommon{serverType: "ErasureSD", signer: signerV4}, false)
	c := &check{t, s.serverType}
	s.SetUpSuite(c)
	defer s.TearDownSuite(c)

	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	if err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		c.Fatalf("bucket create error: %v", err)
	}
	if err := s.adm.AddCannedPolicy(ctx, "keeps-policy-parent", fmt.Appendf(nil, `{"Version":"2012-10-17","Statement":[
{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::%s"]},
{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":["arn:aws:s3:::%s/*"]}]}`, bucket, bucket)); err != nil {
		c.Fatalf("policy add error: %v", err)
	}
	parentAK, parentSK := mustGenerateCredentials(c)
	if err := s.adm.SetUser(ctx, parentAK, parentSK, madmin.AccountEnabled); err != nil {
		c.Fatalf("unable to set user: %v", err)
	}
	if _, err := s.adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{Policies: []string{"keeps-policy-parent"}, User: parentAK}); err != nil {
		c.Fatalf("unable to attach policy: %v", err)
	}

	// The account may read objects; listing is its parent's to do.
	svcAK, svcSK := mustGenerateCredentials(c)
	cr, err := s.adm.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
		Policy:     fmt.Appendf(nil, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::%s/*"]}]}`, bucket),
		TargetUser: parentAK,
		AccessKey:  svcAK,
		SecretKey:  svcSK,
	})
	if err != nil {
		c.Fatalf("unable to create svc acc: %v", err)
	}
	c.mustUpload(ctx, s.client, bucket)
	svcClient := s.getUserClient(c, cr.AccessKey, cr.SecretKey, "")
	c.mustDownload(ctx, svcClient, bucket)
	c.mustNotListObjects(ctx, svcClient, bucket)

	info := func() madmin.InfoServiceAccountResp {
		info, err := s.adm.InfoServiceAccount(ctx, svcAK)
		if err != nil {
			c.Fatalf("unable to get svc acc info: %v", err)
		}
		return info
	}

	_, rotatedSK := mustGenerateCredentials(c)
	later := UTCNow().Add(time.Hour).Truncate(time.Second)
	for _, edit := range []struct {
		name string
		req  madmin.UpdateServiceAccountReq
		took func(madmin.InfoServiceAccountResp) bool
	}{
		{"disable", madmin.UpdateServiceAccountReq{NewStatus: "off"}, func(i madmin.InfoServiceAccountResp) bool { return i.AccountStatus == auth.AccountOff }},
		{"enable", madmin.UpdateServiceAccountReq{NewStatus: "on"}, func(i madmin.InfoServiceAccountResp) bool { return i.AccountStatus == auth.AccountOn }},
		{"description", madmin.UpdateServiceAccountReq{NewDescription: "described"}, func(i madmin.InfoServiceAccountResp) bool { return i.Description == "described" }},
		{"name", madmin.UpdateServiceAccountReq{NewName: "renamed"}, func(i madmin.InfoServiceAccountResp) bool { return i.Name == "renamed" }},
		{"expiry", madmin.UpdateServiceAccountReq{NewExpiration: &later}, func(i madmin.InfoServiceAccountResp) bool { return i.Expiration != nil && i.Expiration.Equal(later) }},
		{"secret-key", madmin.UpdateServiceAccountReq{NewSecretKey: rotatedSK}, func(madmin.InfoServiceAccountResp) bool {
			// The new key signs a request the embedded policy allows.
			svcClient = s.getUserClient(c, svcAK, rotatedSK, "")
			_, err := svcClient.StatObject(ctx, bucket, "some-object", minio.StatObjectOptions{})
			return err == nil
		}},
		{"null-policy", madmin.UpdateServiceAccountReq{NewPolicy: json.RawMessage("null"), NewDescription: "null"}, func(i madmin.InfoServiceAccountResp) bool { return i.Description == "null" }},
	} {
		if err := s.adm.UpdateServiceAccount(ctx, svcAK, edit.req); err != nil {
			c.Fatalf("%s: unable to update svc acc: %v", edit.name, err)
		}
		got := info()
		if got.ImpliedPolicy {
			c.Fatalf("%s: the account lost its embedded policy", edit.name)
		}
		if !edit.took(got) {
			c.Fatalf("%s: the edit did not apply: %+v", edit.name, got)
		}
	}
	c.mustNotListObjects(ctx, svcClient, bucket)

	// An empty policy document asks for the parent's policies.
	if err := s.adm.UpdateServiceAccount(ctx, svcAK, madmin.UpdateServiceAccountReq{NewPolicy: []byte(`{"Statement":[]}`)}); err != nil {
		c.Fatalf("unable to remove the policy of svc acc: %v", err)
	}
	if !info().ImpliedPolicy {
		c.Fatalf("an empty policy document must remove the embedded policy")
	}
	c.mustListObjects(ctx, svcClient, bucket)
}
