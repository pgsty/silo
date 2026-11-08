// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"strings"
	"testing"

	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// batchContextRead is the object read the tests below authorize.
func batchContextRead(f *batchAuthzFixture) batchAuthzRequest {
	return batchAuthzRequest{action: policy.GetObjectAction, bucket: f.bucket, object: "data/a"}
}

// batchContextUser creates a user with statements as its only policy and
// returns its submitter binding.
func batchContextUser(t *testing.T, f *batchAuthzFixture, name, statements string) (auth.Credentials, *batchJobSubmitter) {
	t.Helper()
	batchAuthzPolicy(f.ctx, t, f.sys, name, statements)
	cred := iamAdminUser(f.ctx, t, f.sys, name+"-user", name)
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	return cred, sub
}

func isBatchContextRefusal(err error) bool {
	return isBatchJobAuthzError(err) && strings.Contains(err.Error(), "request context")
}

// A statement whose resources rule the object out does not apply, whatever
// its conditions need, policy variables in condition values included. One
// whose resources match still refuses.
func TestBatchAuthzContextResourceFirst(t *testing.T) {
	f := newBatchAuthzFixture(t)
	const unrelated = `{"Effect":"Deny","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::other-bucket/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/owner":"${aws:UserAgent}"}}}`
	_, sub := batchContextUser(t, f, "context-unrelated", batchAuthzFullAccess+",\n"+unrelated)
	if err := sub.authorize(f.ctx, batchContextRead(f)); err != nil {
		t.Errorf("a Deny on another bucket refused an allowed read: %v", err)
	}

	related := strings.Replace(unrelated, "other-bucket", f.bucket, 1)
	_, sub = batchContextUser(t, f, "context-related", batchAuthzFullAccess+",\n"+related)
	if err := sub.authorize(f.ctx, batchContextRead(f)); !isBatchContextRefusal(err) {
		t.Errorf("a Deny on the object with an unsupplied variable must refuse, got %v", err)
	}

	// A variable in the resource leaves open whether it matches.
	const resourceVar = `{"Effect":"Deny","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/${aws:UserAgent}/*"]}`
	_, sub = batchContextUser(t, f, "context-resource-var", batchAuthzFullAccess+",\n"+resourceVar)
	if err := sub.authorize(f.ctx, batchContextRead(f)); !isBatchContextRefusal(err) {
		t.Errorf("a Deny whose resource holds an unsupplied variable must refuse, got %v", err)
	}
}

// An Allow that needs request context the job does not have grants nothing
// to the job; it neither refuses the job nor grants by an absent key.
func TestBatchAuthzContextAllowDropped(t *testing.T) {
	f := newBatchAuthzFixture(t)
	const ipAllow = `{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::*"],"Condition":{"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}}`
	_, sub := batchContextUser(t, f, "context-ip-allow", batchAuthzFullAccess+",\n"+ipAllow)
	if err := sub.authorize(f.ctx, batchContextRead(f)); err != nil {
		t.Errorf("a conditional Allow refused a read another Allow grants: %v", err)
	}

	// A Null condition holds for an absent key: evaluated without the
	// context, this Allow would grant what no request with an address gets.
	const nullAllow = `{"Effect":"Allow","Action":["admin:StartBatchJob"]},
{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"Null":{"aws:SourceIp":"true"}}}`
	cred, sub := batchContextUser(t, f, "context-null-allow", nullAllow)
	if !f.sys.isAllowedLocally(policy.Args{AccountName: cred.AccessKey, Action: policy.GetObjectAction, BucketName: f.bucket, ObjectName: "data/a", ConditionValues: map[string][]string{}}) {
		t.Fatal("control: without the address the Null Allow grants")
	}
	err := sub.authorize(f.ctx, batchContextRead(f))
	if !isBatchJobAuthzError(err) || isBatchContextRefusal(err) {
		t.Errorf("an Allow that needs the address must grant nothing, and deny rather than refuse; got %v", err)
	}
}

// The same holds for the Allows of a session policy, which only narrows.
func TestBatchAuthzContextSessionAllow(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "context-session-parent", batchAuthzFullAccess)
	parent := iamAdminUser(f.ctx, t, f.sys, "context-session-parent", "context-session-parent")
	for _, tc := range []struct {
		name, statements string
		allowed          bool
	}{
		{"null-only", `{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"Null":{"aws:SourceIp":"true"}}}`, false},
		{"with-plain", `{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"Null":{"aws:SourceIp":"true"}}},
{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/data/*"]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, err := policy.ParseConfig(strings.NewReader(`{"Version":"2012-10-17","Statement":[` + tc.statements + `]}`))
			mustIAM(t, err)
			created, _, err := f.sys.NewServiceAccount(f.ctx, parent.AccessKey, nil, newServiceAccountOpts{sessionPolicy: sp})
			mustIAM(t, err)
			stored, ok := f.sys.GetUser(f.ctx, created.AccessKey)
			if !ok {
				t.Fatal("service account missing")
			}
			sub, err := newBatchJobSubmitter(stored.Credentials)
			mustIAM(t, err)
			err = sub.authorize(f.ctx, batchContextRead(f))
			switch {
			case isBatchContextRefusal(err):
				t.Errorf("a session-policy Allow refused the job: %v", err)
			case tc.allowed && err != nil:
				t.Errorf("the plain session Allow must still grant: %v", err)
			case !tc.allowed && !isBatchJobAuthzError(err):
				t.Errorf("a session policy whose only Allow needs the address must deny, got %v", err)
			}
		})
	}
}
