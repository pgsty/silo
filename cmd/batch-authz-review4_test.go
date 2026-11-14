// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// A tag removal in a newer copy must govern both the authorization and the
// metadata sent by a push. The submitter can read data but cannot read tags.
func TestBatchReviewPushSendsOnlyAuthorizedMetadata(t *testing.T) {
	z, bucket := consistencyPools(t)
	f := newBatchAuthzFixture(t)
	const name = "push/removed-tags"
	first := map[string]string{
		xhttp.AmzObjectTagging:                         "classification=private",
		ReservedMetadataPrefixLower + TaggingTimestamp: UTCNow().Add(-time.Hour).Format(time.RFC3339Nano),
	}
	second := map[string]string{
		xhttp.AmzObjectTagging:                         "",
		ReservedMetadataPrefixLower + TaggingTimestamp: UTCNow().Format(time.RFC3339Nano),
	}
	before := putConsistencyObject(t, z, bucket, name, 0, "test payload", ObjectOptions{Versioned: true, UserDefined: first})
	putConsistencyObject(t, z, bucket, name, 1, "test payload", ObjectOptions{Versioned: true, VersionID: before.VersionID, MTime: before.ModTime, UserDefined: second})
	logical, err := z.replicaObjectInfo(f.ctx, bucket, name, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, err)
	if logical.UserTags != "" {
		t.Fatal("control: the authoritative version must have no tags")
	}
	batchAuthzPolicy(f.ctx, t, f.sys, "data-without-tags", fmt.Sprintf(`
{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::%s/*"]},
{"Effect":"Deny","Action":["s3:GetObjectTagging","s3:GetObjectVersionTagging"],"Resource":["arn:aws:s3:::%s/*"]}`, bucket, bucket))
	cred := iamAdminUser(f.ctx, t, f.sys, "data-without-tags-user", "data-without-tags")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	if err := sub.authorize(f.ctx, batchAuthzRequest{action: policy.GetObjectTaggingAction, bucket: bucket, object: name, versionID: before.VersionID}); !isBatchJobAuthzError(err) {
		t.Fatal("control: reading tags must be denied")
	}
	writes := 0
	var sentTags string
	target, err := minio.NewCore("target.invalid", &minio.Options{
		Region: "us-east-1", Creds: credentials.NewStaticV4("test-access", "test-secret", ""),
		Transport: batchLockTransport(func(r *http.Request) (*http.Response, error) {
			if r.Body != nil {
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
			}
			if r.Method == http.MethodPut {
				writes++
				sentTags = r.Header.Get(xhttp.AmzObjectTagging)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Etag": {"\"test-etag\""}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}),
	})
	mustIAM(t, err)
	r := BatchJobReplicateV1{
		Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: bucket},
		Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: "remote"},
	}
	err = r.ReplicateToTarget(f.ctx, z, target, before, false, sub)
	if err != nil && !isBatchJobAuthzError(err) {
		t.Fatalf("unexpected replication failure: %v", err)
	}
	if writes > 0 && sentTags != logical.UserTags {
		t.Errorf("push must send only metadata covered by authorization: writes=%d sentTags=%q authorizedTags=%q err=%v", writes, sentTags, logical.UserTags, err)
	}
}

// LDAP's short username and its parent DN are distinct identities. The
// background merge must not turn a deny for the verified short name into
// a non-matching statement by replacing it with the parent DN.
func TestBatchReviewLDAPUsernameDeny(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "ldap-short-name-deny", batchAuthzFullAccess+`,
{"Effect":"Deny","Action":["s3:DeleteObjectVersion"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"StringEquals":{"ldap:username":"alice"}}}`)
	const dn = "uid=alice,ou=people,dc=example,dc=org"
	cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{
		"exp": UTCNow().Add(time.Hour).Unix(), ldapUser: dn, ldapActualUser: dn, ldapUserN: "alice",
	}, globalActiveCred.SecretKey)
	mustIAM(t, err)
	cred.ParentUser = dn
	_, err = f.sys.SetTempUser(f.ctx, cred.AccessKey, cred, "ldap-short-name-deny")
	mustIAM(t, err)
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	p, err := sub.principal(f.ctx)
	mustIAM(t, err)
	cred.Claims = p.claims
	req, err := http.NewRequest(http.MethodDelete, "https://localhost/batch-authz/data", nil)
	mustIAM(t, err)
	args := policy.Args{
		AccountName: cred.AccessKey, Claims: p.claims, Action: policy.DeleteObjectVersionAction,
		BucketName: f.bucket, ObjectName: "data", ConditionValues: getConditionValues(req, "", cred),
	}
	if args.ConditionValues["username"][0] != "alice" || f.sys.isAllowedLocally(args) {
		t.Fatal("control: the request evaluator must deny the verified LDAP short username")
	}
	if err := sub.authorize(f.ctx, batchAuthzRequest{action: policy.DeleteObjectVersionAction, bucket: f.bucket, object: "data", versionID: mustGetUUID()}); !isBatchJobAuthzError(err) {
		t.Errorf("batch authorization must preserve the LDAP username deny or fail closed, got %v", err)
	}
}

// Failure to read authoritative metadata is incomplete work, even if one
// pool's copy can still be opened. In particular, skipErrs=false must not
// turn an unreadable entry into a successful archive.
func TestBatchReviewSnowballAuthoritativeReadFailure(t *testing.T) {
	z, bucket := consistencyPools(t)
	const name = "archive/unreadable-copy"
	before := putConsistencyObject(t, z, bucket, name, 0, "test payload", ObjectOptions{Versioned: true})
	set := z.serverPools[1].sets[0]
	getDisks := set.getDisks
	disks := append([]StorageAPI(nil), getDisks()...)
	for i := range disks {
		disks[i] = consistencyReadFaultDisk{StorageAPI: disks[i], bucket: bucket, object: name}
	}
	set.getDisks = func() []StorageAPI { return disks }
	defer func() { set.getDisks = getDisks }()
	gr, err := z.GetObjectNInfo(t.Context(), bucket, name, nil, nil, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, err)
	_, logicalErr := batchAuthoritativeRead(t.Context(), z, bucket, name, gr.ObjInfo)
	gr.Close()
	if logicalErr == nil {
		t.Fatal("control: the authoritative read must fail")
	}
	remote, err := minio.New("archive.invalid", &minio.Options{
		Region: "us-east-1", Creds: credentials.NewStaticV4("test-access", "test-secret", ""),
		Transport: batchLockTransport(func(r *http.Request) (*http.Response, error) {
			if r.Body != nil {
				_, _ = io.Copy(io.Discard, r.Body)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}),
	})
	mustIAM(t, err)
	r := BatchJobReplicateV1{
		Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: bucket},
		Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: "remote"},
	}
	r.Source.Snowball.InMemory = ptr(true)
	r.Source.Snowball.Compress = ptr(false)
	r.Source.Snowball.SkipErrs = ptr(false)
	if err := r.writeAsArchive(t.Context(), z, remote, []ObjectInfo{before}, "", batchRootSubmitter(t)); err == nil {
		t.Error("archive with an unreadable authoritative version must not report success")
	}
}
