// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// A pull into a suspended bucket replaces the null version. Its policy
// decision must name that version even when the source is unversioned S3.
func TestBatchReviewPullImplicitNullVersionAuthorization(t *testing.T) {
	f := newBatchAuthzFixture(t)
	_, err := globalBucketMetadataSys.Update(f.ctx, f.bucket, bucketVersioningConfig, []byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Suspended</Status></VersioningConfiguration>`))
	mustIAM(t, err)
	data := []byte("original null version")
	before, err := f.obj.PutObject(f.ctx, f.bucket, "pull/null", mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{VersionSuspended: true})
	mustIAM(t, err)
	batchAuthzPolicy(f.ctx, t, f.sys, "null-deny", batchAuthzFullAccess+`,
{"Effect":"Deny","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"StringEquals":{"s3:versionid":"null"}}}`)
	cred := iamAdminUser(f.ctx, t, f.sys, "null-deny-user", "null-deny")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	job := batchPullJob(f.bucket)
	job.Source.Type = BatchJobReplicateResourceS3
	err = job.ReplicateFromSource(f.ctx, f.obj, batchLockRemote(t, "replacement"), ObjectInfo{
		Name: before.Name, ModTime: UTCNow(), ETag: "batchetag", UserDefined: map[string]string{},
	}, false, sub)
	if !isBatchJobAuthzError(err) {
		t.Errorf("null version policy must refuse the write, got %v", err)
	}
	after, gerr := f.obj.GetObjectInfo(f.ctx, f.bucket, before.Name, ObjectOptions{VersionID: nullVersionID})
	if gerr != nil || before.ETag != after.ETag {
		t.Errorf("denied null version must remain unchanged: read=%v unchanged=%v", gerr, before.ETag == after.ETag)
	}
}

type batchReviewPrefixWalkFailure struct{ ObjectLayer }

func (a batchReviewPrefixWalkFailure) Walk(ctx context.Context, bucket, prefix string, results chan<- itemOrErr[ObjectInfo], opts WalkOptions) error {
	if prefix != "a/" {
		return a.ObjectLayer.Walk(ctx, bucket, prefix, results, opts)
	}
	go func() {
		defer close(results)
		results <- itemOrErr[ObjectInfo]{Err: errors.New("test: incomplete first prefix")}
	}()
	return nil
}

type batchReviewWalkCutoff struct {
	ObjectLayer
	cutoff string
}

func (a batchReviewWalkCutoff) Walk(ctx context.Context, bucket, prefix string, results chan<- itemOrErr[ObjectInfo], opts WalkOptions) error {
	inner := make(chan itemOrErr[ObjectInfo], 1)
	if err := a.ObjectLayer.Walk(ctx, bucket, prefix, inner, opts); err != nil {
		close(results)
		return err
	}
	go func() {
		defer close(results)
		stopped := false
		for result := range inner {
			if stopped {
				continue
			}
			if result.Err == nil && result.Item.Name >= a.cutoff {
				stopped = true
				result = itemOrErr[ObjectInfo]{Err: errors.New("test: listing stopped before remaining child keys")}
			}
			select {
			case results <- result:
			case <-ctx.Done():
				stopped = true
			}
		}
	}()
	return nil
}

// Listing a directory prefix returns the directory object before its child
// keys. A durable cursor for that directory must preserve unfinished children.
func TestBatchReviewDirectoryCursorKeepsChildrenPending(t *testing.T) {
	f := newBatchAuthzFixture(t)
	for range 12 {
		batchPutVersion(t, f.obj, f.bucket, "a/", nil)
	}
	var pending string
	for i := 0; i < 13; i++ {
		older := f.putVersions(t, fmt.Sprintf("a/key-%02d", i))
		if i == 11 {
			pending = older
		}
	}
	rec, job := f.submit(t, globalActiveCred, fmt.Sprintf(`expire:
  apiVersion: v1
  bucket: %s
  prefix: ["a/"]
  rules:
    - type: object
      purge:
        retainVersions: 1
`, f.bucket))
	if job == nil {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
	}
	_ = job.Expire.Start(f.ctx, batchReviewWalkCutoff{ObjectLayer: f.obj, cutoff: "a/key-11"}, *job)
	ri := f.jobInfo(t, job)
	if ri.Object != "a/" {
		t.Fatalf("control: the completed directory batch must be the cursor, got %q", ri.Object)
	}
	mustIAM(t, job.Expire.Start(f.ctx, f.obj, *job))
	if f.versionExists(t, "a/key-11", pending) {
		t.Error("a directory cursor must not suppress the unvisited child key on resume")
	}
}

// Later prefixes must not advance the completion cursor past an earlier
// prefix whose listing failed. This state is produced by Start itself.
func TestBatchReviewExpireFailedPrefixKeepsWorkPending(t *testing.T) {
	f := newBatchAuthzFixture(t)
	older := f.putVersions(t, "a/todo")
	for i := 0; i < 13; i++ {
		f.putVersions(t, fmt.Sprintf("z/key-%02d", i))
	}
	rec, job := f.submit(t, globalActiveCred, fmt.Sprintf(`expire:
  apiVersion: v1
  bucket: %s
  prefix: ["z/", "a/"]
  rules:
    - type: object
      purge:
        retainVersions: 1
`, f.bucket))
	if job == nil {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
	}
	_ = job.Expire.Start(f.ctx, batchReviewPrefixWalkFailure{f.obj}, *job)
	ri := f.jobInfo(t, job)
	if ri.Object >= "a/todo" {
		t.Errorf("cursor must not cross an incomplete prefix, got %q", ri.Object)
	}
	mustIAM(t, job.Expire.Start(f.ctx, f.obj, *job))
	if f.versionExists(t, "a/todo", older) {
		t.Error("a fresh Start must revisit the key omitted by the failed listing")
	}
}

// A repeated marker replication error must remain a failure on the second
// attempt, including after the retry loop resets its counters.
func TestBatchReviewMarkerRetryRemainsFailed(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchPutVersion(t, f.obj, f.bucket, "marker", nil)
	_, err := f.obj.DeleteObject(f.ctx, f.bucket, "marker", ObjectOptions{Versioned: true})
	mustIAM(t, err)
	oldTransport := globalRemoteTargetTransport
	globalRemoteTargetTransport = batchLockTransport(func(r *http.Request) (*http.Response, error) {
		code, body := http.StatusForbidden, `<Error><Code>AccessDenied</Code><Message>test refusal</Message></Error>`
		if r.URL.Query().Has("location") {
			code, body = http.StatusOK, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`
		}
		return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	t.Cleanup(func() { globalRemoteTargetTransport = oldTransport })
	job := BatchJobRequest{
		ID: "replicate-marker-retry" + getKeySeparator() + "0", Started: UTCNow(), Submitter: batchRootSubmitter(t),
		Replicate: &BatchJobReplicateV1{
			Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: f.bucket},
			Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: "remote", Endpoint: "https://target.invalid", Creds: BatchJobReplicateCredentials{AccessKey: "test-access", SecretKey: "test-secret"}},
		},
	}
	job.Replicate.Flags.Retry.Attempts = 2
	job.Replicate.Flags.Retry.Delay = time.Millisecond
	mustIAM(t, job.Replicate.Start(f.ctx, f.obj, job))
	ri := f.jobInfo(t, &job)
	if ri.Complete || !ri.Failed || ri.DeleteMarkersFailed != 1 {
		t.Errorf("both marker attempts failed: complete=%v failed=%v markerFailures=%d attempts=%d", ri.Complete, ri.Failed, ri.DeleteMarkersFailed, ri.RetryAttempts)
	}
}

// A current parent mapping suppresses the OpenID policy-name fallback.
// Background-condition validation must inspect the same effective policies.
func TestBatchReviewMappedPolicySuppressesClaimFallback(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "mapped-full", batchAuthzFullAccess)
	batchAuthzPolicy(f.ctx, t, f.sys, "unused-claim-policy", `{"Effect":"Deny","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}`)
	parent := iamAdminUser(f.ctx, t, f.sys, "mapped-parent", "mapped-full")
	cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{
		parentClaim: parent.AccessKey, "exp": UTCNow().Add(time.Hour).Unix(), iamPolicyClaimNameOpenID(): "unused-claim-policy",
	}, globalActiveCred.SecretKey)
	mustIAM(t, err)
	cred.ParentUser = parent.AccessKey
	_, err = f.sys.SetTempUser(f.ctx, cred.AccessKey, cred, "")
	mustIAM(t, err)
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	p, err := sub.principal(f.ctx)
	mustIAM(t, err)
	req := batchAuthzRequest{action: policy.GetObjectAction, bucket: f.bucket, object: "mapped/key", versionID: mustGetUUID()}
	if !f.sys.isAllowedLocally(policy.Args{AccountName: p.accessKey, Claims: p.claims, Action: req.action, BucketName: req.bucket, ObjectName: req.object, ConditionValues: p.conditionValues(req)}) {
		t.Fatal("control: the current mapped policy must allow this read")
	}
	if err := sub.authorize(f.ctx, req); err != nil {
		t.Errorf("an unused fallback policy must not refuse a mapped-policy grant: %v", err)
	}
}

func TestBatchReviewBindingAndExpiringServiceControls(t *testing.T) {
	f := newBatchAuthzFixture(t)
	root := batchRootSubmitter(t)
	priorRoot := globalActiveCred
	globalActiveCred.SecretKey = "different-test-root-secret"
	_, err := root.principal(f.ctx)
	globalActiveCred = priorRoot
	if !isBatchJobAuthzError(err) {
		t.Errorf("root-secret change must invalidate the binding: %v", err)
	}
	missing := *root
	missing.Binding = nil
	if _, err := missing.principal(f.ctx); !isBatchJobAuthzError(err) {
		t.Errorf("missing fingerprint must refuse the principal: %v", err)
	}
	batchAuthzPolicy(f.ctx, t, f.sys, "service-parent-full", batchAuthzFullAccess)
	parent := iamAdminUser(f.ctx, t, f.sys, "service-parent", "service-parent-full")
	sp, err := policy.ParseConfig(strings.NewReader(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/*"]}]}`))
	mustIAM(t, err)
	expires := UTCNow().Add(time.Hour)
	cred, _, err := f.sys.NewServiceAccount(f.ctx, parent.AccessKey, nil, newServiceAccountOpts{sessionPolicy: sp, expiration: &expires})
	mustIAM(t, err)
	stored, ok := f.sys.GetUser(f.ctx, cred.AccessKey)
	if !ok {
		t.Fatal("created service account must resolve")
	}
	cred = stored.Credentials
	if !cred.IsTemp() || !cred.IsServiceAccount() {
		t.Fatal("fixture must be an expiring service account")
	}
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	if err := sub.authorize(f.ctx, batchAuthzRequest{action: policy.GetObjectAction, bucket: f.bucket, object: "allowed"}); err != nil {
		t.Errorf("expiring service account must retain its allowed read: %v", err)
	}
	if err := sub.authorize(f.ctx, batchAuthzRequest{action: policy.DeleteObjectAction, bucket: f.bucket, object: "allowed"}); !isBatchJobAuthzError(err) {
		t.Errorf("expiring service account must remain session-policy restricted: %v", err)
	}
}

// An interrupted cross-pool copy can leave the same version in both pools.
// A newer legal-hold field in either copy must prevent key rotation.
func TestBatchReviewRotationUsesAuthoritativePoolHold(t *testing.T) {
	z, bucket := consistencyPools(t)
	const name = "rotation/split-hold"
	previousKMS := GlobalKMS
	GlobalKMS = kms.NewStub("batch-rotation-key")
	t.Cleanup(func() { GlobalKMS = previousKMS })
	dek, err := GlobalKMS.GenerateKey(t.Context(), &kms.GenerateKeyRequest{AssociatedData: kms.Context{bucket: bucket + "/" + name}})
	mustIAM(t, err)
	objectKey := crypto.GenerateKey(dek.Plaintext, nil)
	sealed := objectKey.Seal(dek.Plaintext, crypto.GenerateIV(nil), crypto.S3.String(), bucket, name)
	first := crypto.S3.CreateMetadata(nil, dek.KeyID, dek.Ciphertext, sealed)
	first[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = "OFF"
	first[ReservedMetadataPrefixLower+ObjectLockLegalHoldTimestamp] = UTCNow().Add(-time.Hour).Format(time.RFC3339Nano)
	second := maps.Clone(first)
	second[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = "ON"
	second[ReservedMetadataPrefixLower+ObjectLockLegalHoldTimestamp] = UTCNow().Format(time.RFC3339Nano)
	ciphertext, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader("protected payload"), objectKey))
	mustIAM(t, err)
	before := putConsistencyObject(t, z, bucket, name, 0, string(ciphertext), ObjectOptions{Versioned: true, UserDefined: first})
	putConsistencyObject(t, z, bucket, name, 1, string(ciphertext), ObjectOptions{Versioned: true, VersionID: before.VersionID, MTime: before.ModTime, UserDefined: second})
	logical, err := z.replicaObjectInfo(t.Context(), bucket, name, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, err)
	if !enforceRetentionForDeletion(t.Context(), logical) {
		t.Fatal("control: the authoritative logical version must be held")
	}
	r := BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: sses3}}
	err = r.KeyRotate(t.Context(), z, before, batchRootSubmitter(t))
	if !isErrObjectLocked(err) {
		t.Errorf("rotation must refuse the authoritative legal hold, got %v", err)
	}
	after, gerr := z.serverPools[0].GetObjectInfo(t.Context(), bucket, name, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, gerr)
	if after.UserDefined[crypto.MetaSealedKeyS3] != before.UserDefined[crypto.MetaSealedKeyS3] {
		t.Error("held logical version must not have its key rewritten")
	}
}

// An encryption condition must describe what rotation actually commits,
// even when the requested encryption type differs from the existing type.
func TestBatchReviewRotationEncryptionConditionMatchesResult(t *testing.T) {
	f := newBatchAuthzFixture(t)
	previousKMS := GlobalKMS
	GlobalKMS = kms.NewStub("required-key")
	t.Cleanup(func() { GlobalKMS = previousKMS })
	const name = "rotation/encryption-condition"
	meta := make(map[string]string)
	key, err := newEncryptMetadata(f.ctx, crypto.S3, "", nil, f.bucket, name, meta, nil)
	mustIAM(t, err)
	body, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader("encrypted payload"), key))
	mustIAM(t, err)
	before, err := f.obj.PutObject(f.ctx, f.bucket, name, mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), ObjectOptions{Versioned: true, UserDefined: meta})
	mustIAM(t, err)
	batchAuthzPolicy(f.ctx, t, f.sys, "kms-write-only", `
{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::batch-authz/*"]},
{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"StringEquals":{"s3:x-amz-server-side-encryption":"aws:kms","s3:x-amz-server-side-encryption-aws-kms-key-id":"required-key"}}}`)
	cred := iamAdminUser(f.ctx, t, f.sys, "kms-write-user", "kms-write-only")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	r := BatchJobKeyRotateV1{Bucket: f.bucket, Encryption: BatchJobKeyRotateEncryption{Type: ssekms, Key: "required-key"}}
	err = r.KeyRotate(f.ctx, f.obj, before, sub)
	after, gerr := f.obj.GetObjectInfo(f.ctx, f.bucket, name, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, gerr)
	if err == nil && !crypto.S3KMS.IsEncrypted(after.UserDefined) {
		t.Error("rotation allowed by an aws:kms-only write policy must produce SSE-KMS or refuse the operation")
	}
	if err != nil && before.UserDefined[crypto.MetaSealedKeyS3] != after.UserDefined[crypto.MetaSealedKeyS3] {
		t.Error("a refused rotation must leave the version unchanged")
	}
}

// An explicit null marker collision must retain a held null data version.
func TestBatchReviewPullMarkerNullLock(t *testing.T) {
	f := newBatchAuthzFixture(t)
	meta := batchLockMeta("LEGALHOLD")
	before, err := f.obj.PutObject(f.ctx, f.bucket, "pull/null", mustGetPutObjReader(t, strings.NewReader("held null"), 9, "", ""), ObjectOptions{VersionID: nullVersionID, Versioned: true, UserDefined: meta})
	mustIAM(t, err)
	job := BatchJobReplicateV1{
		Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: "remote"},
		Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: f.bucket},
	}
	err = job.ReplicateFromSource(f.ctx, f.obj, nil, ObjectInfo{
		Name: before.Name, VersionID: nullVersionID, ModTime: UTCNow(), DeleteMarker: true,
	}, false, batchRootSubmitter(t))
	if !isErrObjectLocked(err) {
		t.Errorf("marker collision with protected null data must return ObjectLocked, got %v", err)
	}
	if !batchVersionExists(t, f.obj, f.bucket, before.Name, nullVersionID) {
		t.Fatal("protected null data must remain present")
	}
}
