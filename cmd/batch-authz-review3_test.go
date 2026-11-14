// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// A read policy must use the newest tag state of the logical version even
// when an interrupted movement left an older copy in the preferred pool.
func TestBatchReviewPushUsesAuthoritativePoolTags(t *testing.T) {
	z, bucket := consistencyPools(t)
	f := newBatchAuthzFixture(t)
	const name = "push/tagged"
	first := map[string]string{
		xhttp.AmzObjectTagging:                         "classification=public",
		ReservedMetadataPrefixLower + TaggingTimestamp: UTCNow().Add(-time.Hour).Format(time.RFC3339Nano),
	}
	second := map[string]string{
		xhttp.AmzObjectTagging:                         "classification=private",
		ReservedMetadataPrefixLower + TaggingTimestamp: UTCNow().Format(time.RFC3339Nano),
	}
	before := putConsistencyObject(t, z, bucket, name, 0, "test payload", ObjectOptions{Versioned: true, UserDefined: first})
	putConsistencyObject(t, z, bucket, name, 1, "test payload", ObjectOptions{Versioned: true, VersionID: before.VersionID, MTime: before.ModTime, UserDefined: second})
	logical, err := z.replicaObjectInfo(f.ctx, bucket, name, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, err)
	if logical.UserTags != "classification=private" {
		t.Fatal("control: logical version must have the newer private tag")
	}
	batchAuthzPolicy(f.ctx, t, f.sys, "pooled-push", fmt.Sprintf(`
{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::%s/*"]},
{"Effect":"Deny","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::%s/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/classification":"private"}}}`, bucket, bucket))
	cred := iamAdminUser(f.ctx, t, f.sys, "pooled-push-user", "pooled-push")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	if err := sub.authorize(f.ctx, batchAuthzRequest{action: policy.GetObjectAction, bucket: bucket, object: name, versionID: before.VersionID, tags: logical.UserTags}); !isBatchJobAuthzError(err) {
		t.Fatal("control: authoritative tags must deny the read")
	}
	writes := 0
	target, err := minio.NewCore("target.invalid", &minio.Options{
		Region: "us-east-1", Creds: credentials.NewStaticV4("test-access", "test-secret", ""),
		Transport: batchLockTransport(func(r *http.Request) (*http.Response, error) {
			if r.Body != nil {
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
			}
			if r.Method == http.MethodPut {
				writes++
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
	if !isBatchJobAuthzError(err) || writes != 0 {
		t.Errorf("newer authoritative tags must deny push: err=%v writes=%d", err, writes)
	}
}

// Verified token claims must not replace the actual version being authorized.
func TestBatchReviewVersionConditionResistsClaimCollision(t *testing.T) {
	f := newBatchAuthzFixture(t)
	deniedVersion := mustGetUUID()
	batchAuthzPolicy(f.ctx, t, f.sys, "version-claims", batchAuthzFullAccess+fmt.Sprintf(`,
{"Effect":"Deny","Action":["s3:DeleteObjectVersion"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"StringEquals":{"s3:versionid":"%s"}}}`, deniedVersion))
	parent := iamAdminUser(f.ctx, t, f.sys, "version-claims-parent", "version-claims")
	cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{
		parentClaim: parent.AccessKey, "exp": UTCNow().Add(time.Hour).Unix(), "versionid": "an-unrelated-claim-value",
	}, globalActiveCred.SecretKey)
	mustIAM(t, err)
	cred.ParentUser = parent.AccessKey
	_, err = f.sys.SetTempUser(f.ctx, cred.AccessKey, cred, "")
	mustIAM(t, err)
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	req := batchAuthzRequest{action: policy.DeleteObjectVersionAction, bucket: f.bucket, object: "data", versionID: deniedVersion}
	if err := sub.authorize(f.ctx, req); !isBatchJobAuthzError(err) {
		t.Errorf("a token claim must not replace the actual denied version: %v", err)
	}
}

// Retry totals describe a pass, including markers already successful before
// another item caused that pass to retry.
func TestBatchReviewMarkerSuccessCountResetsOnRetry(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchPutVersion(t, f.obj, f.bucket, "marker", nil)
	_, err := f.obj.DeleteObject(f.ctx, f.bucket, "marker", ObjectOptions{Versioned: true})
	mustIAM(t, err)
	oldTransport := remoteInstanceTransport
	remoteInstanceTransport = atomic.Value{}
	setRemoteInstanceTransport(batchLockTransport(func(r *http.Request) (*http.Response, error) {
		code, body := http.StatusForbidden, `<Error><Code>AccessDenied</Code><Message>test refusal</Message></Error>`
		h := make(http.Header)
		switch {
		case r.URL.Query().Has("location"):
			code, body = http.StatusOK, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`
		case r.Method == http.MethodDelete:
			code, body = http.StatusNoContent, ""
		case r.Method == http.MethodHead && r.URL.Query().Get("versionId") != "":
			code, body = http.StatusMethodNotAllowed, ""
			h.Set("X-Amz-Delete-Marker", "true")
		}
		return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}))
	t.Cleanup(func() { remoteInstanceTransport = oldTransport })
	job := BatchJobRequest{
		ID: "marker-success-retry" + getKeySeparator() + "0", Started: UTCNow(), Submitter: batchRootSubmitter(t),
		Replicate: &BatchJobReplicateV1{
			Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: f.bucket},
			Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: "remote", Endpoint: "https://target.invalid", Creds: BatchJobReplicateCredentials{AccessKey: "test-access", SecretKey: "test-secret"}},
		},
	}
	job.Replicate.Flags.Retry.Attempts = 2
	job.Replicate.Flags.Retry.Delay = time.Millisecond
	mustIAM(t, job.Replicate.Start(f.ctx, f.obj, job))
	ri := f.jobInfo(t, &job)
	if !ri.Failed || ri.RetryAttempts != 2 {
		t.Fatalf("control: data failure must cause two attempts: failed=%v attempts=%d", ri.Failed, ri.RetryAttempts)
	}
	if ri.DeleteMarkers != 1 {
		t.Errorf("one successful marker must be counted once in the final attempt, got %d", ri.DeleteMarkers)
	}
}
