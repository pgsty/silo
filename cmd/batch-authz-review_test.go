// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	polplugin "github.com/minio/minio/internal/config/policy/plugin"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	xnet "github.com/pgsty/silo-pkg/v3/net"
	"github.com/pgsty/silo-pkg/v3/policy"
)

func batchPullJob(bucket string) BatchJobReplicateV1 {
	return BatchJobReplicateV1{
		Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: "remote"},
		Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: bucket},
	}
}

// A pull does not read the destination version it may replace, so a policy
// that conditions the write on that version's tags refuses it; a version
// condition sees the version the pull writes.
func TestBatchPullDestinationConditions(t *testing.T) {
	for _, tc := range []struct {
		name      string
		action    policy.Action
		marker    bool
		condition func(versionID string) string
	}{
		{"tags-put", policy.ReplicateObjectAction, false, func(string) string {
			return `{"StringEquals":{"s3:ExistingObjectTag/class":"protected"}}`
		}},
		{"tags-marker", policy.ReplicateDeleteAction, true, func(string) string {
			return `{"StringEquals":{"s3:ExistingObjectTag/class":"protected"}}`
		}},
		{"version-put", policy.PutObjectAction, false, func(v string) string {
			return fmt.Sprintf(`{"StringEquals":{"s3:versionid":%q}}`, v)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			before := batchPutVersion(t, f.obj, f.bucket, "pull/guarded", map[string]string{xhttp.AmzObjectTagging: "class=protected"})
			batchAuthzPolicy(f.ctx, t, f.sys, "pull-guard", batchAuthzFullAccess+fmt.Sprintf(`,
{"Effect":"Deny","Action":[%q],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":%s}`, tc.action, tc.condition(before.VersionID)))
			cred := iamAdminUser(f.ctx, t, f.sys, "pull-guard-user", "pull-guard")
			sub, err := newBatchJobSubmitter(cred)
			mustIAM(t, err)
			job := batchPullJob(f.bucket)
			err = job.ReplicateFromSource(f.ctx, f.obj, batchLockRemote(t, "replacement"), ObjectInfo{
				Name: before.Name, VersionID: before.VersionID, ModTime: UTCNow(), ETag: "batchetag",
				DeleteMarker: tc.marker, UserDefined: map[string]string{},
			}, false, sub)
			if !isBatchJobAuthzError(err) {
				t.Errorf("pull returned %v, want a refusal", err)
			}
			after, err := f.obj.GetObjectInfo(f.ctx, f.bucket, before.Name, ObjectOptions{VersionID: before.VersionID})
			if err != nil || after.ETag != before.ETag {
				t.Errorf("refused pull changed the destination version: %v", err)
			}
		})
	}
}

// A pull does not encrypt what it writes; encryption headers reported by the
// source do not satisfy a destination policy that requires encryption.
func TestBatchPullEncryptionCondition(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "pull-encryption", `
{"Effect":"Allow","Action":["s3:ReplicateObject"],"Resource":["arn:aws:s3:::batch-authz/*"]},
{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"StringEquals":{"s3:x-amz-server-side-encryption":"aws:kms","s3:x-amz-server-side-encryption-aws-kms-key-id":"required-key"}}}`)
	cred := iamAdminUser(f.ctx, t, f.sys, "pull-encryption-user", "pull-encryption")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	job := batchPullJob(f.bucket)
	version := mustGetUUID()
	err = job.ReplicateFromSource(f.ctx, f.obj, batchLockRemote(t, "content"), ObjectInfo{
		Name: "pull/encrypted", VersionID: version, ModTime: UTCNow(), ETag: "batchetag",
		UserDefined: map[string]string{xhttp.AmzServerSideEncryption: "aws:kms", xhttp.AmzServerSideEncryptionKmsID: "required-key"},
	}, false, sub)
	if err == nil {
		oi, gerr := f.obj.GetObjectInfo(f.ctx, f.bucket, "pull/encrypted", ObjectOptions{VersionID: version})
		mustIAM(t, gerr)
		if !crypto.S3KMS.IsEncrypted(oi.UserDefined) {
			t.Fatal("a pull was allowed by an encryption condition it did not meet")
		}
	}
}

// A conditional Deny on an S3 Tables action covers the S3 data actions it
// implies, under the tables resource form; the job refuses rather than skip it.
func TestBatchJobTableConditionalDeny(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "table-context", batchAuthzFullAccess+`,
{"Effect":"Deny","Action":["s3tables:GetTableData"],"Resource":["arn:aws:s3tables:::bucket/batch-authz/table/table-id"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}`)
	cred := iamAdminUser(f.ctx, t, f.sys, "table-context-user", "table-context")
	if f.sys.isAllowedLocally(policy.Args{AccountName: cred.AccessKey, Action: policy.GetObjectAction, BucketName: f.bucket, ObjectName: "table-id/data", ConditionValues: map[string][]string{"SecureTransport": {"false"}}}) {
		t.Fatal("control: with the request context the Deny applies")
	}
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	if err := sub.authorize(f.ctx, batchAuthzRequest{action: policy.GetObjectAction, bucket: f.bucket, object: "table-id/data"}); !isBatchJobAuthzError(err) {
		t.Fatalf("authorize returned %v, want a refusal", err)
	}
}

type batchArchiveRevocation struct {
	ObjectLayer
	revoke func()
}

func (a *batchArchiveRevocation) GetObjectNInfo(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, opts ObjectOptions) (*GetObjectReader, error) {
	if object == "archive/second" {
		a.revoke()
	}
	return a.ObjectLayer.GetObjectNInfo(ctx, bucket, object, rs, h, opts)
}

// Each snowball entry is authorized for the submitter as it is then.
func TestBatchPushSnowballEntryRevalidation(t *testing.T) {
	f := newBatchAuthzFixture(t)
	cred := iamAdminUser(f.ctx, t, f.sys, "archive-user", "")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	pluginURL, err := xnet.ParseHTTPURL("https://authz.invalid/")
	mustIAM(t, err)
	previous := newGlobalAuthZPluginFn()
	setGlobalAuthZPlugin(polplugin.New(polplugin.Args{
		URL: pluginURL, CloseRespFn: func(r io.ReadCloser) { _ = r.Close() },
		Transport: batchLockTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"result":true}`)), Request: r}, nil
		}),
	}))
	t.Cleanup(func() { setGlobalAuthZPlugin(previous) })
	entries := []ObjectInfo{
		batchPutVersion(t, f.obj, f.bucket, "archive/first", nil),
		batchPutVersion(t, f.obj, f.bucket, "archive/second", nil),
	}
	remote, err := minio.New("archive.invalid", &minio.Options{
		Region: "us-east-1", Creds: credentials.NewStaticV4("batch-access", "batch-secret", ""),
		Transport: batchLockTransport(func(r *http.Request) (*http.Response, error) {
			if r.Body != nil {
				_, _ = io.Copy(io.Discard, r.Body)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}),
	})
	mustIAM(t, err)
	job := BatchJobReplicateV1{Source: BatchJobReplicateSource{Bucket: f.bucket}, Target: BatchJobReplicateTarget{Bucket: "remote"}}
	job.Source.Snowball.InMemory = ptr(true)
	job.Source.Snowball.Compress = ptr(false)
	job.Source.Snowball.SkipErrs = ptr(false)
	api := &batchArchiveRevocation{ObjectLayer: f.obj, revoke: func() { mustIAM(t, f.sys.DeleteUser(f.ctx, cred.AccessKey, false)) }}
	if err = job.writeAsArchive(f.ctx, api, remote, entries, "", sub); !isBatchJobAuthzError(err) {
		t.Fatalf("archive with a revoked submitter returned %v, want a refusal", err)
	}
}

// A definition holds one job type; one with several is refused, so that what
// is authorized is what runs.
func TestBatchJobSeveralSections(t *testing.T) {
	f := newBatchAuthzFixture(t)
	older := f.putVersions(t, "data/a")
	job := f.expireYAML("") + `keyrotate:
  apiVersion: v1
  bucket: other
  encryption:
    type: sse-s3
`
	rec, queued := f.submit(t, globalActiveCred, job)
	if queued != nil {
		f.run(t, queued)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("submission status %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !f.versionExists(t, "data/a", older) {
		t.Fatal("a definition with two job types ran")
	}
}

// Prefixes are walked once each in one order: a cursor in a later prefix is
// after every key of the earlier ones, and an overlapping prefix is not
// walked twice.
func TestBatchExpirePrefixes(t *testing.T) {
	if got := batchCanonicalPrefixes([]string{"z/", "a/", "a/b/", "z/", ""}); len(got) != 1 || got[0] != "" {
		t.Fatalf("canonical prefixes %q", got)
	}
	if got := batchCanonicalPrefixes([]string{"z/", "a/b/", "a/"}); strings.Join(got, ",") != "a/,z/" {
		t.Fatalf("canonical prefixes %q", got)
	}
	f := newBatchAuthzFixture(t)
	done := f.putVersions(t, "a/done")
	todo := f.putVersions(t, "z/todo")
	batchPutVersion(t, f.obj, f.bucket, "x/data", batchLockMeta("LEGALHOLD"))
	batchPutVersion(t, f.obj, f.bucket, "x/data", nil)
	rec, job := f.submit(t, globalActiveCred, fmt.Sprintf(`expire:
  apiVersion: v1
  bucket: %s
  prefix: ["z/", "x/", "a/", "x/"]
  rules:
    - type: object
      purge:
        retainVersions: 1
`, f.bucket))
	if job == nil {
		t.Fatalf("submission status %d: %s", rec.Code, rec.Body.String())
	}
	// A run that completed a/ and stopped.
	ri := &batchJobInfo{JobID: job.ID, JobType: string(job.Type()), StartTime: job.Started, Bucket: f.bucket, Object: "a/done"}
	mustIAM(t, ri.updateAfter(f.ctx, f.obj, 0, *job))
	f.run(t, job)
	if !f.versionExists(t, "a/done", done) {
		t.Error("resume did again a key before the cursor")
	}
	if f.versionExists(t, "z/todo", todo) {
		t.Error("resume skipped a later prefix")
	}
	if got := f.jobInfo(t, job).VersionsSkippedLocked; got != 1 {
		t.Errorf("a locked version under two equal prefixes was counted %d times", got)
	}
}

type batchPartialWalk struct {
	ObjectLayer
	version ObjectInfo
	cancel  context.CancelFunc
	read    chan struct{}
}

func (a *batchPartialWalk) Walk(_ context.Context, _ string, _ string, results chan<- itemOrErr[ObjectInfo], _ WalkOptions) error {
	go func() {
		defer close(results)
		results <- itemOrErr[ObjectInfo]{Item: a.version}
		if a.cancel != nil {
			<-a.read
			a.cancel()
			return
		}
		results <- itemOrErr[ObjectInfo]{Err: errors.New("test: listing failed within a key")}
	}()
	return nil
}

func (a *batchPartialWalk) GetObjectInfo(context.Context, string, string, ObjectOptions) (ObjectInfo, error) {
	if a.read != nil {
		close(a.read)
	}
	return a.version, nil
}

// A rotation whose walk fails or is canceled within a key keeps that key
// after its cursor and does not report completion.
func TestBatchKeyRotationIncompleteWalk(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprintf("canceled=%v", canceled), func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			meta := batchLockMeta("LEGALHOLD")
			meta[crypto.MetaSealedKeyS3] = "test-sealed-key"
			api := &batchPartialWalk{ObjectLayer: f.obj, version: ObjectInfo{Bucket: f.bucket, Name: "rotation/key", VersionID: mustGetUUID(), UserDefined: meta}}
			if canceled {
				api.cancel, api.read = cancel, make(chan struct{})
			}
			job := BatchJobRequest{
				ID: "keyrotate-partial" + getKeySeparator() + "0", Started: UTCNow(), Submitter: batchRootSubmitter(t),
				KeyRotate: &BatchJobKeyRotateV1{Bucket: f.bucket, Encryption: BatchJobKeyRotateEncryption{Type: sses3}},
			}
			_ = job.KeyRotate.Start(ctx, api, job)
			ri := f.jobInfo(t, &job)
			if ri.Complete || ri.Object == api.version.Name || ri.VersionsSkippedLocked != 0 {
				t.Fatalf("incomplete key committed: complete=%v cursor=%q skips=%d", ri.Complete, ri.Object, ri.VersionsSkippedLocked)
			}
		})
	}
}
