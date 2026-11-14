// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
	"go.yaml.in/yaml/v3"
)

// batchAuthzFixture runs batch jobs submitted through the admin API, one job
// at a time and in the test's goroutine.
type batchAuthzFixture struct {
	ctx    context.Context
	sys    *IAMSys
	obj    ObjectLayer
	bucket string
}

func newBatchAuthzFixture(t *testing.T) *batchAuthzFixture {
	t.Helper()
	ctx, sys := iamAdminFixture(t)
	obj := newObjectLayerFn()
	// Match storage-class parity to this fixture's single drive, even after
	// an API test has loaded the configuration of a larger erasure set.
	mustIAM(t, newTestConfig(globalMinioDefaultRegion, obj))
	batchTestJobPool(ctx, t, obj)
	f := &batchAuthzFixture{ctx: ctx, sys: sys, obj: obj, bucket: "batch-authz"}
	mustIAM(t, obj.MakeBucket(ctx, f.bucket, MakeBucketOptions{VersioningEnabled: true}))
	_, err := globalBucketMetadataSys.Update(ctx, f.bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
	mustIAM(t, err)
	return f
}

// batchTestJobPool queues submitted jobs without running them.
func batchTestJobPool(ctx context.Context, t *testing.T, obj ObjectLayer) {
	t.Helper()
	prevPool := globalBatchJobPool
	globalBatchJobPool = &BatchJobPool{
		ctx:       ctx,
		objLayer:  obj,
		jobCh:     make(chan *BatchJobRequest, 10),
		jobOwners: make(map[string]*batchJobOwner),
	}
	globalBatchJobsMetrics.Lock()
	globalBatchJobsMetrics.metrics = make(map[string]*batchJobInfo)
	globalBatchJobsMetrics.Unlock()
	t.Cleanup(func() { globalBatchJobPool = prevPool })
}

// putVersions writes two versions of key and returns the older one.
func (f *batchAuthzFixture) putVersions(t *testing.T, key string) string {
	t.Helper()
	var older string
	for i := range 2 {
		data := []byte(fmt.Sprintf("version %d", i))
		oi, err := f.obj.PutObject(f.ctx, f.bucket, key, mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{Versioned: true})
		mustIAM(t, err)
		if i == 0 {
			older = oi.VersionID
		}
	}
	return older
}

func (f *batchAuthzFixture) versionExists(t *testing.T, key, versionID string) bool {
	t.Helper()
	_, err := f.obj.GetObjectInfo(f.ctx, f.bucket, key, ObjectOptions{VersionID: versionID})
	if err == nil {
		return true
	}
	if isErrVersionNotFound(err) || isErrObjectNotFound(err) {
		return false
	}
	t.Fatal(err)
	return false
}

func (f *batchAuthzFixture) expireYAML(prefix string) string {
	return fmt.Sprintf(`expire:
  apiVersion: v1
  bucket: %s
  prefix: %q
  rules:
    - type: object
      purge:
        retainVersions: 1
`, f.bucket, prefix)
}

// submit sends a job definition to StartBatchJob as cred. An accepted job is
// returned from the queue, not run.
func (f *batchAuthzFixture) submit(t *testing.T, cred auth.Credentials, job string) (*httptest.ResponseRecorder, *BatchJobRequest) {
	t.Helper()
	headers := map[string]string{}
	if cred.IsTemp() && !cred.IsServiceAccount() {
		headers["X-Amz-Security-Token"] = cred.SessionToken
	}
	body := []byte(job)
	req, err := newTestSignedRequestV4(http.MethodPost, "http://localhost/minio/admin/v3/start-job", int64(len(body)), bytes.NewReader(body), cred.AccessKey, cred.SecretKey, headers)
	mustIAM(t, err)
	mustIAM(t, req.ParseForm())
	rec := httptest.NewRecorder()
	req = req.WithContext(newContext(req, rec, "StartBatchJob"))
	adminAPIHandlers{}.StartBatchJob(rec, req)
	if rec.Code != http.StatusOK {
		return rec, nil
	}
	select {
	case queued := <-globalBatchJobPool.jobCh:
		return rec, queued
	default:
		t.Fatal("accepted job was not queued")
		return rec, nil
	}
}

func (f *batchAuthzFixture) run(t *testing.T, job *BatchJobRequest) {
	t.Helper()
	ctx := job.ctx
	if ctx == nil {
		ctx = f.ctx
	}
	switch {
	case job.Expire != nil:
		if err := job.Expire.Start(ctx, f.obj, *job); err != nil {
			t.Logf("start: %v", err)
		}
	default:
		t.Fatalf("unexpected job type %s", job.Type())
	}
	ri := &batchJobInfo{JobID: job.ID, JobType: string(job.Type())}
	if err := ri.load(f.ctx, f.obj, *job); err == nil {
		t.Logf("job %s: %+v", job.ID, ri.clone())
	}
}

func (f *batchAuthzFixture) jobInfo(t *testing.T, job *BatchJobRequest) *batchJobInfo {
	t.Helper()
	ri := &batchJobInfo{JobID: job.ID, JobType: string(job.Type())}
	mustIAM(t, ri.load(f.ctx, f.obj, *job))
	return ri
}

func batchAuthzPolicy(ctx context.Context, t *testing.T, sys *IAMSys, name, statements string) {
	t.Helper()
	p, err := policy.ParseConfig(strings.NewReader(`{"Version":"2012-10-17","Statement":[` + statements + `]}`))
	mustIAM(t, err)
	_, err = sys.SetPolicy(ctx, name, *p)
	mustIAM(t, err)
}

const batchAuthzFullAccess = `{"Effect":"Allow","Action":["admin:StartBatchJob"]},
{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::batch-authz","arn:aws:s3:::batch-authz/*"]}`

// A credential that may start batch jobs but has no access to the bucket
// cannot delete through a job.
func TestBatchJobSubmitterWithoutDataAccess(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "batch-only", `{"Effect":"Allow","Action":["admin:StartBatchJob","admin:ListBatchJobs"]}`)
	cred := iamAdminUser(f.ctx, t, f.sys, "batch-only-user", "batch-only")
	older := f.putVersions(t, "data/a")
	rec, job := f.submit(t, cred, f.expireYAML(""))
	if job != nil {
		f.run(t, job)
	}
	if !f.versionExists(t, "data/a", older) {
		t.Fatal("a job submitted without data access deleted a version")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("submission status %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// A job acts only while the credential that submitted it is the same valid
// credential.
func TestBatchJobSubmitterChangedBeforeStart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *batchAuthzFixture, cred auth.Credentials)
	}{
		{"unchanged", nil},
		{"deleted", func(t *testing.T, f *batchAuthzFixture, cred auth.Credentials) {
			mustIAM(t, f.sys.DeleteUser(f.ctx, cred.AccessKey, false))
		}},
		{"disabled", func(t *testing.T, f *batchAuthzFixture, cred auth.Credentials) {
			_, err := f.sys.SetUserStatus(f.ctx, cred.AccessKey, madmin.AccountDisabled)
			mustIAM(t, err)
		}},
		{"secret-changed", func(t *testing.T, f *batchAuthzFixture, cred auth.Credentials) {
			mustIAM(t, f.sys.SetUserSecretKey(f.ctx, cred.AccessKey, "batch-authz-changed-secret"))
		}},
		{"access-key-reused", func(t *testing.T, f *batchAuthzFixture, cred auth.Credentials) {
			mustIAM(t, f.sys.DeleteUser(f.ctx, cred.AccessKey, false))
			time.Sleep(10 * time.Millisecond)
			iamAdminUser(f.ctx, t, f.sys, cred.AccessKey, "batch-full")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			batchAuthzPolicy(f.ctx, t, f.sys, "batch-full", batchAuthzFullAccess)
			cred := iamAdminUser(f.ctx, t, f.sys, "batch-user", "batch-full")
			older := f.putVersions(t, "data/a")
			rec, job := f.submit(t, cred, f.expireYAML(""))
			if job == nil {
				t.Fatalf("submission status %d: %s", rec.Code, rec.Body.String())
			}
			if tc.change != nil {
				tc.change(t, f, cred)
			}
			f.run(t, job)
			exists := f.versionExists(t, "data/a", older)
			if tc.change == nil && exists {
				t.Fatal("control: an authorized job did not expire the older version")
			}
			if tc.change != nil && !exists {
				t.Fatal("a job ran as a credential that changed after submission")
			}
		})
	}
}

// An expired temporary credential does not keep its job running.
func TestBatchJobSubmitterExpired(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "batch-full", batchAuthzFullAccess)
	parent := iamAdminUser(f.ctx, t, f.sys, "batch-parent", "batch-full")
	cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{parentClaim: parent.AccessKey, "exp": UTCNow().Add(2 * time.Second).Unix()}, globalActiveCred.SecretKey)
	mustIAM(t, err)
	cred.ParentUser = parent.AccessKey
	_, err = f.sys.SetTempUser(f.ctx, cred.AccessKey, cred, "")
	mustIAM(t, err)
	older := f.putVersions(t, "data/a")
	rec, job := f.submit(t, cred, f.expireYAML(""))
	if job == nil {
		t.Fatalf("submission status %d: %s", rec.Code, rec.Body.String())
	}
	time.Sleep(time.Until(cred.Expiration) + time.Second)
	f.run(t, job)
	if !f.versionExists(t, "data/a", older) {
		t.Fatal("a job ran as an expired credential")
	}
}

// A session policy limits the job as it limits requests, also when an
// authorization plugin decides the rest.
func TestBatchJobSessionPolicyDeny(t *testing.T) {
	session := `{"Version":"2012-10-17","Statement":[
{"Effect":"Allow","Action":["admin:StartBatchJob"]},
{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::batch-authz","arn:aws:s3:::batch-authz/*"]},
{"Effect":"Deny","Action":["s3:DeleteObjectVersion"],"Resource":["arn:aws:s3:::batch-authz/*"]}]}`
	for _, tc := range []struct {
		name   string
		plugin bool
	}{{"local", false}, {"plugin-allows", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			batchAuthzPolicy(f.ctx, t, f.sys, "batch-full", batchAuthzFullAccess)
			parent := iamAdminUser(f.ctx, t, f.sys, "batch-parent", "batch-full")
			cred := iamAdminServiceAccount(f.ctx, t, f.sys, parent.AccessKey, "batch-restricted", session)
			if tc.plugin {
				iamAdminPlugin(t, true)
			}
			older := f.putVersions(t, "data/a")
			rec, job := f.submit(t, cred, f.expireYAML(""))
			if job != nil {
				f.run(t, job)
			} else {
				t.Logf("submission status %d: %s", rec.Code, rec.Body.String())
			}
			if !f.versionExists(t, "data/a", older) {
				t.Fatal("a job deleted a version its session policy denies")
			}
		})
	}
}

// A temporary credential's session policy limits its job too.
func TestBatchJobTemporarySessionPolicyDeny(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "batch-full", batchAuthzFullAccess)
	parent := iamAdminUser(f.ctx, t, f.sys, "batch-parent", "batch-full")
	session := `{"Version":"2012-10-17","Statement":[
{"Effect":"Allow","Action":["admin:StartBatchJob"]},
{"Effect":"Allow","Action":["s3:ListBucket","s3:ListBucketVersions","s3:GetObject","s3:GetObjectVersion","s3:DeleteObject"],"Resource":["arn:aws:s3:::batch-authz","arn:aws:s3:::batch-authz/*"]}]}`
	cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{
		parentClaim: parent.AccessKey, "exp": UTCNow().Add(time.Hour).Unix(),
		policy.SessionPolicyName: base64.StdEncoding.EncodeToString([]byte(session)),
	}, globalActiveCred.SecretKey)
	mustIAM(t, err)
	cred.ParentUser = parent.AccessKey
	_, err = f.sys.SetTempUser(f.ctx, cred.AccessKey, cred, "")
	mustIAM(t, err)
	older := f.putVersions(t, "data/a")
	rec, job := f.submit(t, cred, f.expireYAML(""))
	if job != nil {
		f.run(t, job)
	} else {
		t.Logf("submission status %d: %s", rec.Code, rec.Body.String())
	}
	if !f.versionExists(t, "data/a", older) {
		t.Fatal("a job deleted a version its session policy does not allow")
	}
}

// A Deny that depends on request context the job does not have refuses the
// action instead of being skipped.
func TestBatchJobAbsentContextDeny(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "batch-context", batchAuthzFullAccess+`,
{"Effect":"Deny","Action":["s3:DeleteObjectVersion"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}`)
	cred := iamAdminUser(f.ctx, t, f.sys, "batch-user", "batch-context")
	older := f.putVersions(t, "data/a")
	rec, job := f.submit(t, cred, f.expireYAML(""))
	if job != nil {
		f.run(t, job)
	} else {
		t.Logf("submission status %d: %s", rec.Code, rec.Body.String())
	}
	if !f.versionExists(t, "data/a", older) {
		t.Fatal("a job skipped a Deny that depends on request context")
	}
}

// Each object is authorized: a Deny under an allowed prefix keeps its objects.
func TestBatchJobPerObjectDeny(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "batch-keep", batchAuthzFullAccess+`,
{"Effect":"Deny","Action":["s3:DeleteObjectVersion"],"Resource":["arn:aws:s3:::batch-authz/data/keep*"]}`)
	cred := iamAdminUser(f.ctx, t, f.sys, "batch-user", "batch-keep")
	kept := f.putVersions(t, "data/keep")
	rec, job := f.submit(t, cred, f.expireYAML("data/"))
	if job == nil {
		t.Fatalf("submission status %d: %s", rec.Code, rec.Body.String())
	}
	f.run(t, job)
	if !f.versionExists(t, "data/keep", kept) {
		t.Fatal("a job deleted a version that a per-object Deny protects")
	}
	if ri := f.jobInfo(t, job); !ri.Failed || ri.Complete {
		t.Fatalf("refused job: complete=%v failed=%v", ri.Complete, ri.Failed)
	}
}

// A job queued without its submitter, as an earlier release stored it, fails
// and stays failed across another start.
func TestBatchJobWithoutSubmitter(t *testing.T) {
	f := newBatchAuthzFixture(t)
	older := f.putVersions(t, "data/a")
	job := &BatchJobRequest{}
	mustIAM(t, yaml.Unmarshal([]byte(f.expireYAML("")), job))
	job.ID = "expire-legacy" + getKeySeparator() + "0"
	job.User = globalActiveCred.AccessKey
	job.Started = time.Now()
	mustIAM(t, job.save(f.ctx, f.obj))
	for range 2 {
		loaded := &BatchJobRequest{}
		mustIAM(t, loaded.load(f.ctx, f.obj, getJobPath(*job)))
		f.run(t, loaded)
		if !f.versionExists(t, "data/a", older) {
			t.Fatal("a job without a recorded submitter deleted a version")
		}
		if ri := f.jobInfo(t, job); !ri.Failed || ri.Complete {
			t.Fatalf("job without submitter: complete=%v failed=%v", ri.Complete, ri.Failed)
		}
	}
}

// Root and an authorized user can still run jobs.
func TestBatchJobAuthorizedControls(t *testing.T) {
	for _, root := range []bool{true, false} {
		t.Run(fmt.Sprintf("root=%v", root), func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			cred := globalActiveCred
			if !root {
				batchAuthzPolicy(f.ctx, t, f.sys, "batch-full", batchAuthzFullAccess)
				cred = iamAdminUser(f.ctx, t, f.sys, "batch-user", "batch-full")
			}
			older := f.putVersions(t, "data/a")
			rec, job := f.submit(t, cred, f.expireYAML(""))
			if job == nil {
				t.Fatalf("submission status %d: %s", rec.Code, rec.Body.String())
			}
			f.run(t, job)
			if f.versionExists(t, "data/a", older) {
				t.Fatal("an authorized job did not expire the older version")
			}
			if ri := f.jobInfo(t, job); !ri.Complete || ri.Failed {
				t.Fatalf("authorized job: complete=%v failed=%v", ri.Complete, ri.Failed)
			}
		})
	}
}

// The describe output has no secrets of the job.
func TestBatchJobDescribeRedactsSecrets(t *testing.T) {
	f := newBatchAuthzFixture(t)
	secrets := []string{"describe-source-secret", "describe-source-token", "describe-target-secret", "describe-target-token", "describe-notify-token"}
	for _, job := range []BatchJobRequest{
		{ID: "replicate-describe" + getKeySeparator() + "0", Replicate: &BatchJobReplicateV1{
			APIVersion: batchReplJobAPIVersion,
			Source: BatchJobReplicateSource{Bucket: "remote", Endpoint: "https://remote.invalid", Creds: BatchJobReplicateCredentials{
				AccessKey: "describe-source-access", SecretKey: secrets[0], SessionToken: secrets[1],
			}},
			Target: BatchJobReplicateTarget{Bucket: f.bucket, Creds: BatchJobReplicateCredentials{
				AccessKey: "describe-target-access", SecretKey: secrets[2], SessionToken: secrets[3],
			}},
			Flags: BatchJobReplicateFlags{Notify: BatchJobNotification{Endpoint: "https://notify.invalid", Token: secrets[4]}},
		}},
		{ID: "expire-describe" + getKeySeparator() + "0", Expire: &BatchJobExpire{
			APIVersion: batchExpireAPIVersion, Bucket: f.bucket,
			NotificationCfg: BatchJobNotification{Endpoint: "https://notify.invalid", Token: secrets[4]},
		}},
		{ID: "keyrotate-describe" + getKeySeparator() + "0", KeyRotate: &BatchJobKeyRotateV1{
			APIVersion: batchKeyRotateAPIVersion, Bucket: f.bucket,
			Flags: BatchJobKeyRotateFlags{Notify: BatchJobNotification{Endpoint: "https://notify.invalid", Token: secrets[4]}},
		}},
	} {
		data, err := job.MarshalMsg(nil)
		mustIAM(t, err)
		mustIAM(t, saveConfig(f.ctx, f.obj, getJobPath(job), data))
		cred := globalActiveCred
		req, err := newTestSignedRequestV4(http.MethodGet, "http://localhost/minio/admin/v3/describe-job?jobId="+job.ID, 0, nil, cred.AccessKey, cred.SecretKey, nil)
		mustIAM(t, err)
		mustIAM(t, req.ParseForm())
		rec := httptest.NewRecorder()
		req = req.WithContext(newContext(req, rec, "DescribeBatchJob"))
		adminAPIHandlers{}.DescribeBatchJob(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: describe status %d: %s", job.ID, rec.Code, rec.Body.String())
		}
		for _, s := range secrets {
			if strings.Contains(rec.Body.String(), s) {
				t.Errorf("%s: describe output contains %s", job.ID, s)
			}
		}
		if job.Replicate != nil && !strings.Contains(rec.Body.String(), "describe-source-access") {
			t.Errorf("%s: describe output lost the access key", job.ID)
		}
		// The stored job keeps what a run needs.
		stored := &BatchJobRequest{}
		mustIAM(t, stored.load(f.ctx, f.obj, getJobPath(job)))
		if stored.Replicate != nil && stored.Replicate.Source.Creds.SecretKey != secrets[0] {
			t.Errorf("%s: describe changed the stored job", job.ID)
		}
	}
}
