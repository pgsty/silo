// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio/internal/amztime"
	"github.com/minio/minio/internal/auth"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
	"github.com/pgsty/silo-pkg/v3/policy"
)

var batchLockKinds = []string{"COMPLIANCE", "GOVERNANCE", "LEGALHOLD"}

func batchLockMeta(kind string) map[string]string {
	m := map[string]string{}
	switch kind {
	case "COMPLIANCE", "GOVERNANCE":
		m[strings.ToLower(xhttp.AmzObjectLockMode)] = kind
		m[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = amztime.ISO8601Format(UTCNow().Add(24 * time.Hour))
	case "LEGALHOLD":
		m[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = "ON"
	}
	return m
}

func batchPutVersion(t *testing.T, obj ObjectLayer, bucket, key string, meta map[string]string) ObjectInfo {
	t.Helper()
	data := []byte("batch lock " + key)
	oi, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""),
		ObjectOptions{Versioned: true, UserDefined: meta})
	if err != nil {
		t.Fatal(err)
	}
	return oi
}

func batchVersionExists(t *testing.T, obj ObjectLayer, bucket, key, versionID string) bool {
	t.Helper()
	_, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: versionID})
	switch {
	case err == nil:
		return true
	case isErrVersionNotFound(err) || isErrObjectNotFound(err):
		return false
	}
	t.Fatal(err)
	return false
}

// batchJobStatusJSON returns the status response of a job as decoded JSON.
func batchJobStatusJSON(t *testing.T, jobID string) map[string]any {
	t.Helper()
	cred := globalActiveCred
	req, err := newTestSignedRequestV4(http.MethodGet, "http://localhost/minio/admin/v3/status-job?jobId="+jobID, 0, nil, cred.AccessKey, cred.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req = req.WithContext(newContext(req, rec, "BatchJobStatus"))
	adminAPIHandlers{}.BatchJobStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct{ LastMetric map[string]any }
	if err = json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.LastMetric
}

// Batch expiration keeps versions under retention or legal hold, on both
// purge paths, and reports them; unlocked versions are still expired.
func TestBatchExpireObjectLock(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, endpoints: []string{"PutObject"},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			defer r5Capacity(obj.(*erasureServerPools))()
			enableBucketObjectLock(t, bucket)
			f := &batchAuthzFixture{ctx: t.Context(), obj: obj, bucket: bucket}
			batchTestJobPool(t.Context(), t, obj)

			type version struct{ key, id string }
			var locked, unlocked []version
			for _, retain := range []int{0, 1} {
				for _, kind := range batchLockKinds {
					key := fmt.Sprintf("r%d/%s", retain, kind)
					older := batchPutVersion(t, obj, bucket, key, batchLockMeta(kind))
					batchPutVersion(t, obj, bucket, key, nil)
					locked = append(locked, version{key, older.VersionID})
				}
				key := fmt.Sprintf("r%d/plain", retain)
				older := batchPutVersion(t, obj, bucket, key, nil)
				batchPutVersion(t, obj, bucket, key, nil)
				unlocked = append(unlocked, version{key, older.VersionID})
			}

			var jobs []*BatchJobRequest
			for _, retain := range []int{0, 1} {
				job := fmt.Sprintf(`expire:
  apiVersion: v1
  bucket: %s
  prefix: r%d/
  rules:
    - type: object
      purge:
        retainVersions: %d
`, bucket, retain, retain)
				rec, queued := f.submit(t, globalActiveCred, job)
				if queued == nil {
					t.Fatalf("%s: submission status %d: %s", instance, rec.Code, rec.Body.String())
				}
				// Running a job again, as a resumed job does, must not count
				// the versions it left a second time.
				f.run(t, queued)
				f.run(t, queued)
				jobs = append(jobs, queued)
			}

			for _, v := range locked {
				if !batchVersionExists(t, obj, bucket, v.key, v.id) {
					t.Errorf("%s: %s: locked version %s was expired", instance, v.key, v.id)
				}
			}
			for _, v := range unlocked {
				if batchVersionExists(t, obj, bucket, v.key, v.id) {
					t.Errorf("%s: %s: control: unlocked version %s was not expired", instance, v.key, v.id)
				}
			}
			for i, field := range []string{"keysRefused", "versionsSkippedLocked"} {
				m := batchJobStatusJSON(t, jobs[i].ID)
				if got, _ := m[field].(float64); got != float64(len(batchLockKinds)) {
					t.Errorf("%s: retain %d: %s = %v, want %d", instance, i, field, m[field], len(batchLockKinds))
				}
				if m["complete"] != true || m["failed"] != false {
					t.Errorf("%s: retain %d: complete=%v failed=%v", instance, i, m["complete"], m["failed"])
				}
			}
		},
	})
}

type batchLockTransport func(*http.Request) (*http.Response, error)

func (f batchLockTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// batchLockRemote is a source that serves replacement for every read.
func batchLockRemote(t *testing.T, replacement string) *minio.Core {
	t.Helper()
	core, err := minio.NewCore("source.invalid", &minio.Options{
		Region: "us-east-1", Creds: credentials.NewStaticV4("batch-access", "batch-secret", ""),
		Transport: batchLockTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{
				"Content-Length": []string{strconv.Itoa(len(replacement))},
				"Last-Modified":  []string{UTCNow().Format(http.TimeFormat)},
				"Etag":           []string{"\"batchetag\""},
			}, Body: io.NopCloser(strings.NewReader(replacement)), ContentLength: int64(len(replacement)), Request: r}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return core
}

func batchRootSubmitter(t *testing.T) *batchJobSubmitter {
	t.Helper()
	sub, err := newBatchJobSubmitter(globalActiveCred)
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

// A pull leaves a destination version under Object Lock as it is, whether a
// single PUT, a multipart completion or a delete marker would replace it.
func TestBatchPullObjectLock(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, endpoints: []string{"PutObject"},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			defer r5Capacity(obj.(*erasureServerPools))()
			enableBucketObjectLock(t, bucket)
			const replacement = "replacement from remote"
			core := batchLockRemote(t, replacement)
			sub := batchRootSubmitter(t)
			job := BatchJobReplicateV1{
				Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: "remote-bucket"},
				Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: bucket},
			}
			for _, kind := range batchLockKinds {
				for _, path := range []string{"put", "multipart", "marker", "directory"} {
					key := "pull/" + kind + "/" + path
					if path == "directory" {
						key += "/"
					}
					before := batchPutVersion(t, obj, bucket, key, batchLockMeta(kind))
					src := ObjectInfo{Name: key, VersionID: before.VersionID, ModTime: UTCNow(), ETag: "batchetag", UserDefined: map[string]string{}}
					switch path {
					case "multipart":
						src.ETag = "batchetag-1"
					case "marker":
						src.DeleteMarker = true
					}
					err := job.ReplicateFromSource(t.Context(), obj, core, src, false, sub)
					if !isErrObjectLocked(err) {
						t.Errorf("%s: %s: pull returned %v, want ObjectLocked", instance, key, err)
					}
					after, gerr := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: before.VersionID})
					if gerr != nil {
						t.Errorf("%s: %s: locked version lost: %v", instance, key, gerr)
						continue
					}
					if !enforceRetentionForDeletion(t.Context(), after) || after.ETag != before.ETag {
						t.Errorf("%s: %s: locked version was replaced", instance, key)
					}
				}
			}

			// Controls: a new version, and a new delete marker that hides a
			// locked version without replacing it.
			locked := batchPutVersion(t, obj, bucket, "pull/new", batchLockMeta("COMPLIANCE"))
			newVersion := mustGetUUID()
			if err := job.ReplicateFromSource(t.Context(), obj, core, ObjectInfo{
				Name: "pull/new", VersionID: newVersion, ModTime: UTCNow(), ETag: "batchetag", UserDefined: map[string]string{},
			}, false, sub); err != nil {
				t.Fatalf("%s: new version: %v", instance, err)
			}
			if got := readCopyChecksumObject(t, obj, bucket, "pull/new", ObjectOptions{VersionID: newVersion}); string(got) != replacement {
				t.Errorf("%s: new version content %q", instance, got)
			}
			marker := mustGetUUID()
			if err := job.ReplicateFromSource(t.Context(), obj, core, ObjectInfo{
				Name: "pull/new", VersionID: marker, ModTime: UTCNow(), DeleteMarker: true,
			}, false, sub); err != nil {
				t.Fatalf("%s: new marker: %v", instance, err)
			}
			if !batchVersionExists(t, obj, bucket, "pull/new", locked.VersionID) {
				t.Errorf("%s: a new marker removed a locked version", instance)
			}
		},
	})
}

// A pull applies retention as a PUT to the destination would: copied
// retention is validated, and a version without one gets the bucket default.
func TestBatchPullRetentionMetadata(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, endpoints: []string{"PutObject"},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			defer r5Capacity(obj.(*erasureServerPools))()
			meta, err := globalBucketMetadataSys.Get(bucket)
			if err != nil {
				t.Fatal(err)
			}
			meta.ObjectLockConfigXML = []byte(`<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>`)
			meta.VersioningConfigXML = enabledBucketVersioningConfig
			if err = meta.parseAllConfigs(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			globalBucketMetadataSys.Set(bucket, meta)
			core := batchLockRemote(t, "retention content")
			sub := batchRootSubmitter(t)
			job := BatchJobReplicateV1{
				Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: "remote-bucket"},
				Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: bucket},
			}
			pull := func(key string, meta map[string]string) (ObjectInfo, error) {
				vid := mustGetUUID()
				err := job.ReplicateFromSource(t.Context(), obj, core, ObjectInfo{Name: key, VersionID: vid, ModTime: UTCNow().Add(-time.Hour), ETag: "batchetag", UserDefined: meta}, false, sub)
				if err != nil {
					return ObjectInfo{}, err
				}
				return obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: vid})
			}
			oi, err := pull("retention/default", map[string]string{})
			if err != nil {
				t.Fatal(err)
			}
			ret := objectlock.GetObjectRetentionMeta(oi.UserDefined)
			if ret.Mode != objectlock.RetGovernance || !ret.RetainUntilDate.After(UTCNow().Add(23*time.Hour)) {
				t.Errorf("%s: default retention not applied with the destination's time: %+v", instance, ret)
			}
			until := UTCNow().Add(48 * time.Hour)
			oi, err = pull("retention/copied", map[string]string{
				xhttp.AmzObjectLockMode: "COMPLIANCE", xhttp.AmzObjectLockRetainUntilDate: amztime.ISO8601Format(until),
			})
			if err != nil {
				t.Fatal(err)
			}
			if ret = objectlock.GetObjectRetentionMeta(oi.UserDefined); ret.Mode != objectlock.RetCompliance || !ret.RetainUntilDate.Equal(until.Truncate(time.Millisecond)) {
				t.Errorf("%s: copied retention: %+v", instance, ret)
			}
			if _, err = pull("retention/invalid", map[string]string{xhttp.AmzObjectLockMode: "FOREVER", xhttp.AmzObjectLockRetainUntilDate: amztime.ISO8601Format(until)}); err == nil {
				t.Errorf("%s: invalid copied retention was accepted", instance)
			}
		},
	})
}

// Key rotation does not rewrite a version under Object Lock.
func TestBatchKeyRotationObjectLock(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, endpoints: []string{"PutObject", "GetObject"},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			defer r5Capacity(obj.(*erasureServerPools))()
			enableBucketObjectLock(t, bucket)
			oldKMS := GlobalKMS
			GlobalKMS = kms.NewStub("batch-lock-key")
			defer func() { GlobalKMS = oldKMS }()
			sub := batchRootSubmitter(t)
			job := BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: sses3}}
			for _, kind := range append([]string{"none"}, batchLockKinds...) {
				key := "rotate/" + kind
				headers := map[string]string{xhttp.AmzServerSideEncryption: xhttp.AmzEncryptionAES}
				switch kind {
				case "COMPLIANCE", "GOVERNANCE":
					headers[xhttp.AmzObjectLockMode] = kind
					headers[xhttp.AmzObjectLockRetainUntilDate] = UTCNow().Add(24 * time.Hour).Format(time.RFC3339)
				case "LEGALHOLD":
					headers[xhttp.AmzObjectLockLegalHold] = "ON"
				}
				putCopyChecksumSource(t, router, cred, bucket, key, []byte("rotate "+kind), headers)
				before, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{})
				if err != nil || !crypto.S3.IsEncrypted(before.UserDefined) {
					t.Fatalf("%s: %s: encrypted control: %v", instance, key, err)
				}
				err = job.KeyRotate(t.Context(), obj, before, sub)
				after, gerr := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: before.VersionID})
				if gerr != nil {
					t.Fatal(gerr)
				}
				if kind == "none" {
					if err != nil || after.ModTime.Equal(before.ModTime) {
						t.Errorf("%s: control: unlocked version not rotated: %v", instance, err)
					}
					continue
				}
				var locked ObjectLocked
				if !errors.As(err, &locked) || !after.ModTime.Equal(before.ModTime) {
					t.Errorf("%s: %s: rotation of a locked version returned %v; rewritten=%v", instance, key, err, !after.ModTime.Equal(before.ModTime))
				}
			}
		},
	})
}

// A push reads locked versions as any authorized read does, and a submitter
// that may not read a version does not send it.
func TestBatchPushReads(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, endpoints: []string{"PutObject"},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			defer r5Capacity(obj.(*erasureServerPools))()
			enableBucketObjectLock(t, bucket)
			var puts []string
			target, err := minio.NewCore("target.invalid", &minio.Options{
				Region: "us-east-1", Creds: credentials.NewStaticV4("batch-access", "batch-secret", ""),
				Transport: batchLockTransport(func(r *http.Request) (*http.Response, error) {
					if r.Body != nil {
						io.Copy(io.Discard, r.Body)
						r.Body.Close()
					}
					if r.Method == http.MethodPut {
						puts = append(puts, r.URL.Path)
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Etag": []string{"\"pushetag\""}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			job := BatchJobReplicateV1{
				Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: bucket},
				Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: "remote-bucket"},
			}
			src := batchPutVersion(t, obj, bucket, "push/locked", batchLockMeta("COMPLIANCE"))
			if err := job.ReplicateToTarget(t.Context(), obj, target, src, false, batchRootSubmitter(t)); err != nil {
				t.Fatalf("%s: authorized push of a locked version: %v", instance, err)
			}
			if len(puts) != 1 {
				t.Fatalf("%s: authorized push sent %d writes", instance, len(puts))
			}

			// A user that may list but not read.
			p, err := policy.ParseConfig(strings.NewReader(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:StartBatchJob"]},{"Effect":"Allow","Action":["s3:ListBucket","s3:ListBucketVersions"],"Resource":["arn:aws:s3:::` + bucket + `"]}]}`))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = globalIAMSys.SetPolicy(t.Context(), "batch-list-only", *p); err != nil {
				t.Fatal(err)
			}
			user := auth.Credentials{AccessKey: "batch-list-user", SecretKey: "batch-list-user-secret"}
			if _, err = globalIAMSys.CreateUser(t.Context(), user.AccessKey, madmin.AddOrUpdateUserReq{SecretKey: user.SecretKey, Status: madmin.AccountEnabled}); err != nil {
				t.Fatal(err)
			}
			if _, err = globalIAMSys.PolicyDBSet(t.Context(), user.AccessKey, "batch-list-only", regUser, false); err != nil {
				t.Fatal(err)
			}
			sub, err := newBatchJobSubmitter(globalIAMSysUser(t, user.AccessKey))
			if err != nil {
				t.Fatal(err)
			}
			err = job.ReplicateToTarget(t.Context(), obj, target, src, false, sub)
			if !isBatchJobAuthzError(err) || len(puts) != 1 {
				t.Fatalf("%s: unauthorized push returned %v and sent %d writes", instance, err, len(puts)-1)
			}
		},
	})
}

// globalIAMSysUser returns the stored credential of accessKey, as a request
// authenticated with it has.
func globalIAMSysUser(t *testing.T, accessKey string) auth.Credentials {
	t.Helper()
	u, ok := globalIAMSys.store.GetUser(accessKey)
	if !ok {
		t.Fatalf("no user %s", accessKey)
	}
	return u.Credentials
}

// The cursor of a walk done out of order moves only past keys whose items
// are all done, and counts each item once.
func TestBatchProgressCursor(t *testing.T) {
	ri := &batchJobInfo{}
	p := newBatchProgress(ri, "bucket")
	items := []string{"a", "a", "b", "c", "c"}
	seqs := make([]uint64, len(items))
	for i := range items {
		seqs[i] = p.begin()
	}
	skip := batchCounts{versionsSkipped: 1}
	p.done(seqs[1], "a", skip)
	p.done(seqs[3], "c", skip)
	if ri.Object != "" || ri.VersionsSkippedLocked != 0 {
		t.Fatalf("cursor moved before the first item: %q %d", ri.Object, ri.VersionsSkippedLocked)
	}
	p.done(seqs[0], "a", skip)
	p.done(seqs[2], "b", skip)
	// a is done; b is done but c may still have items.
	if ri.Object != "b" && ri.Object != "a" {
		t.Fatalf("cursor %q", ri.Object)
	}
	if ri.Object == "a" && ri.VersionsSkippedLocked != 2 {
		t.Fatalf("counts %d at cursor a", ri.VersionsSkippedLocked)
	}
	// c's last item never finishes, as when a run stops: the cursor stays
	// before c and c is not counted.
	p.finish()
	if ri.Object != "b" || ri.VersionsSkippedLocked != 3 {
		t.Fatalf("interrupted: cursor %q counts %d, want b 3", ri.Object, ri.VersionsSkippedLocked)
	}
	p.done(seqs[4], "c", skip)
	p.finish()
	if ri.Object != "c" || ri.VersionsSkippedLocked != 5 {
		t.Fatalf("finished: cursor %q counts %d, want c 5", ri.Object, ri.VersionsSkippedLocked)
	}
}
