// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Silo Object Storage stack.
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
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio/internal/amztime"
	"github.com/minio/minio/internal/auth"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	xhttp "github.com/minio/minio/internal/http"
)

func retentionOverwriteUnchanged(t *testing.T, before, after ObjectInfo) {
	t.Helper()
	if after.ETag != before.ETag || after.Size != before.Size || after.VersionID != before.VersionID || !after.ModTime.Equal(before.ModTime) {
		t.Error("rejected write changed the stored object")
	}
	if objectlock.GetObjectRetentionMeta(after.UserDefined).String() != objectlock.GetObjectRetentionMeta(before.UserDefined).String() || objectlock.GetObjectLegalHoldMeta(after.UserDefined).Status != objectlock.GetObjectLegalHoldMeta(before.UserDefined).Status {
		t.Error("rejected write changed the stored lock")
	}
}

func TestObjectLockOverwriteConfigUnavailable(t *testing.T) {
	previous := newObjectLayerFn()
	setObjectLayer(nil)
	defer setObjectLayer(previous)
	err := checkObjectLockedForOverwrite(t.Context(), "lock-config-unavailable", "object", func(context.Context, string, string, ObjectOptions) (ObjectInfo, error) {
		t.Fatal("object must not be read without a bucket configuration")
		return ObjectInfo{}, nil
	})
	if !errors.Is(err, errServerNotInitialized) {
		t.Fatalf("unavailable lock configuration must fail closed, got %v", err)
	}
}

func TestPutObjectRetentionMaximumDaysPolicy(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true, LockEnabled: true},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
			for _, conditionalAllow := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/conditional-allow=%t", instance, conditionalAllow), func(t *testing.T) {
					statement := fmt.Sprintf(`{"Effect":"Allow","Action":["s3:PutObjectRetention"],"Resource":["arn:aws:s3:::%s/*"],"Condition":{"NumericLessThanEquals":{"s3:object-lock-remaining-retention-days":"200000"}}}`, bucket)
					if !conditionalAllow {
						statement = fmt.Sprintf(`{"Effect":"Allow","Action":["s3:PutObjectRetention"],"Resource":["arn:aws:s3:::%s/*"]},{"Effect":"Deny","Action":["s3:PutObjectRetention"],"Resource":["arn:aws:s3:::%s/*"],"Condition":{"NumericGreaterThan":{"s3:object-lock-remaining-retention-days":"200000"}}}`, bucket, bucket)
					}
					cred := newRetentionPolicyUser(t, instance, `{"Version":"2012-10-17","Statement":[`+statement+`]}`)
					key := fmt.Sprintf("maximum-retention-%t", conditionalAllow)
					initial, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewReader(nil), 0, "", ""), ObjectOptions{Versioned: true})
					if err != nil {
						t.Fatal(err)
					}
					// Both dates exceed time.Duration's range (~292 years). A saturated
					// Time.Sub would report 106752 days and incorrectly allow 1000 years.
					if status := putRetention(t, router, cred, bucket, key, initial.VersionID, "GOVERNANCE", UTCNow().AddDate(1000, 0, 0), false); status != http.StatusForbidden {
						t.Fatalf("1000-year retention: want 403, got %d", status)
					}
					after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: initial.VersionID})
					if err != nil {
						t.Fatal(err)
					}
					retentionOverwriteUnchanged(t, initial, after)
					if status := putRetention(t, router, cred, bucket, key, initial.VersionID, "GOVERNANCE", UTCNow().AddDate(500, 0, 0), false); status != http.StatusOK {
						t.Fatalf("500-year retention: want 200, got %d", status)
					}
				})
			}
		},
	})
}

func TestAPICopyObjectPreservesVersionAfterSuspension(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
			t.Run(instance, func(t *testing.T) {
				key := "self-copy-after-suspension"
				original, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewBufferString("payload"), 7, "", ""), ObjectOptions{
					Versioned: true, UserDefined: map[string]string{"x-amz-meta-state": "original"},
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig,
					[]byte(`<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`)); err != nil {
					t.Fatal(err)
				}
				rec := retentionAuthzRequest(t, router, root, http.MethodPut, makeTestTargetURL("", bucket, key, nil), nil, map[string]string{
					xhttp.AmzCopySource: "/" + bucket + "/" + key, xhttp.AmzMetadataDirective: "REPLACE", "x-amz-meta-state": "replacement",
				})
				if rec.Code != http.StatusOK {
					t.Fatalf("copy: %d %s", rec.Code, rec.Body.String())
				}
				old, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: original.VersionID})
				if err != nil {
					t.Fatal(err)
				}
				if old.UserDefined["x-amz-meta-state"] != "original" {
					t.Errorf("copy changed metadata of existing UUID %s: %v", original.VersionID, old.UserDefined)
				}
				current, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: nullVersionID})
				if err != nil {
					t.Fatalf("copy must create the null version: %v", err)
				}
				if current.UserDefined["X-Amz-Meta-State"] != "replacement" {
					t.Errorf("new null version metadata: %v", current.UserDefined)
				}
			})
		},
	})
}

// A persisted null upload can survive an upgrade or a versioning transition.
// The completion must see locks committed after the handler's preflight.
func TestMultipartNullObjectLockAfterPreflight(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true, LockEnabled: true},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
			writer := newObjectAttributesAuthzUser(t, instance, bucket, `"s3:PutObject"`)
			for _, mode := range []string{"GOVERNANCE", "COMPLIANCE", "LEGAL-HOLD"} {
				t.Run(instance+"/"+mode, func(t *testing.T) {
					ctx := t.Context()
					key := "multipart-null-" + mode
					opts := ObjectOptions{Versioned: true, VersionID: nullVersionID, ReplicationRequest: true}
					if _, err := obj.PutObject(ctx, bucket, key, mustGetPutObjReader(t, bytes.NewBufferString("original"), 8, "", ""), opts); err != nil {
						t.Fatal(err)
					}
					mp, err := obj.NewMultipartUpload(ctx, bucket, key, opts)
					if err != nil {
						t.Fatal(err)
					}
					part, err := obj.PutObjectPart(ctx, bucket, key, mp.UploadID, 1, mustGetPutObjReader(t, bytes.NewBufferString("replacement"), 11, "", ""), ObjectOptions{})
					if err != nil {
						t.Fatal(err)
					}
					var locked ObjectInfo
					hook := &hookBeforeWrite{ObjectLayer: obj, key: key, before: func() {
						if mode == "LEGAL-HOLD" {
							body := []byte(`<LegalHold><Status>ON</Status></LegalHold>`)
							sum := md5.Sum(body)
							rec := retentionAuthzRequest(t, router, root, http.MethodPut, makeTestTargetURL("", bucket, key, url.Values{"legal-hold": {""}, "versionId": {nullVersionID}}), body, map[string]string{xhttp.ContentMD5: base64.StdEncoding.EncodeToString(sum[:])})
							if rec.Code != http.StatusOK {
								t.Fatalf("set legal hold: %d %s", rec.Code, rec.Body.String())
							}
						} else if status := putRetention(t, router, root, bucket, key, nullVersionID, mode, UTCNow().Add(365*24*time.Hour), false); status != http.StatusOK {
							t.Fatalf("set retention: %d", status)
						}
						var err error
						locked, err = obj.GetObjectInfo(ctx, bucket, key, ObjectOptions{VersionID: nullVersionID})
						if err != nil {
							t.Fatal(err)
						}
					}}
					setObjectLayer(hook)
					defer setObjectLayer(obj)
					body := []byte(multipartConditionCompleteBody([]CompletePart{{PartNumber: 1, ETag: part.ETag}}))
					rec := retentionAuthzRequest(t, router, writer, http.MethodPost, makeTestTargetURL("", bucket, key, url.Values{"uploadId": {mp.UploadID}}), body, nil)
					if hook.before != nil || rec.Code != http.StatusBadRequest {
						t.Fatalf("completion after locking: %d %s", rec.Code, rec.Body.String())
					}
					multipartConditionError(t, rec, "InvalidRequest")
					after, err := obj.GetObjectInfo(ctx, bucket, key, ObjectOptions{VersionID: nullVersionID})
					if err != nil {
						t.Fatal(err)
					}
					retentionOverwriteUnchanged(t, locked, after)
					parts, err := obj.ListObjectParts(ctx, bucket, key, mp.UploadID, 0, 100, ObjectOptions{})
					if err != nil || len(parts.Parts) != 1 || parts.Parts[0].ETag != part.ETag {
						t.Fatalf("rejected completion removed upload parts: %v %+v", err, parts.Parts)
					}
				})
			}
		},
	})
}

// The newer, unlocked copy is in the write pool; the lock exists only in the
// other pool. A set-local check would miss it even while holding a write lock.
func TestPoolsObjectLockOverwrite(t *testing.T) {
	z, _ := consistencyPools(t)
	bucket, _, err := initAPIHandlerTest(t.Context(), z, nil, MakeBucketOptions{VersioningEnabled: true, LockEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"GOVERNANCE", "COMPLIANCE", "LEGAL-HOLD", "expired", "unlocked", "unreadable"} {
		for _, op := range []string{"put", "copy", "self-copy", "multipart"} {
			t.Run(state+"/"+op, func(t *testing.T) {
				ctx := t.Context()
				key := encodeDirObject("null-" + state + "-" + op + "/")
				meta := map[string]string{}
				switch state {
				case "GOVERNANCE", "COMPLIANCE":
					meta[strings.ToLower(xhttp.AmzObjectLockMode)] = state
					meta[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = amztime.ISO8601Format(UTCNow().Add(365 * 24 * time.Hour))
				case "LEGAL-HOLD":
					meta[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = "ON"
				case "expired":
					meta[strings.ToLower(xhttp.AmzObjectLockMode)] = "GOVERNANCE"
					meta[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = amztime.ISO8601Format(UTCNow().Add(-24 * time.Hour))
				}
				seed := ObjectOptions{Versioned: true, VersionID: nullVersionID, ReplicationRequest: true, MTime: UTCNow().Add(-time.Hour), UserDefined: meta}
				putConsistencyObject(t, z, bucket, key, 1, "original", seed)
				seed.UserDefined = map[string]string{}
				seed.MTime = UTCNow()
				putConsistencyObject(t, z, bucket, key, 0, "original", seed)
				before := make([]ObjectInfo, len(z.serverPools))
				for i, pool := range z.serverPools {
					var err error
					before[i], err = pool.GetObjectInfo(ctx, bucket, key, ObjectOptions{VersionID: nullVersionID})
					if err != nil {
						t.Fatal(err)
					}
				}
				defer conditionalPutPool(t, z, key, 0)()
				var source string
				var copyInfo ObjectInfo
				if op == "copy" || op == "self-copy" {
					source = key
					if op == "copy" {
						source = "source-" + state
						putConsistencyObject(t, z, bucket, source, 0, "replacement", ObjectOptions{Versioned: true})
					}
					// Resolve the source before the pool becomes unreadable.
					// The destination must still reject a previously read source.
					gr, gerr := z.GetObjectNInfo(ctx, bucket, source, nil, nil, ObjectOptions{})
					if gerr != nil {
						t.Fatal(gerr)
					}
					defer gr.Close()
					copyInfo = gr.ObjInfo
					copyInfo.metadataOnly = op == "self-copy"
					copyInfo.PutObjReader = mustGetPutObjReader(t, gr, copyInfo.Size, "", "")
					copyInfo.Reader = copyInfo.PutObjReader.Reader
				}
				var restore func()
				if state == "unreadable" {
					restore = conditionalPutSwapDisks(z.serverPools[1], key, func(d StorageAPI) StorageAPI {
						return consistencyReadFaultDisk{StorageAPI: d, bucket: bucket, object: key}
					})
					defer restore()
				}
				opts := ObjectOptions{Versioned: true, VersionID: nullVersionID, UserDefined: map[string]string{"x-amz-meta-updated": "true"}}
				var writeErr error
				switch op {
				case "put":
					_, writeErr = z.PutObject(ctx, bucket, key, mustGetPutObjReader(t, bytes.NewBufferString("replacement"), 11, "", ""), opts)
				case "copy", "self-copy":
					copyInfo.UserDefined = opts.UserDefined
					_, writeErr = z.CopyObject(ctx, bucket, source, bucket, key, copyInfo, ObjectOptions{VersionID: nullVersionID}, opts)
				case "multipart":
					id, parts := multipartConditionUpload(t, z, bucket, key, 0, opts)
					_, writeErr = z.CompleteMultipartUpload(ctx, bucket, key, id, parts, ObjectOptions{Versioned: true})
				}
				allowed := state == "expired" || state == "unlocked"
				if allowed {
					if writeErr != nil {
						t.Fatalf("unlocked write: %v", writeErr)
					}
					return
				}
				if state == "unreadable" {
					if !isErrReadQuorum(writeErr) {
						t.Fatalf("unreadable pool: want quorum error, got %v", writeErr)
					}
					restore()
				} else if !errors.As(writeErr, &ObjectLocked{}) {
					t.Fatalf("lock in other pool: want ObjectLocked, got %v", writeErr)
				}
				for i, original := range before {
					after, gerr := z.serverPools[i].GetObjectInfo(ctx, bucket, key, ObjectOptions{VersionID: nullVersionID})
					if gerr != nil {
						t.Fatal(gerr)
					}
					retentionOverwriteUnchanged(t, original, after)
				}
			})
		}
	}
}

type planReviewGatedBody struct {
	io.ReadCloser
	first   sync.Once
	ready   chan struct{}
	release chan struct{}
}

func (g *planReviewGatedBody) Read(p []byte) (int, error) {
	g.first.Do(func() { close(g.ready); <-g.release })
	return g.ReadCloser.Read(p)
}

func TestPlanReviewSlowDirectoryPut(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true, LockEnabled: true},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
			writer := newObjectAttributesAuthzUser(t, instance, bucket, `"s3:PutObject"`)
			t.Run(instance, func(t *testing.T) {
				key := "slow-body-directory/"
				before, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewBufferString("original"), 8, "", ""), ObjectOptions{Versioned: true, VersionID: nullVersionID})
				if err != nil {
					t.Fatal(err)
				}
				payload := []byte("replacement-body")
				req, err := newTestSignedRequestV4(http.MethodPut, makeTestTargetURL("", bucket, key, nil), int64(len(payload)), bytes.NewReader(payload), writer.AccessKey, writer.SecretKey, nil)
				if err != nil {
					t.Fatal(err)
				}
				gate := &planReviewGatedBody{ReadCloser: req.Body, ready: make(chan struct{}), release: make(chan struct{})}
				req.Body = gate
				var once sync.Once
				release := func() { once.Do(func() { close(gate.release) }) }
				defer release()
				rec := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { router.ServeHTTP(rec, req); close(done) }()
				select {
				case <-gate.ready:
				case <-done:
					t.Fatalf("PUT finished before body: %d %s", rec.Code, rec.Body.String())
				case <-time.After(5 * time.Second):
					t.Fatal("PUT did not reach body read")
				}
				locked := make(chan int, 1)
				go func() {
					locked <- putRetention(t, router, root, bucket, key, nullVersionID, "COMPLIANCE", UTCNow().Add(365*24*time.Hour), false)
				}()
				select {
				case status := <-locked:
					if status != http.StatusOK {
						t.Fatalf("set lock while body paused: %d", status)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("retention update blocked behind paused body")
				}
				release()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("PUT did not finish")
				}
				after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: nullVersionID})
				if err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusBadRequest || after.ETag != before.ETag || objectlock.GetObjectRetentionMeta(after.UserDefined).Mode != objectlock.RetCompliance {
					t.Fatal("paused ordinary PUT overwrote the COMPLIANCE null version after the lock was acknowledged")
				}
			})
		},
	})
}

type planReviewReadFault struct {
	ObjectLayer
	key       string
	fired     bool
	putCalled bool
}

func (p *planReviewReadFault) GetObjectInfo(ctx context.Context, bucket, key string, opts ObjectOptions) (ObjectInfo, error) {
	if key == p.key && opts.VersionID == nullVersionID && !p.fired {
		p.fired = true
		return ObjectInfo{}, InsufficientReadQuorum{}
	}
	return p.ObjectLayer.GetObjectInfo(ctx, bucket, key, opts)
}

func (p *planReviewReadFault) PutObject(ctx context.Context, bucket, key string, data *PutObjReader, opts ObjectOptions) (ObjectInfo, error) {
	if key == p.key {
		p.putCalled = true
	}
	return p.ObjectLayer.PutObject(ctx, bucket, key, data, opts)
}

func TestPlanReviewPreflightReadFailure(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true, LockEnabled: true},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
			writer := newObjectAttributesAuthzUser(t, instance, bucket, `"s3:PutObject"`)
			t.Run(instance, func(t *testing.T) {
				key := "locked-directory-read-fault/"
				_, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewBufferString("original"), 8, "", ""), ObjectOptions{
					Versioned: true, VersionID: nullVersionID, ReplicationRequest: true,
					UserDefined: map[string]string{
						strings.ToLower(xhttp.AmzObjectLockMode):            "COMPLIANCE",
						strings.ToLower(xhttp.AmzObjectLockRetainUntilDate): amztime.ISO8601Format(UTCNow().Add(365 * 24 * time.Hour)),
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				initial, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: nullVersionID})
				if err != nil {
					t.Fatal(err)
				}
				fault := &planReviewReadFault{ObjectLayer: obj, key: key}
				setObjectLayer(fault)
				defer setObjectLayer(obj)
				rec := retentionAuthzRequest(t, router, writer, http.MethodPut, makeTestTargetURL("", bucket, key, nil), []byte("replacement"), nil)
				if !fault.fired {
					t.Fatal("preflight fault was not injected")
				}
				if fault.putCalled {
					t.Fatal("preflight read error allowed PutObject to proceed to storage layer")
				}
				after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: nullVersionID})
				if err != nil {
					t.Fatal(err)
				}
				if rec.Code < 400 {
					t.Errorf("metadata read quorum error was treated as absence: status=%d", rec.Code)
				}
				retentionOverwriteUnchanged(t, initial, after)
			})
		},
	})
}

func TestPlanReviewLegacyMPUCompliance(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true, LockEnabled: true},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
			writer := newObjectAttributesAuthzUser(t, instance, bucket, `"s3:PutObject"`)
			t.Run(instance, func(t *testing.T) {
				key := "legacy-mpu-compliance"
				initial, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewBufferString("original"), 8, "", ""), ObjectOptions{Versioned: true})
				if err != nil {
					t.Fatal(err)
				}
				up, err := obj.NewMultipartUpload(t.Context(), bucket, key, ObjectOptions{Versioned: true, VersionID: initial.VersionID})
				if err != nil {
					t.Fatal(err)
				}
				payload := []byte("replacement-part")
				part, err := obj.PutObjectPart(t.Context(), bucket, key, up.UploadID, 1, mustGetPutObjReader(t, bytes.NewReader(payload), int64(len(payload)), "", ""), ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if status := putRetention(t, router, root, bucket, key, initial.VersionID, "COMPLIANCE", UTCNow().Add(365*24*time.Hour), false); status != http.StatusOK {
					t.Fatalf("set compliance: %d", status)
				}
				before, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: initial.VersionID})
				if err != nil {
					t.Fatal(err)
				}
				body := fmt.Appendf(nil, `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"%s"</ETag></Part></CompleteMultipartUpload>`, part.ETag)
				rec := retentionAuthzRequest(t, router, writer, http.MethodPost, makeTestTargetURL("", bucket, key, url.Values{"uploadId": {up.UploadID}}), body, nil)
				after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: initial.VersionID})
				if err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusForbidden {
					t.Errorf("legacy upload replaced locked UUID: status=%d", rec.Code)
				}
				retentionOverwriteUnchanged(t, before, after)
			})
		},
	})
}

// A recovered upload retains an authentic server-generated version ID while a
// surviving replica reintroduces its already-completed version and lock.
// Only the fixture uses replication privileges; completion uses PutObject only.
func TestRecoveredMultipartUploadAfterReplica(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true, LockEnabled: true},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
			writer := newObjectAttributesAuthzUser(t, instance, bucket, `"s3:PutObject"`)
			t.Run(instance, func(t *testing.T) {
				z := obj.(*erasureServerPools)
				key := "recovered-generated-upload"
				up, err := obj.NewMultipartUpload(t.Context(), bucket, key, ObjectOptions{Versioned: true})
				if err != nil {
					t.Fatal(err)
				}
				er := z.serverPools[0].getHashedSet(key)
				fi, _, err := er.checkUploadIDExists(t.Context(), bucket, key, up.UploadID, true)
				if err != nil {
					t.Fatal(err)
				}
				_, err = obj.PutObject(t.Context(), bucket, key,
					mustGetPutObjReader(t, bytes.NewBufferString("protected-original"), 18, "", ""),
					ObjectOptions{Versioned: true, VersionID: fi.VersionID, ReplicationRequest: true})
				if err != nil {
					t.Fatal(err)
				}
				if status := putRetention(t, router, root, bucket, key, fi.VersionID, "COMPLIANCE", UTCNow().Add(365*24*time.Hour), false); status != http.StatusOK {
					t.Fatalf("setting compliance lock: %d", status)
				}
				before, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: fi.VersionID})
				if err != nil {
					t.Fatal(err)
				}
				partRec := retentionAuthzRequest(t, router, writer, http.MethodPut,
					makeTestTargetURL("", bucket, key, url.Values{"uploadId": {up.UploadID}, "partNumber": {"1"}}),
					[]byte("attacker-replacement"), nil)
				if partRec.Code != http.StatusOK {
					t.Fatalf("upload part: %d %s", partRec.Code, partRec.Body.String())
				}
				etag := multipartConditionResponseETag(partRec)
				body := []byte(multipartConditionCompleteBody([]CompletePart{{PartNumber: 1, ETag: etag}}))
				rec := retentionAuthzRequest(t, router, writer, http.MethodPost,
					makeTestTargetURL("", bucket, key, url.Values{"uploadId": {up.UploadID}}), body, nil)
				after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: fi.VersionID})
				if err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusForbidden {
					t.Errorf("recovered upload bypassed existing UUID guard: status=%d", rec.Code)
				}
				retentionOverwriteUnchanged(t, before, after)
			})
		},
	})
}
