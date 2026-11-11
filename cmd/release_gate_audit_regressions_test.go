// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"archive/zip"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
	"github.com/pgsty/silo-pkg/v3/policy"
)

func TestStrictPolicyParsingRejectsMalformedAndTypoJSON(t *testing.T) {
	invalidDocs := []struct {
		name string
		raw  string
	}{
		{"null-literal", "null"},
		{"array-literal", "[]"},
		{"string-literal", `"policy"`},
		{"trailing-object", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]}]} {"extra":1}`},
		{"typo-statement-key", `{"Version":"2012-10-17","Statment":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]}]}`}, //nolint:misspell
		{"unknown-stmt-field", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Actions":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]}]}`},
	}

	for _, tc := range invalidDocs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePolicyStrictBytes([]byte(tc.raw)); err == nil {
				t.Fatalf("parsePolicyStrictBytes(%s) unexpectedly succeeded", tc.name)
			}
			if _, err := parseSessionPolicyStrictBytes([]byte(tc.raw)); err == nil {
				t.Fatalf("parseSessionPolicyStrictBytes(%s) unexpectedly succeeded", tc.name)
			}
			if _, err := parseBucketPolicyStrictBytes([]byte(tc.raw), "b"); err == nil {
				t.Fatalf("parseBucketPolicyStrictBytes(%s) unexpectedly succeeded", tc.name)
			}
		})
	}

	// Bucket policy must reject unknown Principal keys such as Service instead of treating AWS as empty.
	servicePrincipalPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["s3.amazonaws.com"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]}]}`
	if _, err := parseBucketPolicyStrictBytes([]byte(servicePrincipalPolicy), "b"); err == nil {
		t.Fatal("parseBucketPolicyStrictBytes accepted Principal.Service without AWS key")
	}

	// Explicit session-policy reset documents remain accepted for service accounts,
	// while named IAM policies reject empty statement lists.
	for _, resetDoc := range []string{`{}`, `{"Statement":[]}`, `{"Version":"2012-10-17","Statement":[]}`} {
		sp, err := parseSessionPolicyStrictBytes([]byte(resetDoc))
		if err != nil {
			t.Fatalf("parseSessionPolicyStrictBytes(%s) unexpected error: %v", resetDoc, err)
		}
		if !sp.IsEmpty() {
			t.Fatalf("parseSessionPolicyStrictBytes(%s) expected empty policy", resetDoc)
		}
		if _, err := parsePolicyStrictBytes([]byte(resetDoc)); err == nil {
			t.Fatalf("parsePolicyStrictBytes(%s) accepted empty named policy", resetDoc)
		}
	}

	// Versioning ExcludedPrefixes must be recognized as PrefixesExcluded so Object Lock import rejects it.
	var v versioning.Versioning
	if err := xml.Unmarshal([]byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status><ExcludedPrefixes><Prefix>tmp/</Prefix></ExcludedPrefixes></VersioningConfiguration>`), &v); err != nil {
		t.Fatal(err)
	}
	if !v.PrefixesExcluded() {
		t.Fatal("expected v.PrefixesExcluded() == true when ExcludedPrefixes is populated")
	}
}

func TestLegacyEmptyEmbeddedPolicyServiceAccountStaysDenyAll(t *testing.T) {
	f := newGroupRefreshFixture(t)
	_, err := f.sys.PolicyDBSet(f.ctx, f.parent.AccessKey, "readwrite", regUser, false)
	mustIAM(t, err)

	// Sanity check: parent has full access.
	if !f.sys.IsAllowed(policy.Args{AccountName: f.parent.AccessKey, Action: policy.GetObjectAction, BucketName: "b", ObjectName: "k"}) {
		t.Fatal("expected parent user to allow GetObject")
	}

	const legacyKey = "legacy-deny-all-sa"
	legacyClaims := map[string]any{
		iamPolicyClaimNameSA():   embeddedPolicyType,
		policy.SessionPolicyName: base64.StdEncoding.EncodeToString([]byte(`{"Version":"2012-10-17","Statement":[]}`)),
	}
	_, _, err = f.sys.NewServiceAccount(f.ctx, f.parent.AccessKey, nil, newServiceAccountOpts{
		accessKey:                   legacyKey,
		secretKey:                   "legacy-secret-key-12345",
		claims:                      legacyClaims,
		preserveEmptyEmbeddedPolicy: true,
	})
	mustIAM(t, err)
	mustIAM(t, f.sys.store.LoadIAMCache(f.ctx, false))

	u, valid, err := f.sys.CheckKey(f.ctx, legacyKey)
	mustIAM(t, err)
	if !valid {
		t.Fatal("expected legacy service account to remain valid")
	}
	if f.sys.IsAllowed(policy.Args{AccountName: legacyKey, Claims: u.Credentials.Claims, Action: policy.GetObjectAction, BucketName: "b", ObjectName: "k"}) {
		t.Fatal("legacy empty embedded-policy service account was promoted to parent permissions")
	}

	// Metadata-only edit (nil sessionPolicy) must preserve the deny-all embedded-policy state.
	_, err = f.sys.UpdateServiceAccount(f.ctx, legacyKey, updateServiceAccountOpts{
		description: "metadata-only-update",
	})
	mustIAM(t, err)
	mustIAM(t, f.sys.store.LoadIAMCache(f.ctx, false))

	u, _, err = f.sys.CheckKey(f.ctx, legacyKey)
	mustIAM(t, err)
	if u.Credentials.Description != "metadata-only-update" {
		t.Fatalf("description = %q, want metadata-only-update", u.Credentials.Description)
	}
	if f.sys.IsAllowed(policy.Args{AccountName: legacyKey, Claims: u.Credentials.Claims, Action: policy.GetObjectAction, BucketName: "b", ObjectName: "k"}) {
		t.Fatal("metadata-only edit promoted legacy deny-all service account to parent permissions")
	}

	// Explicit empty reset document clears the inline policy to parent inheritance.
	_, err = f.sys.UpdateServiceAccount(f.ctx, legacyKey, updateServiceAccountOpts{
		sessionPolicy: &policy.Policy{},
	})
	mustIAM(t, err)
	mustIAM(t, f.sys.store.LoadIAMCache(f.ctx, false))

	u, _, err = f.sys.CheckKey(f.ctx, legacyKey)
	mustIAM(t, err)
	if !f.sys.IsAllowed(policy.Args{AccountName: legacyKey, Claims: u.Credentials.Claims, Action: policy.GetObjectAction, BucketName: "b", ObjectName: "k"}) {
		t.Fatal("explicit empty-policy reset did not restore parent inheritance")
	}
}

func TestObjectLockSuspendedAndExcludedNullVersionProtection(t *testing.T) {
	t.Run("multi-pool-null-version-lock", func(t *testing.T) {
		z, bucket := consistencyPools(t)
		const key = "null-locked-obj"
		retainUntil := UTCNow().Add(24 * time.Hour).Format(time.RFC3339)

		// Pool 0 holds a COMPLIANCE-locked null version; Pool 1 holds an unlocked competing copy.
		metaLocked := poolLockMetadata("COMPLIANCE", "OFF", objectLockTestStamp0900, "")
		metaLocked[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = retainUntil
		metaUnlocked := poolLockMetadata("", "OFF", objectLockTestStamp1000, "")
		stamp := UTCNow().Add(-time.Minute)
		putConsistencyObject(t, z, bucket, key, 0, "locked-null", ObjectOptions{
			VersionID: nullVersionID, VersionSuspended: true, MTime: stamp, UserDefined: metaLocked,
		})
		putConsistencyObject(t, z, bucket, key, 1, "locked-null", ObjectOptions{
			VersionID: nullVersionID, VersionSuspended: true, MTime: stamp.Add(time.Second), UserDefined: metaUnlocked,
		})

		// Unaddressed DeleteObject (prefix-excluded or unversioned delete with RefuseLockedOverwrite) must fail closed,
		// even if a newer unlocked UUID version also exists on top of the locked null version.
		putConsistencyObject(t, z, bucket, key, 1, "newer-unlocked-v2", ObjectOptions{
			VersionID: mustGetUUID(), Versioned: true, MTime: stamp.Add(2 * time.Second),
		})
		_, err := z.DeleteObject(t.Context(), bucket, key, ObjectOptions{RefuseLockedOverwrite: true})
		var lockedErr ObjectLocked
		if !errors.As(err, &lockedErr) {
			t.Fatalf("DeleteObject error = %v, want ObjectLocked", err)
		}

		// Verify the COMPLIANCE-locked null version on pool 0 is untouched.
		got, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: nullVersionID, VersionSuspended: true})
		if err != nil {
			t.Fatalf("locked null version lost from pool 0: %v", err)
		}
		if got.UserDefined[strings.ToLower(xhttp.AmzObjectLockMode)] != "COMPLIANCE" {
			t.Fatalf("unexpected retention mode after blocked delete: %+v", got.UserDefined)
		}
	})

	t.Run("api-excluded-prefix-unaddressed-delete-and-bulk-delete", func(t *testing.T) {
		defer DetectTestLeak(t)()
		ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
			t:                 t,
			makeBucketOptions: MakeBucketOptions{LockEnabled: true},
			objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
				const key = "excl/worm-null"
				retainUntil := UTCNow().Add(24 * time.Hour).Format(time.RFC3339)
				meta := map[string]string{
					strings.ToLower(xhttp.AmzObjectLockMode):            "COMPLIANCE",
					strings.ToLower(xhttp.AmzObjectLockRetainUntilDate): retainUntil,
				}
				const payload = "immutable-null-version-data"
				// Write a COMPLIANCE-locked null version AND a newer unlocked UUID version on top of it,
				// then simulate a legacy Object Lock bucket with ExcludedPrefixes loaded in memory.
				_, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, strings.NewReader(payload), int64(len(payload)), "", ""), ObjectOptions{
					Versioned:   false,
					UserDefined: meta,
				})
				if err != nil {
					t.Fatalf("%s: PutObject null: %v", backend, err)
				}
				_, err = obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, strings.NewReader("newer-v2"), int64(len("newer-v2")), "", ""), ObjectOptions{
					Versioned: true,
				})
				if err != nil {
					t.Fatalf("%s: PutObject v2: %v", backend, err)
				}

				bm, err := globalBucketMetadataSys.Get(bucket)
				if err != nil {
					t.Fatalf("%s: get bucket metadata: %v", backend, err)
				}
				bm.versioningConfig = &versioning.Versioning{
					XMLNS:            "http://s3.amazonaws.com/doc/2006-03-01/",
					Status:           versioning.Enabled,
					ExcludedPrefixes: []versioning.ExcludedPrefix{{Prefix: "excl/"}},
				}
				globalBucketMetadataSys.Set(bucket, bm)

				// 1. Unaddressed DELETE /bucket/excl/worm-null must fail closed with ErrObjectLocked (400 InvalidRequest).
				delReq, err := newTestSignedRequestV4(http.MethodDelete, "/"+bucket+"/"+key, 0, nil, cred.AccessKey, cred.SecretKey, nil)
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, delReq)
				if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "WORM protected") {
					t.Fatalf("%s: unaddressed DELETE status = %d, want 400 WORM protected; body=%s", backend, rec.Code, rec.Body.String())
				}

				// 2. Unaddressed Multi-Object Delete POST /bucket?delete must report WORM error per key.
				delBody := `<Delete><Object><Key>` + key + `</Key></Object></Delete>`
				sum := md5.Sum([]byte(delBody))
				headers := map[string]string{
					xhttp.ContentMD5: base64.StdEncoding.EncodeToString(sum[:]),
				}
				bulkReq, err := newTestSignedRequestV4(http.MethodPost, "/"+bucket+"?delete", int64(len(delBody)), strings.NewReader(delBody), cred.AccessKey, cred.SecretKey, headers)
				if err != nil {
					t.Fatal(err)
				}
				rec = httptest.NewRecorder()
				router.ServeHTTP(rec, bulkReq)
				if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "WORM protected") {
					t.Fatalf("%s: DeleteObjects status=%d body=%s, want WORM protected error entry", backend, rec.Code, rec.Body.String())
				}

				// Locked null-version object must remain intact and readable.
				if _, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: nullVersionID, VersionSuspended: true}); err != nil {
					t.Fatalf("%s: locked null-version object disappeared: %v", backend, err)
				}
			},
		})
	})
}

func TestStreamingTrailerEOFAndNegativeDecodedLength(t *testing.T) {
	t.Run("unsigned-trailer-truncated-and-oversized", func(t *testing.T) {
		// Truncated mid-trailer (missing final \r\n\r\n) must return ErrUnexpectedEOF, never nil/EOF.
		truncatedBody := "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA=="
		req := httptest.NewRequest(http.MethodPut, "http://minio.local/b/k", strings.NewReader(truncatedBody))
		req.Header.Set(xhttp.AmzContentSha256, unsignedPayloadTrailer)
		req.Header.Set(xhttp.AmzDecodedContentLength, "5")
		req.Header.Set(awsTrailerHeader, "x-amz-checksum-crc32")

		rd, code := newUnsignedV4ChunkedReader(req, true)
		if code != ErrNone {
			t.Fatalf("newUnsignedV4ChunkedReader code = %v", code)
		}
		_, err := io.ReadAll(rd)
		rd.Close()
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated trailer ReadAll error = %v, want io.ErrUnexpectedEOF", err)
		}

		// Oversized trailer (> 64 KiB without \r\n\r\n) must reject cleanly without unbounded growth.
		oversizedBody := "1\r\na\r\n0\r\nx-amz-checksum-crc32:" + strings.Repeat("A", 64*1024+1024)
		req2 := httptest.NewRequest(http.MethodPut, "http://minio.local/b/k", strings.NewReader(oversizedBody))
		req2.Header.Set(xhttp.AmzContentSha256, unsignedPayloadTrailer)
		req2.Header.Set(xhttp.AmzDecodedContentLength, "1")
		req2.Header.Set(awsTrailerHeader, "x-amz-checksum-crc32")

		rd2, code := newUnsignedV4ChunkedReader(req2, true)
		if code != ErrNone {
			t.Fatalf("newUnsignedV4ChunkedReader oversized code = %v", code)
		}
		_, err = io.ReadAll(rd2)
		rd2.Close()
		if err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("oversized trailer ReadAll error = %v, want non-EOF error", err)
		}
	})

	t.Run("negative-decoded-content-length-rejected", func(t *testing.T) {
		defer DetectTestLeak(t)()
		ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
			t:         t,
			endpoints: []string{"PutObject"},
			objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
				req, err := newStreamingUnsignedTrailerRequest(http.MethodPut, getPutObjectURL("", bucket, "neg-len"), []byte("abc"), UTCNow())
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set(xhttp.AmzDecodedContentLength, "-5")
				if err := signRequestV4(req, cred.AccessKey, cred.SecretKey); err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("%s: negative X-Amz-Decoded-Content-Length status = %d, want 400; body=%s", backend, rec.Code, rec.Body.String())
				}
				if _, err := obj.GetObjectInfo(t.Context(), bucket, "neg-len", ObjectOptions{}); err == nil {
					t.Fatalf("%s: object stored despite negative X-Amz-Decoded-Content-Length", backend)
				}
			},
		})
	})
}

func signV4WithScopeDate(req *http.Request, accessKey, secretKey, region string, reqTime, scopeTime time.Time, payloadHash string) {
	req.Header.Set(xhttp.AmzDate, reqTime.Format(iso8601Format))
	req.Header.Set(xhttp.AmzContentSha256, payloadHash)
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", req.Host)
	}
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req.Host, payloadHash, reqTime.Format(iso8601Format))
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonicalHeaders,
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", scopeTime.Format(yyyymmdd), region)
	sum := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		signV4Algorithm,
		reqTime.Format(iso8601Format),
		scope,
		hex.EncodeToString(sum[:]),
	}, "\n")
	signingKey := getSigningKey(secretKey, scopeTime, region, serviceS3)
	sig := getSignature(signingKey, stringToSign)
	req.Header.Set(xhttp.Authorization, fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		signV4Algorithm, accessKey, scope, strings.Join(signedHeaders, ";"), sig))
}

func TestSigV4ScopeDateMismatchRejected(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:         t,
		endpoints: []string{"GetObject", "PutObject"},
		objAPITest: func(_ ObjectLayer, backend, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
			now := UTCNow()
			yesterday := now.Add(-24 * time.Hour)
			const region = globalMinioDefaultRegion

			// 1. Standard Header SigV4
			req := httptest.NewRequest(http.MethodGet, "http://minio.local/"+bucket+"/obj", nil)
			signV4WithScopeDate(req, cred.AccessKey, cred.SecretKey, region, now, yesterday, emptySHA256)
			if code := doesSignatureMatch(emptySHA256, req, region, serviceS3); code == ErrNone {
				t.Fatalf("%s: doesSignatureMatch accepted mismatched scope date", backend)
			}

			// 2. Streaming Seed SigV4
			sreq := httptest.NewRequest(http.MethodPut, "http://minio.local/"+bucket+"/obj", strings.NewReader("0\r\n\r\n"))
			sreq.Header.Set(xhttp.AmzDecodedContentLength, "0")
			signV4WithScopeDate(sreq, cred.AccessKey, cred.SecretKey, region, now, yesterday, streamingContentSHA256)
			if _, _, _, _, code := calculateSeedSignature(sreq, false); code == ErrNone {
				t.Fatalf("%s: calculateSeedSignature accepted mismatched scope date", backend)
			}

			// 3. Presigned SigV4
			q := url.Values{}
			scope := fmt.Sprintf("%s/%s/s3/aws4_request", yesterday.Format(yyyymmdd), region)
			q.Set(xhttp.AmzAlgorithm, signV4Algorithm)
			q.Set(xhttp.AmzCredential, cred.AccessKey+"/"+scope)
			q.Set(xhttp.AmzDate, now.Format(iso8601Format))
			q.Set(xhttp.AmzExpires, "300")
			q.Set(xhttp.AmzSignedHeaders, "host")
			preq := httptest.NewRequest(http.MethodGet, "http://minio.local/"+bucket+"/obj?"+q.Encode(), nil)
			canonicalPresigned := strings.Join([]string{
				http.MethodGet,
				preq.URL.EscapedPath(),
				preq.URL.Query().Encode(),
				"host:" + preq.Host + "\n",
				"host",
				unsignedPayload,
			}, "\n")
			psum := sha256.Sum256([]byte(canonicalPresigned))
			pSTS := strings.Join([]string{
				signV4Algorithm,
				now.Format(iso8601Format),
				scope,
				hex.EncodeToString(psum[:]),
			}, "\n")
			pSig := getSignature(getSigningKey(cred.SecretKey, yesterday, region, serviceS3), pSTS)
			q.Set(xhttp.AmzSignature, pSig)
			preq.URL.RawQuery = q.Encode()
			if code := doesPresignedSignatureMatch(unsignedPayload, preq, region, serviceS3); code == ErrNone {
				t.Fatalf("%s: doesPresignedSignatureMatch accepted mismatched scope date", backend)
			}

			// 4. POST Policy SigV4
			policyDoc := fmt.Sprintf(`{"expiration":%q,"conditions":[["eq","$bucket",%q],["eq","$x-amz-date",%q],["eq","$x-amz-credential",%q],["eq","$x-amz-algorithm","AWS4-HMAC-SHA256"]]}`,
				now.Add(10*time.Minute).Format(iso8601Format), bucket, now.Format(iso8601Format), cred.AccessKey+"/"+scope)
			policyB64 := base64.StdEncoding.EncodeToString([]byte(policyDoc))
			mac := hmac.New(sha256.New, getSigningKey(cred.SecretKey, yesterday, region, serviceS3))
			mac.Write([]byte(policyB64))
			postSig := hex.EncodeToString(mac.Sum(nil))
			formValues := http.Header{}
			formValues.Set(xhttp.AmzAlgorithm, signV4Algorithm)
			formValues.Set(xhttp.AmzCredential, cred.AccessKey+"/"+scope)
			formValues.Set(xhttp.AmzDate, now.Format(iso8601Format))
			formValues.Set(xhttp.AmzSignature, postSig)
			formValues.Set("Policy", policyB64)
			if _, code := doesPolicySignatureV4Match(formValues); code == ErrNone {
				t.Fatalf("%s: doesPolicySignatureV4Match accepted mismatched scope date", backend)
			}
		},
	})
}

func TestBatchKeyRotateLegacyXLV1AndSSES3ToKMS(t *testing.T) {
	f := newBatchAuthzFixture(t)
	previous := GlobalKMS
	t.Cleanup(func() { GlobalKMS = previous })
	configured, err := kms.NewBuiltin("rotate-key", bytes.Repeat([]byte{0x37}, 32))
	mustIAM(t, err)
	GlobalKMS = configured

	t.Run("sse-s3-multipart-to-sse-kms-empty-context", func(t *testing.T) {
		const object = "sses3-mp/item"
		const payload = "multipart sse-s3 migrated to sse-kms without losing multipart flag"
		metadata := map[string]string{
			crypto.MetaMultipart: "1",
		}
		key, err := newEncryptMetadata(f.ctx, crypto.S3, "", nil, f.bucket, object, metadata, nil)
		mustIAM(t, err)
		ciphertext, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader(payload), key))
		mustIAM(t, err)
		original, err := f.obj.PutObject(f.ctx, f.bucket, object, mustGetPutObjReader(t, bytes.NewReader(ciphertext), int64(len(ciphertext)), "", ""), ObjectOptions{
			Versioned:   true,
			UserDefined: metadata,
		})
		mustIAM(t, err)

		rec, job := f.submit(t, globalActiveCred, fmt.Sprintf("keyrotate:\n  apiVersion: v1\n  bucket: %s\n  prefix: sses3-mp/\n  encryption:\n    type: sse-kms\n    key: rotate-key\n", f.bucket))
		if job == nil {
			t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
		}
		mustIAM(t, job.KeyRotate.Start(f.ctx, f.obj, *job))
		progress := f.jobInfo(t, job)
		if !progress.Complete || progress.Failed || progress.Objects != 1 {
			t.Fatalf("SSE-S3 -> SSE-KMS rotation failed: %+v", progress)
		}

		after, err := f.obj.GetObjectInfo(f.ctx, f.bucket, object, ObjectOptions{VersionID: original.VersionID})
		mustIAM(t, err)
		if !crypto.S3KMS.IsEncrypted(after.UserDefined) || crypto.S3.IsEncrypted(after.UserDefined) {
			t.Fatalf("unexpected encryption headers after SSE-S3 -> SSE-KMS: %+v", after.UserDefined)
		}
		if after.UserDefined[crypto.MetaMultipart] != "1" {
			t.Fatalf("MetaMultipart stripped during SSE-S3 -> SSE-KMS rotation: %+v", after.UserDefined)
		}
		actual, err := crypto.S3KMS.UnsealObjectKey(configured, after.UserDefined, f.bucket, object)
		mustIAM(t, err)
		if actual != key {
			t.Fatal("data encryption key changed during metadata rotation")
		}
	})

	t.Run("legacy-xlv1-stream-rewrite-rotation", func(t *testing.T) {
		const legacyBucket = "legacy-xlv1-bucket"
		mustIAM(t, f.obj.MakeBucket(f.ctx, legacyBucket, MakeBucketOptions{}))

		const object = "legacy/obj"
		payload := strings.Repeat("legacy XLV1 object rotated cleanly to XLV2 without panic! ", 4096)
		metadata := map[string]string{
			xhttp.AmzObjectTagging: "tier=legacy",
		}
		key, err := newEncryptMetadata(f.ctx, crypto.S3KMS, "rotate-key", nil, legacyBucket, object, metadata, kms.Context{"stage": "v1"})
		mustIAM(t, err)
		ciphertext, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader(payload), key))
		mustIAM(t, err)
		plainMD5 := md5.Sum([]byte(payload))
		sealedETag := hex.EncodeToString(key.SealETag(plainMD5[:]))
		metadata["etag"] = sealedETag

		_, err = f.obj.PutObject(f.ctx, legacyBucket, object, mustGetPutObjReader(t, bytes.NewReader(ciphertext), int64(len(ciphertext)), "", ""), ObjectOptions{
			UserDefined: metadata,
		})
		mustIAM(t, err)

		// Convert stored XLV2 layout on the single test disk into a real XLV1 xl.json + part.1 layout.
		disk := f.obj.(*erasureServerPools).serverPools[0].sets[0].getDisks()[0]
		xlDisk := disk.(*xlStorageDiskIDCheck).storage
		xlDisk.Lock()
		xlDisk.formatLegacy = true
		xlDisk.Unlock()
		t.Cleanup(func() {
			xlDisk.Lock()
			xlDisk.formatLegacy = false
			xlDisk.Unlock()
		})

		fi, err := disk.ReadVersion(f.ctx, "", legacyBucket, object, "", ReadOptions{})
		mustIAM(t, err)

		partPath := pathJoin(object, fi.DataDir, "part.1")
		rawPartBytes, err := disk.ReadAll(f.ctx, legacyBucket, partPath)
		mustIAM(t, err)

		mustIAM(t, disk.Delete(f.ctx, legacyBucket, pathJoin(object, xlStorageFormatFile), DeleteOptions{}))
		mustIAM(t, disk.Delete(f.ctx, legacyBucket, partPath, DeleteOptions{}))
		mustIAM(t, disk.AppendFile(f.ctx, legacyBucket, pathJoin(object, "part.1"), rawPartBytes))

		fi.Metadata["etag"] = sealedETag
		v1Obj := xlMetaV1Object{
			Version: xlMetaVersion101,
			Format:  xlMetaFormat,
			Stat: StatInfo{
				Size:    fi.Size,
				ModTime: fi.ModTime,
			},
			Erasure: fi.Erasure,
			Meta:    fi.Metadata,
			Parts:   fi.Parts,
		}
		v1Obj.Minio.Release = "RELEASE.2019-12-30T05-45-39Z"
		v1Bytes, err := json.Marshal(v1Obj)
		mustIAM(t, err)
		mustIAM(t, disk.AppendFile(f.ctx, legacyBucket, pathJoin(object, xlStorageFormatFileV1), v1Bytes))

		legacyOI, err := f.obj.GetObjectInfo(f.ctx, legacyBucket, object, ObjectOptions{})
		mustIAM(t, err)
		if !legacyOI.Legacy {
			t.Fatal("expected test fixture object to report Legacy (XLV1) == true")
		}

		newCtxB64 := base64.StdEncoding.EncodeToString([]byte(`{"stage":"v2"}`))
		rec, job := f.submit(t, globalActiveCred, fmt.Sprintf("keyrotate:\n  apiVersion: v1\n  bucket: %s\n  prefix: legacy/\n  encryption:\n    type: sse-kms\n    key: rotate-key\n    context: %s\n", legacyBucket, newCtxB64))
		if job == nil {
			t.Fatalf("submit legacy keyrotate: %d %s", rec.Code, rec.Body.String())
		}
		mustIAM(t, job.KeyRotate.Start(f.ctx, f.obj, *job))
		progress := f.jobInfo(t, job)
		if !progress.Complete || progress.Failed || progress.Objects != 1 {
			t.Fatalf("legacy XLV1 rotation failed: %+v", progress)
		}

		after, err := f.obj.GetObjectInfo(f.ctx, legacyBucket, object, ObjectOptions{})
		mustIAM(t, err)
		if after.Legacy {
			t.Fatal("expected rotated legacy object to be upgraded to XLV2 (Legacy == false)")
		}
		if after.UserTags != "tier=legacy" {
			t.Fatalf("UserTags = %q, want tier=legacy", after.UserTags)
		}
		if got := readCopyChecksumObject(t, f.obj, legacyBucket, object, ObjectOptions{}); string(got) != payload {
			t.Fatalf("decrypted content = %q, want %q", string(got), payload)
		}
		newObjKey, err := crypto.S3KMS.UnsealObjectKey(configured, after.UserDefined, legacyBucket, object)
		mustIAM(t, err)
		unsealedETag, err := DecryptETag(newObjKey, ObjectInfo{ETag: after.ETag})
		mustIAM(t, err)
		if wantETag := hex.EncodeToString(plainMD5[:]); unsealedETag != wantETag {
			t.Fatalf("unsealed ETag = %q, want %q", unsealedETag, wantETag)
		}
	})
}

func createTestPolicyUser(t *testing.T, policyJSON string) auth.Credentials {
	t.Helper()
	ctx := t.Context()
	ak, sk, err := auth.GenerateCredentials()
	if err != nil {
		t.Fatal(err)
	}
	creds := auth.Credentials{AccessKey: ak, SecretKey: sk}
	if _, err = globalIAMSys.CreateUser(ctx, creds.AccessKey, madmin.AddOrUpdateUserReq{
		SecretKey: creds.SecretKey,
		Status:    madmin.AccountEnabled,
	}); err != nil {
		t.Fatal(err)
	}
	parsed, err := policy.ParseConfig(strings.NewReader(policyJSON))
	if err != nil {
		t.Fatalf("parse policy: %v\n%s", err, policyJSON)
	}
	pName := "audit-policy-" + mustGetUUID()
	if _, err = globalIAMSys.SetPolicy(ctx, pName, *parsed); err != nil {
		t.Fatal(err)
	}
	if _, err = globalIAMSys.PolicyDBSet(ctx, creds.AccessKey, pName, regUser, false); err != nil {
		t.Fatal(err)
	}
	return creds
}

func TestObjectTagAndVersionAuthSymmetry(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t,
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, adminCred auth.Credentials, t *testing.T) {
			if _, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
				t.Fatalf("%s: enable versioning: %v", backend, err)
			}

			// Create v1 (env=prod) and v2 (env=dev) of src-obj.
			v1, err := obj.PutObject(t.Context(), bucket, "src-obj", mustGetPutObjReader(t, strings.NewReader("prod-secret"), int64(len("prod-secret")), "", ""), ObjectOptions{
				Versioned:   true,
				UserDefined: map[string]string{xhttp.AmzObjectTagging: "env=prod"},
			})
			if err != nil {
				t.Fatal(err)
			}
			v2, err := obj.PutObject(t.Context(), bucket, "src-obj", mustGetPutObjReader(t, strings.NewReader("dev-public"), int64(len("dev-public")), "", ""), ObjectOptions{
				Versioned:   true,
				UserDefined: map[string]string{xhttp.AmzObjectTagging: "env=dev"},
			})
			if err != nil {
				t.Fatal(err)
			}

			// Also create a ZIP object with env=prod tag to verify ZIP sub-handlers enforce ExistingObjectTag.
			var zipBuf bytes.Buffer
			zw := zip.NewWriter(&zipBuf)
			zf, err := zw.Create("inside.txt")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = zf.Write([]byte("zip-inner"))
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			_, err = obj.PutObject(t.Context(), bucket, "archive.zip", mustGetPutObjReader(t, bytes.NewReader(zipBuf.Bytes()), int64(zipBuf.Len()), "", ""), ObjectOptions{
				Versioned:   true,
				UserDefined: map[string]string{xhttp.AmzObjectTagging: "env=prod"},
			})
			if err != nil {
				t.Fatal(err)
			}

			// User A:
			// - Can read/tag ONLY objects/versions tagged env=dev.
			// - Can write dst/* ONLY when RequestObjectTag/env == dev (plus unconditional PutObject on prod-readable copy test).
			userAPolicy := fmt.Sprintf(`{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": [
							"s3:GetObject",
							"s3:GetObjectVersion",
							"s3:GetObjectTagging",
							"s3:GetObjectVersionTagging",
							"s3:PutObjectTagging",
							"s3:PutObjectVersionTagging",
							"s3:DeleteObjectTagging",
							"s3:DeleteObjectVersionTagging"
						],
						"Resource": ["arn:aws:s3:::%s/*"],
						"Condition": {"StringEquals": {"s3:ExistingObjectTag/env": ["dev"]}}
					},
					{
						"Effect": "Allow",
						"Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"],
						"Resource": ["arn:aws:s3:::%s"]
					},
					{
						"Effect": "Allow",
						"Action": ["s3:PutObject"],
						"Resource": ["arn:aws:s3:::%s/dst-*"],
						"Condition": {"StringEquals": {"s3:RequestObjectTag/env": ["dev"]}}
					},
					{
						"Effect": "Allow",
						"Action": ["s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
						"Resource": ["arn:aws:s3:::%s/mp-*"]
					}
				]
			}`, bucket, bucket, bucket, bucket)
			userA := createTestPolicyUser(t, userAPolicy)

			// 1. CopyObject from v1 (env=prod) must fail 403 due to source ExistingObjectTag.
			cpDenied, err := newTestSignedRequestV4(http.MethodPut, "/"+bucket+"/dst-denied", 0, nil, userA.AccessKey, userA.SecretKey, map[string]string{
				xhttp.AmzCopySource:    "/" + bucket + "/src-obj?versionId=" + v1.VersionID,
				xhttp.AmzTagDirective:  "REPLACE",
				xhttp.AmzObjectTagging: "env=dev",
			})
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, cpDenied)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: CopyObject from env=prod version status=%d, want 403", backend, rec.Code)
			}

			// 2. CopyObject from v2 (env=dev) with COPY directive succeeds (RequestObjectTag/env == dev from copied tags).
			cpOK, err := newTestSignedRequestV4(http.MethodPut, "/"+bucket+"/dst-ok", 0, nil, userA.AccessKey, userA.SecretKey, map[string]string{
				xhttp.AmzCopySource:   "/" + bucket + "/src-obj?versionId=" + v2.VersionID,
				xhttp.AmzTagDirective: "COPY",
			})
			if err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, cpOK)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: CopyObject from env=dev with COPY directive status=%d body=%s, want 200", backend, rec.Code, rec.Body.String())
			}

			// 3. RequestObjectTag spoofing defense on COPY directive:
			// User B can read all versions of src-obj, but can PutObject to dst-* ONLY when RequestObjectTag/env == dev.
			// Copying v1 (env=prod) with Tagging-Directive: COPY and a spoofed X-Amz-Tagging: env=dev header MUST fail 403!
			userBPolicy := fmt.Sprintf(`{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:GetObjectVersionTagging"],
						"Resource": ["arn:aws:s3:::%s/src-obj"]
					},
					{
						"Effect": "Allow",
						"Action": ["s3:PutObject", "s3:PutObjectTagging"],
						"Resource": ["arn:aws:s3:::%s/dst-*"],
						"Condition": {"StringEquals": {"s3:RequestObjectTag/env": ["dev"]}}
					},
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject"],
						"Resource": ["arn:aws:s3:::%s/src-obj"]
					}
				]
			}`, bucket, bucket, bucket)
			userB := createTestPolicyUser(t, userBPolicy)

			cpSpoof, err := newTestSignedRequestV4(http.MethodPut, "/"+bucket+"/dst-spoof", 0, nil, userB.AccessKey, userB.SecretKey, map[string]string{
				xhttp.AmzCopySource:    "/" + bucket + "/src-obj?versionId=" + v1.VersionID,
				xhttp.AmzTagDirective:  "COPY",
				xhttp.AmzObjectTagging: "env=dev",
			})
			if err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, cpSpoof)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: CopyObject accepted spoofed X-Amz-Tagging under COPY directive: status=%d body=%s", backend, rec.Code, rec.Body.String())
			}

			// 4. UploadPartCopy enforces ExistingObjectTag on versioned source!
			initMP, err := newTestSignedRequestV4(http.MethodPost, "/"+bucket+"/mp-target?uploads", 0, nil, userA.AccessKey, userA.SecretKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, initMP)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: CreateMultipartUpload status=%d body=%s", backend, rec.Code, rec.Body.String())
			}
			var initResp InitiateMultipartUploadResponse
			if err := xml.Unmarshal(rec.Body.Bytes(), &initResp); err != nil {
				t.Fatal(err)
			}

			upcDenied, err := newTestSignedRequestV4(http.MethodPut, fmt.Sprintf("/%s/mp-target?partNumber=1&uploadId=%s", bucket, url.QueryEscape(initResp.UploadID)), 0, nil, userA.AccessKey, userA.SecretKey, map[string]string{
				xhttp.AmzCopySource: "/" + bucket + "/src-obj?versionId=" + v1.VersionID,
			})
			if err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, upcDenied)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: UploadPartCopy from env=prod status=%d, want 403", backend, rec.Code)
			}

			upcOK, err := newTestSignedRequestV4(http.MethodPut, fmt.Sprintf("/%s/mp-target?partNumber=1&uploadId=%s", bucket, url.QueryEscape(initResp.UploadID)), 0, nil, userA.AccessKey, userA.SecretKey, map[string]string{
				xhttp.AmzCopySource: "/" + bucket + "/src-obj?versionId=" + v2.VersionID,
			})
			if err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, upcOK)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: UploadPartCopy from env=dev status=%d body=%s, want 200", backend, rec.Code, rec.Body.String())
			}

			// 5. GET / HEAD with X-Amz-Tagging-Directive: ACCESS must NOT leak X-Amz-Tagging when GetObjectTagging is denied!
			noTagReadPolicy := fmt.Sprintf(`{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": ["s3:GetObject", "s3:GetObjectVersion"],
					"Resource": ["arn:aws:s3:::%s/*"]
				}]
			}`, bucket)
			userNoTag := createTestPolicyUser(t, noTagReadPolicy)
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				req, err := newTestSignedRequestV4(method, "/"+bucket+"/src-obj?versionId="+v1.VersionID, 0, nil, userNoTag.AccessKey, userNoTag.SecretKey, map[string]string{
					xhttp.AmzTagDirective: "ACCESS",
				})
				if err != nil {
					t.Fatal(err)
				}
				rec = httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s: %s status=%d, want 200", backend, method, rec.Code)
				}
				if gotTag := rec.Header().Get(xhttp.AmzObjectTagging); gotTag != "" {
					t.Fatalf("%s: %s leaked X-Amz-Tagging=%q without GetObjectVersionTagging permission", backend, method, gotTag)
				}
				if gotCnt := rec.Header().Get(xhttp.AmzTagCount); gotCnt != "" {
					t.Fatalf("%s: %s leaked X-Amz-Tagging-Count=%q without GetObjectVersionTagging permission", backend, method, gotCnt)
				}
			}

			// 6. ListObjectVersions with metadata=true filters <UserTags> per version's ExistingObjectTag!
			listVerReq, err := newTestSignedRequestV4(http.MethodGet, "/"+bucket+"?versions=&metadata=true&prefix=src-obj", 0, nil, userA.AccessKey, userA.SecretKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, listVerReq)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: ListObjectVersions status=%d body=%s", backend, rec.Code, rec.Body.String())
			}
			bodyStr := rec.Body.String()
			if strings.Contains(bodyStr, "env=prod") {
				t.Fatalf("%s: ListObjectVersions metadata=true leaked unauthorized version tags env=prod: %s", backend, bodyStr)
			}
			if !strings.Contains(bodyStr, "env=dev") {
				t.Fatalf("%s: ListObjectVersions metadata=true omitted authorized version tags env=dev: %s", backend, bodyStr)
			}

			// 7. GetObjectTagging & DeleteObjectTagging with ?versionId= enforce ExistingObjectTag on that version!
			for _, method := range []string{http.MethodGet, http.MethodDelete} {
				tagDenied, err := newTestSignedRequestV4(method, "/"+bucket+"/src-obj?tagging=&versionId="+v1.VersionID, 0, nil, userA.AccessKey, userA.SecretKey, nil)
				if err != nil {
					t.Fatal(err)
				}
				rec = httptest.NewRecorder()
				router.ServeHTTP(rec, tagDenied)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("%s: %s tagging on v1 (env=prod) status=%d, want 403", backend, method, rec.Code)
				}
			}
			getTagOK, err := newTestSignedRequestV4(http.MethodGet, "/"+bucket+"/src-obj?tagging=&versionId="+v2.VersionID, 0, nil, userA.AccessKey, userA.SecretKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, getTagOK)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: GET tagging on v2 (env=dev) status=%d, want 200", backend, rec.Code)
			}

			// 8. Archive x-minio-extract sub-handlers (HEAD/GET/ListObjectsV2) reject access when archive ExistingObjectTag mismatches!
			for _, tc := range []struct {
				name, method, target string
			}{
				{"zip-get", http.MethodGet, "/" + bucket + "/archive.zip/inside.txt"},
				{"zip-head", http.MethodHead, "/" + bucket + "/archive.zip/inside.txt"},
				{"zip-list", http.MethodGet, "/" + bucket + "?list-type=2&prefix=archive.zip/"},
			} {
				zreq, err := newTestSignedRequestV4(tc.method, tc.target, 0, nil, userA.AccessKey, userA.SecretKey, map[string]string{
					"x-minio-extract": "true",
				})
				if err != nil {
					t.Fatal(err)
				}
				rec = httptest.NewRecorder()
				router.ServeHTTP(rec, zreq)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("%s: %s on env=prod archive status=%d, want 403", backend, tc.name, rec.Code)
				}
			}

			// Clean up multipart upload with admin credentials so DetectTestLeak sees no background state.
			abortReq, err := newTestSignedRequestV4(http.MethodDelete, fmt.Sprintf("/%s/mp-target?uploadId=%s", bucket, url.QueryEscape(initResp.UploadID)), 0, nil, adminCred.AccessKey, adminCred.SecretKey, nil)
			if err == nil {
				router.ServeHTTP(httptest.NewRecorder(), abortReq)
			}
		},
	})
}
