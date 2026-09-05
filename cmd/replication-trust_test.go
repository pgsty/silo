// Copyright (c) 2015-2026 MinIO, Inc.
// Copyright (c) 2026 PGSTY
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package cmd

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
	"github.com/pgsty/silo-pkg/v3/policy"
)

func TestAPIReplicationTrustProtectsSSECReads(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPIReplicationTrustProtectsSSECReads,
	})
}

func testAPIReplicationTrustProtectsSSECReads(_ ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	key := bytes.Repeat([]byte{0x31}, 32)
	keyMD5 := md5.Sum(key)
	data := bytes.Repeat([]byte("replication-trust-ssec-"), 256)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
	object := "replication-trust/ssec-read"
	putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data, sseHeaders)

	readerOnly := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:GetObject"`)
	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:GetObject","s3:ReplicateObject"`)

	marker := map[string]string{xhttp.MinIOSourceReplicationRequest: "true"}
	wrongCaseMarker := map[string]string{xhttp.MinIOSourceReplicationRequest: "TRUE"}
	conditionalMarker := map[string]string{
		xhttp.MinIOSourceReplicationRequest: "true",
		xhttp.IfNoneMatch:                   "*",
	}

	for _, test := range []struct {
		name       string
		method     string
		creds      auth.Credentials
		headers    map[string]string
		wantStatus int
		wantPlain  bool
		wantCipher bool
	}{
		{name: "get/reader/fake-marker", method: http.MethodGet, creds: readerOnly, headers: marker, wantStatus: http.StatusBadRequest},
		{name: "get/replicator/trusted", method: http.MethodGet, creds: replicator, headers: marker, wantStatus: http.StatusOK, wantCipher: true},
		{name: "get/root/trusted", method: http.MethodGet, creds: credentials, headers: marker, wantStatus: http.StatusOK, wantCipher: true},
		{name: "get/replicator/wrong-case", method: http.MethodGet, creds: replicator, headers: wrongCaseMarker, wantStatus: http.StatusBadRequest},
		{name: "get/reader/key", method: http.MethodGet, creds: readerOnly, headers: sseHeaders, wantStatus: http.StatusOK, wantPlain: true},
		{name: "head/reader/fake-marker", method: http.MethodHead, creds: readerOnly, headers: marker, wantStatus: http.StatusBadRequest},
		{name: "head/reader/conditional-oracle", method: http.MethodHead, creds: readerOnly, headers: conditionalMarker, wantStatus: http.StatusBadRequest},
		{name: "head/replicator/trusted", method: http.MethodHead, creds: replicator, headers: marker, wantStatus: http.StatusOK},
		{name: "head/replicator/wrong-case", method: http.MethodHead, creds: replicator, headers: wrongCaseMarker, wantStatus: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, err := newTestSignedRequestV4(test.method, getGetObjectURL("", bucketName, object), 0, nil,
				test.creds.AccessKey, test.creds.SecretKey, test.headers)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			apiRouter.ServeHTTP(rec, req)
			if rec.Code != test.wantStatus {
				t.Fatalf("%s: status %d, want %d: %s", instanceType, rec.Code, test.wantStatus, rec.Body.String())
			}
			if test.wantPlain && !bytes.Equal(rec.Body.Bytes(), data) {
				t.Fatal("ordinary SSE-C GET did not return plaintext")
			}
			if test.wantCipher && (len(rec.Body.Bytes()) == 0 || bytes.Equal(rec.Body.Bytes(), data)) {
				t.Fatal("trusted replication GET did not return ciphertext")
			}
		})
	}
}

func TestReplicationTrustControlsInternalOptionsAndEvents(t *testing.T) {
	mtime := time.Date(2026, 8, 31, 12, 34, 56, 123, time.UTC)
	headers := make(http.Header)
	headers.Set(xhttp.MinIOSourceReplicationRequest, "true")
	headers.Set(xhttp.MinIOSourceETag, "source-etag")
	headers.Set(xhttp.MinIOSourceMTime, mtime.Format(time.RFC3339Nano))
	headers.Set(xhttp.MinIOReplicationActualObjectSize, "123")
	headers.Set(ReplicationSsecChecksumHeader, "checksum")

	ordinary, err := putOptsFromHeaders(t.Context(), headers, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.ReplicationRequest || ordinary.PreserveETag != "" || !ordinary.MTime.IsZero() {
		t.Fatalf("ordinary options trusted internal headers: %#v", ordinary)
	}

	trusted, err := putOptsFromHeaders(t.Context(), headers, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted.ReplicationRequest || trusted.PreserveETag != "source-etag" || !trusted.MTime.Equal(mtime) {
		t.Fatalf("trusted options lost source state: %#v", trusted)
	}

	completeReq := &http.Request{Header: headers.Clone(), Form: make(url.Values)}
	ordinaryComplete, err := completeMultipartOpts(t.Context(), completeReq, "bucket", "object")
	if err != nil {
		t.Fatal(err)
	}
	if ordinaryComplete.ReplicationRequest || len(ordinaryComplete.UserDefined) != 0 {
		t.Fatalf("ordinary completion trusted internal metadata: %#v", ordinaryComplete)
	}
	trustedCompleteCtx := withReplicationTrust(t.Context(), true, false)
	trustedComplete, err := completeMultipartOpts(trustedCompleteCtx, completeReq.WithContext(trustedCompleteCtx), "bucket", "object")
	if err != nil {
		t.Fatal(err)
	}
	if !trustedComplete.ReplicationRequest || trustedComplete.UserDefined[ReservedMetadataPrefix+"Actual-Object-Size"] != "123" ||
		trustedComplete.UserDefined[ReplicationSsecChecksumHeader] != "checksum" {
		t.Fatalf("trusted completion lost internal metadata: %#v", trustedComplete)
	}

	req := &http.Request{Header: headers.Clone(), Form: make(url.Values)}
	req = req.WithContext(context.Background())
	if _, ok := extractReqParams(req)[xhttp.MinIOSourceReplicationRequest]; ok {
		t.Fatal("untrusted marker suppressed events")
	}
	trustedCtx := withReplicationTrust(req.Context(), true, false)
	req = req.WithContext(trustedCtx)
	if _, ok := extractReqParams(req)[xhttp.MinIOSourceReplicationRequest]; !ok {
		t.Fatal("trusted replication marker was not propagated to events")
	}
}

func TestAPIPutObjectReplicationTrust(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPIPutObjectReplicationTrust,
	})
}

func testAPIPutObjectReplicationTrust(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, _ auth.Credentials, t *testing.T,
) {
	putOnly := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject"`)
	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject","s3:ReplicateObject"`)
	payload := []byte("replication trust put payload")
	sourceMTime := time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC)

	request := func(t *testing.T, object string, creds auth.Credentials, status string, check bool) *httptest.ResponseRecorder {
		t.Helper()
		headers := map[string]string{
			xhttp.MinIOSourceReplicationRequest: "true",
			xhttp.MinIOSourceETag:               "source-etag",
			xhttp.MinIOSourceMTime:              sourceMTime.Format(time.RFC3339Nano),
		}
		if status != "" {
			headers[xhttp.AmzBucketReplicationStatus] = status
		}
		if check {
			headers[xhttp.MinIOSourceReplicationCheck] = "true"
		}
		req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, object),
			int64(len(payload)), bytes.NewReader(payload), creds.AccessKey, creds.SecretKey, headers)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return rec
	}

	t.Run("untrusted marker is ordinary", func(t *testing.T) {
		object := "replication-trust/put-ordinary"
		if rec := request(t, object, putOnly, "PENDING", false); rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if info.ETag == "source-etag" || info.ModTime.Equal(sourceMTime) {
			t.Fatalf("untrusted source state was preserved: ETag=%q MTime=%v", info.ETag, info.ModTime)
		}
		assertObjectMetadataKeysAbsent(t, info.UserDefined, xhttp.AmzBucketReplicationStatus)
	})

	t.Run("unauthorized replica is denied", func(t *testing.T) {
		object := "replication-trust/put-denied-replica"
		if rec := request(t, object, putOnly, "REPLICA", false); rec.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", rec.Code, rec.Body.String())
		}
		if _, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{}); err == nil {
			t.Fatal("unauthorized replica write created an object")
		}
	})

	t.Run("trusted batch preserves source state", func(t *testing.T) {
		object := "replication-trust/put-batch"
		if rec := request(t, object, replicator, "", false); rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if info.ETag != "source-etag" || !info.ModTime.Equal(sourceMTime) {
			t.Fatalf("trusted source state lost: ETag=%q MTime=%v", info.ETag, info.ModTime)
		}
		assertObjectMetadataKeysAbsent(t, info.UserDefined, xhttp.AmzBucketReplicationStatus)
	})

	t.Run("trusted replica persists replica state", func(t *testing.T) {
		object := "replication-trust/put-replica"
		if rec := request(t, object, replicator, "REPLICA", false); rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if info.UserDefined[xhttp.AmzBucketReplicationStatus] != "REPLICA" {
			t.Fatalf("replica status not persisted: %#v", info.UserDefined)
		}
	})

	for _, test := range []struct {
		name       string
		creds      auth.Credentials
		wantStatus int
	}{
		{name: "validity check requires ReplicateObject", creds: putOnly, wantStatus: http.StatusForbidden},
		{name: "validity check succeeds for replicator", creds: replicator, wantStatus: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			object := "replication-trust/put-check-" + strconv.Itoa(test.wantStatus)
			if rec := request(t, object, test.creds, "REPLICA", true); rec.Code != test.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, test.wantStatus, rec.Body.String())
			}
			if _, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{}); err == nil {
				t.Fatal("replication validity check created an object")
			}
		})
	}
}

func TestAPISnowballReplicationTrustIsPerEntry(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPISnowballReplicationTrustIsPerEntry,
	})
}

func testAPISnowballReplicationTrustIsPerEntry(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, _ auth.Credentials, t *testing.T,
) {
	const (
		allowedPrefix = "snowball/allowed/"
		deniedPrefix  = "snowball/denied/"
		sourceETag    = "0123456789abcdef0123456789abcdef"
	)
	creds := newSnowballReplicationTrustUser(t, instanceType, bucketName, allowedPrefix)

	var body bytes.Buffer
	tw := tar.NewWriter(&body)
	objects := make([]struct {
		name    string
		trusted bool
	}, 0, 32)
	for i := 0; i < 16; i++ {
		for _, entry := range []struct {
			prefix  string
			trusted bool
		}{
			{prefix: allowedPrefix, trusted: true},
			{prefix: deniedPrefix},
		} {
			name := entry.prefix + strconv.Itoa(i)
			data := []byte("snowball replication trust " + name)
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
			objects = append(objects, struct {
				name    string
				trusted bool
			}{name: name, trusted: entry.trusted})
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	headers := map[string]string{
		xhttp.AmzSnowballExtract:            "true",
		xhttp.MinIOSourceReplicationRequest: "true",
		xhttp.MinIOSourceETag:               sourceETag,
	}
	for _, test := range []struct {
		name    string
		trailer bool
	}{
		{name: "signed-v4"},
		{name: "streaming-unsigned-trailer", trailer: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var req *http.Request
			var err error
			if test.trailer {
				req, err = newStreamingUnsignedTrailerRequest(http.MethodPut,
					getPutObjectURL("", bucketName, "snowball.tar"), body.Bytes(), UTCNow())
				if err == nil {
					for name, value := range headers {
						req.Header.Set(name, value)
					}
					err = signRequestV4(req, creds.AccessKey, creds.SecretKey)
				}
			} else {
				req, err = newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, "snowball.tar"),
					int64(body.Len()), bytes.NewReader(body.Bytes()), creds.AccessKey, creds.SecretKey, headers)
			}
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			apiRouter.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: Snowball PUT status %d: %s", instanceType, rec.Code, rec.Body.String())
			}

			for _, object := range objects {
				info, err := obj.GetObjectInfo(t.Context(), bucketName, object.name, ObjectOptions{})
				if err != nil {
					t.Fatalf("%s: get %s: %v", instanceType, object.name, err)
				}
				if object.trusted && info.ETag != sourceETag {
					t.Errorf("%s: trusted entry %s ETag = %q, want source ETag", instanceType, object.name, info.ETag)
				}
				if !object.trusted && info.ETag == sourceETag {
					t.Errorf("%s: untrusted entry %s preserved source ETag", instanceType, object.name)
				}
			}
		})
	}
}

func TestAPISnowballInheritsBucketEncryption(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPISnowballInheritsBucketEncryption,
	})
}

func testAPISnowballInheritsBucketEncryption(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousKMS := GlobalKMS
	GlobalKMS = kms.NewStub("snowball-default-encryption")
	defer func() { GlobalKMS = previousKMS }()
	sseXML := []byte(`<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)
	if _, err := globalBucketMetadataSys.Update(t.Context(), bucketName, bucketSSEConfig, sseXML); err != nil {
		t.Fatalf("%s: configure bucket encryption: %v", instanceType, err)
	}

	var body bytes.Buffer
	tw := tar.NewWriter(&body)
	objects := []string{"encrypted/one", "encrypted/two"}
	for _, object := range objects {
		data := []byte("snowball bucket encryption " + object)
		if err := tw.WriteHeader(&tar.Header{Name: object, Mode: 0o600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, "encrypted-snowball.tar"),
		int64(body.Len()), bytes.NewReader(body.Bytes()), credentials.AccessKey, credentials.SecretKey,
		map[string]string{xhttp.AmzSnowballExtract: "true"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	apiRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: Snowball PUT status %d: %s", instanceType, rec.Code, rec.Body.String())
	}
	for _, object := range objects {
		info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatalf("%s: get %s: %v", instanceType, object, err)
		}
		if _, encrypted := crypto.IsEncrypted(info.UserDefined); !encrypted {
			t.Errorf("%s: extracted entry %s did not inherit bucket encryption", instanceType, object)
		}
	}
}

func newSnowballReplicationTrustUser(t *testing.T, instanceType, bucketName, allowedPrefix string) auth.Credentials {
	t.Helper()
	ctx := t.Context()
	accessKey, secretKey, err := auth.GenerateCredentials()
	if err != nil {
		t.Fatalf("%s: generate credentials: %v", instanceType, err)
	}
	creds := auth.Credentials{AccessKey: accessKey, SecretKey: secretKey}
	if _, err = globalIAMSys.CreateUser(ctx, creds.AccessKey, madmin.AddOrUpdateUserReq{
		SecretKey: creds.SecretKey,
		Status:    madmin.AccountEnabled,
	}); err != nil {
		t.Fatalf("%s: create Snowball user: %v", instanceType, err)
	}

	policyJSON := `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": ["s3:PutObject"],
   "Resource": ["arn:aws:s3:::` + bucketName + `/*"]
  },
  {
   "Effect": "Allow",
   "Action": ["s3:ReplicateObject"],
   "Resource": ["arn:aws:s3:::` + bucketName + `/` + allowedPrefix + `*"]
  }
 ]
}`
	parsed, err := policy.ParseConfig(strings.NewReader(policyJSON))
	if err != nil {
		t.Fatalf("%s: parse Snowball policy: %v", instanceType, err)
	}
	policyName := "snowball-replication-trust-" + mustGetUUID()
	if _, err = globalIAMSys.SetPolicy(ctx, policyName, *parsed); err != nil {
		t.Fatalf("%s: install Snowball policy: %v", instanceType, err)
	}
	if _, err = globalIAMSys.PolicyDBSet(ctx, creds.AccessKey, policyName, regUser, false); err != nil {
		t.Fatalf("%s: attach Snowball policy: %v", instanceType, err)
	}
	return creds
}

func TestAPICopyObjectMarkerOnlyDoesNotCopyCiphertext(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPICopyObjectMarkerOnlyDoesNotCopyCiphertext,
	})
}

func testAPICopyObjectMarkerOnlyDoesNotCopyCiphertext(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	key := bytes.Repeat([]byte{0x57}, 32)
	keyMD5 := md5.Sum(key)
	data := bytes.Repeat([]byte("copy marker-only plaintext "), 256)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
	srcObject := "replication-trust/copy-ssec-source"
	dstObject := "replication-trust/copy-marker-only"
	putCopyChecksumSource(t, apiRouter, credentials, bucketName, srcObject, data, sseHeaders)

	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName,
		`"s3:GetObject","s3:PutObject","s3:ReplicateObject"`)
	headers := map[string]string{
		xhttp.AmzCopySource:                                url.QueryEscape(SlashSeparator + bucketName + SlashSeparator + srcObject),
		xhttp.MinIOSourceReplicationRequest:                "true",
		xhttp.AmzServerSideEncryptionCopyCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCopyCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCopyCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
	req, err := newTestSignedRequestV4(http.MethodPut, getCopyObjectURL("", bucketName, dstObject), 0, nil,
		replicator.AccessKey, replicator.SecretKey, headers)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	apiRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: CopyObject status %d: %s", instanceType, rec.Code, rec.Body.String())
	}
	assertObjectContents(t, obj, bucketName, dstObject, data)
}

func TestAPIDeleteObjectReplicationTrust(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPIDeleteObjectReplicationTrust,
	})
}

func testAPIDeleteObjectReplicationTrust(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, _ auth.Credentials, t *testing.T,
) {
	deleteOnly := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:DeleteObject"`)
	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:DeleteObject","s3:ReplicateDelete"`)
	payload := []byte("delete replication trust")

	put := func(t *testing.T, object string) {
		t.Helper()
		if _, err := obj.PutObject(t.Context(), bucketName, object,
			mustGetPutObjReader(t, bytes.NewReader(payload), int64(len(payload)), "", ""), ObjectOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	remove := func(t *testing.T, object string, creds auth.Credentials, versionID string, deleteMarker, check bool) *httptest.ResponseRecorder {
		t.Helper()
		headers := map[string]string{
			xhttp.MinIOSourceReplicationRequest: "true",
			xhttp.AmzBucketReplicationStatus:    "REPLICA",
		}
		if deleteMarker {
			headers[xhttp.MinIOSourceDeleteMarker] = "true"
		}
		if check {
			headers[xhttp.MinIOSourceReplicationCheck] = "true"
		}
		target := getDeleteObjectURL("", bucketName, object)
		if versionID != "" {
			target += "?" + url.Values{xhttp.VersionID: {versionID}}.Encode()
		}
		req, err := newTestSignedRequestV4(http.MethodDelete, target,
			0, nil, creds.AccessKey, creds.SecretKey, headers)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return rec
	}

	t.Run("replica status without ReplicateDelete is denied", func(t *testing.T) {
		object := "replication-trust/delete-denied"
		put(t, object)
		if rec := remove(t, object, deleteOnly, "", false, false); rec.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", rec.Code, rec.Body.String())
		}
		if _, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{}); err != nil {
			t.Fatalf("denied delete removed object: %v", err)
		}
	})

	t.Run("trusted replica delete remains supported", func(t *testing.T) {
		object := "replication-trust/delete-allowed"
		put(t, object)
		if rec := remove(t, object, replicator, "", false, false); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d, want 204: %s", rec.Code, rec.Body.String())
		}
	})

	for _, shape := range []struct {
		name         string
		deleteMarker bool
	}{
		{name: "delete-marker", deleteMarker: true},
		{name: "version-purge"},
	} {
		t.Run("validity check/"+shape.name, func(t *testing.T) {
			for _, test := range []struct {
				name       string
				creds      auth.Credentials
				wantStatus int
			}{
				{name: "requires ReplicateDelete", creds: deleteOnly, wantStatus: http.StatusForbidden},
				{name: "succeeds for replicator", creds: replicator, wantStatus: http.StatusBadRequest},
			} {
				t.Run(test.name, func(t *testing.T) {
					object := "replication-trust/delete-check-" + shape.name + "-" + strconv.Itoa(test.wantStatus)
					put(t, object)
					if rec := remove(t, object, test.creds, mustGetUUID(), shape.deleteMarker, true); rec.Code != test.wantStatus {
						t.Fatalf("status %d, want %d: %s", rec.Code, test.wantStatus, rec.Body.String())
					}
					if _, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{}); err != nil {
						t.Fatalf("replication validity check removed object: %v", err)
					}
				})
			}
		})
	}
}

func TestAPISSECMultipartReplicationTrust(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPISSECMultipartReplicationTrust,
	})
}

func testAPISSECMultipartReplicationTrust(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject","s3:GetObject","s3:ReplicateObject"`)
	putOnly := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject"`)
	key := bytes.Repeat([]byte{0x42}, 32)
	keyMD5 := md5.Sum(key)
	data := bytes.Repeat([]byte("trusted multipart replication "), 4096)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}

	// A marker alone must not let an ordinary writer upload raw bytes into an
	// SSE-C multipart upload without presenting the customer key.
	fakeObject := "replication-trust/ssec-multipart-fake"
	fakeNewReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, fakeObject),
		0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	fakeNewRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(fakeNewRec, fakeNewReq)
	if fakeNewRec.Code != http.StatusOK {
		t.Fatalf("fake-path NewMultipart status %d: %s", fakeNewRec.Code, fakeNewRec.Body.String())
	}
	var fakeInit InitiateMultipartUploadResponse
	if err = xmlDecoder(fakeNewRec.Body, &fakeInit, int64(fakeNewRec.Body.Len())); err != nil {
		t.Fatal(err)
	}
	fakePartReq, err := newTestSignedRequestV4(http.MethodPut,
		getPutObjectPartURL("", bucketName, fakeObject, fakeInit.UploadID, "1"), int64(len(data)), bytes.NewReader(data),
		putOnly.AccessKey, putOnly.SecretKey, map[string]string{xhttp.MinIOSourceReplicationRequest: "true"})
	if err != nil {
		t.Fatal(err)
	}
	fakePartRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(fakePartRec, fakePartReq)
	if fakePartRec.Code != http.StatusBadRequest {
		t.Fatalf("fake marker PutPart status %d, want 400: %s", fakePartRec.Code, fakePartRec.Body.String())
	}

	object := "replication-trust/ssec-multipart"

	// Create the source as a real SSE-C multipart object so the encrypted part
	// layout and metadata match what the replication worker reads.
	newReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	newRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(newRec, newReq)
	if newRec.Code != http.StatusOK {
		t.Fatalf("source NewMultipart status %d: %s", newRec.Code, newRec.Body.String())
	}
	var sourceInit InitiateMultipartUploadResponse
	if err = xmlDecoder(newRec.Body, &sourceInit, int64(newRec.Body.Len())); err != nil {
		t.Fatal(err)
	}

	partReq, err := newTestSignedRequestV4(http.MethodPut,
		getPutObjectPartURL("", bucketName, object, sourceInit.UploadID, "1"), int64(len(data)), bytes.NewReader(data),
		credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	partRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(partRec, partReq)
	if partRec.Code != http.StatusOK {
		t.Fatalf("source PutPart status %d: %s", partRec.Code, partRec.Body.String())
	}
	sourcePartETag := canonicalizeETag(partRec.Header()[xhttp.ETag][0])
	sourceCompleteBody, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{{PartNumber: 1, ETag: sourcePartETag}}})
	if err != nil {
		t.Fatal(err)
	}
	completeReq, err := newTestSignedRequestV4(http.MethodPost,
		getCompleteMultipartUploadURL("", bucketName, object, sourceInit.UploadID), int64(len(sourceCompleteBody)),
		bytes.NewReader(sourceCompleteBody), credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	completeRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(completeRec, completeReq)
	if completeRec.Code != http.StatusOK {
		t.Fatalf("source Complete status %d: %s", completeRec.Code, completeRec.Body.String())
	}

	gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{ReplicationRequest: true})
	if err != nil {
		t.Fatal(err)
	}
	sourceInfo := gr.ObjInfo
	rawPart, err := io.ReadAll(gr)
	gr.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(rawPart) == 0 || bytes.Equal(rawPart, data) {
		t.Fatal("source replication read did not return encrypted bytes")
	}

	replicationOpts, isMP, err := putReplicationOpts(t.Context(), "", sourceInfo)
	if err != nil {
		t.Fatal(err)
	}
	if !isMP {
		t.Fatal("SSE-C multipart source was not recognized as multipart")
	}
	replicationOpts.Internal.SourceMTime = time.Time{}
	replicationHeaders := make(map[string]string)
	for name, values := range replicationOpts.Header() {
		if len(values) > 0 {
			replicationHeaders[name] = values[0]
		}
	}

	// Start the destination upload over the same key. The existing object stays
	// readable until Complete, so buffering rawPart above mirrors a remote peer.
	replNewReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
		0, nil, replicator.AccessKey, replicator.SecretKey, replicationHeaders)
	if err != nil {
		t.Fatal(err)
	}
	replNewRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(replNewRec, replNewReq)
	if replNewRec.Code != http.StatusOK {
		t.Fatalf("replica NewMultipart status %d: %s", replNewRec.Code, replNewRec.Body.String())
	}
	var replicaInit InitiateMultipartUploadResponse
	if err = xmlDecoder(replNewRec.Body, &replicaInit, int64(replNewRec.Body.Len())); err != nil {
		t.Fatal(err)
	}

	replPartHeaders := map[string]string{xhttp.MinIOSourceReplicationRequest: "true"}
	replPartReq, err := newTestSignedRequestV4(http.MethodPut,
		getPutObjectPartURL("", bucketName, object, replicaInit.UploadID, "1"), int64(len(rawPart)), bytes.NewReader(rawPart),
		replicator.AccessKey, replicator.SecretKey, replPartHeaders)
	if err != nil {
		t.Fatal(err)
	}
	replPartRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(replPartRec, replPartReq)
	if replPartRec.Code != http.StatusOK {
		t.Fatalf("replica PutPart status %d: %s", replPartRec.Code, replPartRec.Body.String())
	}
	replPartETag := canonicalizeETag(replPartRec.Header()[xhttp.ETag][0])
	replCompleteBody, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{{PartNumber: 1, ETag: replPartETag}}})
	if err != nil {
		t.Fatal(err)
	}
	actualSize, err := sourceInfo.GetActualSize()
	if err != nil {
		t.Fatal(err)
	}
	replCompleteHeaders := map[string]string{
		xhttp.MinIOSourceReplicationRequest:    "true",
		xhttp.MinIOSourceMTime:                 sourceInfo.ModTime.Format(time.RFC3339Nano),
		xhttp.MinIOSourceETag:                  sourceInfo.ETag,
		xhttp.MinIOReplicationActualObjectSize: strconv.FormatInt(actualSize, 10),
	}
	replCompleteReq, err := newTestSignedRequestV4(http.MethodPost,
		getCompleteMultipartUploadURL("", bucketName, object, replicaInit.UploadID), int64(len(replCompleteBody)),
		bytes.NewReader(replCompleteBody), replicator.AccessKey, replicator.SecretKey, replCompleteHeaders)
	if err != nil {
		t.Fatal(err)
	}
	replCompleteRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(replCompleteRec, replCompleteReq)
	if replCompleteRec.Code != http.StatusOK {
		t.Fatalf("replica Complete status %d: %s", replCompleteRec.Code, replCompleteRec.Body.String())
	}

	getReq, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	getRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET replicated object status %d: %s", getRec.Code, getRec.Body.String())
	}
	if !bytes.Equal(getRec.Body.Bytes(), data) {
		t.Fatal("replicated SSE-C multipart object did not decrypt to source plaintext")
	}

	// A replicated SSE-C part is written as raw ciphertext, so its stored
	// ActualSize is the ciphertext length. GetObjectAttributes must still
	// report the part's plaintext length, which for this single-part object
	// is the whole object size.
	attributes := attributesPartsFetch(t, apiRouter, credentials, bucketName, object, sseHeaders)
	if len(attributes.ObjectParts.Parts) != 1 {
		t.Fatalf("replica attributes part count %d, want 1", len(attributes.ObjectParts.Parts))
	}
	if got := attributes.ObjectParts.Parts[0].Size; got != int64(len(data)) {
		t.Errorf("replica attributes part 1 size=%d, want plaintext size %d", got, len(data))
	}
	if attributes.ObjectSize != int64(len(data)) {
		t.Errorf("replica attributes ObjectSize=%d, want %d", attributes.ObjectSize, len(data))
	}
	if attributes.ObjectParts.Parts[0].Size != attributes.ObjectSize {
		t.Errorf("replica attributes part 1 size=%d does not match ObjectSize=%d",
			attributes.ObjectParts.Parts[0].Size, attributes.ObjectSize)
	}
}

// TestAPIStreamingTrailerWithUntrustedReplicationHeaders verifies that a
// request which does not earn replication trust is still processed as an
// ordinary upload. The streaming body reader fills the original request's
// trailer while the handler continues with a header-stripped clone, so the
// trailing checksum must remain visible through that clone.
func TestAPIStreamingTrailerWithUntrustedReplicationHeaders(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPIStreamingTrailerWithUntrustedReplicationHeaders})
}

func testAPIStreamingTrailerWithUntrustedReplicationHeaders(obj ObjectLayer, instanceType, bucketName string, apiRouter http.Handler, _ auth.Credentials, t *testing.T) {
	putOnly := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject"`)
	payload := bytes.Repeat([]byte("trailer probe "), 4096)
	send := func(targetURL string) *httptest.ResponseRecorder {
		req, err := newStreamingUnsignedTrailerRequest(http.MethodPut, targetURL, payload, UTCNow())
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(xhttp.MinIOSourceReplicationRequest, "true")
		req.Header.Set(xhttp.MinIOSourceETag, "forged-etag")
		if err := signRequestV4(req, putOnly.AccessKey, putOnly.SecretKey); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return rec
	}

	if rec := send(getPutObjectURL("", bucketName, "trailer-object")); rec.Code != http.StatusOK {
		t.Fatalf("%s: PutObject status %d: %s", instanceType, rec.Code, rec.Body.String())
	}
	info, err := obj.GetObjectInfo(t.Context(), bucketName, "trailer-object", ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Size != int64(len(payload)) || info.ETag == "forged-etag" {
		t.Fatalf("%s: stored size %d etag %q, want %d bytes with a computed etag", instanceType, info.Size, info.ETag, len(payload))
	}

	upload, err := obj.NewMultipartUpload(t.Context(), bucketName, "trailer-multipart", ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rec := send(getPutObjectPartURL("", bucketName, "trailer-multipart", upload.UploadID, "1")); rec.Code != http.StatusOK {
		t.Fatalf("%s: PutObjectPart status %d: %s", instanceType, rec.Code, rec.Body.String())
	}
	parts, err := obj.ListObjectParts(t.Context(), bucketName, "trailer-multipart", upload.UploadID, 0, 10, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(parts.Parts) != 1 || parts.Parts[0].Size != int64(len(payload)) {
		t.Fatalf("%s: uploaded parts %+v, want one part of %d bytes", instanceType, parts.Parts, len(payload))
	}
}

// TestAPICopyObjectReplicaLegalHoldTimestamp verifies that a replicated legal
// hold update records its own timestamp under the legal-hold key: a replica
// that arrives later with an older timestamp must not change the hold, the
// retention timestamp must stay untouched, and a newer replica still applies.
func TestAPICopyObjectReplicaLegalHoldTimestamp(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testAPICopyObjectReplicaLegalHoldTimestamp,
		makeBucketOptions: MakeBucketOptions{LockEnabled: true},
	})
}

func testAPICopyObjectReplicaLegalHoldTimestamp(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, _ auth.Credentials, t *testing.T,
) {
	object := "replication-trust/legal-hold"
	if _, err := obj.PutObject(t.Context(), bucketName, object, mustGetPutObjReader(t, bytes.NewReader([]byte("held")), 4, "", ""), ObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName,
		`"s3:GetObject","s3:PutObject","s3:ReplicateObject","s3:PutObjectLegalHold","s3:GetObjectLegalHold","s3:GetObjectRetention"`)
	apply := func(status, stamp string) {
		t.Helper()
		headers := map[string]string{
			xhttp.AmzCopySource:                       url.QueryEscape(SlashSeparator + bucketName + SlashSeparator + object),
			xhttp.AmzMetadataDirective:                replaceDirective,
			xhttp.MinIOSourceReplicationRequest:       "true",
			xhttp.AmzBucketReplicationStatus:          "REPLICA",
			xhttp.AmzObjectLockLegalHold:              status,
			xhttp.MinIOSourceObjectLegalHoldTimestamp: stamp,
		}
		req, err := newTestSignedRequestV4(http.MethodPut, getCopyObjectURL("", bucketName, object), 0, nil,
			replicator.AccessKey, replicator.SecretKey, headers)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: replica CopyObject legal hold %s @ %s: status %d: %s", instanceType, status, stamp, rec.Code, rec.Body.String())
		}
	}
	state := func() (hold, holdStamp string, hasRetentionStamp bool) {
		t.Helper()
		info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, hasRetentionStamp = info.UserDefined[ReservedMetadataPrefixLower+ObjectLockRetentionTimestamp]
		return info.UserDefined[strings.ToLower(xhttp.AmzObjectLockLegalHold)], info.UserDefined[ReservedMetadataPrefixLower+ObjectLockLegalHoldTimestamp], hasRetentionStamp
	}

	apply("ON", "2026-09-03T10:00:00Z")
	apply("OFF", "2026-09-03T09:00:00Z") // stale replica: must be ignored
	if hold, stamp, retention := state(); hold != "ON" || stamp != "2026-09-03T10:00:00Z" || retention {
		t.Fatalf("%s: after stale OFF: hold=%q legal-hold timestamp=%q retention timestamp present=%v", instanceType, hold, stamp, retention)
	}
	apply("OFF", "2026-09-03T11:00:00Z") // newer replica: applies
	if hold, stamp, retention := state(); hold != "OFF" || stamp != "2026-09-03T11:00:00Z" || retention {
		t.Fatalf("%s: after newer OFF: hold=%q legal-hold timestamp=%q retention timestamp present=%v", instanceType, hold, stamp, retention)
	}
}
