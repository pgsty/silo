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
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/sio"
)

// TestAPISSECReplicationTargetHead pins what the replication sender's target
// HEAD sees for an SSE-C object, which is what replicateAll's dispatch relies
// on: a keyless HEAD answers 400 InvalidRequest (so the sender must retransmit
// rather than compare), a missing key still answers 404 NoSuchKey (so a missing
// replica keeps healing), a HEAD carrying the internal replication marker
// answers with the replica metadata (what the resync accounting HEAD now
// sends), and the metadata-only CopyObject the sender used to fall into fails
// with ExcessData on any non-empty object. See pgsty/silo#120.
func TestAPISSECReplicationTargetHead(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testAPISSECReplicationTargetHead,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true},
	})
}

func testAPISSECReplicationTargetHead(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	key := bytes.Repeat([]byte{0x42}, 32)
	keyMD5 := md5.Sum(key)
	data := bytes.Repeat([]byte("ssec-keyless-head-"), 512)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
	object := "ssec-keyless-head/replica"
	putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data, sseHeaders)

	// The replication target credential holds the standard replication actions.
	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName,
		`"s3:GetObject","s3:PutObject","s3:ReplicateObject","s3:ReplicateDelete","s3:ReplicateTags"`)

	// Exactly the header set replicateAll's StatObject sends today.
	senderHeaders := map[string]string{
		"X-Minio-Source-Proxy-Request": "false",
		xhttp.AmzTagDirective:          "ACCESS",
	}
	// The same request with the internal replication marker added.
	markedHeaders := map[string]string{
		"X-Minio-Source-Proxy-Request":      "false",
		xhttp.AmzTagDirective:               "ACCESS",
		xhttp.MinIOSourceReplicationRequest: "true",
	}

	head := func(t *testing.T, creds auth.Credentials, obj, versionID string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		headURL := getGetObjectURL("", bucketName, obj)
		if versionID != "" {
			// replicateAll addresses the source version (minio-go
			// api-get-options.go toQueryValues).
			headURL += "?versionId=" + versionID
		}
		req, err := newTestSignedRequestV4(http.MethodHead, headURL, 0, nil,
			creds.AccessKey, creds.SecretKey, headers)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return rec
	}

	sseDesc := errorCodes[ErrSSEEncryptedObject].Description

	baseInfo, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sourceVersion := baseInfo.VersionID

	t.Run("sender-head-today-is-rejected", func(t *testing.T) {
		rec := head(t, replicator, object, sourceVersion, senderHeaders)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: keyless HEAD status %d, want 400", instanceType, rec.Code)
		}
		if got := rec.Header().Get("x-minio-error-code"); got != "InvalidRequest" {
			t.Fatalf("%s: error code %q, want InvalidRequest", instanceType, got)
		}
		desc := strings.Trim(rec.Header().Get("x-minio-error-desc"), `"`)
		if !strings.Contains(desc, sseDesc) {
			t.Fatalf("%s: error desc %q does not carry %q", instanceType, desc, sseDesc)
		}
		t.Logf("%s: keyless HEAD -> %d %s / %s", instanceType, rec.Code,
			rec.Header().Get("x-minio-error-code"), desc)
	})

	t.Run("missing-object-head-is-distinguishable", func(t *testing.T) {
		rec := head(t, replicator, "ssec-keyless-head/absent", "", senderHeaders)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: missing-object HEAD status %d, want 404", instanceType, rec.Code)
		}
		if got := rec.Header().Get("x-minio-error-code"); got != "NoSuchKey" {
			t.Fatalf("%s: missing-object error code %q, want NoSuchKey", instanceType, got)
		}
	})

	t.Run("marked-head-answers-with-metadata", func(t *testing.T) {
		rec := head(t, replicator, object, sourceVersion, markedHeaders)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: marked keyless HEAD status %d, want 200: %s", instanceType, rec.Code, rec.Body.String())
		}
		// setObjectHeaders assigns the ETag through the raw header map with the
		// non canonical key "ETag", so read it the same way.
		etag := ""
		if v := rec.Header()[xhttp.ETag]; len(v) > 0 {
			etag = strings.Trim(v[0], `"`)
		}
		clen := rec.Header().Get(xhttp.ContentLength)
		lastMod := rec.Header().Get(xhttp.LastModified)
		if etag == "" || clen == "" || lastMod == "" {
			t.Fatalf("%s: marked HEAD lacks comparison metadata etag=%q len=%q mtime=%q",
				instanceType, etag, clen, lastMod)
		}

		// What replicateAll would compare this against: the source ObjectInfo it
		// obtained from GetObjectNInfo(..., ReplicationRequest: true).
		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		srcInfo := gr.ObjInfo
		gr.Close()
		srcSize, err := srcInfo.GetActualSize()
		if err != nil {
			t.Fatal(err)
		}
		headSize, err := strconv.ParseInt(clen, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: source ETag=%q (len %d) size=%d ; target HEAD ETag=%q (len %d) size=%d",
			instanceType, srcInfo.ETag, len(srcInfo.ETag), srcSize, etag, len(etag), headSize)
		if headSize != srcSize {
			t.Errorf("%s: getReplicationAction size mismatch: source %d target %d", instanceType, srcSize, headSize)
		}
		if srcInfo.ETag != etag {
			t.Logf("%s: NOTE getReplicationAction would see an ETag mismatch (source keeps the sealed ETag, "+
				"the target HEAD returns the last 32 bytes) and therefore return replicateAll", instanceType)
		}
	})

	t.Run("zero-byte-metadata-copy-succeeds", func(t *testing.T) {
		// A zero-byte SSE-C object has nothing for the plaintext-sized reader to
		// overrun, so the same copy request succeeds. The ExcessData failure is a
		// property of non-empty objects.
		zero := "ssec-keyless-head/zero"
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, zero, nil, sseHeaders)
		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, zero, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		zi := gr.ObjInfo
		gr.Close()

		copySrc := url.QueryEscape(SlashSeparator+bucketName+SlashSeparator+zero) + "?versionId=" + zi.VersionID
		headers := map[string]string{
			xhttp.AmzCopySource:                 copySrc,
			xhttp.MinIOSourceReplicationRequest: "true",
		}
		for k, v := range getCopyObjMetadata(zi, "") {
			if strings.EqualFold(k, "content-length") {
				continue
			}
			headers[k] = v
		}
		headers[xhttp.AmzObjectTagging] = "keyless-head=zero"
		req, err := newTestSignedRequestV4(http.MethodPut,
			getCopyObjectURL("", bucketName, zero)+"?versionId="+zi.VersionID, 0, nil,
			replicator.AccessKey, replicator.SecretKey, headers)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		after, gerr := obj.GetObjectInfo(t.Context(), bucketName, zero, ObjectOptions{})
		if gerr != nil {
			t.Fatal(gerr)
		}
		t.Logf("%s: zero-byte metadata CopyObject -> %d; stored SSE-C=%v size=%d tags=%q",
			instanceType, rec.Code, crypto.SSEC.IsEncrypted(after.UserDefined), after.Size, after.UserTags)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: zero-byte metadata CopyObject status %d: %s", instanceType, rec.Code, rec.Body.String())
		}
	})

	t.Run("metadata-copy-is-what-resync-runs", func(t *testing.T) {
		// Exactly what replicateAll runs at cmd/bucket-replication.go:1582 once
		// the keyless HEAD has been misread: a same bucket, same key CopyObject
		// built from getCopyObjMetadata plus the replication marker, carrying no
		// customer key. getCopyObjMetadata already sets REPLICA status and
		// x-amz-tagging-directive: REPLACE, so the request is replica trusted.
		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		srcInfo := gr.ObjInfo
		gr.Close()

		// minio-go addresses the source version on the copy source and in the
		// destination query (api-compose-object.go:307,314).
		copySrc := url.QueryEscape(SlashSeparator+bucketName+SlashSeparator+object) + "?versionId=" + srcInfo.VersionID
		headers := map[string]string{
			xhttp.AmzCopySource:                 copySrc,
			xhttp.MinIOSourceReplicationRequest: "true",
		}
		copyMeta := getCopyObjMetadata(srcInfo, "")
		for k, v := range copyMeta {
			// net/http derives the request body length from a literal
			// Content-Length header; minio-go relies on req.ContentLength, so
			// drop it here to keep the in-process request faithful.
			if strings.EqualFold(k, "content-length") {
				t.Logf("%s: dropping content-length=%q from the copy metadata", instanceType, v)
				continue
			}
			headers[k] = v
		}
		t.Logf("%s: copy metadata keys: %v", instanceType, slices.Sorted(maps.Keys(copyMeta)))
		copyURL := getCopyObjectURL("", bucketName, object) + "?versionId=" + srcInfo.VersionID
		req, err := newTestSignedRequestV4(http.MethodPut, copyURL, 0, nil,
			replicator.AccessKey, replicator.SecretKey, headers)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		t.Logf("%s: replication metadata CopyObject (version %s) -> %d %s", instanceType, srcInfo.VersionID, rec.Code,
			strings.ReplaceAll(rec.Body.String(), "\n", " "))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: metadata CopyObject status %d, want 400", instanceType, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "<Code>ExcessData</Code>") {
			t.Fatalf("%s: metadata CopyObject did not fail with ExcessData: %s", instanceType, rec.Body.String())
		}

		// Whatever the status, the object must still read back with the key.
		greq, gerr := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, object), 0, nil,
			credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if gerr != nil {
			t.Fatal(gerr)
		}
		grec := httptest.NewRecorder()
		apiRouter.ServeHTTP(grec, greq)
		if grec.Code != http.StatusOK || !bytes.Equal(grec.Body.Bytes(), data) {
			t.Errorf("%s: after the replication metadata CopyObject the object no longer reads back: %d (%d bytes)",
				instanceType, grec.Code, grec.Body.Len())
		} else {
			t.Logf("%s: object still reads back correctly with the customer key", instanceType)
		}
	})
}

// TestAPISSECReplicaRetransmitOverExistingVersion asserts that a full
// retransmit of an SSE-C object reaches the destination when the replica
// already exists with the source version and ETag. checkPreconditionsPUT used
// to reject a matching PreserveETag plus VersionID with 412 for the multipart
// path (the single-part sealed ETag is truncated before the comparison), and
// the sender turns 412 into success, so no part was ever sent and an SSE-C
// replica could never be repaired or updated. See pgsty/silo#120.
func TestAPISSECReplicaRetransmitOverExistingVersion(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testAPISSECReplicaRetransmitOverExistingVersion,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true},
	})
}

func testAPISSECReplicaRetransmitOverExistingVersion(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	key := bytes.Repeat([]byte{0x43}, 32)
	keyMD5 := md5.Sum(key)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName,
		`"s3:GetObject","s3:PutObject","s3:ReplicateObject"`)

	replicaHeaders := func(t *testing.T, oi ObjectInfo) map[string]string {
		t.Helper()
		opts, _, err := putReplicationOpts(t.Context(), "", oi)
		if err != nil {
			t.Fatal(err)
		}
		opts.Internal.SourceMTime = time.Time{}
		out := make(map[string]string)
		for name, values := range opts.Header() {
			if len(values) > 0 {
				out[name] = values[0]
			}
		}
		out[xhttp.MinIOSourceReplicationRequest] = "true"
		out[xhttp.AmzBucketReplicationStatus] = "REPLICA"
		out[xhttp.MinIOSourceETag] = oi.ETag
		return out
	}

	t.Run("single-part-replica-put", func(t *testing.T) {
		data := bytes.Repeat([]byte("single-part-ssec-replica-"), 400)
		object := "ssec-duplicate/single"
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data, sseHeaders)

		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		srcInfo := gr.ObjInfo
		cipher, err := io.ReadAll(gr)
		gr.Close()
		if err != nil {
			t.Fatal(err)
		}
		// The source changed a tag after the replica was written: the
		// retransmit must carry it onto the same version.
		srcInfo.UserTags = "retransmit=single"
		hdrs := replicaHeaders(t, srcInfo)
		putURL := getPutObjectURL("", bucketName, object) + "?versionId=" + srcInfo.VersionID
		req, err := newTestSignedRequestV4(http.MethodPut, putURL, int64(len(cipher)),
			bytes.NewReader(cipher), replicator.AccessKey, replicator.SecretKey, hdrs)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: single-part replica PUT status %d, want 200: %s", instanceType, rec.Code, rec.Body.String())
		}
		assertRetransmittedVersion(t, obj, apiRouter, credentials, bucketName, object, srcInfo.VersionID, "retransmit=single", data, sseHeaders)
	})

	t.Run("zero-byte-replica-put", func(t *testing.T) {
		object := "ssec-duplicate/zero"
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, nil, sseHeaders)

		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		srcInfo := gr.ObjInfo
		cipher, err := io.ReadAll(gr)
		gr.Close()
		if err != nil {
			t.Fatal(err)
		}
		srcInfo.UserTags = "retransmit=zero"
		hdrs := replicaHeaders(t, srcInfo)
		putURL := getPutObjectURL("", bucketName, object) + "?versionId=" + srcInfo.VersionID
		req, err := newTestSignedRequestV4(http.MethodPut, putURL, int64(len(cipher)),
			bytes.NewReader(cipher), replicator.AccessKey, replicator.SecretKey, hdrs)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: zero-byte replica PUT status %d, want 200: %s", instanceType, rec.Code, rec.Body.String())
		}
		assertRetransmittedVersion(t, obj, apiRouter, credentials, bucketName, object, srcInfo.VersionID, "retransmit=zero", nil, sseHeaders)
	})

	t.Run("multipart-replica-newmpu", func(t *testing.T) {
		data := bytes.Repeat([]byte("multipart-ssec-replica-"), 4096)
		object := "ssec-duplicate/multipart"

		newReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
			0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		newRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(newRec, newReq)
		if newRec.Code != http.StatusOK {
			t.Fatalf("%s: source NewMultipart %d: %s", instanceType, newRec.Code, newRec.Body.String())
		}
		var srcInit InitiateMultipartUploadResponse
		if err = xmlDecoder(newRec.Body, &srcInit, int64(newRec.Body.Len())); err != nil {
			t.Fatal(err)
		}
		partReq, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectPartURL("", bucketName, object, srcInit.UploadID, "1"), int64(len(data)),
			bytes.NewReader(data), credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		partRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(partRec, partReq)
		if partRec.Code != http.StatusOK {
			t.Fatalf("%s: source PutPart %d: %s", instanceType, partRec.Code, partRec.Body.String())
		}
		body, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{
			{PartNumber: 1, ETag: canonicalizeETag(partRec.Header()[xhttp.ETag][0])},
		}})
		if err != nil {
			t.Fatal(err)
		}
		completeReq, err := newTestSignedRequestV4(http.MethodPost,
			getCompleteMultipartUploadURL("", bucketName, object, srcInit.UploadID), int64(len(body)),
			bytes.NewReader(body), credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		completeRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(completeRec, completeReq)
		if completeRec.Code != http.StatusOK {
			t.Fatalf("%s: source Complete %d: %s", instanceType, completeRec.Code, completeRec.Body.String())
		}

		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		srcInfo := gr.ObjInfo
		gr.Close()

		srcInfo.UserTags = "retransmit=multipart"
		hdrs := replicaHeaders(t, srcInfo)
		mpuURL := getNewMultipartURL("", bucketName, object) + "&versionId=" + srcInfo.VersionID
		req, err := newTestSignedRequestV4(http.MethodPost, mpuURL, 0, nil,
			replicator.AccessKey, replicator.SecretKey, hdrs)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		t.Logf("%s: multipart replica NewMultipartUpload over the same version+ETag -> %d %s (source ETag %q, multipart=%v)",
			instanceType, rec.Code, strings.ReplaceAll(rec.Body.String(), "\n", " "),
			srcInfo.ETag, crypto.IsMultiPart(srcInfo.UserDefined))
		if rec.Code == http.StatusPreconditionFailed {
			t.Fatalf("%s: multipart replica upload short-circuited with 412; the sender turns that into "+
				"success, so no part is ever sent", instanceType)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: replica NewMultipart status %d: %s", instanceType, rec.Code, rec.Body.String())
		}

		// Finish the replica upload the way the sender does and prove the object
		// is still readable with the customer key afterwards.
		gr2, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		rawPart, err := io.ReadAll(gr2)
		gr2.Close()
		if err != nil {
			t.Fatal(err)
		}
		var replicaInit InitiateMultipartUploadResponse
		if err = xmlDecoder(rec.Body, &replicaInit, int64(rec.Body.Len())); err != nil {
			t.Fatal(err)
		}
		partReq2, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectPartURL("", bucketName, object, replicaInit.UploadID, "1"), int64(len(rawPart)),
			bytes.NewReader(rawPart), replicator.AccessKey, replicator.SecretKey,
			map[string]string{xhttp.MinIOSourceReplicationRequest: "true"})
		if err != nil {
			t.Fatal(err)
		}
		partRec2 := httptest.NewRecorder()
		apiRouter.ServeHTTP(partRec2, partReq2)
		if partRec2.Code != http.StatusOK {
			t.Fatalf("%s: replica PutPart %d: %s", instanceType, partRec2.Code, partRec2.Body.String())
		}
		actualSize, err := srcInfo.GetActualSize()
		if err != nil {
			t.Fatal(err)
		}
		completeBody2, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{
			{PartNumber: 1, ETag: canonicalizeETag(partRec2.Header()[xhttp.ETag][0])},
		}})
		if err != nil {
			t.Fatal(err)
		}
		completeReq2, err := newTestSignedRequestV4(http.MethodPost,
			getCompleteMultipartUploadURL("", bucketName, object, replicaInit.UploadID), int64(len(completeBody2)),
			bytes.NewReader(completeBody2), replicator.AccessKey, replicator.SecretKey, map[string]string{
				xhttp.MinIOSourceReplicationRequest:    "true",
				xhttp.MinIOSourceMTime:                 srcInfo.ModTime.Format(time.RFC3339Nano),
				xhttp.MinIOSourceETag:                  srcInfo.ETag,
				xhttp.MinIOReplicationActualObjectSize: strconv.FormatInt(actualSize, 10),
			})
		if err != nil {
			t.Fatal(err)
		}
		completeRec2 := httptest.NewRecorder()
		apiRouter.ServeHTTP(completeRec2, completeReq2)
		if completeRec2.Code != http.StatusOK {
			t.Fatalf("%s: replica Complete %d: %s", instanceType, completeRec2.Code, completeRec2.Body.String())
		}
		assertRetransmittedVersion(t, obj, apiRouter, credentials, bucketName, object, srcInfo.VersionID, "retransmit=multipart", data, sseHeaders)
	})

	t.Run("repairs-an-undecodable-existing-version", func(t *testing.T) {
		// A pre-fix destination (issue #109) could persist an SSE-C replica as
		// compress(ciphertext) or a re-encrypted body, leaving a stored length
		// that is not a valid encryption stream. Resync repairs such a version by
		// retransmitting the source's raw ciphertext, but the write must not first
		// require the stored, damaged object to decrypt. See issue #120.
		data := bytes.Repeat([]byte("SILO raw SSE-C recovery\n"), 400)
		object := "ssec-duplicate/undecodable"
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data, sseHeaders)

		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		srcInfo := gr.ObjInfo
		cipher, err := io.ReadAll(gr)
		gr.Close()
		if err != nil {
			t.Fatal(err)
		}

		// Stage the damage: overwrite the version with a body too short to be a
		// valid encryption stream, standing in for the compression/re-encryption
		// an old destination left behind. The staging write itself is a raw
		// replica over the still-valid version, so it stores verbatim.
		damaged := []byte("dmg!!")
		if _, derr := sio.DecryptedSize(uint64(len(damaged))); derr == nil {
			t.Fatalf("%s: fixture body of %d bytes is a valid stream length, not undecodable", instanceType, len(damaged))
		}
		stageHdrs := replicaHeaders(t, srcInfo)
		stageURL := getPutObjectURL("", bucketName, object) + "?versionId=" + srcInfo.VersionID
		stageReq, err := newTestSignedRequestV4(http.MethodPut, stageURL, int64(len(damaged)),
			bytes.NewReader(damaged), replicator.AccessKey, replicator.SecretKey, stageHdrs)
		if err != nil {
			t.Fatal(err)
		}
		stageRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(stageRec, stageReq)
		if stageRec.Code != http.StatusOK {
			t.Fatalf("%s: could not stage the damaged replica: %d %s", instanceType, stageRec.Code, stageRec.Body.String())
		}
		// The staged version is genuinely undecodable at the object layer, which
		// is exactly what makes DecryptObjectInfo fail during the overwrite.
		staged, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{VersionID: srcInfo.VersionID})
		if err != nil {
			t.Fatal(err)
		}
		if _, derr := staged.DecryptedSize(); derr == nil {
			t.Fatalf("%s: staged replica is decodable, cannot exercise the repair path", instanceType)
		}

		// Retransmit the correct ciphertext over the same version. Before the
		// raw-replica precondition exemption this failed with XMinioObjectTampered
		// because the damaged object could not decrypt; it must now repair.
		srcInfo.UserTags = "retransmit=undecodable"
		hdrs := replicaHeaders(t, srcInfo)
		putURL := getPutObjectURL("", bucketName, object) + "?versionId=" + srcInfo.VersionID
		req, err := newTestSignedRequestV4(http.MethodPut, putURL, int64(len(cipher)),
			bytes.NewReader(cipher), replicator.AccessKey, replicator.SecretKey, hdrs)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: retransmit over an undecodable version status %d, want 200: %s", instanceType, rec.Code, rec.Body.String())
		}
		assertRetransmittedVersion(t, obj, apiRouter, credentials, bucketName, object, srcInfo.VersionID, "retransmit=undecodable", data, sseHeaders)
	})

	// setupHealthySSECVersion writes a normal SSE-C object and returns its
	// ObjectInfo (for building replica headers), its ciphertext, and the
	// client-visible ETag a keyed reader sees -- the decrypted ETag, which is
	// distinct from the stored sealed ETag.
	setupHealthySSECVersion := func(t *testing.T, object string, data []byte) (srcInfo ObjectInfo, cipher []byte, clientETag string) {
		t.Helper()
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data, sseHeaders)
		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{ReplicationRequest: true})
		if err != nil {
			t.Fatal(err)
		}
		srcInfo = gr.ObjInfo
		cipher, err = io.ReadAll(gr)
		gr.Close()
		if err != nil {
			t.Fatal(err)
		}
		// The client-visible ETag is the decrypted one, which the handler derives
		// with the customer key through DecryptObjectInfo; compute it the same way.
		keyHeader := http.Header{}
		for k, v := range sseHeaders {
			keyHeader.Set(k, v)
		}
		clientETag = getDecryptedETag(keyHeader, srcInfo, false)
		if clientETag == "" || clientETag == srcInfo.ETag {
			t.Fatalf("%s: client ETag %q is not distinct from the sealed ETag %q", instanceType, clientETag, srcInfo.ETag)
		}
		return srcInfo, cipher, clientETag
	}

	// A conditional replica PUT must compare the public precondition against the
	// client-visible ETag, not the stored sealed one. Skipping DecryptObjectInfo
	// for every raw SSE-C replica (not only a pure overwrite) left oi.ETag sealed
	// and inverted both conditions.
	t.Run("if-match-on-the-client-etag-proceeds", func(t *testing.T) {
		object := "ssec-duplicate/cond-if-match"
		srcInfo, cipher, clientETag := setupHealthySSECVersion(t, object, bytes.Repeat([]byte("cond-if-match-"), 64))
		hdrs := replicaHeaders(t, srcInfo)
		hdrs[xhttp.IfMatch] = "\"" + clientETag + "\""
		req, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectURL("", bucketName, object)+"?versionId="+srcInfo.VersionID,
			int64(len(cipher)), bytes.NewReader(cipher), replicator.AccessKey, replicator.SecretKey, hdrs)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: If-Match on the client ETag status %d, want 200: %s", instanceType, rec.Code, rec.Body.String())
		}
	})

	t.Run("if-none-match-on-the-client-etag-fails", func(t *testing.T) {
		object := "ssec-duplicate/cond-if-none-match"
		srcInfo, cipher, clientETag := setupHealthySSECVersion(t, object, bytes.Repeat([]byte("cond-if-none-"), 64))
		hdrs := replicaHeaders(t, srcInfo)
		hdrs[xhttp.IfNoneMatch] = "\"" + clientETag + "\""
		req, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectURL("", bucketName, object)+"?versionId="+srcInfo.VersionID,
			int64(len(cipher)), bytes.NewReader(cipher), replicator.AccessKey, replicator.SecretKey, hdrs)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusPreconditionFailed {
			t.Fatalf("%s: If-None-Match on the client ETag status %d, want 412: %s", instanceType, rec.Code, rec.Body.String())
		}
	})
}

// assertRetransmittedVersion checks that a retransmit landed on the addressed
// version: the changed tag is stored on it and it still reads back with the
// customer key.
func assertRetransmittedVersion(t *testing.T, obj ObjectLayer, apiRouter http.Handler, credentials auth.Credentials,
	bucketName, object, versionID, wantTags string, want []byte, sseHeaders map[string]string,
) {
	t.Helper()
	info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{VersionID: versionID})
	if err != nil {
		t.Fatalf("version %s after retransmit: %v", versionID, err)
	}
	if info.UserTags != wantTags {
		t.Errorf("version %s tags after retransmit %q, want %q", versionID, info.UserTags, wantTags)
	}
	if !crypto.SSEC.IsEncrypted(info.UserDefined) {
		t.Errorf("version %s lost its SSE-C seal after retransmit", versionID)
	}
	getReq, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, object)+"?versionId="+versionID,
		0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	getRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK || !bytes.Equal(getRec.Body.Bytes(), want) {
		t.Fatalf("version %s does not read back with the customer key after retransmit: %d (%d bytes, want %d)",
			versionID, getRec.Code, getRec.Body.Len(), len(want))
	}
}

// TestPutReplicationOptsRetentionRemoval asserts that a source version whose
// retention was removed (stored as an empty mode and date) still builds
// replication options, carrying the removal's ordering timestamp and no value.
func TestPutReplicationOptsRetentionRemoval(t *testing.T) {
	removedAt := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	oi := ObjectInfo{
		Bucket: "b", Name: "o", VersionID: "v1", ModTime: removedAt.Add(-time.Hour),
		UserDefined: map[string]string{
			strings.ToLower(xhttp.AmzObjectLockMode):                   "",
			strings.ToLower(xhttp.AmzObjectLockRetainUntilDate):        "",
			ReservedMetadataPrefixLower + ObjectLockRetentionTimestamp: removedAt.Format(time.RFC3339Nano),
		},
	}
	opts, _, err := putReplicationOpts(t.Context(), "", oi)
	if err != nil {
		t.Fatalf("putReplicationOpts on a removed retention: %v", err)
	}
	if opts.Mode != "" || !opts.RetainUntilDate.IsZero() {
		t.Errorf("removal sent as a retention: mode %q date %v", opts.Mode, opts.RetainUntilDate)
	}
	if !opts.Internal.RetentionTimestamp.Equal(removedAt) {
		t.Errorf("removal timestamp %v, want %v", opts.Internal.RetentionTimestamp, removedAt)
	}
	if hdr := opts.Header(); hdr.Get(xhttp.AmzObjectLockMode) != "" || hdr.Get(xhttp.AmzObjectLockRetainUntilDate) != "" ||
		hdr.Get(xhttp.MinIOSourceObjectRetentionTimestamp) == "" {
		t.Errorf("removal headers %v: want no lock value and a retention timestamp", hdr)
	}
}

// TestAPISSECReplicaWriteExemptionIsKeyedOnTheIncomingWrite pins the predicate
// of the duplicate version and ETag exemption: it applies to an authenticated
// replica write that carries an SSE-C seal, whatever the destination holds, and
// not to a plaintext replica write that happens to match an SSE-C destination
// version. See pgsty/silo#120.
func TestAPISSECReplicaWriteExemptionIsKeyedOnTheIncomingWrite(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testAPISSECReplicaWriteExemptionIsKeyedOnTheIncomingWrite,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true},
	})
}

func testAPISSECReplicaWriteExemptionIsKeyedOnTheIncomingWrite(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	key := bytes.Repeat([]byte{0x44}, 32)
	keyMD5 := md5.Sum(key)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName,
		`"s3:GetObject","s3:PutObject","s3:ReplicateObject"`)

	rawOf := func(t *testing.T, object string) (ObjectInfo, []byte) {
		t.Helper()
		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer gr.Close()
		raw, err := io.ReadAll(gr)
		if err != nil {
			t.Fatal(err)
		}
		return gr.ObjInfo, raw
	}
	replicaHeaders := func(t *testing.T, oi ObjectInfo) map[string]string {
		t.Helper()
		opts, _, err := putReplicationOpts(t.Context(), "", oi)
		if err != nil {
			t.Fatal(err)
		}
		opts.Internal.SourceMTime = time.Time{}
		out := make(map[string]string)
		for name, values := range opts.Header() {
			if len(values) > 0 {
				out[name] = values[0]
			}
		}
		out[xhttp.MinIOSourceReplicationRequest] = "true"
		out[xhttp.AmzBucketReplicationStatus] = "REPLICA"
		out[xhttp.MinIOSourceETag] = oi.ETag
		return out
	}
	replicaPut := func(t *testing.T, object, versionID string, body []byte, hdrs map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		req, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectURL("", bucketName, object)+"?versionId="+versionID, int64(len(body)),
			bytes.NewReader(body), replicator.AccessKey, replicator.SecretKey, hdrs)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return rec
	}

	// putSSECMultipart stores a one-part SSE-C multipart object: unlike a
	// single-part SSE-C object, whose stored ETag is the sealed one and never
	// matches the sender's, a multipart ETag compares equal, which is what
	// makes the duplicate version and ETag check reachable at all.
	putSSECMultipart := func(t *testing.T, object string, data []byte) {
		t.Helper()
		newReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
			0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		newRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(newRec, newReq)
		if newRec.Code != http.StatusOK {
			t.Fatalf("%s: NewMultipart %d: %s", instanceType, newRec.Code, newRec.Body.String())
		}
		var init InitiateMultipartUploadResponse
		if err = xmlDecoder(newRec.Body, &init, int64(newRec.Body.Len())); err != nil {
			t.Fatal(err)
		}
		partReq, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectPartURL("", bucketName, object, init.UploadID, "1"), int64(len(data)),
			bytes.NewReader(data), credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		partRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(partRec, partReq)
		if partRec.Code != http.StatusOK {
			t.Fatalf("%s: PutPart %d: %s", instanceType, partRec.Code, partRec.Body.String())
		}
		body, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{
			{PartNumber: 1, ETag: canonicalizeETag(partRec.Header()[xhttp.ETag][0])},
		}})
		if err != nil {
			t.Fatal(err)
		}
		completeReq, err := newTestSignedRequestV4(http.MethodPost,
			getCompleteMultipartUploadURL("", bucketName, object, init.UploadID), int64(len(body)),
			bytes.NewReader(body), credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		completeRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(completeRec, completeReq)
		if completeRec.Code != http.StatusOK {
			t.Fatalf("%s: Complete %d: %s", instanceType, completeRec.Code, completeRec.Body.String())
		}
	}

	t.Run("plaintext-replica-over-ssec-version-is-still-rejected", func(t *testing.T) {
		object := "ssec-exemption/ssec-destination"
		putSSECMultipart(t, object, bytes.Repeat([]byte("ssec-destination-"), 4096))
		srcInfo, raw := rawOf(t, object)
		hdrs := replicaHeaders(t, srcInfo)
		// Without the seal the incoming write is a plaintext replica that merely
		// carries the stored version and ETag: the duplicate check still applies.
		for name := range hdrs {
			if strings.HasPrefix(name, "X-Minio-Replication-Server-Side-Encryption-") {
				delete(hdrs, name)
			}
		}
		rec := replicaPut(t, object, srcInfo.VersionID, raw, hdrs)
		if rec.Code != http.StatusPreconditionFailed {
			t.Fatalf("%s: plaintext replica write over an existing SSE-C version answered %d, want 412: %s",
				instanceType, rec.Code, rec.Body.String())
		}
	})

	t.Run("ssec-replica-over-plaintext-version-is-exempted", func(t *testing.T) {
		object := "ssec-exemption/plain-destination"
		// A plaintext version first, then an SSE-C version of the same key so
		// the seal is bound to this object path.
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, []byte("plaintext destination version"), nil)
		plainInfo, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		data := bytes.Repeat([]byte("ssec-source-"), 400)
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data, sseHeaders)
		srcInfo, raw := rawOf(t, object)

		// The incoming write carries the SSE-C seal and addresses the plaintext
		// version with its ETag: the exemption is decided by the incoming
		// write, not by what the destination holds.
		hdrs := replicaHeaders(t, srcInfo)
		hdrs[xhttp.MinIOSourceETag] = plainInfo.ETag
		rec := replicaPut(t, object, plainInfo.VersionID, raw, hdrs)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: SSE-C replica write over a matching plaintext version answered %d, want 200: %s",
				instanceType, rec.Code, rec.Body.String())
		}
		getReq, err := newTestSignedRequestV4(http.MethodGet,
			getGetObjectURL("", bucketName, object)+"?versionId="+plainInfo.VersionID, 0, nil,
			credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		getRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(getRec, getReq)
		if getRec.Code != http.StatusOK || !bytes.Equal(getRec.Body.Bytes(), data) {
			t.Fatalf("%s: the retransmitted version does not read back with the customer key: %d (%d bytes)",
				instanceType, getRec.Code, getRec.Body.Len())
		}
	})
}

// Retain-until values in the millisecond form ISO8601Format round-trips to, so
// a value applied through the handler reads back byte-for-byte.
const (
	retransmitRetainUntilNewer = "2031-01-01T00:00:00.000Z"
	retransmitRetainUntilStale = "2028-01-01T00:00:00.000Z"
)

// TestAPISSECReplicaRetransmitObjectLockOrdering proves that the full SSE-C
// replica retransmit orders the Object Lock update it carries against the state
// already stored on the addressed version, the same way the metadata CopyObject
// path does. Before issue #120 routed these writes through PutObjectHandler the
// handler applied the incoming retention and legal hold directly and never
// persisted the ordering timestamps, so a retransmit carrying an older value
// could overwrite a destination version's newer one. See pgsty/silo#120.
func TestAPISSECReplicaRetransmitObjectLockOrdering(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testAPISSECReplicaRetransmitObjectLockOrdering,
		makeBucketOptions: MakeBucketOptions{LockEnabled: true},
	})
}

func testAPISSECReplicaRetransmitObjectLockOrdering(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	key := bytes.Repeat([]byte{0x45}, 32)
	keyMD5 := md5.Sum(key)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}

	// seed writes a fresh SSE-C source version with no Object Lock state and
	// returns its version id.
	seed := func(t *testing.T, object string) string {
		t.Helper()
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, object,
			bytes.Repeat([]byte("ssec-lock-ordering-"), 64), sseHeaders)
		info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return info.VersionID
	}

	// retransmit sends the full SSE-C replica retransmit the sender emits for the
	// addressed version, over its raw ciphertext, carrying exactly the given
	// Object Lock headers on top of the replica seal. The credential is the admin
	// user so the retention and legal-hold permission checks pass; the request is
	// still a trusted replica because it carries the marker and REPLICA status.
	retransmit := func(t *testing.T, object, versionID string, lockHeaders map[string]string) {
		t.Helper()
		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true,
			VersionID:          versionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		srcInfo := gr.ObjInfo
		cipher, err := io.ReadAll(gr)
		gr.Close()
		if err != nil {
			t.Fatal(err)
		}
		opts, _, err := putReplicationOpts(t.Context(), "", srcInfo)
		if err != nil {
			t.Fatal(err)
		}
		opts.Internal.SourceMTime = time.Time{}
		hdrs := make(map[string]string)
		for name, values := range opts.Header() {
			if len(values) > 0 {
				hdrs[name] = values[0]
			}
		}
		hdrs[xhttp.MinIOSourceReplicationRequest] = "true"
		hdrs[xhttp.AmzBucketReplicationStatus] = "REPLICA"
		hdrs[xhttp.MinIOSourceETag] = srcInfo.ETag
		// The case owns the lock instruction: drop any lock header the sender
		// derived from the source version.
		for _, name := range []string{
			xhttp.AmzObjectLockMode, xhttp.AmzObjectLockRetainUntilDate, xhttp.AmzObjectLockLegalHold,
			xhttp.MinIOSourceObjectRetentionTimestamp, xhttp.MinIOSourceObjectLegalHoldTimestamp,
		} {
			delete(hdrs, name)
		}
		maps.Copy(hdrs, lockHeaders)

		req, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectURL("", bucketName, object)+"?versionId="+versionID, int64(len(cipher)),
			bytes.NewReader(cipher), credentials.AccessKey, credentials.SecretKey, hdrs)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: replica retransmit PUT status %d, want 200: %s", instanceType, rec.Code, rec.Body.String())
		}
	}

	t.Run("older-legal-hold-off-does-not-clear-newer-on", func(t *testing.T) {
		object := "ssec-lock-ordering/legal-hold"
		versionID := seed(t, object)

		// Establish the newer legal hold ON. Its timestamp persistence is proven
		// by the retention sibling test, so here only require the value took
		// effect before the older OFF arrives, so the clobber below is what tells
		// a fixed handler from a broken one.
		retransmit(t, object, versionID, map[string]string{
			xhttp.AmzObjectLockLegalHold:              "ON",
			xhttp.MinIOSourceObjectLegalHoldTimestamp: objectLockTestStamp1000,
		})
		if got := readObjectLockFields(t, obj, bucketName, object, versionID); got.legalHold != "ON" {
			t.Fatalf("%s: seeding legal hold ON failed: got %+v", instanceType, got)
		}

		// A retransmit carrying an older legal-hold OFF must not clear it.
		retransmit(t, object, versionID, map[string]string{
			xhttp.AmzObjectLockLegalHold:              "OFF",
			xhttp.MinIOSourceObjectLegalHoldTimestamp: objectLockTestStamp0900,
		})
		want := objectLockFields{legalHold: "ON", legalHoldStamp: objectLockTestStamp1000}
		if got := readObjectLockFields(t, obj, bucketName, object, versionID); got != want {
			t.Fatalf("%s: an older legal-hold OFF cleared the newer ON: got %+v, want %+v", instanceType, got, want)
		}
	})

	t.Run("newer-retention-applies-and-persists-its-timestamp", func(t *testing.T) {
		object := "ssec-lock-ordering/retention-applies"
		versionID := seed(t, object)

		retransmit(t, object, versionID, map[string]string{
			xhttp.AmzObjectLockMode:                   "GOVERNANCE",
			xhttp.AmzObjectLockRetainUntilDate:        retransmitRetainUntilNewer,
			xhttp.MinIOSourceObjectRetentionTimestamp: objectLockTestStamp1000,
		})
		// The value applies and, crucially, the ordering timestamp is persisted so
		// a later stale update can be recognized as older.
		want := objectLockFields{
			mode: "GOVERNANCE", retainUntil: retransmitRetainUntilNewer, retentionStamp: objectLockTestStamp1000,
		}
		if got := readObjectLockFields(t, obj, bucketName, object, versionID); got != want {
			t.Fatalf("%s: newer retention did not apply and persist its timestamp: got %+v, want %+v", instanceType, got, want)
		}
	})

	t.Run("stale-retention-update-is-ignored", func(t *testing.T) {
		object := "ssec-lock-ordering/retention-stale"
		versionID := seed(t, object)

		// Establish the newer retention first; its timestamp persistence is proven
		// by the sibling test above, so here only require the value took effect, so
		// the stale overwrite below is what tells a fixed handler from a broken one.
		retransmit(t, object, versionID, map[string]string{
			xhttp.AmzObjectLockMode:                   "GOVERNANCE",
			xhttp.AmzObjectLockRetainUntilDate:        retransmitRetainUntilNewer,
			xhttp.MinIOSourceObjectRetentionTimestamp: objectLockTestStamp1000,
		})
		if got := readObjectLockFields(t, obj, bucketName, object, versionID); got.mode != "GOVERNANCE" || got.retainUntil != retransmitRetainUntilNewer {
			t.Fatalf("%s: seeding the newer retention failed: got %+v", instanceType, got)
		}

		// A retransmit carrying an older retention with a different date must be
		// ignored; the newer date and its ordering timestamp survive.
		retransmit(t, object, versionID, map[string]string{
			xhttp.AmzObjectLockMode:                   "GOVERNANCE",
			xhttp.AmzObjectLockRetainUntilDate:        retransmitRetainUntilStale,
			xhttp.MinIOSourceObjectRetentionTimestamp: objectLockTestStamp0900,
		})
		want := objectLockFields{
			mode: "GOVERNANCE", retainUntil: retransmitRetainUntilNewer, retentionStamp: objectLockTestStamp1000,
		}
		if got := readObjectLockFields(t, obj, bucketName, object, versionID); got != want {
			t.Fatalf("%s: a stale retention update overwrote the newer one: got %+v, want %+v", instanceType, got, want)
		}
	})
}

// TestAPISSECReplicaRetransmitMultipartObjectLockOrdering proves the ordering
// fix also covers the multipart initiation path #120 routes an SSE-C replica
// through: NewMultipartUploadHandler reads the addressed version's stored lock
// state and orders the incoming update against it, so a large-object retransmit
// carrying an older legal-hold OFF cannot clear a newer ON. See pgsty/silo#120.
func TestAPISSECReplicaRetransmitMultipartObjectLockOrdering(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testAPISSECReplicaRetransmitMultipartObjectLockOrdering,
		makeBucketOptions: MakeBucketOptions{LockEnabled: true},
	})
}

func testAPISSECReplicaRetransmitMultipartObjectLockOrdering(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	key := bytes.Repeat([]byte{0x46}, 32)
	keyMD5 := md5.Sum(key)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}

	// replicaSealHeaders returns the sender's replica seal and marker headers for
	// the addressed version, with every Object Lock header stripped so the case
	// owns the lock instruction.
	replicaSealHeaders := func(t *testing.T, srcInfo ObjectInfo) map[string]string {
		t.Helper()
		opts, _, err := putReplicationOpts(t.Context(), "", srcInfo)
		if err != nil {
			t.Fatal(err)
		}
		opts.Internal.SourceMTime = time.Time{}
		hdrs := make(map[string]string)
		for name, values := range opts.Header() {
			if len(values) > 0 {
				hdrs[name] = values[0]
			}
		}
		hdrs[xhttp.MinIOSourceReplicationRequest] = "true"
		hdrs[xhttp.AmzBucketReplicationStatus] = "REPLICA"
		hdrs[xhttp.MinIOSourceETag] = srcInfo.ETag
		for _, name := range []string{
			xhttp.AmzObjectLockMode, xhttp.AmzObjectLockRetainUntilDate, xhttp.AmzObjectLockLegalHold,
			xhttp.MinIOSourceObjectRetentionTimestamp, xhttp.MinIOSourceObjectLegalHoldTimestamp,
		} {
			delete(hdrs, name)
		}
		return hdrs
	}

	object := "ssec-lock-ordering/multipart"
	// A single-part SSE-C source is enough; the retransmit re-uploads its bytes
	// as one multipart part and commits the addressed version.
	putCopyChecksumSource(t, apiRouter, credentials, bucketName, object,
		bytes.Repeat([]byte("ssec-multipart-lock-ordering-"), 64), sseHeaders)
	base, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	versionID := base.VersionID

	// Establish the newer legal hold ON through the single-part PUT retransmit.
	{
		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true, VersionID: versionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		srcInfo := gr.ObjInfo
		cipher, rerr := io.ReadAll(gr)
		gr.Close()
		if rerr != nil {
			t.Fatal(rerr)
		}
		hdrs := replicaSealHeaders(t, srcInfo)
		hdrs[xhttp.AmzObjectLockLegalHold] = "ON"
		hdrs[xhttp.MinIOSourceObjectLegalHoldTimestamp] = objectLockTestStamp1000
		req, rerr := newTestSignedRequestV4(http.MethodPut,
			getPutObjectURL("", bucketName, object)+"?versionId="+versionID, int64(len(cipher)),
			bytes.NewReader(cipher), credentials.AccessKey, credentials.SecretKey, hdrs)
		if rerr != nil {
			t.Fatal(rerr)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: seeding legal hold ON via PUT status %d: %s", instanceType, rec.Code, rec.Body.String())
		}
		if got := readObjectLockFields(t, obj, bucketName, object, versionID); got.legalHold != "ON" {
			t.Fatalf("%s: seeding legal hold ON failed: got %+v", instanceType, got)
		}
	}

	// A multipart retransmit carrying an older legal-hold OFF must not clear it.
	gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
		ReplicationRequest: true, VersionID: versionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	srcInfo := gr.ObjInfo
	cipher, err := io.ReadAll(gr)
	gr.Close()
	if err != nil {
		t.Fatal(err)
	}
	actualSize, err := srcInfo.GetActualSize()
	if err != nil {
		t.Fatal(err)
	}

	newHdrs := replicaSealHeaders(t, srcInfo)
	newHdrs[xhttp.AmzObjectLockLegalHold] = "OFF"
	newHdrs[xhttp.MinIOSourceObjectLegalHoldTimestamp] = objectLockTestStamp0900
	newReq, err := newTestSignedRequestV4(http.MethodPost,
		getNewMultipartURL("", bucketName, object)+"&versionId="+versionID, 0, nil,
		credentials.AccessKey, credentials.SecretKey, newHdrs)
	if err != nil {
		t.Fatal(err)
	}
	newRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(newRec, newReq)
	if newRec.Code != http.StatusOK {
		t.Fatalf("%s: replica NewMultipartUpload status %d: %s", instanceType, newRec.Code, newRec.Body.String())
	}
	var init InitiateMultipartUploadResponse
	if err = xmlDecoder(newRec.Body, &init, int64(newRec.Body.Len())); err != nil {
		t.Fatal(err)
	}

	partReq, err := newTestSignedRequestV4(http.MethodPut,
		getPutObjectPartURL("", bucketName, object, init.UploadID, "1"), int64(len(cipher)),
		bytes.NewReader(cipher), credentials.AccessKey, credentials.SecretKey,
		map[string]string{xhttp.MinIOSourceReplicationRequest: "true"})
	if err != nil {
		t.Fatal(err)
	}
	partRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(partRec, partReq)
	if partRec.Code != http.StatusOK {
		t.Fatalf("%s: replica PutObjectPart status %d: %s", instanceType, partRec.Code, partRec.Body.String())
	}

	completeBody, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{
		{PartNumber: 1, ETag: canonicalizeETag(partRec.Header()[xhttp.ETag][0])},
	}})
	if err != nil {
		t.Fatal(err)
	}
	completeReq, err := newTestSignedRequestV4(http.MethodPost,
		getCompleteMultipartUploadURL("", bucketName, object, init.UploadID), int64(len(completeBody)),
		bytes.NewReader(completeBody), credentials.AccessKey, credentials.SecretKey, map[string]string{
			xhttp.MinIOSourceReplicationRequest:    "true",
			xhttp.MinIOSourceMTime:                 srcInfo.ModTime.Format(time.RFC3339Nano),
			xhttp.MinIOSourceETag:                  srcInfo.ETag,
			xhttp.MinIOReplicationActualObjectSize: strconv.FormatInt(actualSize, 10),
		})
	if err != nil {
		t.Fatal(err)
	}
	completeRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(completeRec, completeReq)
	if completeRec.Code != http.StatusOK {
		t.Fatalf("%s: replica CompleteMultipartUpload status %d: %s", instanceType, completeRec.Code, completeRec.Body.String())
	}

	want := objectLockFields{legalHold: "ON", legalHoldStamp: objectLockTestStamp1000}
	if got := readObjectLockFields(t, obj, bucketName, object, versionID); got != want {
		t.Fatalf("%s: an older legal-hold OFF via multipart cleared the newer ON: got %+v, want %+v", instanceType, got, want)
	}
}

// TestReplicaStoredLock verifies how a replica write reads the destination
// version's stored lock state before ordering its update: a present version
// yields its state, a missing object or version yields an empty state so a first
// write is not blocked, and any other read error (a quorum loss, a timeout) is
// returned so the caller fails the write instead of ordering an incoming update
// against lock state it merely could not read. See pgsty/silo#120.
func TestReplicaStoredLock(t *testing.T) {
	fixed := func(oi ObjectInfo, err error) GetObjectInfoFn {
		return func(context.Context, string, string, ObjectOptions) (ObjectInfo, error) { return oi, err }
	}
	stored := ObjectInfo{UserDefined: map[string]string{
		strings.ToLower(xhttp.AmzObjectLockLegalHold):              "ON",
		ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: objectLockTestStamp1000,
	}}

	t.Run("present-version-returns-its-state", func(t *testing.T) {
		got, err := replicaStoredLock(context.Background(), fixed(stored, nil), "b", "o", "v")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.legalHold != "ON" || got.legalHoldTimestamp != objectLockTestStamp1000 {
			t.Fatalf("stored lock state = %+v, want legal hold ON stamped %q", got, objectLockTestStamp1000)
		}
	})

	for name, notFound := range map[string]error{
		"object-not-found":  ObjectNotFound{Bucket: "b", Object: "o"},
		"version-not-found": VersionNotFound{Bucket: "b", Object: "o", VersionID: "v"},
	} {
		t.Run(name+"-is-empty-state", func(t *testing.T) {
			got, err := replicaStoredLock(context.Background(), fixed(ObjectInfo{}, notFound), "b", "o", "v")
			if err != nil {
				t.Fatalf("a not-found read must not error: %v", err)
			}
			if got != (objectLockState{}) {
				t.Fatalf("a not-found read must yield empty state, got %+v", got)
			}
		})
	}

	t.Run("transient-read-error-propagates", func(t *testing.T) {
		boom := InsufficientReadQuorum{}
		got, err := replicaStoredLock(context.Background(), fixed(ObjectInfo{}, boom), "b", "o", "v")
		if err == nil {
			t.Fatal("a transient read error must propagate, not be treated as absent lock state")
		}
		if isErrObjectNotFound(err) || isErrVersionNotFound(err) {
			t.Fatalf("transient error misclassified as not-found: %v", err)
		}
		if got != (objectLockState{}) {
			t.Fatalf("on a read error the caller must get empty state and fail the write, got %+v", got)
		}
	})
}

// TestPutReplicationOptsRetentionRemovalTimestampOnly asserts that a version
// whose retention was removed on the retransmit PUT path -- stored as an
// ordering timestamp with the value keys absent, not empty -- still builds
// replication options that carry the removal timestamp, so the next hop can
// order the removal instead of keeping obsolete retention. See pgsty/silo#120.
func TestPutReplicationOptsRetentionRemovalTimestampOnly(t *testing.T) {
	removedAt := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	oi := ObjectInfo{
		Bucket: "b", Name: "o", VersionID: "v1", ModTime: removedAt.Add(-time.Hour),
		UserDefined: map[string]string{
			// Only the reserved ordering timestamp; no mode/date keys at all.
			ReservedMetadataPrefixLower + ObjectLockRetentionTimestamp: removedAt.Format(time.RFC3339Nano),
		},
	}
	opts, _, err := putReplicationOpts(t.Context(), "", oi)
	if err != nil {
		t.Fatalf("putReplicationOpts on a timestamp-only removal: %v", err)
	}
	if opts.Mode != "" || !opts.RetainUntilDate.IsZero() {
		t.Errorf("removal sent as a retention: mode %q date %v", opts.Mode, opts.RetainUntilDate)
	}
	if !opts.Internal.RetentionTimestamp.Equal(removedAt) {
		t.Errorf("removal timestamp %v, want %v", opts.Internal.RetentionTimestamp, removedAt)
	}
	if hdr := opts.Header(); hdr.Get(xhttp.AmzObjectLockMode) != "" || hdr.Get(xhttp.AmzObjectLockRetainUntilDate) != "" ||
		hdr.Get(xhttp.MinIOSourceObjectRetentionTimestamp) == "" {
		t.Errorf("removal headers %v: want no lock value and a retention timestamp", hdr)
	}
}

// TestAPIReplicaMarkerOnlyAppliesObjectLock guards the regression the shared
// ordering helper could introduce: a trusted peer write that carries the
// internal replication marker but NOT REPLICA status (replicationRequest true,
// replicaTrusted false) must keep ordinary write semantics and apply its
// validated Object Lock, not restore an empty stored state. It covers an
// explicit legal hold and a bucket-default retention, on both the PUT and the
// multipart-initiation paths. See pgsty/silo#120 (Codex finding 3).
func TestAPIReplicaMarkerOnlyAppliesObjectLock(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testAPIReplicaMarkerOnlyAppliesObjectLock,
		makeBucketOptions: MakeBucketOptions{LockEnabled: true},
	})
}

func testAPIReplicaMarkerOnlyAppliesObjectLock(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	// A trusted peer credential holding ReplicateObject plus the lock permissions
	// checkPutObjectLockAllowed enforces even for a marker-only write.
	peer := newObjectAttributesAuthzUser(t, instanceType, bucketName,
		`"s3:GetObject","s3:PutObject","s3:ReplicateObject","s3:PutObjectRetention","s3:PutObjectLegalHold"`)

	// Bucket default retention, so a marker-only write with no lock headers still
	// has a validated retention to apply.
	lockCfg := []byte(`<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>`)
	if _, err := globalBucketMetadataSys.Update(t.Context(), bucketName, objectLockConfig, lockCfg); err != nil {
		t.Fatalf("%s: configure bucket default retention: %v", instanceType, err)
	}

	// markerOnly returns the trusted-but-not-REPLICA header set plus extra: the
	// internal marker with no REPLICA status.
	markerOnly := func(extra map[string]string) map[string]string {
		h := map[string]string{xhttp.MinIOSourceReplicationRequest: "true"}
		maps.Copy(h, extra)
		return h
	}
	data := bytes.Repeat([]byte("marker-only-lock-"), 32)

	markerOnlyMPU := func(t *testing.T, object string, lockHeaders map[string]string) {
		t.Helper()
		newReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object), 0, nil,
			peer.AccessKey, peer.SecretKey, markerOnly(lockHeaders))
		if err != nil {
			t.Fatal(err)
		}
		newRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(newRec, newReq)
		if newRec.Code != http.StatusOK {
			t.Fatalf("%s: marker-only NewMultipartUpload %d: %s", instanceType, newRec.Code, newRec.Body.String())
		}
		var init InitiateMultipartUploadResponse
		if err = xmlDecoder(newRec.Body, &init, int64(newRec.Body.Len())); err != nil {
			t.Fatal(err)
		}
		partReq, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectPartURL("", bucketName, object, init.UploadID, "1"), int64(len(data)),
			bytes.NewReader(data), peer.AccessKey, peer.SecretKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		partRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(partRec, partReq)
		if partRec.Code != http.StatusOK {
			t.Fatalf("%s: marker-only PutObjectPart %d: %s", instanceType, partRec.Code, partRec.Body.String())
		}
		body, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{
			{PartNumber: 1, ETag: canonicalizeETag(partRec.Header()[xhttp.ETag][0])},
		}})
		if err != nil {
			t.Fatal(err)
		}
		completeReq, err := newTestSignedRequestV4(http.MethodPost,
			getCompleteMultipartUploadURL("", bucketName, object, init.UploadID), int64(len(body)),
			bytes.NewReader(body), peer.AccessKey, peer.SecretKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		completeRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(completeRec, completeReq)
		if completeRec.Code != http.StatusOK {
			t.Fatalf("%s: marker-only CompleteMultipartUpload %d: %s", instanceType, completeRec.Code, completeRec.Body.String())
		}
	}
	markerOnlyPUT := func(t *testing.T, object string, lockHeaders map[string]string) {
		t.Helper()
		req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, object), int64(len(data)),
			bytes.NewReader(data), peer.AccessKey, peer.SecretKey, markerOnly(lockHeaders))
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: marker-only PUT %d: %s", instanceType, rec.Code, rec.Body.String())
		}
	}
	lockOf := func(t *testing.T, object string) objectLockState {
		t.Helper()
		info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return storedObjectLockState(info.UserDefined)
	}

	// An explicit legal hold on a marker-only write must be applied, not dropped.
	// A legal-hold request suppresses the bucket default retention, so the version
	// carries only the hold.
	explicitHold := map[string]string{xhttp.AmzObjectLockLegalHold: "ON"}

	t.Run("put-explicit-legal-hold", func(t *testing.T) {
		object := "marker-only/put-legal-hold"
		markerOnlyPUT(t, object, explicitHold)
		if got := lockOf(t, object); got.legalHold != "ON" {
			t.Fatalf("%s: marker-only PUT dropped the explicit legal hold: got %+v", instanceType, got)
		}
	})
	t.Run("mpu-explicit-legal-hold", func(t *testing.T) {
		object := "marker-only/mpu-legal-hold"
		markerOnlyMPU(t, object, explicitHold)
		if got := lockOf(t, object); got.legalHold != "ON" {
			t.Fatalf("%s: marker-only multipart dropped the explicit legal hold: got %+v", instanceType, got)
		}
	})
	t.Run("put-bucket-default-retention", func(t *testing.T) {
		object := "marker-only/put-default-retention"
		markerOnlyPUT(t, object, nil)
		if got := lockOf(t, object); got.mode != "GOVERNANCE" || got.retainUntil == "" {
			t.Fatalf("%s: marker-only PUT dropped the bucket default retention: got %+v", instanceType, got)
		}
	})
	t.Run("mpu-bucket-default-retention", func(t *testing.T) {
		object := "marker-only/mpu-default-retention"
		markerOnlyMPU(t, object, nil)
		if got := lockOf(t, object); got.mode != "GOVERNANCE" || got.retainUntil == "" {
			t.Fatalf("%s: marker-only multipart dropped the bucket default retention: got %+v", instanceType, got)
		}
	})
}

// TestAPIReplicaMultipartNewerHoldSurvivesCompletion verifies that a legal hold
// that reaches a destination version AFTER a replica multipart upload was
// initiated is not rolled back when that upload completes. The initiation
// resolves the lock against the version as it then stands, but completion
// re-orders the carried lock against the version read under the namespace write
// lock that guards the replacement, so a newer hold (with its newer timestamp)
// survives. See pgsty/silo#120 (Codex finding 1).
func TestAPIReplicaMultipartNewerHoldSurvivesCompletion(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testAPIReplicaMultipartNewerHoldSurvivesCompletion,
		makeBucketOptions: MakeBucketOptions{LockEnabled: true},
	})
}

func testAPIReplicaMultipartNewerHoldSurvivesCompletion(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	key := bytes.Repeat([]byte{0x47}, 32)
	keyMD5 := md5.Sum(key)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
	object := "mpu-lock-boundary/obj"

	// seal returns the sender's SSE-C replica seal and marker headers for the
	// addressed version, with every Object Lock header stripped so the case owns
	// the lock instruction.
	seal := func(t *testing.T, srcInfo ObjectInfo) map[string]string {
		t.Helper()
		opts, _, err := putReplicationOpts(t.Context(), "", srcInfo)
		if err != nil {
			t.Fatal(err)
		}
		opts.Internal.SourceMTime = time.Time{}
		hdrs := make(map[string]string)
		for name, values := range opts.Header() {
			if len(values) > 0 {
				hdrs[name] = values[0]
			}
		}
		hdrs[xhttp.MinIOSourceReplicationRequest] = "true"
		hdrs[xhttp.AmzBucketReplicationStatus] = "REPLICA"
		hdrs[xhttp.MinIOSourceETag] = srcInfo.ETag
		for _, name := range []string{
			xhttp.AmzObjectLockMode, xhttp.AmzObjectLockRetainUntilDate, xhttp.AmzObjectLockLegalHold,
			xhttp.MinIOSourceObjectRetentionTimestamp, xhttp.MinIOSourceObjectLegalHoldTimestamp,
		} {
			delete(hdrs, name)
		}
		return hdrs
	}
	rawOf := func(t *testing.T, versionID string) (ObjectInfo, []byte) {
		t.Helper()
		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{
			ReplicationRequest: true, VersionID: versionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		srcInfo := gr.ObjInfo
		cipher, rerr := io.ReadAll(gr)
		gr.Close()
		if rerr != nil {
			t.Fatal(rerr)
		}
		return srcInfo, cipher
	}

	// A destination SSE-C version with no lock.
	putCopyChecksumSource(t, apiRouter, credentials, bucketName, object,
		bytes.Repeat([]byte("mpu-lock-boundary-"), 64), sseHeaders)
	base, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	versionID := base.VersionID
	srcInfo, cipher := rawOf(t, versionID)

	// Initiate an SSE-C replica multipart carrying legal hold OFF stamped 09:00.
	// The destination has no lock yet, so the decision made now is OFF@09:00.
	newHdrs := seal(t, srcInfo)
	newHdrs[xhttp.AmzObjectLockLegalHold] = "OFF"
	newHdrs[xhttp.MinIOSourceObjectLegalHoldTimestamp] = objectLockTestStamp0900
	newReq, err := newTestSignedRequestV4(http.MethodPost,
		getNewMultipartURL("", bucketName, object)+"&versionId="+versionID, 0, nil,
		credentials.AccessKey, credentials.SecretKey, newHdrs)
	if err != nil {
		t.Fatal(err)
	}
	newRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(newRec, newReq)
	if newRec.Code != http.StatusOK {
		t.Fatalf("%s: replica NewMultipartUpload %d: %s", instanceType, newRec.Code, newRec.Body.String())
	}
	var init InitiateMultipartUploadResponse
	if err = xmlDecoder(newRec.Body, &init, int64(newRec.Body.Len())); err != nil {
		t.Fatal(err)
	}

	// After initiation, a newer legal hold ON@10:00 lands on the same version
	// through an independent SSE-C replica PUT retransmit.
	putHdrs := seal(t, srcInfo)
	putHdrs[xhttp.AmzObjectLockLegalHold] = "ON"
	putHdrs[xhttp.MinIOSourceObjectLegalHoldTimestamp] = objectLockTestStamp1000
	putReq, err := newTestSignedRequestV4(http.MethodPut,
		getPutObjectURL("", bucketName, object)+"?versionId="+versionID, int64(len(cipher)),
		bytes.NewReader(cipher), credentials.AccessKey, credentials.SecretKey, putHdrs)
	if err != nil {
		t.Fatal(err)
	}
	putRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("%s: interleaving replica PUT %d: %s", instanceType, putRec.Code, putRec.Body.String())
	}
	if got := readObjectLockFields(t, obj, bucketName, object, versionID); got.legalHold != "ON" {
		t.Fatalf("%s: the interleaving PUT did not set the newer ON: got %+v", instanceType, got)
	}

	// Finish the multipart upload the sender's way and prove the newer ON survives.
	partReq, err := newTestSignedRequestV4(http.MethodPut,
		getPutObjectPartURL("", bucketName, object, init.UploadID, "1"), int64(len(cipher)),
		bytes.NewReader(cipher), credentials.AccessKey, credentials.SecretKey,
		map[string]string{xhttp.MinIOSourceReplicationRequest: "true"})
	if err != nil {
		t.Fatal(err)
	}
	partRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(partRec, partReq)
	if partRec.Code != http.StatusOK {
		t.Fatalf("%s: replica PutObjectPart %d: %s", instanceType, partRec.Code, partRec.Body.String())
	}
	actualSize, err := srcInfo.GetActualSize()
	if err != nil {
		t.Fatal(err)
	}
	body, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{
		{PartNumber: 1, ETag: canonicalizeETag(partRec.Header()[xhttp.ETag][0])},
	}})
	if err != nil {
		t.Fatal(err)
	}
	completeReq, err := newTestSignedRequestV4(http.MethodPost,
		getCompleteMultipartUploadURL("", bucketName, object, init.UploadID), int64(len(body)),
		bytes.NewReader(body), credentials.AccessKey, credentials.SecretKey, map[string]string{
			xhttp.MinIOSourceReplicationRequest:    "true",
			xhttp.MinIOSourceMTime:                 srcInfo.ModTime.Format(time.RFC3339Nano),
			xhttp.MinIOSourceETag:                  srcInfo.ETag,
			xhttp.MinIOReplicationActualObjectSize: strconv.FormatInt(actualSize, 10),
		})
	if err != nil {
		t.Fatal(err)
	}
	completeRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(completeRec, completeReq)
	if completeRec.Code != http.StatusOK {
		t.Fatalf("%s: replica CompleteMultipartUpload %d: %s", instanceType, completeRec.Code, completeRec.Body.String())
	}

	// The completion re-ordered the carried OFF@09:00 against the ON@10:00 that
	// reached the version after initiation: the newer hold and its timestamp win.
	want := objectLockFields{legalHold: "ON", legalHoldStamp: objectLockTestStamp1000}
	if got := readObjectLockFields(t, obj, bucketName, object, versionID); got != want {
		t.Fatalf("%s: a newer legal hold that arrived after initiation was rolled back at completion: got %+v, want %+v",
			instanceType, got, want)
	}
}

// TestReplicaPutObjectLockReconcileUnderWriteLock exercises the PUT counterpart
// of the multipart reconcile: a replica full write reaches the object layer
// carrying the Object Lock its handler resolved, but the addressed version has
// since taken a newer lock update. PutObject must re-order the incoming lock
// against the version read under the write lock, so the newer stored value is
// kept. Driving the object layer directly stands in for the handler-read /
// backend-commit interleave without a timing race. See pgsty/silo#120.
func TestReplicaPutObjectLockReconcileUnderWriteLock(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testReplicaPutObjectLockReconcileUnderWriteLock,
		makeBucketOptions: MakeBucketOptions{LockEnabled: true},
	})
}

func testReplicaPutObjectLockReconcileUnderWriteLock(obj ObjectLayer, instanceType, bucketName string,
	_ http.Handler, _ auth.Credentials, t *testing.T,
) {
	ctx := t.Context()

	seedVersion := func(t *testing.T, object string, meta map[string]string) string {
		t.Helper()
		info, err := obj.PutObject(ctx, bucketName, object,
			mustGetPutObjReader(t, bytes.NewReader([]byte("data")), 4, "", ""),
			ObjectOptions{Versioned: true, UserDefined: meta})
		if err != nil {
			t.Fatal(err)
		}
		return info.VersionID
	}
	// replicaWrite overwrites the addressed version the way a replica retransmit
	// reaches the object layer, with the in-lock reconcile enabled.
	replicaWrite := func(t *testing.T, object, versionID string, meta map[string]string) {
		t.Helper()
		_, err := obj.PutObject(ctx, bucketName, object,
			mustGetPutObjReader(t, bytes.NewReader([]byte("data")), 4, "", ""),
			ObjectOptions{Versioned: true, VersionID: versionID, ReplicaLockReconcile: true, UserDefined: meta})
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Run("older-legal-hold-off-does-not-clear-newer-on", func(t *testing.T) {
		object := "reconcile/put-legal-hold"
		versionID := seedVersion(t, object, map[string]string{
			strings.ToLower(xhttp.AmzObjectLockLegalHold):              "ON",
			ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: objectLockTestStamp1000,
		})
		replicaWrite(t, object, versionID, map[string]string{
			strings.ToLower(xhttp.AmzObjectLockLegalHold):              "OFF",
			ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: objectLockTestStamp0900,
		})
		want := objectLockFields{legalHold: "ON", legalHoldStamp: objectLockTestStamp1000}
		if got := readObjectLockFields(t, obj, bucketName, object, versionID); got != want {
			t.Fatalf("%s: in-lock reconcile let an older OFF overwrite the newer stored ON: got %+v, want %+v",
				instanceType, got, want)
		}
	})

	t.Run("stale-retention-does-not-overwrite-newer", func(t *testing.T) {
		object := "reconcile/put-retention"
		versionID := seedVersion(t, object, map[string]string{
			strings.ToLower(xhttp.AmzObjectLockMode):                   "GOVERNANCE",
			strings.ToLower(xhttp.AmzObjectLockRetainUntilDate):        retransmitRetainUntilNewer,
			ReservedMetadataPrefixLower + ObjectLockRetentionTimestamp: objectLockTestStamp1000,
		})
		replicaWrite(t, object, versionID, map[string]string{
			strings.ToLower(xhttp.AmzObjectLockMode):                   "GOVERNANCE",
			strings.ToLower(xhttp.AmzObjectLockRetainUntilDate):        retransmitRetainUntilStale,
			ReservedMetadataPrefixLower + ObjectLockRetentionTimestamp: objectLockTestStamp0900,
		})
		want := objectLockFields{
			mode: "GOVERNANCE", retainUntil: retransmitRetainUntilNewer, retentionStamp: objectLockTestStamp1000,
		}
		if got := readObjectLockFields(t, obj, bucketName, object, versionID); got != want {
			t.Fatalf("%s: in-lock reconcile let a stale retention overwrite the newer stored one: got %+v, want %+v",
				instanceType, got, want)
		}
	})

	t.Run("newer-incoming-hold-applies", func(t *testing.T) {
		object := "reconcile/put-newer-applies"
		versionID := seedVersion(t, object, map[string]string{
			strings.ToLower(xhttp.AmzObjectLockLegalHold):              "OFF",
			ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: objectLockTestStamp0900,
		})
		replicaWrite(t, object, versionID, map[string]string{
			strings.ToLower(xhttp.AmzObjectLockLegalHold):              "ON",
			ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: objectLockTestStamp1000,
		})
		want := objectLockFields{legalHold: "ON", legalHoldStamp: objectLockTestStamp1000}
		if got := readObjectLockFields(t, obj, bucketName, object, versionID); got != want {
			t.Fatalf("%s: in-lock reconcile did not apply the newer incoming hold: got %+v, want %+v",
				instanceType, got, want)
		}
	})

	t.Run("pre-upgrade-shape-on-absent-version-is-preserved", func(t *testing.T) {
		// A pre-upgrade upload persisted validated lock values WITHOUT their
		// ordering timestamps. Completing it while the destination version is
		// absent must keep those values: there is nothing to order against, so the
		// reconcile is skipped rather than deleting the accepted lock. The same
		// not-found handling guards CompleteMultipartUpload.
		object := "reconcile/put-absent-version"
		absentVersion := mustGetUUID()
		_, err := obj.PutObject(ctx, bucketName, object,
			mustGetPutObjReader(t, bytes.NewReader([]byte("data")), 4, "", ""),
			ObjectOptions{Versioned: true, VersionID: absentVersion, ReplicaLockReconcile: true, UserDefined: map[string]string{
				strings.ToLower(xhttp.AmzObjectLockMode):            "GOVERNANCE",
				strings.ToLower(xhttp.AmzObjectLockRetainUntilDate): retransmitRetainUntilNewer,
				strings.ToLower(xhttp.AmzObjectLockLegalHold):       "ON",
			}})
		if err != nil {
			t.Fatal(err)
		}
		want := objectLockFields{mode: "GOVERNANCE", retainUntil: retransmitRetainUntilNewer, legalHold: "ON"}
		if got := readObjectLockFields(t, obj, bucketName, object, absentVersion); got != want {
			t.Fatalf("%s: a pre-upgrade lock (no ordering timestamps) on an absent version was stripped: got %+v, want %+v",
				instanceType, got, want)
		}
	})
}

// TestReplicaLockReconcileNullVersion covers the null version, which persisted
// upload metadata records as an empty VersionID. The completion reconcile must
// order the incoming lock against the null version's own stored state -- looked
// up as the null version, not the latest -- so a retransmit addressing the null
// version cannot be reconciled against an unrelated UUID version, and a null
// version absent while a UUID version exists is not mistaken for present. Single
// erasure set. See pgsty/silo#120.
func TestReplicaLockReconcileNullVersion(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testReplicaLockReconcileNullVersion,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true},
	})
}

func testReplicaLockReconcileNullVersion(obj ObjectLayer, instanceType, bucketName string,
	_ http.Handler, _ auth.Credentials, t *testing.T,
) {
	ctx := t.Context()
	// A protected retransmit must preserve both the source ciphertext and
	// its seal. Generate it once for the stored null version and its retry.
	var ciphertext bytes.Buffer
	if _, err := sio.Encrypt(&ciphertext, bytes.NewReader([]byte("data")), sio.Config{Key: bytes.Repeat([]byte{1}, 32)}); err != nil {
		t.Fatal(err)
	}

	// completeNullMPU runs an SSE-C replica multipart upload addressing the null
	// version (VersionSuspended) carrying uploadLock, through the reconcile.
	completeNullMPU := func(t *testing.T, object string, uploadLock map[string]string) {
		t.Helper()
		meta := map[string]string{crypto.MetaSealedKeySSEC: "dummy-sealed-key"}
		maps.Copy(meta, uploadLock)
		res, err := obj.NewMultipartUpload(ctx, bucketName, object, ObjectOptions{VersionSuspended: true, UserDefined: meta})
		if err != nil {
			t.Fatal(err)
		}
		part, err := obj.PutObjectPart(ctx, bucketName, object, res.UploadID, 1,
			mustGetPutObjReader(t, bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len()), "", ""), ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := obj.CompleteMultipartUpload(ctx, bucketName, object, res.UploadID,
			[]CompletePart{{PartNumber: 1, ETag: part.ETag}},
			ObjectOptions{VersionSuspended: true, ReplicaLockReconcile: true}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("null-and-uuid-present-reconciles-the-null-version", func(t *testing.T) {
		object := "reconcile/null-vs-uuid"
		// The null version holds a newer legal hold ON@10:00.
		if _, err := obj.PutObject(ctx, bucketName, object,
			mustGetPutObjReader(t, bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len()), "", ""),
			ObjectOptions{VersionSuspended: true, MTime: time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC), UserDefined: map[string]string{
				crypto.MetaSealedKeySSEC:                                   "dummy-sealed-key",
				strings.ToLower(xhttp.AmzObjectLockLegalHold):              "ON",
				ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: objectLockTestStamp1000,
			}}); err != nil {
			t.Fatal(err)
		}
		// A later UUID version holds an unrelated OFF@11:00 and is the latest.
		uuidInfo, err := obj.PutObject(ctx, bucketName, object,
			mustGetPutObjReader(t, bytes.NewReader([]byte("data")), 4, "", ""),
			ObjectOptions{Versioned: true, MTime: time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC), UserDefined: map[string]string{
				strings.ToLower(xhttp.AmzObjectLockLegalHold):              "OFF",
				ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: objectLockTestStamp1100,
			}})
		if err != nil {
			t.Fatal(err)
		}

		// A null-version SSE-C retransmit carrying an older OFF@09:00.
		completeNullMPU(t, object, map[string]string{
			strings.ToLower(xhttp.AmzObjectLockLegalHold):              "OFF",
			ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: objectLockTestStamp0900,
		})

		// The null version keeps its own newer ON@10:00; the UUID is untouched.
		wantNull := objectLockFields{legalHold: "ON", legalHoldStamp: objectLockTestStamp1000}
		if got := readObjectLockFields(t, obj, bucketName, object, nullVersionID); got != wantNull {
			t.Fatalf("%s: null-version completion reconciled against the wrong version: got %+v, want %+v", instanceType, got, wantNull)
		}
		wantUUID := objectLockFields{legalHold: "OFF", legalHoldStamp: objectLockTestStamp1100}
		if got := readObjectLockFields(t, obj, bucketName, object, uuidInfo.VersionID); got != wantUUID {
			t.Fatalf("%s: the UUID version was changed by a null-version completion: got %+v, want %+v", instanceType, got, wantUUID)
		}
	})

	t.Run("absent-null-with-uuid-keeps-accepted-lock", func(t *testing.T) {
		object := "reconcile/null-absent"
		// Only a UUID version exists; there is no null version.
		if _, err := obj.PutObject(ctx, bucketName, object,
			mustGetPutObjReader(t, bytes.NewReader([]byte("data")), 4, "", ""),
			ObjectOptions{Versioned: true, MTime: time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC), UserDefined: map[string]string{
				strings.ToLower(xhttp.AmzObjectLockLegalHold):              "OFF",
				ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: objectLockTestStamp1100,
			}}); err != nil {
			t.Fatal(err)
		}

		// A null-version retransmit with its own validated legal hold ON. The null
		// version does not exist, so the write must keep its accepted lock rather
		// than order against the unrelated UUID version.
		completeNullMPU(t, object, map[string]string{
			strings.ToLower(xhttp.AmzObjectLockLegalHold): "ON",
		})
		if got := readObjectLockFields(t, obj, bucketName, object, nullVersionID); got.legalHold != "ON" {
			t.Fatalf("%s: an absent null version was reconciled against the UUID version: got %+v", instanceType, got)
		}
	})
}
