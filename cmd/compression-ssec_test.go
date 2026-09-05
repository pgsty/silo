// Copyright (c) 2015-2026 MinIO, Inc.
// Copyright (c) 2026 PGSTY
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/klauspost/compress/s2"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

// disableCompression turns the global compression config off and returns a
// restore func. It is the replication destination that applies no transform of
// its own; setCopyChecksumCompression covers the enabled cases.
func disableCompression() func() {
	globalCompressConfigMu.Lock()
	previous := globalCompressConfig
	globalCompressConfig.Enabled = false
	globalCompressConfigMu.Unlock()

	return func() {
		globalCompressConfigMu.Lock()
		globalCompressConfig = previous
		globalCompressConfigMu.Unlock()
	}
}

// ssecTestHeaders builds the customer key headers for a key made of the given
// repeated byte.
func ssecTestHeaders(b byte) map[string]string {
	key := bytes.Repeat([]byte{b}, 32)
	keyMD5 := md5.Sum(key)
	return map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
}

// assertStoredSSECUncompressed requires the stored object to be SSE-C sealed
// and to carry no compression marker, so that "not compressed" is never
// reported for an object that is not encrypted either.
func assertStoredSSECUncompressed(t *testing.T, obj ObjectLayer, bucketName, object string) ObjectInfo {
	t.Helper()
	info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, sealed := info.UserDefined[crypto.MetaSealedKeySSEC]; !sealed {
		t.Fatalf("%s is not SSE-C sealed, the fixture proves nothing (userDefined=%v)", object, info.UserDefined)
	}
	if marker, compressed := info.UserDefined[ReservedMetadataPrefix+"compression"]; compressed {
		t.Errorf("%s was stored as a compressed SSE-C object (compression=%q); such an object cannot be replicated",
			object, marker)
	}
	return info
}

// assertSSECPlaintext GETs an SSE-C object with its customer key and requires
// the body to equal the plaintext.
func assertSSECPlaintext(t *testing.T, apiRouter http.Handler, credentials auth.Credentials,
	bucketName, object string, sseHeaders map[string]string, want []byte,
) {
	t.Helper()
	req, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	apiRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status %d: %s", object, rec.Code, rec.Body.String())
	}
	if bytes.Equal(rec.Body.Bytes(), want) {
		return
	}
	body := rec.Body.Bytes()
	head := body
	if len(head) > 16 {
		head = head[:16]
	}
	t.Errorf("GET %s returned %d bytes, want the %d byte plaintext; first bytes % x",
		object, len(body), len(want), head)
	// Name the failure mode: a body that s2-decodes to the plaintext is the raw
	// S2 stream of a compressed source shipped without its compression marker.
	if decoded, derr := io.ReadAll(s2.NewReader(bytes.NewReader(body))); derr == nil && bytes.Equal(decoded, want) {
		t.Errorf("the returned body is the raw S2 stream: s2-decoding it yields the %d byte plaintext", len(want))
	}
}

// TestAPISSECCompressionReplicaStaysReadable replicates an SSE-C object written
// with compression enabled and allow_encryption=on, and requires the replica to
// read back as the source plaintext.
//
// The source object is read the way the replication worker reads it
// (ReplicationRequest, hence NoDecryption), its wire headers come from the
// production option builder putReplicationOpts, and the replica is written the
// way a destination that applies no transform of its own stores it: compression
// off and no default encryption.
//
// Before the SSE-C compression exclusion the source was stored as
// encrypt(s2(plaintext)) while putReplicationOpts dropped
// X-Minio-Internal-compression, so the replica decrypted to an S2 stream and a
// correct-key GET returned HTTP 200 with the wrong body.
func TestAPISSECCompressionReplicaStaysReadable(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPISSECCompressionReplicaStaysReadable,
	})
}

func testAPISSECCompressionReplicaStaysReadable(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject","s3:GetObject","s3:ReplicateObject"`)
	sseHeaders := ssecTestHeaders(0x42)
	// Highly compressible and comfortably above minCompressibleSize (4096).
	data := bytes.Repeat([]byte("silo compressed ssec replication payload "), 8192)

	t.Run(instanceType+"/single-put", func(t *testing.T) {
		object := "replication/ssec-single.txt"

		// --- Source side: compression ON with allow_encryption ON. ---
		restore := setCopyChecksumCompression(true)
		srcReq, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, object),
			int64(len(data)), bytes.NewReader(data), credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			restore()
			t.Fatal(err)
		}
		srcRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(srcRec, srcReq)
		if srcRec.Code != http.StatusOK {
			restore()
			t.Fatalf("source PUT status %d: %s", srcRec.Code, srcRec.Body.String())
		}
		sourceInfo := assertStoredSSECUncompressed(t, obj, bucketName, object)
		t.Logf("source: stored size=%d compression=%q plaintext=%d", sourceInfo.Size,
			sourceInfo.UserDefined[ReservedMetadataPrefix+"compression"], len(data))

		// The replication worker's read: raw stored bytes, no decryption.
		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{},
			ObjectOptions{ReplicationRequest: true})
		if err != nil {
			restore()
			t.Fatal(err)
		}
		sourceInfo = gr.ObjInfo
		raw, err := io.ReadAll(gr)
		gr.Close()
		if err != nil {
			restore()
			t.Fatal(err)
		}

		replicationOpts, isMP, err := putReplicationOpts(t.Context(), "", sourceInfo)
		if err != nil {
			restore()
			t.Fatalf("putReplicationOpts rejected the source: %v", err)
		}
		if isMP {
			restore()
			t.Fatal("single PUT source classified as multipart")
		}
		headers := map[string]string{}
		for name, values := range replicationOpts.Header() {
			if len(values) > 0 {
				headers[name] = values[0]
			}
		}
		restore()

		// --- Destination side: NO compression, NO default encryption. ---
		restoreDst := disableCompression()
		defer restoreDst()

		replReq, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, object),
			int64(len(raw)), bytes.NewReader(raw), replicator.AccessKey, replicator.SecretKey, headers)
		if err != nil {
			t.Fatal(err)
		}
		replRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(replRec, replReq)
		if replRec.Code != http.StatusOK {
			t.Fatalf("replica PUT status %d: %s", replRec.Code, replRec.Body.String())
		}

		info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("replica: stored size=%d compression=%q actual-size=%q", info.Size,
			info.UserDefined[ReservedMetadataPrefix+"compression"],
			info.UserDefined[ReservedMetadataPrefix+"actual-size"])
		assertSSECPlaintext(t, apiRouter, credentials, bucketName, object, sseHeaders, data)
	})

	t.Run(instanceType+"/multipart", func(t *testing.T) {
		object := "replication/ssec-mpu.txt"

		restore := setCopyChecksumCompression(true)
		newReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
			0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			restore()
			t.Fatal(err)
		}
		newRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(newRec, newReq)
		if newRec.Code != http.StatusOK {
			restore()
			t.Fatalf("source NewMultipart status %d: %s", newRec.Code, newRec.Body.String())
		}
		var sourceInit InitiateMultipartUploadResponse
		if err = xmlDecoder(newRec.Body, &sourceInit, int64(newRec.Body.Len())); err != nil {
			restore()
			t.Fatal(err)
		}
		partReq, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectPartURL("", bucketName, object, sourceInit.UploadID, "1"),
			int64(len(data)), bytes.NewReader(data), credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			restore()
			t.Fatal(err)
		}
		partRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(partRec, partReq)
		if partRec.Code != http.StatusOK {
			restore()
			t.Fatalf("source PutPart status %d: %s", partRec.Code, partRec.Body.String())
		}
		completeBody, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{
			{PartNumber: 1, ETag: canonicalizeETag(partRec.Header()[xhttp.ETag][0])},
		}})
		if err != nil {
			restore()
			t.Fatal(err)
		}
		completeReq, err := newTestSignedRequestV4(http.MethodPost,
			getCompleteMultipartUploadURL("", bucketName, object, sourceInit.UploadID),
			int64(len(completeBody)), bytes.NewReader(completeBody), credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			restore()
			t.Fatal(err)
		}
		completeRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(completeRec, completeReq)
		if completeRec.Code != http.StatusOK {
			restore()
			t.Fatalf("source Complete status %d: %s", completeRec.Code, completeRec.Body.String())
		}
		assertStoredSSECUncompressed(t, obj, bucketName, object)

		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{},
			ObjectOptions{ReplicationRequest: true})
		if err != nil {
			restore()
			t.Fatal(err)
		}
		sourceInfo := gr.ObjInfo
		rawPart, err := io.ReadAll(gr)
		gr.Close()
		if err != nil {
			restore()
			t.Fatal(err)
		}
		actualSize, err := sourceInfo.GetActualSize()
		if err != nil {
			restore()
			t.Fatal(err)
		}
		t.Logf("source mpu: stored size=%d actual-size=%d rawRead=%d plaintext=%d compression=%q",
			sourceInfo.Size, actualSize, len(rawPart), len(data),
			sourceInfo.UserDefined[ReservedMetadataPrefix+"compression"])

		replicationOpts, isMP, err := putReplicationOpts(t.Context(), "", sourceInfo)
		if err != nil {
			restore()
			t.Fatalf("putReplicationOpts rejected the source: %v", err)
		}
		if !isMP {
			restore()
			t.Fatal("SSE-C multipart source not recognized as multipart")
		}
		replicationOpts.Internal.SourceMTime = time.Time{}
		headers := map[string]string{}
		for name, values := range replicationOpts.Header() {
			if len(values) > 0 {
				headers[name] = values[0]
			}
		}
		restore()

		// --- Destination: no compression, no default encryption. ---
		restoreDst := disableCompression()
		defer restoreDst()

		replNewReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
			0, nil, replicator.AccessKey, replicator.SecretKey, headers)
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
		replPartReq, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectPartURL("", bucketName, object, replicaInit.UploadID, "1"),
			int64(len(rawPart)), bytes.NewReader(rawPart), replicator.AccessKey, replicator.SecretKey,
			map[string]string{xhttp.MinIOSourceReplicationRequest: "true"})
		if err != nil {
			t.Fatal(err)
		}
		replPartRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(replPartRec, replPartReq)
		if replPartRec.Code != http.StatusOK {
			t.Fatalf("replica PutPart status %d: %s", replPartRec.Code, replPartRec.Body.String())
		}
		replCompleteBody, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{
			{PartNumber: 1, ETag: canonicalizeETag(replPartRec.Header()[xhttp.ETag][0])},
		}})
		if err != nil {
			t.Fatal(err)
		}
		replCompleteReq, err := newTestSignedRequestV4(http.MethodPost,
			getCompleteMultipartUploadURL("", bucketName, object, replicaInit.UploadID),
			int64(len(replCompleteBody)), bytes.NewReader(replCompleteBody), replicator.AccessKey, replicator.SecretKey,
			map[string]string{
				xhttp.MinIOSourceReplicationRequest:    "true",
				xhttp.MinIOSourceMTime:                 sourceInfo.ModTime.Format(time.RFC3339Nano),
				xhttp.MinIOSourceETag:                  sourceInfo.ETag,
				xhttp.MinIOReplicationActualObjectSize: strconv.FormatInt(actualSize, 10),
			})
		if err != nil {
			t.Fatal(err)
		}
		replCompleteRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(replCompleteRec, replCompleteReq)
		if replCompleteRec.Code != http.StatusOK {
			t.Fatalf("replica Complete status %d: %s", replCompleteRec.Code, replCompleteRec.Body.String())
		}

		info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		reportedActual, aerr := info.GetActualSize()
		t.Logf("replica mpu: stored size=%d compression=%q actual-size=%q GetActualSize=%d(err=%v)",
			info.Size, info.UserDefined[ReservedMetadataPrefix+"compression"],
			info.UserDefined[ReservedMetadataPrefix+"actual-size"], reportedActual, aerr)
		assertSSECPlaintext(t, apiRouter, credentials, bucketName, object, sseHeaders, data)
	})
}

// TestAPISSECCompressionProducerMatrix pins the scope of the exclusion across
// the PutObject and NewMultipartUpload producers: SSE-C is never compressed,
// while plaintext, SSE-S3 and SSE-KMS keep following allow_encryption.
func TestAPISSECCompressionProducerMatrix(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPISSECCompressionProducerMatrix,
	})
}

func testAPISSECCompressionProducerMatrix(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	ssecHeaders := ssecTestHeaders(0x5a)
	sseS3Headers := map[string]string{xhttp.AmzServerSideEncryption: xhttp.AmzEncryptionAES}
	sseKMSHeaders := map[string]string{
		xhttp.AmzServerSideEncryption:      xhttp.AmzEncryptionKMS,
		xhttp.AmzServerSideEncryptionKmsID: "compressed-ssec-producer-matrix",
	}
	previousKMS := GlobalKMS
	GlobalKMS = kms.NewStub("compressed-ssec-producer-matrix")
	defer func() { GlobalKMS = previousKMS }()

	big := bytes.Repeat([]byte("silo producer matrix payload "), 8192)
	small := bytes.Repeat([]byte("s"), 1024) // below minCompressibleSize

	for _, tc := range []struct {
		name           string
		allowEncrypted bool
		headers        map[string]string
		body           []byte
		wantCompressed bool
	}{
		// SSE-C is excluded from compression in both configurations, because the
		// replication wire cannot carry the compression state.
		{"ssec+allow_encryption-on+large", true, ssecHeaders, big, false},
		{"ssec+allow_encryption-on+small", true, ssecHeaders, small, false},
		{"ssec+allow_encryption-off+large", false, ssecHeaders, big, false},
		// Plaintext still compresses in both configurations.
		{"plain+allow_encryption-on+large", true, nil, big, true},
		{"plain+allow_encryption-off+large", false, nil, big, true},
		// SSE-S3 and SSE-KMS are the reason allow_encryption exists: the server
		// owns the key, so the source decompresses before replicating.
		{"sse-s3+allow_encryption-on+large", true, sseS3Headers, big, true},
		{"sse-s3+allow_encryption-off+large", false, sseS3Headers, big, false},
		{"sse-kms+allow_encryption-on+large", true, sseKMSHeaders, big, true},
		{"sse-kms+allow_encryption-off+large", false, sseKMSHeaders, big, false},
	} {
		t.Run(instanceType+"/put/"+tc.name, func(t *testing.T) {
			restore := setCopyChecksumCompression(tc.allowEncrypted)
			defer restore()
			object := "producer/" + tc.name + ".txt"
			req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, object),
				int64(len(tc.body)), bytes.NewReader(tc.body), credentials.AccessKey, credentials.SecretKey, tc.headers)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			apiRouter.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("PUT status %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			_, compressed := info.UserDefined[ReservedMetadataPrefix+"compression"]
			if compressed != tc.wantCompressed {
				t.Errorf("compressed=%v, want %v (userDefined=%v)", compressed, tc.wantCompressed, info.UserDefined)
			}
		})
	}

	// NewMultipartUpload has no size gate, so the exclusion turns on the SSE-C
	// and allow_encryption combination alone.
	for _, tc := range []struct {
		name           string
		allowEncrypted bool
		headers        map[string]string
		wantCompressed bool
	}{
		{"ssec+allow_encryption-on", true, ssecHeaders, false},
		{"ssec+allow_encryption-off", false, ssecHeaders, false},
		{"plain+allow_encryption-on", true, nil, true},
	} {
		t.Run(instanceType+"/mpu/"+tc.name, func(t *testing.T) {
			restore := setCopyChecksumCompression(tc.allowEncrypted)
			defer restore()
			object := "producer/mpu-" + tc.name + ".txt"
			req, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
				0, nil, credentials.AccessKey, credentials.SecretKey, tc.headers)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			apiRouter.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("NewMultipartUpload status %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			var init InitiateMultipartUploadResponse
			if err = xmlDecoder(rec.Body, &init, int64(rec.Body.Len())); err != nil {
				t.Fatal(err)
			}
			mi, err := obj.GetMultipartInfo(t.Context(), bucketName, object, init.UploadID, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			_, compressed := mi.UserDefined[ReservedMetadataPrefix+"compression"]
			if compressed != tc.wantCompressed {
				t.Errorf("upload compressed=%v, want %v", compressed, tc.wantCompressed)
			}
		})
	}
}

// TestAPISSECCompressionSkippedOnCopyObject covers the third producer:
// CopyObjectHandler decides compression before it encrypts, so a copy with a
// destination customer key and allow_encryption=on used to store a compressed
// SSE-C object from a plaintext source. It also covers the reverse direction,
// where only copy-source customer headers are present and compression must
// still apply.
func TestAPISSECCompressionSkippedOnCopyObject(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPISSECCompressionSkippedOnCopyObject,
		endpoints:  []string{"CopyObject", "PutObject", "GetObject"},
	})
}

func testAPISSECCompressionSkippedOnCopyObject(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	ssecHeaders := ssecTestHeaders(0x7c)
	data := bytes.Repeat([]byte("copy object compressed ssec payload "), 8192)

	restore := setCopyChecksumCompression(true)
	defer restore()

	// An unencrypted source, stored compressed because compression is on. Only
	// the copy adds encryption, so only the copy can change the decision.
	src := "copysrc/plain.txt"
	req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, src),
		int64(len(data)), bytes.NewReader(data), credentials.AccessKey, credentials.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	apiRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("source PUT status %d: %s", rec.Code, rec.Body.String())
	}

	dst := "copydst/ssec.txt"
	copyHeaders := map[string]string{"X-Amz-Copy-Source": SlashSeparator + bucketName + SlashSeparator + src}
	for k, v := range ssecHeaders {
		copyHeaders[k] = v
	}
	copyReq, err := newTestSignedRequestV4(http.MethodPut, getCopyObjectURL("", bucketName, dst),
		0, nil, credentials.AccessKey, credentials.SecretKey, copyHeaders)
	if err != nil {
		t.Fatal(err)
	}
	copyRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(copyRec, copyReq)
	if copyRec.Code != http.StatusOK {
		t.Fatalf("CopyObject status %d: %s", copyRec.Code, copyRec.Body.String())
	}

	assertStoredSSECUncompressed(t, obj, bucketName, dst)
	assertSSECPlaintext(t, apiRouter, credentials, bucketName, dst, ssecHeaders, data)

	// The plaintext source is untouched by the copy and stays compressed.
	srcInfo, err := obj.GetObjectInfo(t.Context(), bucketName, src, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, compressed := srcInfo.UserDefined[ReservedMetadataPrefix+"compression"]; !compressed {
		t.Errorf("the plaintext copy source lost compression (userDefined=%v)", srcInfo.UserDefined)
	}

	// The reverse direction: a copy-source customer key is not a destination
	// key, so copying the SSE-C object on to a plaintext destination still
	// compresses. crypto.SSEC.IsRequested ignores the copy-source headers.
	plain := "copydst/decrypted.txt"
	decryptHeaders := map[string]string{
		"X-Amz-Copy-Source": SlashSeparator + bucketName + SlashSeparator + dst,
		xhttp.AmzServerSideEncryptionCopyCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCopyCustomerKey:       ssecHeaders[xhttp.AmzServerSideEncryptionCustomerKey],
		xhttp.AmzServerSideEncryptionCopyCustomerKeyMD5:    ssecHeaders[xhttp.AmzServerSideEncryptionCustomerKeyMD5],
	}
	decryptReq, err := newTestSignedRequestV4(http.MethodPut, getCopyObjectURL("", bucketName, plain),
		0, nil, credentials.AccessKey, credentials.SecretKey, decryptHeaders)
	if err != nil {
		t.Fatal(err)
	}
	decryptRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(decryptRec, decryptReq)
	if decryptRec.Code != http.StatusOK {
		t.Fatalf("CopyObject to a plaintext destination status %d: %s", decryptRec.Code, decryptRec.Body.String())
	}
	plainInfo, err := obj.GetObjectInfo(t.Context(), bucketName, plain, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, sealed := plainInfo.UserDefined[crypto.MetaSealedKeySSEC]; sealed {
		t.Fatalf("%s is still SSE-C sealed, the fixture proves nothing", plain)
	}
	if _, compressed := plainInfo.UserDefined[ReservedMetadataPrefix+"compression"]; !compressed {
		t.Errorf("a copy carrying only copy-source SSE-C headers was not compressed (userDefined=%v)", plainInfo.UserDefined)
	}
}

// TestAPISSECCompressionSkippedOnSnowballExtract covers the fourth producer:
// PutObjectExtractHandler decides compression per entry before it encrypts, so
// a tar extract carrying customer key headers used to store every entry as a
// compressed SSE-C object.
func TestAPISSECCompressionSkippedOnSnowballExtract(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPISSECCompressionSkippedOnSnowballExtract,
	})
}

func testAPISSECCompressionSkippedOnSnowballExtract(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	entry := "extracted/entry.txt"
	payload := bytes.Repeat([]byte("snowball compressed ssec entry "), 4096)

	var body bytes.Buffer
	tw := tar.NewWriter(&body)
	if err := tw.WriteHeader(&tar.Header{Name: entry, Mode: 0o600, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	restore := setCopyChecksumCompression(true)
	defer restore()

	ssecHeaders := ssecTestHeaders(0x2d)
	headers := map[string]string{xhttp.AmzSnowballExtract: "true"}
	for k, v := range ssecHeaders {
		headers[k] = v
	}
	req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, "snowball.tar"),
		int64(body.Len()), bytes.NewReader(body.Bytes()), credentials.AccessKey, credentials.SecretKey, headers)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	apiRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("snowball extract status %d: %s", rec.Code, rec.Body.String())
	}

	assertStoredSSECUncompressed(t, obj, bucketName, entry)
	assertSSECPlaintext(t, apiRouter, credentials, bucketName, entry, ssecHeaders, payload)
}

// TestSSECBatchReplicationCannotRead is the control for the corruption path:
// batch replication reads without ReplicationRequest, so NoDecryption is never
// set and a non-empty SSE-C source fails at read time. Batch replication
// therefore cannot reach the replica shape in
// TestAPISSECCompressionReplicaStaysReadable; it cannot replicate a non-empty
// SSE-C object at all, compressed or not. A zero-byte object takes the reader
// shortcut, whose key check passes without a customer key.
func TestSSECBatchReplicationCannotRead(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testSSECBatchReplicationCannotRead,
	})
}

func testSSECBatchReplicationCannotRead(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	ssecHeaders := ssecTestHeaders(0x6b)
	data := bytes.Repeat([]byte("batch ssec payload "), 8192)
	object := "batch/ssec-plain.txt"

	restore := disableCompression()
	defer restore()

	req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, object),
		int64(len(data)), bytes.NewReader(data), credentials.AccessKey, credentials.SecretKey, ssecHeaders)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	apiRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("source PUT status %d: %s", rec.Code, rec.Body.String())
	}

	// The read shape used by BatchJobReplicateV1.ReplicateToTarget and
	// writeAsArchive: no ReplicationRequest, so NoDecryption is never set.
	gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{})
	if err == nil {
		gr.Close()
		t.Fatal("batch-shaped read of an SSE-C object unexpectedly succeeded")
	}
	t.Logf("batch-shaped read of an SSE-C object fails as expected: %v", err)

	// Control: the replication worker's read shape succeeds and yields ciphertext.
	gr2, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{},
		ObjectOptions{ReplicationRequest: true})
	if err != nil {
		t.Fatalf("replication-shaped read failed: %v", err)
	}
	raw, err := io.ReadAll(gr2)
	gr2.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, data) {
		t.Fatal("replication-shaped read returned plaintext")
	}
	t.Logf("replication-shaped read returns %d bytes of ciphertext (plaintext %d)", len(raw), len(data))
}
