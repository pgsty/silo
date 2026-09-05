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
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

// TestAPISSECReplicaSkipsDestinationTransforms asserts that a validated raw
// SSE-C replica write is stored byte for byte, whatever default encryption or
// compression the destination bucket has configured, and that the exemption is
// gated on replication trust rather than on the headers alone.
func TestAPISSECReplicaSkipsDestinationTransforms(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPISSECReplicaSkipsDestinationTransforms,
	})
}

func testAPISSECReplicaSkipsDestinationTransforms(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject","s3:GetObject","s3:ReplicateObject"`)
	putOnly := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject","s3:GetObject"`)

	key := bytes.Repeat([]byte{0x42}, 32)
	keyMD5 := md5.Sum(key)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
	data := bytes.Repeat([]byte("silo ssec replica payload "), 8192) // > minCompressibleSize

	// makeSource writes a real client SSE-C object, then reads it back the way
	// the replication worker does and builds the replica wire headers from the
	// production option builder. The SSE-C sealed key is bound to bucket and
	// object path, so a replica is only unsealable at the same key: the caller
	// writes the raw bytes back over the same name, as a real destination does.
	makeSource := func(t *testing.T, object string) ([]byte, map[string]string, ObjectInfo) {
		t.Helper()
		srcReq, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, object),
			int64(len(data)), bytes.NewReader(data), credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		srcRec := httptest.NewRecorder()
		apiRouter.ServeHTTP(srcRec, srcReq)
		if srcRec.Code != http.StatusOK {
			t.Fatalf("%s: source PUT status %d: %s", instanceType, srcRec.Code, srcRec.Body.String())
		}

		gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{ReplicationRequest: true})
		if err != nil {
			t.Fatal(err)
		}
		sourceInfo := gr.ObjInfo
		raw, err := io.ReadAll(gr)
		gr.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 || bytes.Equal(raw, data) {
			t.Fatal("source replication read did not return encrypted bytes")
		}
		if sourceInfo.UserDefined[ReservedMetadataPrefix+"compression"] != "" {
			t.Fatal("source SSE-C object was compressed; the fixture is not a raw SSE-C source")
		}
		replicationOpts, isMP, err := putReplicationOpts(t.Context(), "", sourceInfo)
		if err != nil {
			t.Fatal(err)
		}
		if isMP {
			t.Fatal("single PUT SSE-C source was classified as multipart")
		}
		headers := make(map[string]string)
		for name, values := range replicationOpts.Header() {
			if len(values) > 0 {
				headers[name] = values[0]
			}
		}
		if headers["X-Minio-Replication-Server-Side-Encryption-Sealed-Key"] == "" {
			t.Fatal("replication options did not carry the source SSE-C seal")
		}
		return raw, headers, sourceInfo
	}

	putReplica := func(t *testing.T, object string, raw []byte, creds auth.Credentials, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, object),
			int64(len(raw)), bytes.NewReader(raw), creds.AccessKey, creds.SecretKey, headers)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return rec
	}

	withDefaultSSE := func(t *testing.T) func() {
		t.Helper()
		previousKMS := GlobalKMS
		GlobalKMS = kms.NewStub("ssec-replica-default-encryption")
		sseXML := []byte(`<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)
		if _, err := globalBucketMetadataSys.Update(t.Context(), bucketName, bucketSSEConfig, sseXML); err != nil {
			t.Fatalf("configure bucket encryption: %v", err)
		}
		return func() {
			if _, err := globalBucketMetadataSys.Delete(t.Context(), bucketName, bucketSSEConfig); err != nil {
				t.Fatalf("remove bucket encryption: %v", err)
			}
			GlobalKMS = previousKMS
		}
	}

	withCompression := func(t *testing.T) func() {
		t.Helper()
		globalCompressConfigMu.Lock()
		previous := globalCompressConfig
		globalCompressConfig.Enabled = true
		globalCompressConfig.Extensions = []string{".txt"}
		globalCompressConfig.MimeTypes = nil
		globalCompressConfig.AllowEncrypted = false
		globalCompressConfigMu.Unlock()
		return func() {
			globalCompressConfigMu.Lock()
			globalCompressConfig = previous
			globalCompressConfigMu.Unlock()
		}
	}

	for _, tc := range []struct {
		name         string
		setup        func(*testing.T) func()
		extraHeaders map[string]string
	}{
		{name: "default-sse-s3", setup: withDefaultSSE},
		{name: "compression", setup: withCompression},
		// A trusted peer that also sends an explicit public SSE header must
		// not re-encrypt: skipping the bucket default alone would not stop it.
		{name: "explicit-sse-header", extraHeaders: map[string]string{xhttp.AmzServerSideEncryption: xhttp.AmzEncryptionAES}},
	} {
		t.Run(instanceType+"/"+tc.name, func(t *testing.T) {
			object := "replication/ssec-" + tc.name + ".txt"
			raw, replicationHeaders, sourceInfo := makeSource(t, object)

			if tc.setup != nil {
				cleanup := tc.setup(t)
				defer cleanup()
			}
			for k, v := range tc.extraHeaders {
				replicationHeaders[k] = v
			}

			rec := putReplica(t, object, raw, replicator, replicationHeaders)
			if rec.Code != http.StatusOK {
				t.Fatalf("replica PUT status %d: %s", rec.Code, rec.Body.String())
			}

			info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{crypto.MetaSealedKeySSEC, crypto.MetaIV, crypto.MetaAlgorithm} {
				if got, want := info.UserDefined[name], sourceInfo.UserDefined[name]; got != want {
					t.Errorf("%s: replica has %q, source has %q", name, got, want)
				}
			}
			for _, name := range []string{crypto.MetaSealedKeyS3, crypto.MetaKeyID, ReservedMetadataPrefix + "compression"} {
				if v, ok := info.UserDefined[name]; ok {
					t.Errorf("replica gained destination metadata %s=%q", name, v)
				}
			}
			if info.Size != int64(len(raw)) {
				t.Errorf("replica size %d, want the source ciphertext size %d", info.Size, len(raw))
			}

			getReq, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, object),
				0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
			if err != nil {
				t.Fatal(err)
			}
			getRec := httptest.NewRecorder()
			apiRouter.ServeHTTP(getRec, getReq)
			if getRec.Code != http.StatusOK {
				t.Fatalf("GET replica status %d: %s", getRec.Code, getRec.Body.String())
			}
			if !bytes.Equal(getRec.Body.Bytes(), data) {
				t.Fatalf("replica did not decrypt to the source plaintext (got %d bytes, want %d)",
					getRec.Body.Len(), len(data))
			}
		})
	}

	// The multipart replica path shares the same two decisions at
	// NewMultipartUpload. Every later part follows the upload's stored
	// metadata, so asserting on the init is enough.
	for _, tc := range []struct {
		name  string
		setup func(*testing.T) func()
	}{
		{name: "mpu-default-sse-s3", setup: withDefaultSSE},
		{name: "mpu-compression", setup: withCompression},
	} {
		t.Run(instanceType+"/"+tc.name, func(t *testing.T) {
			object := "replication/ssec-" + tc.name + ".txt"
			_, replicationHeaders, sourceInfo := makeSource(t, object)

			cleanup := tc.setup(t)
			defer cleanup()

			req, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
				0, nil, replicator.AccessKey, replicator.SecretKey, replicationHeaders)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			apiRouter.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("replica NewMultipart status %d: %s", rec.Code, rec.Body.String())
			}
			var init InitiateMultipartUploadResponse
			if err = xmlDecoder(rec.Body, &init, int64(rec.Body.Len())); err != nil {
				t.Fatal(err)
			}
			mi, err := obj.GetMultipartInfo(t.Context(), bucketName, object, init.UploadID, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{crypto.MetaSealedKeySSEC, crypto.MetaIV, crypto.MetaAlgorithm} {
				if got, want := mi.UserDefined[name], sourceInfo.UserDefined[name]; got != want {
					t.Errorf("%s: replica upload has %q, source has %q", name, got, want)
				}
			}
			for _, name := range []string{crypto.MetaSealedKeyS3, crypto.MetaKeyID, ReservedMetadataPrefix + "compression"} {
				if v, ok := mi.UserDefined[name]; ok {
					t.Errorf("replica upload gained destination metadata %s=%q", name, v)
				}
			}
		})
	}

	// Control: the same seal headers from a principal without
	// s3:ReplicateObject must not buy the exemption. The headers are stripped
	// and the object is transformed exactly as an ordinary upload would be.
	t.Run(instanceType+"/untrusted-is-still-transformed", func(t *testing.T) {
		object := "replication/ssec-untrusted.txt"
		raw, replicationHeaders, _ := makeSource(t, object)

		cleanup := withCompression(t)
		defer cleanup()

		untrusted := make(map[string]string, len(replicationHeaders))
		for k, v := range replicationHeaders {
			untrusted[k] = v
		}
		delete(untrusted, xhttp.AmzBucketReplicationStatus)

		rec := putReplica(t, object, raw, putOnly, untrusted)
		if rec.Code != http.StatusOK {
			t.Fatalf("untrusted PUT status %d: %s", rec.Code, rec.Body.String())
		}
		info, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := info.UserDefined[crypto.MetaSealedKeySSEC]; ok {
			t.Error("untrusted writer smuggled an SSE-C seal into stored metadata")
		}
		if _, ok := info.UserDefined[ReservedMetadataPrefix+"compression"]; !ok {
			t.Error("untrusted upload skipped destination compression")
		}
	})
}

// TestAPISSECMultipartReplicaRoundTripWithCompression drives a full multipart
// replica: a real SSE-C multipart source, the replica upload, its parts and
// Complete, then a GET with the customer key, all with destination compression
// enabled. Asserting on the init metadata alone would not prove that the parts
// were stored unmodified.
func TestAPISSECMultipartReplicaRoundTripWithCompression(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPISSECMultipartReplicaRoundTripWithCompression,
	})
}

func testAPISSECMultipartReplicaRoundTripWithCompression(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject","s3:GetObject","s3:ReplicateObject"`)
	key := bytes.Repeat([]byte{0x37}, 32)
	keyMD5 := md5.Sum(key)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
	data := bytes.Repeat([]byte("silo ssec multipart replica payload "), 4096)
	object := "replication/ssec-multipart-roundtrip.txt"

	// Source: a real SSE-C multipart object, so the part layout and metadata
	// are what the replication worker actually reads.
	newRec := httptest.NewRecorder()
	newReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	apiRouter.ServeHTTP(newRec, newReq)
	if newRec.Code != http.StatusOK {
		t.Fatalf("source NewMultipart status %d: %s", newRec.Code, newRec.Body.String())
	}
	var sourceInit InitiateMultipartUploadResponse
	if err = xmlDecoder(newRec.Body, &sourceInit, int64(newRec.Body.Len())); err != nil {
		t.Fatal(err)
	}
	partReq, err := newTestSignedRequestV4(http.MethodPut,
		getPutObjectPartURL("", bucketName, object, sourceInit.UploadID, "1"),
		int64(len(data)), bytes.NewReader(data), credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	partRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(partRec, partReq)
	if partRec.Code != http.StatusOK {
		t.Fatalf("source PutPart status %d: %s", partRec.Code, partRec.Body.String())
	}
	completeBody, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{
		{PartNumber: 1, ETag: canonicalizeETag(partRec.Header()[xhttp.ETag][0])},
	}})
	if err != nil {
		t.Fatal(err)
	}
	completeReq, err := newTestSignedRequestV4(http.MethodPost,
		getCompleteMultipartUploadURL("", bucketName, object, sourceInit.UploadID),
		int64(len(completeBody)), bytes.NewReader(completeBody), credentials.AccessKey, credentials.SecretKey, sseHeaders)
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

	// Destination compression on for the whole replica write.
	globalCompressConfigMu.Lock()
	previousCompress := globalCompressConfig
	globalCompressConfig.Enabled = true
	globalCompressConfig.Extensions = []string{".txt"}
	globalCompressConfig.MimeTypes = nil
	globalCompressConfig.AllowEncrypted = false
	globalCompressConfigMu.Unlock()
	defer func() {
		globalCompressConfigMu.Lock()
		globalCompressConfig = previousCompress
		globalCompressConfigMu.Unlock()
	}()

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
	mi, err := obj.GetMultipartInfo(t.Context(), bucketName, object, replicaInit.UploadID, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mi.UserDefined[ReservedMetadataPrefix+"compression"]; ok {
		t.Fatal("replica upload was marked compressed")
	}
	if _, ok := mi.UserDefined[ReservedMetadataPrefix+"Encrypted-Multipart"]; !ok {
		t.Error("replica upload lost the encrypted-multipart marker")
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
	actualSize, err := sourceInfo.GetActualSize()
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
	if v, ok := info.UserDefined[ReservedMetadataPrefix+"compression"]; ok {
		t.Errorf("replica gained destination compression %q", v)
	}

	getReq, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	getRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET replicated multipart object status %d: %s", getRec.Code, getRec.Body.String())
	}
	if !bytes.Equal(getRec.Body.Bytes(), data) {
		t.Fatalf("replicated SSE-C multipart object did not decrypt to source plaintext (got %d bytes, want %d)",
			getRec.Body.Len(), len(data))
	}
}

// TestPutReplicationOptsRejectsCompressedSSEC covers the source-side guard: a
// compressed SSE-C object cannot be represented on the replication wire, so the
// shared option builder must refuse it rather than emit a replica that decrypts
// to an S2 stream. Uncompressed SSE-C and compressed plaintext stay accepted.
func TestPutReplicationOptsRejectsCompressedSSEC(t *testing.T) {
	sealed := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 64))
	iv := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))

	newInfo := func(ssec, compressed bool) ObjectInfo {
		oi := ObjectInfo{
			Bucket:      "src",
			Name:        "obj.txt",
			VersionID:   "v1",
			Size:        1024,
			ContentType: "text/plain",
			UserDefined: map[string]string{},
		}
		if ssec {
			oi.UserDefined[crypto.MetaSealedKeySSEC] = sealed
			oi.UserDefined[crypto.MetaIV] = iv
			oi.UserDefined[crypto.MetaAlgorithm] = "DAREv2-HMAC-SHA256"
		}
		if compressed {
			oi.UserDefined[ReservedMetadataPrefix+"compression"] = compressionAlgorithmV2
			oi.UserDefined[ReservedMetadataPrefix+"actual-size"] = "2048"
		}
		return oi
	}

	for _, tc := range []struct {
		name       string
		ssec       bool
		compressed bool
		wantErr    bool
	}{
		{name: "compressed-ssec-rejected", ssec: true, compressed: true, wantErr: true},
		{name: "plain-ssec-accepted", ssec: true},
		{name: "compressed-plaintext-accepted", compressed: true},
		{name: "plain-accepted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oi := newInfo(tc.ssec, tc.compressed)
			if _, _, err := putReplicationOpts(t.Context(), "", oi); (err != nil) != tc.wantErr {
				t.Fatalf("putReplicationOpts err=%v, wantErr=%v", err, tc.wantErr)
			}
			// The batch path shares the same builder and propagates its error.
			if _, _, err := batchReplicationOpts(t.Context(), "", oi); (err != nil) != tc.wantErr {
				t.Fatalf("batchReplicationOpts err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
