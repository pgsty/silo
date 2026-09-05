// Copyright (c) 2015-2026 MinIO, Inc.
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
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
)

func TestAPICopyObjectMetadataOnlyCompression(t *testing.T) {
	defer DetectTestLeak(t)()
	for _, versioned := range []bool{false, true} {
		name := "unversioned"
		if versioned {
			name = "versioned"
		}
		t.Run(name, func(t *testing.T) {
			ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
				t:                 t,
				objAPITest:        testAPICopyObjectMetadataOnlyCompression,
				endpoints:         []string{"CopyObject", "PutObject", "GetObject"},
				makeBucketOptions: MakeBucketOptions{VersioningEnabled: versioned},
			})
		})
	}
}

func testAPICopyObjectMetadataOnlyCompression(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	data := bytes.Repeat([]byte("metadata-only-copy-plaintext-"), 64*1024)
	want := mustChecksum(t, hash.ChecksumCRC32, data)
	object := "copy-metadata/existing-checksum.txt"
	putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data,
		map[string]string{xhttp.AmzChecksumCRC32: want})
	before, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil || before.IsCompressed() {
		t.Fatalf("%s: invalid metadata-copy precondition: compressed=%v size=%d err=%v",
			instanceType, before.IsCompressed(), before.Size, err)
	}

	restoreCompression := setCopyChecksumCompression(true)
	compressionRestored := false
	defer func() {
		if !compressionRestored {
			restoreCompression()
		}
	}()

	rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, object, object,
		map[string]string{xhttp.AmzMetadataDirective: "REPLACE"})
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: metadata-only CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
	}
	assertCopyChecksum(t, obj, bucketName, object, hash.ChecksumCRC32, data, false, nil)
	if got := readCopyChecksumObject(t, obj, bucketName, object, ObjectOptions{}); !bytes.Equal(got, data) {
		prefix := got
		if len(prefix) > 100 {
			prefix = prefix[:100]
		}
		t.Fatalf("%s: metadata-only CopyObject body differs: got %d bytes, want %d, prefix %q",
			instanceType, len(got), len(data), prefix)
	}
	afterMetadataCopy, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.VersionID != "" && afterMetadataCopy.VersionID == before.VersionID {
		t.Fatalf("%s: versioned metadata-only copy did not create a new version", instanceType)
	}

	destination := "copy-metadata/rewritten.txt"
	rec = copyChecksumRequest(t, apiRouter, credentials, bucketName, object, destination, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: data-rewriting CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
	}
	assertCopyChecksum(t, obj, bucketName, destination, hash.ChecksumCRC32, data, true, nil)

	compressedObject := "copy-metadata/preserve-compressed.txt"
	putCopyChecksumSource(t, apiRouter, credentials, bucketName, compressedObject, data,
		map[string]string{xhttp.AmzChecksumCRC32: want})
	assertCopyChecksum(t, obj, bucketName, compressedObject, hash.ChecksumCRC32, data, true, nil)

	restoreCompression()
	compressionRestored = true
	rec = copyChecksumRequest(t, apiRouter, credentials, bucketName, compressedObject, compressedObject,
		map[string]string{xhttp.AmzMetadataDirective: "REPLACE"})
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: compressed metadata-only CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
	}
	assertCopyChecksum(t, obj, bucketName, compressedObject, hash.ChecksumCRC32, data, true, nil)
	if got := readCopyChecksumObject(t, obj, bucketName, compressedObject, ObjectOptions{}); !bytes.Equal(got, data) {
		t.Fatalf("%s: compressed metadata-only CopyObject body differs", instanceType)
	}
}

func TestAPICopyObjectSSECKeyRotationKeepsCompressionState(t *testing.T) {
	defer DetectTestLeak(t)()
	for _, versioned := range []bool{false, true} {
		name := "unversioned"
		if versioned {
			name = "versioned"
		}
		t.Run(name, func(t *testing.T) {
			ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
				t:                 t,
				objAPITest:        testAPICopyObjectSSECKeyRotationKeepsCompressionState,
				endpoints:         []string{"CopyObject", "PutObject", "GetObject"},
				makeBucketOptions: MakeBucketOptions{VersioningEnabled: versioned},
			})
		})
	}
}

func testAPICopyObjectSSECKeyRotationKeepsCompressionState(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	data := bytes.Repeat([]byte("key-rotation-plaintext-"), 64*1024)
	object := "copy-metadata/key-rotation.txt"
	oldKey := bytes.Repeat([]byte{0x11}, 32)
	oldMD5 := md5.Sum(oldKey)
	newKey := bytes.Repeat([]byte{0x22}, 32)
	newMD5 := md5.Sum(newKey)

	putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data, map[string]string{
		xhttp.AmzChecksumCRC32:                         mustChecksum(t, hash.ChecksumCRC32, data),
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(oldKey),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(oldMD5[:]),
	})
	before, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil || before.IsCompressed() {
		t.Fatalf("%s: invalid key-rotation precondition: compressed=%v err=%v", instanceType, before.IsCompressed(), err)
	}

	restoreCompression := setCopyChecksumCompression(true)
	defer restoreCompression()
	rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, object, object, map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm:     xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:           base64.StdEncoding.EncodeToString(newKey),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:        base64.StdEncoding.EncodeToString(newMD5[:]),
		xhttp.AmzServerSideEncryptionCopyCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCopyCustomerKey:       base64.StdEncoding.EncodeToString(oldKey),
		xhttp.AmzServerSideEncryptionCopyCustomerKeyMD5:    base64.StdEncoding.EncodeToString(oldMD5[:]),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: key rotation failed: %d %s", instanceType, rec.Code, rec.Body.String())
	}
	assertCopyChecksumResponse(t, rec, hash.ChecksumCRC32, data)
	after, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if after.IsCompressed() {
		t.Fatalf("%s: metadata-only key rotation stamped compression metadata", instanceType)
	}
	if before.VersionID != "" && after.VersionID == before.VersionID {
		t.Fatalf("%s: versioned key rotation did not create a new version", instanceType)
	}

	getHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(newKey),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(newMD5[:]),
	}
	req, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, getHeaders)
	if err != nil {
		t.Fatalf("failed to build GetObject request: %v", err)
	}
	response := httptest.NewRecorder()
	apiRouter.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), data) {
		t.Fatalf("%s: post-rotation GetObject returned %d with %d bytes, want 200 with %d bytes: %s",
			instanceType, response.Code, response.Body.Len(), len(data), response.Body.String())
	}
}

// TestAPICopyObjectMetadataOnlyNullVersion covers the copy whose source is a
// null version on a bucket that gained versioning after the object was written.
// The object layer cannot reference such a version, so it rewrites the data and
// the recorded compression metadata has to describe the rewritten bytes.
func TestAPICopyObjectMetadataOnlyNullVersion(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPICopyObjectMetadataOnlyNullVersion,
		endpoints:  []string{"CopyObject", "PutObject", "GetObject"},
	})
}

func testAPICopyObjectMetadataOnlyNullVersion(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	restoreCompression := setCopyChecksumCompression(true)
	compressionRestored := false
	defer func() {
		if !compressionRestored {
			restoreCompression()
		}
	}()

	data := bytes.Repeat([]byte("null-version-metadata-copy-"), 64*1024)
	want := mustChecksum(t, hash.ChecksumCRC32, data)
	object := "copy-metadata/null-version.txt"
	putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data,
		map[string]string{xhttp.AmzChecksumCRC32: want})

	before, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !before.IsCompressed() || before.VersionID != "" {
		t.Fatalf("%s: invalid null-version precondition: compressed=%v versionID=%q",
			instanceType, before.IsCompressed(), before.VersionID)
	}

	// Versioning is enabled after the write, so the object keeps a null version.
	if _, err := globalBucketMetadataSys.Update(t.Context(), bucketName,
		bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatalf("%s: unable to enable versioning: %v", instanceType, err)
	}
	if !globalBucketVersioningSys.PrefixEnabled(bucketName, object) {
		t.Fatalf("%s: versioning did not become enabled", instanceType)
	}

	// Without compression the rewritten destination stores plaintext.
	restoreCompression()
	compressionRestored = true

	rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, object, object,
		map[string]string{xhttp.AmzMetadataDirective: "REPLACE"})
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: metadata-only CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
	}

	after := assertCopyChecksum(t, obj, bucketName, object, hash.ChecksumCRC32, data, false, nil)
	if after.VersionID == "" {
		t.Fatalf("%s: versioned copy did not create a new version", instanceType)
	}
	if got := readCopyChecksumObject(t, obj, bucketName, object, ObjectOptions{}); !bytes.Equal(got, data) {
		t.Fatalf("%s: copied object body differs: got %d bytes, want %d", instanceType, len(got), len(data))
	}
}

func TestAPICopyObjectMetadataOnlyNullVersionCompressesRewrite(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPICopyObjectMetadataOnlyNullVersionCompressesRewrite,
		endpoints:  []string{"CopyObject", "PutObject", "GetObject"},
	})
}

func testAPICopyObjectMetadataOnlyNullVersionCompressesRewrite(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	globalCompressConfigMu.Lock()
	previousCompression := globalCompressConfig
	globalCompressConfig.Enabled = false
	globalCompressConfigMu.Unlock()
	defer func() {
		globalCompressConfigMu.Lock()
		globalCompressConfig = previousCompression
		globalCompressConfigMu.Unlock()
	}()

	data := bytes.Repeat([]byte("null-version-compress-rewrite-"), 64*1024)
	want := mustChecksum(t, hash.ChecksumCRC32, data)
	object := "copy-metadata/null-version-compress.txt"
	putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data,
		map[string]string{xhttp.AmzChecksumCRC32: want})

	before, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.IsCompressed() || before.VersionID != "" {
		t.Fatalf("%s: invalid null-version precondition: compressed=%v versionID=%q",
			instanceType, before.IsCompressed(), before.VersionID)
	}
	if _, err := globalBucketMetadataSys.Update(t.Context(), bucketName,
		bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatalf("%s: unable to enable versioning: %v", instanceType, err)
	}

	restoreCopyCompression := setCopyChecksumCompression(false)
	defer restoreCopyCompression()
	rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, object, object,
		map[string]string{xhttp.AmzMetadataDirective: "REPLACE"})
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: metadata-only CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
	}

	after := assertCopyChecksum(t, obj, bucketName, object, hash.ChecksumCRC32, data, true, nil)
	if after.VersionID == "" {
		t.Fatalf("%s: versioned copy did not create a new version", instanceType)
	}
	if got := readCopyChecksumObject(t, obj, bucketName, object, ObjectOptions{}); !bytes.Equal(got, data) {
		t.Fatalf("%s: copied object body differs: got %d bytes, want %d", instanceType, len(got), len(data))
	}
}

func TestCopyRewritesObjectData(t *testing.T) {
	tests := []struct {
		name         string
		metadataOnly bool
		srcOpts      ObjectOptions
		dstOpts      ObjectOptions
		want         bool
	}{
		{
			name: "data copy always rewrites",
			want: true,
		},
		// PostRestoreObjectHandler, updateRestoreMetadata and batchKeyRotate all
		// address the same version on both sides and never set Versioned, so they
		// only ever reach these two cases.
		{
			name:         "unversioned in-place metadata update",
			metadataOnly: true,
		},
		{
			name:         "addressed version updated in place",
			metadataOnly: true,
			srcOpts:      ObjectOptions{VersionID: "v1"},
			dstOpts:      ObjectOptions{VersionID: "v1"},
		},
		{
			name:         "versioned self referential version",
			metadataOnly: true,
			srcOpts:      ObjectOptions{VersionID: "v1"},
			dstOpts:      ObjectOptions{Versioned: true},
		},
		{
			name:         "versioned null source version cannot be referenced",
			metadataOnly: true,
			dstOpts:      ObjectOptions{Versioned: true},
			want:         true,
		},
		{
			name:         "suspended destination with an addressed source version",
			metadataOnly: true,
			srcOpts:      ObjectOptions{VersionID: "v1"},
			dstOpts:      ObjectOptions{VersionSuspended: true, VersionID: nullVersionID},
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := copyRewritesObjectData(tt.metadataOnly, tt.srcOpts, tt.dstOpts); got != tt.want {
				t.Fatalf("copyRewritesObjectData() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAPICopyObjectSSECKeyRotationNullVersion covers an SSE-C key rotation whose
// source is a null version on a bucket that gained versioning after the object
// was written. A rotation only rewraps the object key held in metadata, so it
// may not take the metadata-only path when the object layer stores new object
// data; the rotation has to re-encrypt instead.
func TestAPICopyObjectSSECKeyRotationNullVersion(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPICopyObjectSSECKeyRotationNullVersion,
		endpoints:  []string{"CopyObject", "PutObject", "GetObject"},
	})
}

func testAPICopyObjectSSECKeyRotationNullVersion(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	testAPICopyObjectSSECKeyRotationNullVersionWithCompression(obj, instanceType, bucketName,
		apiRouter, credentials, false, t)
}

func TestAPICopyObjectSSECKeyRotationNullVersionSkipsCompression(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPICopyObjectSSECKeyRotationNullVersionSkipsCompression,
		endpoints:  []string{"CopyObject", "PutObject", "GetObject"},
	})
}

func testAPICopyObjectSSECKeyRotationNullVersionSkipsCompression(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	testAPICopyObjectSSECKeyRotationNullVersionWithCompression(obj, instanceType, bucketName,
		apiRouter, credentials, true, t)
}

func testAPICopyObjectSSECKeyRotationNullVersionWithCompression(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, compressAtCopy bool, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	data := bytes.Repeat([]byte("key-rotation-null-version-"), 64*1024)
	object := "copy-metadata/key-rotation-null.txt"
	oldKey := bytes.Repeat([]byte{0x11}, 32)
	oldMD5 := md5.Sum(oldKey)
	newKey := bytes.Repeat([]byte{0x22}, 32)
	newMD5 := md5.Sum(newKey)

	putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, data, map[string]string{
		xhttp.AmzChecksumCRC32:                         mustChecksum(t, hash.ChecksumCRC32, data),
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(oldKey),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(oldMD5[:]),
	})
	before, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.VersionID != "" {
		t.Fatalf("%s: invalid null-version precondition: versionID=%q", instanceType, before.VersionID)
	}

	// Versioning is enabled after the write, so the object keeps a null version.
	if _, err := globalBucketMetadataSys.Update(t.Context(), bucketName,
		bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatalf("%s: unable to enable versioning: %v", instanceType, err)
	}
	if !globalBucketVersioningSys.PrefixEnabled(bucketName, object) {
		t.Fatalf("%s: versioning did not become enabled", instanceType)
	}
	if compressAtCopy {
		restoreCompression := setCopyChecksumCompression(true)
		defer restoreCompression()
	}

	rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, object, object, map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm:     xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:           base64.StdEncoding.EncodeToString(newKey),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:        base64.StdEncoding.EncodeToString(newMD5[:]),
		xhttp.AmzServerSideEncryptionCopyCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCopyCustomerKey:       base64.StdEncoding.EncodeToString(oldKey),
		xhttp.AmzServerSideEncryptionCopyCustomerKeyMD5:    base64.StdEncoding.EncodeToString(oldMD5[:]),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: key rotation failed: %d %s", instanceType, rec.Code, rec.Body.String())
	}

	assertCopyChecksumResponse(t, rec, hash.ChecksumCRC32, data)

	getHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(newKey),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(newMD5[:]),
	}
	req, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, getHeaders)
	if err != nil {
		t.Fatalf("failed to build GetObject request: %v", err)
	}
	response := httptest.NewRecorder()
	apiRouter.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), data) {
		t.Fatalf("%s: post-rotation GetObject returned %d with %d bytes, want 200 with %d bytes: %s",
			instanceType, response.Code, response.Body.Len(), len(data), response.Body.String())
	}

	decryptHeaders := http.Header{}
	for key, value := range getHeaders {
		decryptHeaders.Set(key, value)
	}
	// This SSE-C rewrite stays uncompressed even with compression enabled at copy
	// time. The plaintext sibling
	// TestAPICopyObjectMetadataOnlyNullVersionCompressesRewrite keeps the
	// coverage that a compressed rewrite records matching metadata.
	after := assertCopyChecksum(t, obj, bucketName, object, hash.ChecksumCRC32, data, false, decryptHeaders)
	if after.VersionID == "" {
		t.Fatalf("%s: rotation into a versioned bucket did not create a new version", instanceType)
	}
	// The rotation could not be applied in place, so the object was re-encrypted
	// under a fresh object key. That regenerates the encrypted ETag, unlike an
	// in-place rotation which leaves the stored bytes and the ETag alone.
	if after.ETag == before.ETag {
		t.Fatalf("%s: re-encrypting rotation kept the source ETag %q", instanceType, after.ETag)
	}
}

// TestAPICopyObjectSSECKeyRotationNullVersionWrongKey pins source-key
// authentication in both the standalone rotation fix and the later zero-byte
// read hardening.
func TestAPICopyObjectSSECKeyRotationNullVersionWrongKey(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPICopyObjectSSECKeyRotationNullVersionWrongKey,
		endpoints:  []string{"CopyObject", "PutObject", "GetObject"},
	})
}

func testAPICopyObjectSSECKeyRotationNullVersionWrongKey(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	object := "copy-metadata/key-rotation-null-empty.txt"
	oldKey := bytes.Repeat([]byte{0x11}, 32)
	oldMD5 := md5.Sum(oldKey)
	wrongKey := bytes.Repeat([]byte{0x33}, 32)
	wrongMD5 := md5.Sum(wrongKey)
	newKey := bytes.Repeat([]byte{0x22}, 32)
	newMD5 := md5.Sum(newKey)

	putCopyChecksumSource(t, apiRouter, credentials, bucketName, object, nil, map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(oldKey),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(oldMD5[:]),
	})
	before, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.Size != 0 || before.VersionID != "" || len(before.Checksum) != 0 {
		t.Fatalf("%s: invalid empty null-version precondition: size=%d versionID=%q checksum=%d",
			instanceType, before.Size, before.VersionID, len(before.Checksum))
	}

	if _, err := globalBucketMetadataSys.Update(t.Context(), bucketName,
		bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatalf("%s: unable to enable versioning: %v", instanceType, err)
	}

	rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, object, object, map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm:     xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:           base64.StdEncoding.EncodeToString(newKey),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:        base64.StdEncoding.EncodeToString(newMD5[:]),
		xhttp.AmzServerSideEncryptionCopyCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCopyCustomerKey:       base64.StdEncoding.EncodeToString(wrongKey),
		xhttp.AmzServerSideEncryptionCopyCustomerKeyMD5:    base64.StdEncoding.EncodeToString(wrongMD5[:]),
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("%s: rotation with an incorrect source key returned %d, want %d: %s",
			instanceType, rec.Code, http.StatusForbidden, rec.Body.String())
	}

	rec = copyChecksumRequest(t, apiRouter, credentials, bucketName, object, object, map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm:     xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:           base64.StdEncoding.EncodeToString(newKey),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:        base64.StdEncoding.EncodeToString(newMD5[:]),
		xhttp.AmzServerSideEncryptionCopyCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCopyCustomerKey:       base64.StdEncoding.EncodeToString(newKey),
		xhttp.AmzServerSideEncryptionCopyCustomerKeyMD5:    base64.StdEncoding.EncodeToString(newMD5[:]),
	})
	// The zero-byte read path authenticates the source key before the
	// rotation-specific equal-key distinction, matching non-empty reads.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("%s: rotation with equal invalid keys returned %d, want %d: %s",
			instanceType, rec.Code, http.StatusForbidden, rec.Body.String())
	}

	after, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if after.VersionID != "" {
		t.Fatalf("%s: rejected rotation still created version %q", instanceType, after.VersionID)
	}

	// The object stays readable with the key it was written under.
	req, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, map[string]string{
			xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
			xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(oldKey),
			xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(oldMD5[:]),
		})
	if err != nil {
		t.Fatalf("failed to build GetObject request: %v", err)
	}
	response := httptest.NewRecorder()
	apiRouter.ServeHTTP(response, req)
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("%s: original object no longer readable: %d with %d bytes: %s",
			instanceType, response.Code, response.Body.Len(), response.Body.String())
	}
}
