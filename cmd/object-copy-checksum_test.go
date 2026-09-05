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
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

func setCopyChecksumCompression(allowEncrypted bool) func() {
	globalCompressConfigMu.Lock()
	previous := globalCompressConfig
	globalCompressConfig.Enabled = true
	globalCompressConfig.Extensions = []string{".txt"}
	globalCompressConfig.MimeTypes = nil
	globalCompressConfig.AllowEncrypted = allowEncrypted
	globalCompressConfigMu.Unlock()

	return func() {
		globalCompressConfigMu.Lock()
		globalCompressConfig = previous
		globalCompressConfigMu.Unlock()
	}
}

func copyChecksumRequest(t *testing.T, apiRouter http.Handler, credentials auth.Credentials,
	bucket, source, destination string, headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	req, err := newTestSignedRequestV4(http.MethodPut, getCopyObjectURL("", bucket, destination),
		0, nil, credentials.AccessKey, credentials.SecretKey, headers)
	if err != nil {
		t.Fatalf("failed to build CopyObject request: %v", err)
	}
	req.Header.Set(xhttp.AmzCopySource, SlashSeparator+pathJoin(bucket, source))
	rec := httptest.NewRecorder()
	apiRouter.ServeHTTP(rec, req)
	return rec
}

func putCopyChecksumSource(t *testing.T, apiRouter http.Handler, credentials auth.Credentials,
	bucket, object string, data []byte, headers map[string]string,
) {
	t.Helper()
	req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucket, object),
		int64(len(data)), bytes.NewReader(data), credentials.AccessKey, credentials.SecretKey, headers)
	if err != nil {
		t.Fatalf("failed to build PutObject request: %v", err)
	}
	rec := httptest.NewRecorder()
	apiRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PutObject(%s) failed: %d %s", object, rec.Code, rec.Body.String())
	}
}

func readCopyChecksumObject(t *testing.T, obj ObjectLayer, bucket, object string, opts ObjectOptions) []byte {
	t.Helper()
	gr, err := obj.GetObjectNInfo(t.Context(), bucket, object, nil, nil, opts)
	if err != nil {
		t.Fatalf("GetObjectNInfo(%s) failed: %v", object, err)
	}
	defer gr.Close()
	data, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("reading %s failed: %v", object, err)
	}
	return data
}

func assertCopyChecksum(t *testing.T, obj ObjectLayer, bucket, object string, typ hash.ChecksumType,
	data []byte, compressed bool, decryptHeaders http.Header,
) ObjectInfo {
	t.Helper()
	oi, err := obj.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{})
	if err != nil {
		t.Fatalf("GetObjectInfo(%s) failed: %v", object, err)
	}
	if oi.IsCompressed() != compressed {
		t.Fatalf("%s compressed=%v, want %v", object, oi.IsCompressed(), compressed)
	}
	checksums, _ := oi.decryptChecksums(0, decryptHeaders)
	if got, want := checksums[typ.String()], mustChecksum(t, typ, data); got != want {
		t.Fatalf("%s stored %s checksum %q, want logical object checksum %q (all: %v)",
			object, typ.String(), got, want, checksums)
	}
	if got := checksums[xhttp.AmzChecksumType]; got != xhttp.AmzChecksumTypeFullObject {
		t.Fatalf("%s checksum type %q, want %q", object, got, xhttp.AmzChecksumTypeFullObject)
	}
	return oi
}

func assertCopyChecksumResponse(t *testing.T, rec *httptest.ResponseRecorder, typ hash.ChecksumType, data []byte) {
	t.Helper()
	var response CopyObjectResponse
	if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("unable to decode CopyObjectResult: %v", err)
	}
	var got string
	switch typ.Base() {
	case hash.ChecksumCRC32:
		got = response.ChecksumCRC32
	case hash.ChecksumCRC32C:
		got = response.ChecksumCRC32C
	case hash.ChecksumSHA1:
		got = response.ChecksumSHA1
	case hash.ChecksumSHA256:
		got = response.ChecksumSHA256
	case hash.ChecksumCRC64NVME:
		got = response.ChecksumCRC64NVME
	}
	if want := mustChecksum(t, typ, data); got != want {
		t.Fatalf("CopyObjectResult %s checksum %q, want %q: %s", typ.String(), got, want, rec.Body.String())
	}
	if response.ChecksumType != xhttp.AmzChecksumTypeFullObject {
		t.Fatalf("CopyObjectResult checksum type %q, want %q", response.ChecksumType, xhttp.AmzChecksumTypeFullObject)
	}
}

// TestAPICopyObjectServerSideChecksum verifies that server-computed checksums
// cover the logical object, never the compressed storage stream.
func TestAPICopyObjectServerSideChecksum(t *testing.T) {
	defer DetectTestLeak(t)()
	for _, versioned := range []bool{false, true} {
		name := "unversioned"
		if versioned {
			name = "versioned"
		}
		t.Run(name, func(t *testing.T) {
			ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
				t:                 t,
				objAPITest:        testAPICopyObjectServerSideChecksum,
				endpoints:         []string{"CopyObject", "PutObject", "HeadObject", "GetObject"},
				makeBucketOptions: MakeBucketOptions{VersioningEnabled: versioned},
			})
		})
	}
}

func testAPICopyObjectServerSideChecksum(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	restoreCompression := setCopyChecksumCompression(true)
	defer restoreCompression()

	data := bytes.Repeat([]byte("copy-object-checksum-plaintext-"), 64*1024)
	source := "copy-checksum/source.bin"
	if _, err := obj.PutObject(t.Context(), bucketName, source,
		mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{}); err != nil {
		t.Fatalf("%s: source PutObject failed: %v", instanceType, err)
	}

	compressedReader, _ := newS2CompressReader(bytes.NewReader(data), int64(len(data)), false)
	compressed, err := io.ReadAll(compressedReader)
	if closeErr := compressedReader.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("%s: independently compressing test data failed: %v", instanceType, err)
	}

	cases := []struct {
		name       string
		typ        hash.ChecksumType
		explicit   bool
		extension  string
		compressed bool
	}{
		{name: "compressed/CRC32", typ: hash.ChecksumCRC32, explicit: true, extension: ".txt", compressed: true},
		{name: "compressed/CRC32C", typ: hash.ChecksumCRC32C, explicit: true, extension: ".txt", compressed: true},
		{name: "compressed/SHA1", typ: hash.ChecksumSHA1, explicit: true, extension: ".txt", compressed: true},
		{name: "compressed/SHA256", typ: hash.ChecksumSHA256, explicit: true, extension: ".txt", compressed: true},
		{name: "compressed/CRC64NVME", typ: hash.ChecksumCRC64NVME, explicit: true, extension: ".txt", compressed: true},
		{name: "compressed/default", typ: hash.ChecksumCRC64NVME, extension: ".txt", compressed: true},
		{name: "plain/CRC32", typ: hash.ChecksumCRC32, explicit: true, extension: ".bin"},
		{name: "plain/default", typ: hash.ChecksumCRC64NVME, extension: ".bin"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string(nil)
			if tc.explicit {
				headers = map[string]string{xhttp.AmzChecksumAlgo: tc.typ.String()}
			}
			destination := "copy-checksum/destination-" + tc.typ.String() + "-" + string(rune('a'+i)) + tc.extension
			rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, source, destination, headers)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
			}
			assertCopyChecksumResponse(t, rec, tc.typ, data)

			info := assertCopyChecksum(t, obj, bucketName, destination, tc.typ, data, tc.compressed, nil)
			md5sum := md5.Sum(data)
			if got, want := info.ETag, hex.EncodeToString(md5sum[:]); got != want {
				t.Fatalf("%s: ETag %q, want logical object MD5 %q", instanceType, got, want)
			}
			if tc.compressed {
				logical := mustChecksum(t, tc.typ, data)
				if transformed := mustChecksum(t, tc.typ, compressed); logical == transformed {
					t.Fatalf("%s: test payload does not distinguish logical and compressed checksum domains", instanceType)
				}
			}
			if got := readCopyChecksumObject(t, obj, bucketName, destination, ObjectOptions{}); !bytes.Equal(got, data) {
				t.Fatalf("%s: round-trip body differs for %s", instanceType, tc.name)
			}

			if tc.name == "compressed/CRC32" {
				for _, method := range []string{http.MethodHead, http.MethodGet} {
					url := getHeadObjectURL("", bucketName, destination)
					if method == http.MethodGet {
						url = getGetObjectURL("", bucketName, destination)
					}
					req, err := newTestSignedRequestV4(method, url, 0, nil,
						credentials.AccessKey, credentials.SecretKey,
						map[string]string{xhttp.AmzChecksumMode: "ENABLED"})
					if err != nil {
						t.Fatalf("failed to build %s request: %v", method, err)
					}
					response := httptest.NewRecorder()
					apiRouter.ServeHTTP(response, req)
					if response.Code != http.StatusOK {
						t.Fatalf("%s returned %d: %s", method, response.Code, response.Body.String())
					}
					if got, want := response.Header().Get(tc.typ.Key()), mustChecksum(t, tc.typ, data); got != want {
						t.Fatalf("%s returned checksum %q, want %q", method, got, want)
					}
					if method == http.MethodGet && !bytes.Equal(response.Body.Bytes(), data) {
						t.Fatalf("GET response body differs")
					}
				}
			}
		})
	}
}

func TestAPICopyObjectServerSideChecksumEncryption(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPICopyObjectServerSideChecksumEncryption,
		endpoints:  []string{"CopyObject", "PutObject", "GetObject"},
	})
}

func testAPICopyObjectServerSideChecksumEncryption(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	restoreCompression := setCopyChecksumCompression(true)
	defer restoreCompression()

	data := bytes.Repeat([]byte("encrypted-copy-checksum-plaintext-"), 48*1024)
	source := "copy-checksum/encrypted-source.bin"
	if _, err := obj.PutObject(t.Context(), bucketName, source,
		mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{}); err != nil {
		t.Fatalf("%s: source PutObject failed: %v", instanceType, err)
	}

	t.Run("SSE-S3", func(t *testing.T) {
		secretKey, err := kms.ParseSecretKey("my-minio-key:5lF+0pJM0OWwlQrvK2S/I7W9mO4a6rJJI7wzj7v09cw=")
		if err != nil {
			t.Fatal(err)
		}
		previousKMS := GlobalKMS
		GlobalKMS = secretKey
		defer func() { GlobalKMS = previousKMS }()

		for _, variant := range []struct {
			name       string
			extension  string
			compressed bool
		}{
			{name: "encrypted-only", extension: ".bin"},
			{name: "compressed-encrypted", extension: ".txt", compressed: true},
		} {
			t.Run(variant.name, func(t *testing.T) {
				destination := "copy-checksum/sse-s3-" + variant.name + variant.extension
				rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, source, destination, map[string]string{
					xhttp.AmzChecksumAlgo:         hash.ChecksumCRC32.String(),
					xhttp.AmzServerSideEncryption: xhttp.AmzEncryptionAES,
				})
				if rec.Code != http.StatusOK {
					t.Fatalf("%s: SSE-S3 CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
				}
				assertCopyChecksumResponse(t, rec, hash.ChecksumCRC32, data)
				assertCopyChecksum(t, obj, bucketName, destination, hash.ChecksumCRC32, data, variant.compressed, nil)
				if got := readCopyChecksumObject(t, obj, bucketName, destination, ObjectOptions{}); !bytes.Equal(got, data) {
					t.Fatalf("%s: SSE-S3 round-trip body differs", instanceType)
				}
			})
		}

		encryptedSource := "copy-checksum/sse-s3-source.bin"
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, encryptedSource, data,
			map[string]string{xhttp.AmzServerSideEncryption: xhttp.AmzEncryptionAES})
		destination := "copy-checksum/sse-s3-source-copy.txt"
		rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, encryptedSource, destination,
			map[string]string{xhttp.AmzChecksumAlgo: hash.ChecksumCRC32.String()})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: SSE-S3 source CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
		}
		assertCopyChecksumResponse(t, rec, hash.ChecksumCRC32, data)
		assertCopyChecksum(t, obj, bucketName, destination, hash.ChecksumCRC32, data, true, nil)
		if got := readCopyChecksumObject(t, obj, bucketName, destination, ObjectOptions{}); !bytes.Equal(got, data) {
			t.Fatalf("%s: SSE-S3 source round-trip body differs", instanceType)
		}
	})

	t.Run("SSE-C", func(t *testing.T) {
		previousTLS := globalIsTLS
		globalIsTLS = true
		defer func() { globalIsTLS = previousTLS }()

		key := bytes.Repeat([]byte{0x2a}, 32)
		keyMD5 := md5.Sum(key)
		headers := map[string]string{
			xhttp.AmzChecksumAlgo:                          hash.ChecksumCRC32.String(),
			xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
			xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
			xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
		}
		decryptHeaders := http.Header{}
		for key, value := range headers {
			decryptHeaders.Set(key, value)
		}

		getHeaders := make(map[string]string, len(headers))
		for key, value := range headers {
			if key != xhttp.AmzChecksumAlgo {
				getHeaders[key] = value
			}
		}
		for _, variant := range []struct {
			name       string
			extension  string
			compressed bool
		}{
			{name: "encrypted-only", extension: ".bin"},
			// SSE-C is excluded from compression whatever allow_encryption says,
			// so a compressible destination extension changes nothing here. The
			// SSE-S3 sibling above keeps the compressed-encrypted coverage.
			{name: "compressible-extension", extension: ".txt"},
		} {
			t.Run(variant.name, func(t *testing.T) {
				destination := "copy-checksum/sse-c-" + variant.name + variant.extension
				rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, source, destination, headers)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s: SSE-C CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
				}
				assertCopyChecksumResponse(t, rec, hash.ChecksumCRC32, data)
				assertCopyChecksum(t, obj, bucketName, destination, hash.ChecksumCRC32, data, variant.compressed, decryptHeaders)

				req, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, destination),
					0, nil, credentials.AccessKey, credentials.SecretKey, getHeaders)
				if err != nil {
					t.Fatalf("failed to build SSE-C GetObject request: %v", err)
				}
				response := httptest.NewRecorder()
				apiRouter.ServeHTTP(response, req)
				if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), data) {
					t.Fatalf("%s: SSE-C GetObject returned %d with %d bytes, want 200 with %d bytes",
						instanceType, response.Code, response.Body.Len(), len(data))
				}
			})
		}

		oldKey := bytes.Repeat([]byte{0x31}, 32)
		oldKeyMD5 := md5.Sum(oldKey)
		newKey := bytes.Repeat([]byte{0x42}, 32)
		newKeyMD5 := md5.Sum(newKey)
		encryptedSource := "copy-checksum/sse-c-different-key-source.bin"
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, encryptedSource, data, map[string]string{
			xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
			xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(oldKey),
			xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(oldKeyMD5[:]),
		})

		destination := "copy-checksum/sse-c-different-key-destination.bin"
		rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, encryptedSource, destination, map[string]string{
			xhttp.AmzChecksumAlgo:                              hash.ChecksumCRC32.String(),
			xhttp.AmzServerSideEncryptionCustomerAlgorithm:     xhttp.AmzEncryptionAES,
			xhttp.AmzServerSideEncryptionCustomerKey:           base64.StdEncoding.EncodeToString(newKey),
			xhttp.AmzServerSideEncryptionCustomerKeyMD5:        base64.StdEncoding.EncodeToString(newKeyMD5[:]),
			xhttp.AmzServerSideEncryptionCopyCustomerAlgorithm: xhttp.AmzEncryptionAES,
			xhttp.AmzServerSideEncryptionCopyCustomerKey:       base64.StdEncoding.EncodeToString(oldKey),
			xhttp.AmzServerSideEncryptionCopyCustomerKeyMD5:    base64.StdEncoding.EncodeToString(oldKeyMD5[:]),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: different-key SSE-C CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
		}
		assertCopyChecksumResponse(t, rec, hash.ChecksumCRC32, data)
		if got, want := rec.Header().Get(hash.ChecksumCRC32.Key()), mustChecksum(t, hash.ChecksumCRC32, data); got != want {
			t.Fatalf("%s: different-key SSE-C response header checksum %q, want %q", instanceType, got, want)
		}
		if got := rec.Header().Get(xhttp.AmzChecksumType); got != xhttp.AmzChecksumTypeFullObject {
			t.Fatalf("%s: different-key SSE-C response checksum type %q, want %q", instanceType, got, xhttp.AmzChecksumTypeFullObject)
		}
		newKeyHeaders := http.Header{
			xhttp.AmzServerSideEncryptionCustomerAlgorithm: []string{xhttp.AmzEncryptionAES},
			xhttp.AmzServerSideEncryptionCustomerKey:       []string{base64.StdEncoding.EncodeToString(newKey)},
			xhttp.AmzServerSideEncryptionCustomerKeyMD5:    []string{base64.StdEncoding.EncodeToString(newKeyMD5[:])},
		}
		assertCopyChecksum(t, obj, bucketName, destination, hash.ChecksumCRC32, data, false, newKeyHeaders)
	})
}

func TestAPICopyObjectServerSideChecksumSourceVariants(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPICopyObjectServerSideChecksumSourceVariants,
		endpoints: []string{
			"NewMultipart", "PutObjectPart", "CompleteMultipart", "ListObjectParts",
			"CopyObject", "PutObject", "HeadObject", "GetObject",
		},
	})
}

func testAPICopyObjectServerSideChecksumSourceVariants(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	restoreCompression := setCopyChecksumCompression(true)
	defer restoreCompression()

	data := bytes.Repeat([]byte("source-variant-plaintext-"), 64*1024)

	t.Run("compressed-source", func(t *testing.T) {
		source := "copy-checksum/compressed-source.txt"
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, source, data, nil)
		if info, err := obj.GetObjectInfo(t.Context(), bucketName, source, ObjectOptions{}); err != nil || !info.IsCompressed() {
			t.Fatalf("%s: compressed source precondition failed: compressed=%v err=%v", instanceType, info.IsCompressed(), err)
		}
		destination := "copy-checksum/compressed-source-copy.txt"
		rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, source, destination,
			map[string]string{xhttp.AmzChecksumAlgo: hash.ChecksumCRC32.String()})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
		}
		assertCopyChecksumResponse(t, rec, hash.ChecksumCRC32, data)
		assertCopyChecksum(t, obj, bucketName, destination, hash.ChecksumCRC32, data, true, nil)

		rec = copyChecksumRequest(t, apiRouter, credentials, bucketName, source, source, map[string]string{
			xhttp.AmzChecksumAlgo:      hash.ChecksumSHA256.String(),
			xhttp.AmzMetadataDirective: "REPLACE",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: in-place CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
		}
		assertCopyChecksumResponse(t, rec, hash.ChecksumSHA256, data)
		assertCopyChecksum(t, obj, bucketName, source, hash.ChecksumSHA256, data, true, nil)
		if got := readCopyChecksumObject(t, obj, bucketName, source, ObjectOptions{}); !bytes.Equal(got, data) {
			t.Fatalf("%s: in-place CopyObject body differs", instanceType)
		}
	})

	t.Run("full-checksum-source", func(t *testing.T) {
		source := "copy-checksum/full-checksum-source.bin"
		want := mustChecksum(t, hash.ChecksumCRC32, data)
		putCopyChecksumSource(t, apiRouter, credentials, bucketName, source, data,
			map[string]string{xhttp.AmzChecksumCRC32: want})
		destination := "copy-checksum/full-checksum-copy.txt"
		rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, source, destination, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
		}
		assertCopyChecksumResponse(t, rec, hash.ChecksumCRC32, data)
		assertCopyChecksum(t, obj, bucketName, destination, hash.ChecksumCRC32, data, true, nil)
	})

	t.Run("multipart-composite-source", func(t *testing.T) {
		typ := hash.ChecksumCRC32
		parts, full := multipartChecksumTestData()
		source := "copy-checksum/multipart-source.bin"
		uploadID := newMultipartUploadHTTP(t, apiRouter, credentials, bucketName, source,
			typ.String(), xhttp.AmzChecksumTypeComposite)
		etags := uploadPartsHTTP(t, apiRouter, credentials, bucketName, source, uploadID, typ, parts)
		partChecksums := make([]string, len(parts))
		for i, part := range parts {
			partChecksums[i] = mustChecksum(t, typ, part)
		}
		rec := completeMultipartUploadHTTP(t, apiRouter, credentials, bucketName, source, uploadID,
			etags, partChecksums, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: CompleteMultipartUpload failed: %d %s", instanceType, rec.Code, rec.Body.String())
		}
		sourceInfo, err := obj.GetObjectInfo(t.Context(), bucketName, source, ObjectOptions{})
		if err != nil {
			t.Fatalf("%s: source GetObjectInfo failed: %v", instanceType, err)
		}
		if _, multipart := sourceInfo.decryptChecksums(0, nil); !multipart {
			t.Fatalf("%s: source checksum is not multipart composite", instanceType)
		}

		destination := "copy-checksum/multipart-copy.txt"
		rec = copyChecksumRequest(t, apiRouter, credentials, bucketName, source, destination, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
		}
		assertCopyChecksumResponse(t, rec, typ, full)
		assertCopyChecksum(t, obj, bucketName, destination, typ, full, true, nil)
		if got := readCopyChecksumObject(t, obj, bucketName, destination, ObjectOptions{}); !bytes.Equal(got, full) {
			t.Fatalf("%s: multipart source round-trip body differs", instanceType)
		}
	})

	for _, boundary := range []struct {
		name       string
		data       []byte
		compressed bool
	}{
		{name: "at-threshold", data: bytes.Repeat([]byte{'a'}, minCompressibleSize)},
		{name: "over-threshold", data: bytes.Repeat([]byte{'a'}, minCompressibleSize+1), compressed: true},
		{name: "indexed", data: bytes.Repeat([]byte{'a'}, compMinIndexSize+1), compressed: true},
		{name: "empty", data: nil},
	} {
		t.Run(boundary.name, func(t *testing.T) {
			source := "copy-checksum/" + boundary.name + "-source.bin"
			if _, err := obj.PutObject(t.Context(), bucketName, source,
				mustGetPutObjReader(t, bytes.NewReader(boundary.data), int64(len(boundary.data)), "", ""), ObjectOptions{}); err != nil {
				t.Fatalf("%s: source PutObject failed: %v", instanceType, err)
			}
			destination := "copy-checksum/" + boundary.name + "-copy.txt"
			rec := copyChecksumRequest(t, apiRouter, credentials, bucketName, source, destination,
				map[string]string{xhttp.AmzChecksumAlgo: hash.ChecksumCRC32.String()})
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: CopyObject failed: %d %s", instanceType, rec.Code, rec.Body.String())
			}
			assertCopyChecksumResponse(t, rec, hash.ChecksumCRC32, boundary.data)
			assertCopyChecksum(t, obj, bucketName, destination, hash.ChecksumCRC32, boundary.data, boundary.compressed, nil)
		})
	}
}

func TestPutObjectRejectsMissingServerSideChecksum(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testPutObjectRejectsMissingServerSideChecksum,
		endpoints:  []string{"PutObject"},
	})
}

func testPutObjectRejectsMissingServerSideChecksum(obj ObjectLayer, instanceType, bucketName string,
	_ http.Handler, _ auth.Credentials, t *testing.T,
) {
	data := []byte("the object layer must not silently omit a requested checksum")
	for _, test := range []struct {
		name       string
		hasherType hash.ChecksumType
	}{
		{name: "missing"},
		{name: "mismatched", hasherType: hash.ChecksumCRC32C},
	} {
		t.Run(test.name, func(t *testing.T) {
			object := "copy-checksum/" + test.name + "-server-side-checksum"
			reader := mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", "")
			if test.hasherType.IsSet() {
				reader.AddServerSideChecksumHasher(test.hasherType)
			}
			_, err := obj.PutObject(t.Context(), bucketName, object, reader,
				ObjectOptions{WantServerSideChecksumType: hash.ChecksumCRC32})
			if err == nil || !strings.Contains(err.Error(), "server-side checksum") {
				t.Fatalf("%s: PutObject error %v, want server-side checksum invariant error", instanceType, err)
			}
			if _, err = obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{}); !isErrObjectNotFound(err) {
				t.Fatalf("%s: failed PutObject left an object behind: %v", instanceType, err)
			}
		})
	}
}
