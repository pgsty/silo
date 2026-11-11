// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

// Place uploaded versions in specific pools, while retaining the real HTTP
// encryption/compression pipeline and the normal pools-layer copy operation.
type copyUploadPool struct {
	*erasureServerPools
	uploadPool int
}

func (z *copyUploadPool) PutObject(ctx context.Context, bucket, object string, r *PutObjReader, opts ObjectOptions) (ObjectInfo, error) {
	return z.serverPools[z.uploadPool].PutObject(ctx, bucket, object, r, opts)
}

func TestAPICopyHistoricalVersionAcrossPools(t *testing.T) {
	z, _ := consistencyPools(t)
	placed := &copyUploadPool{erasureServerPools: z}
	bucket, router, err := initAPIHandlerTest(t.Context(), placed, nil, MakeBucketOptions{VersioningEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	setObjectLayer(placed)
	if _, err = globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatal(err)
	}
	previousKMS, previousTLS := GlobalKMS, globalIsTLS
	GlobalKMS = kms.NewStub("copy-key")
	globalIsTLS = true
	defer func() { GlobalKMS, globalIsTLS = previousKMS, previousTLS }()
	customer := func(value byte) map[string]string {
		key := bytes.Repeat([]byte{value}, 32)
		sum := md5.Sum(key)
		return map[string]string{xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES, xhttp.AmzServerSideEncryptionCustomerKey: base64.StdEncoding.EncodeToString(key), xhttp.AmzServerSideEncryptionCustomerKeyMD5: base64.StdEncoding.EncodeToString(sum[:])}
	}
	for _, mode := range []string{"plain", "compressed", "sse-s3", "sse-c"} {
		for _, sourcePool := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/source=%d", mode, sourcePool), func(t *testing.T) {
				compressed := mode == "compressed"
				restore := setCopyChecksumCompression(true)
				globalCompressConfigMu.Lock()
				globalCompressConfig.Enabled = compressed
				globalCompressConfigMu.Unlock()
				defer restore()
				sourceHeaders := map[string]string{xhttp.AmzChecksumCRC32: ""}
				if mode == "sse-s3" {
					sourceHeaders[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionAES
				}
				if mode == "sse-c" {
					maps.Copy(sourceHeaders, customer(0x11))
				}
				data := bytes.Repeat([]byte("historical encrypted compressed content-"), 8192)
				sourceHeaders[xhttp.AmzChecksumCRC32] = mustChecksum(t, hash.ChecksumCRC32, data)
				key := fmt.Sprintf("copy-%s-%d.txt", mode, sourcePool)
				placed.uploadPool = sourcePool
				putCopyChecksumSource(t, router, globalActiveCred, bucket, key, data, sourceHeaders)
				original, err := z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if original.VersionID == "" {
					t.Fatal("fixture has no version ID")
				}
				if _, err := z.serverPools[sourcePool].GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: original.VersionID}); err != nil {
					t.Fatal(err)
				}
				if original.IsCompressed() != compressed {
					t.Fatalf("fixture compressed=%v", original.IsCompressed())
				}
				placed.uploadPool = 1 - sourcePool
				putCopyChecksumSource(t, router, globalActiveCred, bucket, key, []byte("newer version"), nil)
				newer, err := z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				// Toggle compression so metadata has to describe the bytes written now.
				restore()
				restoreTarget := setCopyChecksumCompression(true)
				globalCompressConfigMu.Lock()
				globalCompressConfig.Enabled = !compressed
				globalCompressConfigMu.Unlock()
				defer restoreTarget()
				headers := map[string]string{xhttp.AmzMetadataDirective: "REPLACE"}
				getHeaders := map[string]string{}
				if mode == "sse-s3" {
					headers[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionAES
				}
				if mode == "sse-c" {
					maps.Copy(headers, customer(0x22))
					maps.Copy(getHeaders, customer(0x22))
					old := customer(0x11)
					headers[xhttp.AmzServerSideEncryptionCopyCustomerAlgorithm] = old[xhttp.AmzServerSideEncryptionCustomerAlgorithm]
					headers[xhttp.AmzServerSideEncryptionCopyCustomerKey] = old[xhttp.AmzServerSideEncryptionCustomerKey]
					headers[xhttp.AmzServerSideEncryptionCopyCustomerKeyMD5] = old[xhttp.AmzServerSideEncryptionCustomerKeyMD5]
				}
				rec := copyChecksumRequest(t, router, globalActiveCred, bucket, key+"?versionId="+original.VersionID, key, headers)
				if rec.Code != http.StatusOK {
					t.Fatalf("copy: %d %s", rec.Code, rec.Body.String())
				}
				copied, err := z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{})
				if err != nil || copied.VersionID == "" || copied.VersionID == original.VersionID || copied.VersionID == newer.VersionID {
					t.Fatalf("copy did not create a version: %+v %v", copied, err)
				}
				if copied.IsCompressed() != (!compressed && mode != "sse-c") {
					t.Fatalf("copy did not use destination compression setting: %v", copied.IsCompressed())
				}
				if _, err = z.serverPools[1-sourcePool].GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: copied.VersionID}); err != nil {
					t.Fatalf("copy was not placed with destination: %v", err)
				}
				read := func(version string, headers map[string]string, want []byte) {
					t.Helper()
					req, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucket, key)+"?versionId="+version, 0, nil, globalActiveCred.AccessKey, globalActiveCred.SecretKey, headers)
					if err != nil {
						t.Fatal(err)
					}
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), want) {
						t.Fatalf("GET version %s: %d body length=%d, want %d", version, rec.Code, rec.Body.Len(), len(want))
					}
				}
				read(copied.VersionID, getHeaders, data)
				oldHeaders := map[string]string{}
				if mode == "sse-c" {
					oldHeaders = customer(0x11)
				}
				read(original.VersionID, oldHeaders, data)
				read(newer.VersionID, nil, []byte("newer version"))
			})
		}
	}
}

// Internal metadata updates do not all set MetadataChg. They must still
// address the requested historical version, and must never create a new one.
func TestPoolsCopyExactVersionMetadata(t *testing.T) {
	z, bucket := consistencyPools(t)
	for sourcePool := range 2 {
		key := fmt.Sprintf("exact-%d", sourcePool)
		older := putConsistencyObject(t, z, bucket, key, sourcePool, "old data", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour)})
		newer := putConsistencyObject(t, z, bucket, key, 1-sourcePool, "new data", ObjectOptions{Versioned: true, MTime: UTCNow()})
		gr, err := z.GetObjectNInfo(t.Context(), bucket, key, nil, nil, ObjectOptions{VersionID: older.VersionID, NoLock: true})
		if err != nil {
			t.Fatal(err)
		}
		info := gr.ObjInfo
		info.Reader, err = hash.NewReader(t.Context(), gr, info.Size, "", "", info.Size)
		if err != nil {
			gr.Close()
			t.Fatal(err)
		}
		info.PutObjReader = NewPutObjReader(info.Reader)
		info.metadataOnly = true
		info.UserDefined["updated"] = "yes"
		_, err = z.CopyObject(t.Context(), bucket, key, bucket, key, info, ObjectOptions{VersionID: older.VersionID}, ObjectOptions{Versioned: true, VersionID: older.VersionID, MTime: older.ModTime})
		gr.Close()
		if err != nil {
			t.Fatal(err)
		}
		got, err := z.serverPools[sourcePool].GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: older.VersionID})
		if err != nil || got.UserDefined["updated"] != "yes" {
			t.Fatalf("historical metadata not updated: %v %v", got.UserDefined, err)
		}
		got, err = z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{})
		if err != nil || got.VersionID != newer.VersionID || got.UserDefined["updated"] != "" {
			t.Fatalf("latest changed: %+v %v", got, err)
		}
		if got := readCopyChecksumObject(t, z, bucket, key, ObjectOptions{VersionID: older.VersionID}); string(got) != "old data" {
			t.Fatalf("historical body changed: %q", got)
		}
	}
}
