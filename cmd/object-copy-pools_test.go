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
	GlobalKMS, err = kms.NewBuiltin("copy-key", bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	globalIsTLS = true
	defer func() { GlobalKMS, globalIsTLS = previousKMS, previousTLS }()
	customer := func(value byte) map[string]string {
		key := bytes.Repeat([]byte{value}, 32)
		sum := md5.Sum(key)
		return map[string]string{xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES, xhttp.AmzServerSideEncryptionCustomerKey: base64.StdEncoding.EncodeToString(key), xhttp.AmzServerSideEncryptionCustomerKeyMD5: base64.StdEncoding.EncodeToString(sum[:])}
	}
	for _, tc := range []struct{ mode, movement string }{
		{"plain", "active"},
		{"compressed", "active"},
		{"sse-s3", "active"},
		{"sse-c", "active"},
		{"sse-kms", "active"},
		{"sse-c", "decommission"},
		{"sse-kms", "rebalance"},
	} {
		mode := tc.mode
		for _, sourcePool := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/%s/source=%d", mode, tc.movement, sourcePool), func(t *testing.T) {
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
				if mode == "sse-kms" {
					sourceHeaders[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionKMS
					sourceHeaders[xhttp.AmzServerSideEncryptionKmsID] = "copy-key"
					sourceHeaders[xhttp.AmzServerSideEncryptionKmsContext] = base64.StdEncoding.EncodeToString([]byte(`{"tenant":"source"}`))
				}
				if mode == "sse-c" {
					maps.Copy(sourceHeaders, customer(0x11))
				}
				pattern := []byte("historical encrypted compressed content-")
				repeats := 8192
				if mode == "plain" {
					repeats = compMinIndexSize/len(pattern) + 1
				}
				data := bytes.Repeat(pattern, repeats)
				sourceHeaders[xhttp.AmzChecksumCRC32] = mustChecksum(t, hash.ChecksumCRC32, data)
				key := fmt.Sprintf("copy-%s-%s-%d.txt", mode, tc.movement, sourcePool)
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
				setCopyMovingPool(t, z, sourcePool, tc.movement)
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
				if mode == "sse-kms" {
					headers[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionKMS
					headers[xhttp.AmzServerSideEncryptionKmsID] = "copy-key"
					headers[xhttp.AmzServerSideEncryptionKmsContext] = base64.StdEncoding.EncodeToString([]byte(`{"tenant":"destination"}`))
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
				if copied.IsCompressed() && len(data) > compMinIndexSize {
					if len(copied.Parts) == 0 || len(copied.Parts[0].Index) == 0 {
						t.Fatalf("compressed multi-block copy lost seek index: %+v", copied.Parts)
					}
					rangeHeaders := maps.Clone(getHeaders)
					rangeHeaders["Range"] = "bytes=6000000-6000127"
					req, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucket, key)+"?versionId="+copied.VersionID, 0, nil, globalActiveCred.AccessKey, globalActiveCred.SecretKey, rangeHeaders)
					if err != nil {
						t.Fatal(err)
					}
					rrec := httptest.NewRecorder()
					router.ServeHTTP(rrec, req)
					if rrec.Code != http.StatusPartialContent || !bytes.Equal(rrec.Body.Bytes(), data[6000000:6000128]) {
						t.Fatalf("ranged GET on compressed copy: %d len=%d", rrec.Code, rrec.Body.Len())
					}
				}
				if mode == "sse-kms" {
					assertFederationKMSContext(t, copied, headers[xhttp.AmzServerSideEncryptionKmsContext])
					assertFederationKMSContext(t, original, sourceHeaders[xhttp.AmzServerSideEncryptionKmsContext])
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

func setCopyMovingPool(t *testing.T, z *erasureServerPools, pool int, movement string) {
	t.Helper()
	switch movement {
	case "decommission":
		z.poolMetaMutex.Lock()
		z.poolMeta.Pools[pool].Decommission = &PoolDecommissionInfo{}
		z.poolMetaMutex.Unlock()
		t.Cleanup(func() {
			z.poolMetaMutex.Lock()
			z.poolMeta.Pools[pool].Decommission = nil
			z.poolMetaMutex.Unlock()
		})
	case "rebalance":
		z.rebalMu.Lock()
		z.rebalMeta = &rebalanceMeta{PoolStats: []*rebalanceStats{{}, {}}}
		z.rebalMeta.PoolStats[pool] = &rebalanceStats{Participating: true, Info: rebalanceInfo{Status: rebalStarted}}
		z.rebalMu.Unlock()
		t.Cleanup(func() { z.rebalMu.Lock(); z.rebalMeta = nil; z.rebalMu.Unlock() })
	}
}

// The content that a metadata-only replica preserves must be the same content
// that reads selected, even when write allocation would skip its pool.
func TestCopyReplicaMetadataMovingPool(t *testing.T) {
	z, _ := consistencyPools(t)
	bucket, router, err := initAPIHandlerTest(t.Context(), z, nil, MakeBucketOptions{LockEnabled: true})
	mustIAM(t, err)
	setObjectLayer(z)
	_, err = globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
	mustIAM(t, err)
	const body = "current-body"
	for _, api := range []bool{false, true} {
		for sourcePool := range 2 {
			for _, movement := range []string{"decommission", "rebalance"} {
				for _, kind := range []string{"uuid", "null"} {
					for _, duplicate := range []string{"absent", "older", "tie"} {
						// The lower pool index wins equal ModTimes, just as on reads.
						if duplicate == "tie" && sourcePool != 0 {
							continue
						}
						t.Run(fmt.Sprintf("api=%t/source=%d/%s/%s/%s", api, sourcePool, movement, kind, duplicate), func(t *testing.T) {
							key := fmt.Sprintf("metadata-%t-%d-%s-%s-%s", api, sourcePool, movement, kind, duplicate)
							oi := putConsistencyObject(t, z, bucket, key, sourcePool, body, ObjectOptions{
								Versioned: kind == "uuid", MTime: UTCNow().Add(-time.Minute),
								WantChecksum: hash.NewChecksumFromData(hash.ChecksumCRC32, []byte(body)),
							})
							version := oi.VersionID
							if version == "" {
								version = nullVersionID
							}
							if duplicate != "absent" {
								stamp := oi.ModTime
								if duplicate == "older" {
									stamp = stamp.Add(-time.Hour)
								}
								putConsistencyObject(t, z, bucket, key, 1-sourcePool, "stale---body", ObjectOptions{
									Versioned: kind == "uuid", VersionID: version, MTime: stamp,
									UserDefined: poolLockMetadata("", "ON", "", objectLockTestStamp1000),
								})
							}
							if got := readCopyChecksumObject(t, z, bucket, key, ObjectOptions{VersionID: version}); string(got) != body {
								t.Fatalf("fixture: %q", got)
							}
							setCopyMovingPool(t, z, sourcePool, movement)
							if api {
								headers := map[string]string{
									xhttp.AmzCopySource:        "/" + bucket + "/" + key + "?versionId=" + version,
									xhttp.AmzMetadataDirective: "REPLACE", "X-Amz-Meta-Updated": "yes",
									xhttp.MinIOSourceReplicationRequest: "true", xhttp.AmzBucketReplicationStatus: "REPLICA",
								}
								rec := r5Request(t, router, globalActiveCred, http.MethodPut, "/"+bucket+"/"+key+"?versionId="+version, "", headers)
								if rec.Code != http.StatusOK {
									t.Fatalf("metadata copy: %d %s", rec.Code, rec.Body.String())
								}
								assertCopyChecksumResponse(t, rec, hash.ChecksumCRC32, []byte(body))
							} else {
								oi.metadataOnly = true
								oi.UserDefined["X-Amz-Meta-Updated"] = "yes"
								_, err = z.CopyObject(t.Context(), bucket, key, bucket, key, oi,
									ObjectOptions{VersionID: version}, ObjectOptions{Versioned: kind == "uuid", VersionID: version, MTime: oi.ModTime, ReplicaLockReconcile: true})
								mustIAM(t, err)
							}
							if got := readCopyChecksumObject(t, z, bucket, key, ObjectOptions{VersionID: version}); string(got) != body {
								t.Fatalf("metadata copy replaced content: %q", got)
							}
							stored, err := z.serverPools[sourcePool].GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: version})
							mustIAM(t, err)
							if stored.UserDefined["X-Amz-Meta-Updated"] != "yes" || !bytes.Equal(stored.Checksum, oi.Checksum) {
								t.Fatalf("metadata/checksum: %v, %x; want checksum %x", stored.UserDefined, stored.Checksum, oi.Checksum)
							}
							if duplicate != "absent" && storedObjectLockState(stored.UserDefined).legalHold != "ON" {
								t.Fatal("lost protection from the retired copy")
							}
							_, err = z.serverPools[1-sourcePool].GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: version})
							if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
								t.Fatalf("stale copy not retired: %v", err)
							}
						})
					}
				}
			}
		}
	}
}

func TestAPICopyRewriteMovingPool(t *testing.T) {
	z, _ := consistencyPools(t)
	placed := &copyUploadPool{erasureServerPools: z}
	bucket, router, err := initAPIHandlerTest(t.Context(), placed, nil, MakeBucketOptions{})
	mustIAM(t, err)
	setObjectLayer(placed)
	previousKMS := GlobalKMS
	GlobalKMS, err = kms.NewBuiltin("copy-key", bytes.Repeat([]byte{0x33}, 32))
	mustIAM(t, err)
	defer func() { GlobalKMS = previousKMS }()
	for sourcePool := range 2 {
		for _, movement := range []string{"decommission", "rebalance"} {
			for _, mode := range []string{"sse-s3", "checksum", "default-checksum", "invalid-self-copy"} {
				t.Run(fmt.Sprintf("source=%d/%s/%s", sourcePool, movement, mode), func(t *testing.T) {
					key := fmt.Sprintf("rewrite-%d-%s-%s", sourcePool, movement, mode)
					data := []byte("rewriting a source on a draining pool")
					sourceHeaders := map[string]string{}
					if mode != "default-checksum" {
						sourceHeaders[xhttp.AmzChecksumCRC32] = mustChecksum(t, hash.ChecksumCRC32, data)
					}
					placed.uploadPool = sourcePool
					putCopyChecksumSource(t, router, globalActiveCred, bucket, key, data, sourceHeaders)
					setCopyMovingPool(t, z, sourcePool, movement)
					headers := map[string]string{xhttp.AmzMetadataDirective: "REPLACE"}
					wantChecksum := hash.ChecksumCRC32
					switch mode {
					case "sse-s3":
						headers[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionAES
					case "checksum", "invalid-self-copy":
						headers[xhttp.AmzChecksumAlgo] = "SHA256"
						wantChecksum = hash.ChecksumSHA256
						if mode == "invalid-self-copy" {
							delete(headers, xhttp.AmzMetadataDirective)
						}
					case "default-checksum":
						wantChecksum = hash.ChecksumCRC64NVME
					}
					rec := copyChecksumRequest(t, router, globalActiveCred, bucket, key, key, headers)
					if mode == "invalid-self-copy" {
						if rec.Code != http.StatusBadRequest {
							t.Fatalf("invalid self-copy: %d %s", rec.Code, rec.Body.String())
						}
						_, err := z.serverPools[1-sourcePool].GetObjectInfo(t.Context(), bucket, key, ObjectOptions{})
						if !isErrObjectNotFound(err) {
							t.Fatalf("rejected copy wrote a destination: %v", err)
						}
						return
					}
					if rec.Code != http.StatusOK {
						t.Fatalf("rewrite: %d %s", rec.Code, rec.Body.String())
					}
					assertCopyChecksumResponse(t, rec, wantChecksum, data)
					if got := readCopyChecksumObject(t, z, bucket, key, ObjectOptions{}); !bytes.Equal(got, data) {
						t.Fatalf("rewritten body: %q", got)
					}
					if _, err := z.serverPools[1-sourcePool].GetObjectInfo(t.Context(), bucket, key, ObjectOptions{}); err != nil {
						t.Fatalf("rewrite did not reach active pool: %v", err)
					}
					assertCopyChecksum(t, z, bucket, key, wantChecksum, data, false, nil)
				})
			}
		}
	}
}
