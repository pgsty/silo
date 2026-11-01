//go:build consistency_strict

// Preserved diagnostic for the deferred strict-read policy. This is not a
// maintenance release gate; failures record intentionally unresolved risks.

// Copyright (c) 2026 Feng Ruohang
//
// This file is part of Silo Object Storage stack
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
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

// An acknowledged recovery overwrite must resolve the unreadable pool, even
// when another pool already has a readable copy of the same object.
// Real inline metadata is combined in the same 15-old/1-new state used by
// that regression. Capacity adapters only make destination choice deterministic.
func TestPoolsMinorityOverwriteRecovery(t *testing.T) {
	for _, versioning := range []string{"unversioned", "versioned", "suspended"} {
		for _, mode := range []string{"single-pool", "dual-pool-only-inconsistent-copy", "dual-pool-readable-other-copy"} {
			t.Run(versioning+"/"+mode, func(t *testing.T) {
				testPoolsMinorityOverwriteRecovery(t, mode, versioning, "")
			})
		}
	}
	for _, encryption := range []string{"SSE-C", "SSE-S3", "SSE-KMS"} {
		t.Run(encryption, func(t *testing.T) {
			testPoolsMinorityOverwriteRecovery(t, "dual-pool-readable-other-copy", "unversioned", encryption)
		})
	}
}

func testPoolsMinorityOverwriteRecovery(t *testing.T, mode, versioning, encryption string) {
	t.Helper()
	var z *erasureServerPools
	if mode == "single-pool" {
		z, _ = mutationPools(t)
	} else {
		z, _ = consistencyPools(t)
	}
	const object = "review-retry"
	for _, pool := range z.serverPools {
		restore := conditionalPutSwapDisks(pool, object, func(d StorageAPI) StorageAPI { return conditionalPutCapacityDisk{StorageAPI: d} })
		defer restore()
	}
	bucket, router := conditionalPutBucket(t, z, versioning)
	oldTime := time.Now().UTC().Add(-time.Hour)
	oldBody := bytes.Repeat([]byte{'a'}, 8192)
	pendingBody := bytes.Repeat([]byte{'b'}, 8192)
	recoveryBody := bytes.Repeat([]byte{'c'}, 8192)
	seed := func(pool int, body []byte, when time.Time) {
		t.Helper()
		putConsistencyObject(t, z, bucket, object, pool, string(body), ObjectOptions{MTime: when})
	}
	seed(0, oldBody, oldTime)
	disks := z.serverPools[0].getHashedSet(object).getDisks()
	oldMeta := make([][]byte, len(disks))
	for i, disk := range disks {
		oldMeta[i] = mustReadNullQuorumMeta(t, disk, bucket, object)
	}
	seed(0, pendingBody, oldTime.Add(time.Minute))
	for i := 0; i < len(disks)-1; i++ {
		if err := disks[i].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, oldMeta[i]); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "dual-pool-readable-other-copy" {
		seed(1, oldBody, oldTime.Add(-time.Minute))
		// Ordinary allocation can select this healthy other pool.
		// Force that permitted choice without altering metadata reads.
		restore := conditionalPutPool(t, z, object, 1)
		defer restore()
	}
	before := consistencyRequest(t, router, http.MethodGet, bucket, object, "")
	if before.Code != http.StatusServiceUnavailable {
		t.Fatalf("fixture must refuse ambiguous read; got %d", before.Code)
	}
	var headers, readHeaders map[string]string
	if encryption != "" {
		oldKMS, oldTLS := GlobalKMS, globalIsTLS
		GlobalKMS, globalIsTLS = kms.NewStub("recovery-key"), true
		defer func() { GlobalKMS, globalIsTLS = oldKMS, oldTLS }()
		headers = map[string]string{xhttp.AmzServerSideEncryption: xhttp.AmzEncryptionAES}
		switch encryption {
		case "SSE-C":
			key := bytes.Repeat([]byte{0x42}, 32)
			digest := md5.Sum(key)
			headers = map[string]string{
				xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
				xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
				xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(digest[:]),
			}
			readHeaders = headers
		case "SSE-KMS":
			headers[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionKMS
			headers[xhttp.AmzServerSideEncryptionKmsID] = "recovery-key"
		}
	}
	url := getPutObjectURL("", bucket, object)
	result := multipartConditionRequest(t, router, http.MethodPut, url, string(recoveryBody), headers)
	t.Logf("recovery PUT HTTP=%d response=%s", result.Code, result.Body.String())
	if result.Code != http.StatusOK {
		t.Fatalf("unconditional recovery PUT: %d %s", result.Code, result.Body.String())
	}
	after := multipartConditionRequest(t, router, http.MethodGet, url, "", readHeaders)
	t.Logf("after acknowledged recovery PUT: GET HTTP=%d matches_new=%t", after.Code, bytes.Equal(after.Body.Bytes(), recoveryBody))
	for i, pool := range z.serverPools {
		oi, err := pool.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{})
		t.Logf("pool=%d mtime=%s err=%v", i, oi.ModTime, err)
	}
	if after.Code != http.StatusOK || !bytes.Equal(after.Body.Bytes(), recoveryBody) {
		t.Fatalf("acknowledged recovery overwrite did not restore reads: HTTP=%d body=%s", after.Code, after.Body.String())
	}
}

// Read failures activated by a completed disk mutation verify that a recovery
// ACK is not issued from preflight information alone.
type recoveryReadFaultDisk struct {
	StorageAPI
	bucket, object string
	fail           *atomic.Bool
	afterRename    bool
}

func (d recoveryReadFaultDisk) ReadXL(ctx context.Context, bucket, object string, data bool) (RawFileInfo, error) {
	if bucket == d.bucket && object == d.object && d.fail.Load() {
		return RawFileInfo{}, errDiskNotFound
	}
	return d.StorageAPI.ReadXL(ctx, bucket, object, data)
}

func (d recoveryReadFaultDisk) ReadVersion(ctx context.Context, orig, bucket, object, version string, opts ReadOptions) (FileInfo, error) {
	if bucket == d.bucket && object == d.object && d.fail.Load() {
		return FileInfo{}, errDiskNotFound
	}
	return d.StorageAPI.ReadVersion(ctx, orig, bucket, object, version, opts)
}

func (d recoveryReadFaultDisk) RenameData(ctx context.Context, sv, sp string, fi FileInfo, dv, dp string, opts RenameOptions) (RenameDataResp, error) {
	res, err := d.StorageAPI.RenameData(ctx, sv, sp, fi, dv, dp, opts)
	if err == nil && d.afterRename && dv == d.bucket && dp == d.object {
		d.fail.Store(true)
	}
	return res, err
}

func TestPoolsRecoveryRefusesUnresolvedPools(t *testing.T) {
	for _, mode := range []string{"two-inconsistent", "suspended", "rebalancing", "offline", "read-fails-after-commit", "newer-readable-other-copy"} {
		t.Run(mode, func(t *testing.T) {
			z, _ := consistencyPools(t)
			const object = "refused-recovery"
			bucket, router := conditionalPutBucket(t, z, "unversioned")
			for _, pool := range z.serverPools {
				restore := conditionalPutSwapDisks(pool, object, func(d StorageAPI) StorageAPI { return conditionalPutCapacityDisk{StorageAPI: d} })
				defer restore()
			}
			base := time.Now().UTC().Add(-time.Hour)
			old := bytes.Repeat([]byte{'a'}, 8192)
			pending := bytes.Repeat([]byte{'b'}, 8192)
			replacement := bytes.Repeat([]byte{'c'}, 8192)
			inconsistent := func(pool int) {
				t.Helper()
				putConsistencyObject(t, z, bucket, object, pool, string(old), ObjectOptions{MTime: base})
				disks := z.serverPools[pool].getHashedSet(object).getDisks()
				saved := make([][]byte, len(disks))
				for i, d := range disks {
					saved[i] = mustReadNullQuorumMeta(t, d, bucket, object)
				}
				putConsistencyObject(t, z, bucket, object, pool, string(pending), ObjectOptions{MTime: base.Add(time.Minute)})
				for i := 0; i < len(disks)-1; i++ {
					if err := disks[i].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, saved[i]); err != nil {
						t.Fatal(err)
					}
				}
			}
			inconsistent(0)
			otherTime := base.Add(-time.Minute)
			if mode == "newer-readable-other-copy" {
				otherTime = base.Add(2 * time.Hour)
			}
			putConsistencyObject(t, z, bucket, object, 1, string(old), ObjectOptions{MTime: otherTime})
			if mode == "two-inconsistent" {
				inconsistent(1)
			}
			// Select a healthy destination if the resolver incorrectly ignores pool0.
			postCommitFailure := mode == "read-fails-after-commit" || mode == "newer-readable-other-copy"
			if !postCommitFailure {
				restore := conditionalPutPool(t, z, object, 1)
				defer restore()
			}
			if mode == "suspended" {
				z.poolMetaMutex.Lock()
				z.poolMeta.Pools[0].Decommission = &PoolDecommissionInfo{}
				z.poolMetaMutex.Unlock()
			}
			if mode == "rebalancing" {
				z.rebalMu.Lock()
				z.rebalMeta = &rebalanceMeta{PoolStats: []*rebalanceStats{{Participating: true, Info: rebalanceInfo{Status: rebalStarted}}, {}}}
				z.rebalMu.Unlock()
			}
			var fail atomic.Bool
			if mode == "offline" || mode == "read-fails-after-commit" {
				fail.Store(mode == "offline")
				restore := conditionalPutSwapDisks(z.serverPools[0], object, func(d StorageAPI) StorageAPI {
					return recoveryReadFaultDisk{StorageAPI: d, bucket: bucket, object: object, fail: &fail, afterRename: mode == "read-fails-after-commit"}
				})
				defer restore()
			}
			snapshot := func() [][32]byte {
				var result [][32]byte
				for _, pool := range z.serverPools {
					for _, disk := range pool.getHashedSet(object).getDisks() {
						b, err := disk.ReadAll(t.Context(), bucket, object+"/"+xlStorageFormatFile)
						if err != nil {
							t.Fatal(err)
						}
						result = append(result, sha256.Sum256(b))
					}
				}
				return result
			}
			before := snapshot()
			req, err := newTestSignedRequestV4(http.MethodPut, getGetObjectURL("", bucket, object), int64(len(replacement)), bytes.NewReader(replacement), globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			result := httptest.NewRecorder()
			router.ServeHTTP(result, req.WithContext(t.Context()))
			if result.Code != http.StatusServiceUnavailable {
				t.Errorf("unresolved recovery returned HTTP=%d: %s", result.Code, result.Body.String())
			}
			switch {
			case !postCommitFailure:
				after := snapshot()
				for i := range before {
					if before[i] != after[i] {
						t.Errorf("refused preflight modified shard %d", i)
					}
				}
			case mode == "read-fails-after-commit":
				fail.Store(false)
				got := consistencyRequest(t, router, http.MethodGet, bucket, object, "")
				if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), replacement) {
					t.Errorf("read validation failure must not undo committed recovery: HTTP=%d", got.Code)
				}
			default:
				// A readable but different latest copy cannot confirm recovery.
				// The committed replacement must still remain in its target pool.
				r, err := z.serverPools[0].GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(r)
				r.Close()
				if err != nil || !bytes.Equal(body, replacement) {
					t.Fatalf("failed recovery validation must preserve committed data: %v", err)
				}
			}
		})
	}
}
