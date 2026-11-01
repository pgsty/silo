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
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

// Change allocation capacity only; metadata and data use real fixture disks.
// Restoring the adapters also lets encrypted fixtures move the write target
// between requests without changing the production allocation policy.
type conditionalPutCapacityDisk struct {
	StorageAPI
	full bool
}

func (d conditionalPutCapacityDisk) DiskInfo(ctx context.Context, opts DiskInfoOptions) (DiskInfo, error) {
	info, err := d.StorageAPI.DiskInfo(ctx, opts)
	info.Total, info.Used = 1<<40, 0
	if d.full {
		info.Used = info.Total - (1 << 20)
	}
	info.Free = info.Total - info.Used
	return info, err
}

// Keep getDisks immutable while background IAM and storage readers use it.
// GetDisks takes this same mutex when it copies the backing disk list.
func conditionalPutSwapDisks(pool *erasureSets, object string, wrap func(StorageAPI) StorageAPI) func() {
	setIndex := pool.getHashedSet(object).setIndex
	pool.erasureDisksMu.Lock()
	previous := pool.erasureDisks[setIndex]
	disks := append([]StorageAPI(nil), previous...)
	for i, disk := range disks {
		disks[i] = wrap(disk)
	}
	pool.erasureDisks[setIndex] = disks
	pool.erasureDisksMu.Unlock()
	return func() {
		pool.erasureDisksMu.Lock()
		pool.erasureDisks[setIndex] = previous
		pool.erasureDisksMu.Unlock()
	}
}

func conditionalPutPool(t *testing.T, z *erasureServerPools, object string, target int) func() {
	t.Helper()
	var restore []func()
	for i, pool := range z.serverPools {
		restore = append(restore, conditionalPutSwapDisks(pool, object, func(disk StorageAPI) StorageAPI {
			return conditionalPutCapacityDisk{StorageAPI: disk, full: i != target}
		}))
	}
	return func() {
		for _, fn := range restore {
			fn()
		}
	}
}

func conditionalPutBucket(t *testing.T, z *erasureServerPools, mode string) (string, http.Handler) {
	t.Helper()
	bucket, router, err := initAPIHandlerTest(t.Context(), z, nil, MakeBucketOptions{VersioningEnabled: mode != "unversioned"})
	if err != nil {
		t.Fatal(err)
	}
	if mode == "suspended" {
		if _, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig,
			[]byte(`<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`)); err != nil {
			t.Fatal(err)
		}
	}
	return bucket, router
}

func TestPoolsConditionalPutHTTP(t *testing.T) {
	for _, mode := range []string{"unversioned", "versioned", "suspended"} {
		t.Run(mode, func(t *testing.T) {
			z, _ := consistencyPools(t)
			bucket, router := conditionalPutBucket(t, z, mode)
			for target := range 2 {
				for _, tc := range []struct {
					name                  string
					oldCopy, localCurrent bool
					condition             string
					status                int
				}{
					{"stale-etag-accepted", true, false, "old", http.StatusPreconditionFailed},
					{"current-etag-rejected", true, false, "current", http.StatusOK},
					{"create-only-overwrites-other-pool", false, false, "none", http.StatusPreconditionFailed},
					{"current-etag-missing-in-write-pool", false, false, "current", http.StatusOK},
					{"control-current-in-write-pool", true, true, "current", http.StatusOK},
					{"control-stale-etag-rejected", true, true, "old", http.StatusPreconditionFailed},
					{"none-match-current-etag", true, false, "none-current", http.StatusPreconditionFailed},
					{"none-match-old-etag", true, false, "none-old", http.StatusOK},
				} {
					t.Run(fmt.Sprintf("target=%d/%s", target, tc.name), func(t *testing.T) {
						object := fmt.Sprintf("%d-%s", target, tc.name)
						currentPool := 1 - target
						if tc.localCurrent {
							currentPool = target
						}
						opts := ObjectOptions{Versioned: mode == "versioned", VersionSuspended: mode == "suspended", MTime: UTCNow().Add(-time.Hour)}
						oldETag := "absent-old"
						if tc.oldCopy {
							oldETag = putConsistencyObject(t, z, bucket, object, 1-currentPool, "old", opts).ETag
						}
						opts.MTime = UTCNow().Add(-time.Minute)
						current := putConsistencyObject(t, z, bucket, object, currentPool, "current", opts)
						defer conditionalPutPool(t, z, object, target)()
						idx, err := z.getWritePoolIdx(t.Context(), bucket, object, 11, false)
						if err != nil || idx != target {
							t.Fatalf("allocation target=%d: idx=%d err=%v", target, idx, err)
						}
						headers := map[string]string{xhttp.IfMatch: fmt.Sprintf("%q", current.ETag)}
						if tc.condition == "old" {
							headers[xhttp.IfMatch] = fmt.Sprintf("%q", oldETag)
						}
						if tc.condition == "none" {
							headers = map[string]string{xhttp.IfNoneMatch: "*"}
						}
						if tc.condition == "none-current" {
							headers = map[string]string{xhttp.IfNoneMatch: fmt.Sprintf("%q", current.ETag)}
						}
						if tc.condition == "none-old" {
							headers = map[string]string{xhttp.IfNoneMatch: fmt.Sprintf("%q", oldETag)}
						}
						url := getPutObjectURL("", bucket, object)
						before := multipartConditionRequest(t, router, http.MethodGet, url, "", nil)
						if before.Code != http.StatusOK || before.Body.String() != "current" || multipartConditionResponseETag(before) != current.ETag {
							t.Fatalf("invalid current object: %d %q %v", before.Code, before.Body.String(), before.Header())
						}
						put := multipartConditionRequest(t, router, http.MethodPut, url, "replacement", headers)
						if put.Code != tc.status {
							t.Errorf("PUT status=%d want=%d: %s", put.Code, tc.status, put.Body.String())
						}
						if put.Code == http.StatusPreconditionFailed {
							multipartConditionError(t, put, "PreconditionFailed")
							if multipartConditionResponseETag(put) != current.ETag || put.Header().Get(xhttp.LastModified) != before.Header().Get(xhttp.LastModified) {
								t.Errorf("412 headers do not describe current object: %v", put.Header())
							}
						}
						get := multipartConditionRequest(t, router, http.MethodGet, url, "", nil)
						wantBody, wantETag := "current", current.ETag
						if tc.status == http.StatusOK {
							wantBody, wantETag = "replacement", fmt.Sprintf("%x", md5.Sum([]byte("replacement")))
						}
						t.Logf("PUT %d; GET %d bytes=%q ETag=%s", put.Code, get.Code, get.Body.String(), multipartConditionResponseETag(get))
						if get.Code != http.StatusOK || get.Body.String() != wantBody || multipartConditionResponseETag(get) != wantETag {
							t.Errorf("GET=%d bytes=%q ETag=%s; want %q %s", get.Code, get.Body.String(), multipartConditionResponseETag(get), wantBody, wantETag)
						}
					})
				}
			}
		})
	}
}

func TestPoolsConditionalPutHTTPAbsence(t *testing.T) {
	for _, state := range []string{"missing", "uuid-marker", "null-marker"} {
		for _, match := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/match=%t", state, match), func(t *testing.T) {
				z, _ := consistencyPools(t)
				mode := "versioned"
				if state == "null-marker" {
					mode = "suspended"
				}
				bucket, router := conditionalPutBucket(t, z, mode)
				object := "absent-key"
				if state != "missing" {
					putConsistencyObject(t, z, bucket, object, 0, "old", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour)})
					vid := mustGetUUID()
					if state == "null-marker" {
						vid = nullVersionID
					}
					if _, err := z.serverPools[1].DeleteObject(t.Context(), bucket, object, ObjectOptions{Versioned: true, VersionID: vid, DeleteMarker: true, MTime: UTCNow().Add(-time.Minute)}); err != nil {
						t.Fatal(err)
					}
				}
				defer conditionalPutPool(t, z, object, 0)()
				headers := map[string]string{xhttp.IfNoneMatch: "*"}
				want := http.StatusOK
				if match {
					headers = map[string]string{xhttp.IfMatch: "*"}
					want = http.StatusNotFound
				}
				url := getPutObjectURL("", bucket, object)
				put := multipartConditionRequest(t, router, http.MethodPut, url, "new", headers)
				if put.Code != want {
					t.Fatalf("PUT %d want %d: %s", put.Code, want, put.Body.String())
				}
				get := multipartConditionRequest(t, router, http.MethodGet, url, "", nil)
				if match {
					multipartConditionError(t, put, "NoSuchKey")
					if get.Code != http.StatusNotFound {
						t.Fatalf("failed PUT exposed data: %d %s", get.Code, get.Body.String())
					}
				} else if get.Code != http.StatusOK || get.Body.String() != "new" || multipartConditionResponseETag(get) != multipartConditionResponseETag(put) {
					t.Fatalf("successful create GET: %d %q %v", get.Code, get.Body.String(), get.Header())
				}
			})
		}
	}
}

func TestPoolsConditionalPutUnreadable(t *testing.T) {
	for faultPool := range 2 {
		for _, present := range []bool{false, true} {
			for _, match := range []bool{false, true} {
				t.Run(fmt.Sprintf("fault-pool=%d/present=%t/match=%t", faultPool, present, match), func(t *testing.T) {
					z, _ := consistencyPools(t)
					bucket, router := conditionalPutBucket(t, z, "unversioned")
					object := "unreadable-key"
					if present {
						putConsistencyObject(t, z, bucket, object, 0, "old", ObjectOptions{MTime: UTCNow().Add(-time.Hour)})
						putConsistencyObject(t, z, bucket, object, 1, "current", ObjectOptions{MTime: UTCNow().Add(-time.Minute)})
					}
					defer conditionalPutPool(t, z, object, 0)()
					restoreFault := conditionalPutSwapDisks(z.serverPools[faultPool], object, func(disk StorageAPI) StorageAPI {
						return consistencyReadFaultDisk{StorageAPI: disk, bucket: bucket, object: object}
					})
					defer restoreFault()
					headers := map[string]string{xhttp.IfNoneMatch: "*"}
					if match {
						headers = map[string]string{xhttp.IfMatch: "*"}
					}
					url := getPutObjectURL("", bucket, object)
					put := multipartConditionRequest(t, router, http.MethodPut, url, "replacement", headers)
					if put.Code != http.StatusServiceUnavailable {
						t.Errorf("unverified PUT must fail: %d %s", put.Code, put.Body.String())
					}
					called := 0
					_, err := z.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader("replacement"), 11, "", ""), ObjectOptions{HasIfMatch: match, CheckPrecondFn: func(ObjectInfo) bool { called++; return false }})
					if !isErrReadQuorum(err) || called != 0 {
						t.Errorf("lookup error=%v callback calls=%d", err, called)
					}
					restoreFault()
					get := multipartConditionRequest(t, router, http.MethodGet, url, "", nil)
					if present {
						if get.Code != http.StatusOK || get.Body.String() != "current" || multipartConditionResponseETag(get) != fmt.Sprintf("%x", md5.Sum([]byte("current"))) {
							t.Fatalf("failed PUT changed object: %d %q", get.Code, get.Body.String())
						}
					} else if get.Code != http.StatusNotFound {
						t.Fatalf("failed PUT created object: %d %q", get.Code, get.Body.String())
					}
				})
			}
		}
	}
}

func TestPoolsConditionalPutEncryptedETag(t *testing.T) {
	for _, kind := range []string{"SSE-C", "SSE-S3", "SSE-KMS"} {
		t.Run(kind, func(t *testing.T) {
			z, _ := consistencyPools(t)
			bucket, router := conditionalPutBucket(t, z, "unversioned")
			oldKMS, oldTLS := GlobalKMS, globalIsTLS
			GlobalKMS, globalIsTLS = kms.NewStub("conditional-put-key"), true
			defer func() { GlobalKMS, globalIsTLS = oldKMS, oldTLS }()
			headers := map[string]string{xhttp.AmzServerSideEncryption: xhttp.AmzEncryptionAES}
			readHeaders := map[string]string{}
			if kind == "SSE-C" {
				key := bytes.Repeat([]byte{0x42}, 32)
				digest := md5.Sum(key)
				headers = map[string]string{
					xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
					xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
					xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(digest[:]),
				}
				readHeaders = maps.Clone(headers)
			}
			if kind == "SSE-KMS" {
				headers[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionKMS
				headers[xhttp.AmzServerSideEncryptionKmsID] = "conditional-put-key"
			}
			object := "encrypted-key"
			url := getPutObjectURL("", bucket, object)
			restore := conditionalPutPool(t, z, object, 0)
			old := multipartConditionRequest(t, router, http.MethodPut, url, "old", headers)
			restore()
			restore = conditionalPutPool(t, z, object, 1)
			current := multipartConditionRequest(t, router, http.MethodPut, url, "current", headers)
			restore()
			if old.Code != http.StatusOK || current.Code != http.StatusOK {
				t.Fatalf("encrypted setup: %d %s / %d %s", old.Code, old.Body.String(), current.Code, current.Body.String())
			}
			defer conditionalPutPool(t, z, object, 0)()
			for _, stale := range []bool{true, false} {
				h := maps.Clone(headers)
				h[xhttp.IfMatch] = fmt.Sprintf("%q", multipartConditionResponseETag(current))
				wantStatus, wantBody, wantETag := http.StatusOK, "replacement", ""
				if stale {
					h[xhttp.IfMatch] = fmt.Sprintf("%q", multipartConditionResponseETag(old))
					wantStatus, wantBody, wantETag = http.StatusPreconditionFailed, "current", multipartConditionResponseETag(current)
				}
				put := multipartConditionRequest(t, router, http.MethodPut, url, "replacement", h)
				if put.Code != wantStatus {
					t.Fatalf("encrypted condition: %d want %d: %s", put.Code, wantStatus, put.Body.String())
				}
				if !stale {
					wantETag = multipartConditionResponseETag(put)
				}
				get := multipartConditionRequest(t, router, http.MethodGet, url, "", readHeaders)
				if get.Code != http.StatusOK || get.Body.String() != wantBody || multipartConditionResponseETag(get) != wantETag {
					t.Fatalf("encrypted GET: %d %q %v", get.Code, get.Body.String(), get.Header())
				}
			}
		})
	}
}

func TestPoolsConditionalPutVersionSelection(t *testing.T) {
	for _, kind := range []string{"public-version", "replica", "replica-preserve-etag", "movement", "no-lock", "tie", "draining"} {
		t.Run(kind, func(t *testing.T) {
			z, bucket := consistencyPools(t)
			object := "version-selection"
			addressed := putConsistencyObject(t, z, bucket, object, 1, "addressed", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour)})
			current := putConsistencyObject(t, z, bucket, object, 1, "current", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Minute)})
			opts := ObjectOptions{Versioned: true, VersionID: addressed.VersionID, HasIfMatch: true}
			want := current
			switch kind {
			case "replica":
				opts.ReplicaLockReconcile, opts.ReplicationRequest = true, true
				want = addressed
			case "replica-preserve-etag":
				opts.PreserveETag = addressed.ETag
				opts.ReplicaLockReconcile, opts.ReplicationRequest = true, true
				want = addressed
			case "movement":
				opts.DataMovement, opts.SrcPoolIdx, opts.MTime = true, 1, addressed.ModTime
				want = addressed
			case "tie":
				want = putConsistencyObject(t, z, bucket, object, 0, "tie-winner", ObjectOptions{Versioned: true, MTime: current.ModTime})
			case "draining":
				z.poolMetaMutex.Lock()
				z.poolMeta.Pools[1].Decommission = &PoolDecommissionInfo{}
				z.poolMetaMutex.Unlock()
			}
			defer conditionalPutPool(t, z, object, 0)()
			ctx := t.Context()
			if kind == "no-lock" {
				lk := z.NewNSLock(bucket, object)
				lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
				if err != nil {
					t.Fatal(err)
				}
				defer lk.Unlock(lkctx)
				ctx, opts.NoLock = lkctx.Context(), true
			}
			called := 0
			opts.UserDefined = make(map[string]string)
			opts.CheckPrecondFn = func(oi ObjectInfo) bool {
				called++
				if oi.ETag != want.ETag || oi.VersionID != want.VersionID {
					t.Errorf("comparison ETag/version=%s/%s want %s/%s", oi.ETag, oi.VersionID, want.ETag, want.VersionID)
				}
				return oi.ETag != want.ETag
			}
			oi, err := z.PutObject(ctx, bucket, object, mustGetPutObjReader(t, strings.NewReader("replacement"), 11, "", ""), opts)
			if err != nil || called != 1 {
				t.Fatalf("PUT err=%v callback calls=%d", err, called)
			}
			if oi.VersionID != addressed.VersionID {
				t.Fatalf("destination version changed: %s", oi.VersionID)
			}
			if opts.PreserveETag != "" && oi.ETag != opts.PreserveETag {
				t.Fatalf("PreserveETag changed: %s", oi.ETag)
			}
		})
	}
}

func TestPoolsConditionalPutReplicaDuplicateHTTP(t *testing.T) {
	for _, null := range []bool{false, true} {
		t.Run(fmt.Sprintf("null=%t", null), func(t *testing.T) {
			z, _ := consistencyPools(t)
			bucket, router := conditionalPutBucket(t, z, "versioned")
			object := "replica-duplicate"
			vid := mustGetUUID()
			if null {
				vid = nullVersionID
			}
			addressed := putConsistencyObject(t, z, bucket, object, 1, "addressed", ObjectOptions{Versioned: true, VersionID: vid, MTime: UTCNow().Add(-time.Hour)})
			current := putConsistencyObject(t, z, bucket, object, 1, "current", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Minute)})
			defer conditionalPutPool(t, z, object, 0)()
			headers := map[string]string{
				xhttp.MinIOSourceReplicationRequest: "true",
				xhttp.AmzBucketReplicationStatus:    "REPLICA",
				xhttp.MinIOSourceETag:               addressed.ETag,
				xhttp.MinIOSourceMTime:              addressed.ModTime.Format(time.RFC3339Nano),
			}
			url := getPutObjectURL("", bucket, object)
			put := multipartConditionRequest(t, router, http.MethodPut, url+"?versionId="+vid, "addressed", headers)
			if put.Code != http.StatusPreconditionFailed {
				t.Fatalf("replica duplicate: %d %s", put.Code, put.Body.String())
			}
			multipartConditionError(t, put, "PreconditionFailed")
			get := multipartConditionRequest(t, router, http.MethodGet, url, "", nil)
			if get.Code != http.StatusOK || get.Body.String() != "current" || multipartConditionResponseETag(get) != current.ETag {
				t.Fatalf("duplicate changed current object: %d %q", get.Code, get.Body.String())
			}
			get = multipartConditionRequest(t, router, http.MethodGet, url+"?versionId="+vid, "", nil)
			if get.Code != http.StatusOK || get.Body.String() != "addressed" || multipartConditionResponseETag(get) != addressed.ETag {
				t.Fatalf("duplicate changed addressed version: %d %q", get.Code, get.Body.String())
			}
		})
	}
}

func TestPoolsConditionalPutConcurrentHTTP(t *testing.T) {
	z, _ := consistencyPools(t)
	bucket, router := conditionalPutBucket(t, z, "unversioned")
	for _, match := range []bool{false, true} {
		for iteration := range 5 {
			t.Run(fmt.Sprintf("match=%t/iteration=%d", match, iteration), func(t *testing.T) {
				object := fmt.Sprintf("concurrent-%t-%d", match, iteration)
				headers := map[string]string{xhttp.IfNoneMatch: "*"}
				if match {
					oi := putConsistencyObject(t, z, bucket, object, 1, "old", ObjectOptions{MTime: UTCNow().Add(-time.Minute)})
					headers = map[string]string{xhttp.IfMatch: fmt.Sprintf("%q", oi.ETag)}
				}
				defer conditionalPutPool(t, z, object, 0)()
				start := make(chan struct{})
				results := make(chan *httptest.ResponseRecorder, 2)
				url := getPutObjectURL("", bucket, object)
				for i := range 2 {
					body := fmt.Sprintf("writer-%d", i)
					req, err := newTestSignedRequestV4(http.MethodPut, url, int64(len(body)), strings.NewReader(body), globalActiveCred.AccessKey, globalActiveCred.SecretKey, headers)
					if err != nil {
						t.Fatal(err)
					}
					go func() {
						<-start
						rec := httptest.NewRecorder()
						router.ServeHTTP(rec, req)
						results <- rec
					}()
				}
				close(start)
				success, failed, winnerETag := 0, 0, ""
				for range 2 {
					result := <-results
					switch result.Code {
					case http.StatusOK:
						success++
						winnerETag = multipartConditionResponseETag(result)
					case http.StatusPreconditionFailed:
						failed++
						multipartConditionError(t, result, "PreconditionFailed")
					default:
						t.Errorf("unexpected PUT %d: %s", result.Code, result.Body.String())
					}
				}
				if success != 1 || failed != 1 {
					t.Fatalf("success=%d precondition failures=%d", success, failed)
				}
				get := multipartConditionRequest(t, router, http.MethodGet, url, "", nil)
				if get.Code != http.StatusOK || multipartConditionResponseETag(get) != winnerETag || fmt.Sprintf("%x", md5.Sum(get.Body.Bytes())) != winnerETag {
					t.Fatalf("winner lost: %d %q %v", get.Code, get.Body.String(), get.Header())
				}
			})
		}
	}
}

func TestPoolsConditionalPutSerializesMutation(t *testing.T) {
	for _, deletion := range []bool{false, true} {
		t.Run(fmt.Sprintf("delete=%t", deletion), func(t *testing.T) {
			z, bucket := consistencyPools(t)
			object := "conditional-mutation"
			current := putConsistencyObject(t, z, bucket, object, 1, "current", ObjectOptions{MTime: UTCNow().Add(-time.Minute)})
			defer conditionalPutPool(t, z, object, 0)()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate := &consistencyGateReader{Reader: strings.NewReader("replacement"), entered: make(chan struct{}), resume: make(chan struct{})}
			release := func() { gate.release.Do(func() { close(gate.resume) }) }
			defer release()
			reader := mustGetPutObjReader(t, gate, 11, "", "")
			written := make(chan error, 1)
			go func() {
				_, err := z.PutObject(ctx, bucket, object, reader, ObjectOptions{HasIfMatch: true, CheckPrecondFn: func(oi ObjectInfo) bool { return oi.ETag != current.ETag }})
				written <- err
			}()
			select {
			case <-gate.entered:
			case err := <-written:
				t.Fatalf("PUT failed before body read: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			mutated := make(chan error, 1)
			go func() {
				var err error
				if deletion {
					_, err = z.DeleteObject(ctx, bucket, object, ObjectOptions{})
				} else {
					_, err = z.PutObjectMetadata(ctx, bucket, object, ObjectOptions{EvalMetadataFn: func(oi *ObjectInfo, _ error) (ReplicateDecision, error) {
						oi.UserDefined["x-amz-meta-after-put"] = "present"
						return ReplicateDecision{}, nil
					}})
				}
				mutated <- err
			}()
			select {
			case err := <-mutated:
				t.Fatalf("mutation escaped PUT lock: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			release()
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if err := <-mutated; err != nil {
				t.Fatal(err)
			}
			oi, err := z.GetObjectInfo(ctx, bucket, object, ObjectOptions{})
			if deletion {
				if !isErrObjectNotFound(err) {
					t.Fatalf("delete lost: %v", err)
				}
			} else if err != nil || oi.UserDefined["x-amz-meta-after-put"] != "present" || oi.ETag != fmt.Sprintf("%x", md5.Sum([]byte("replacement"))) {
				t.Fatalf("metadata/PUT lost: %+v %v", oi, err)
			}
		})
	}
}

func TestSinglePoolConditionalPutHTTP(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	obj, dirs, err := prepareErasure16(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	t.Cleanup(func() { cancel(); z.Shutdown(context.Background()); removeRoots(dirs) })
	if !z.SinglePool() {
		t.Fatal("fixture is not a single pool")
	}
	bucket, router := conditionalPutBucket(t, z, "unversioned")
	object := "single-pool-condition"
	defer conditionalPutPool(t, z, object, 0)()
	url := getPutObjectURL("", bucket, object)
	for _, tc := range []struct {
		body, match, none string
		status            int
	}{
		{"missing", "*", "", http.StatusNotFound},
		{"first", "", "*", http.StatusOK},
		{"blocked", "", "*", http.StatusPreconditionFailed},
		{"blocked", "stale", "", http.StatusPreconditionFailed},
		{"second", fmt.Sprintf("%x", md5.Sum([]byte("first"))), "", http.StatusOK},
	} {
		rec := multipartConditionRequest(t, router, http.MethodPut, url, tc.body, map[string]string{xhttp.IfMatch: tc.match, xhttp.IfNoneMatch: tc.none})
		if rec.Code != tc.status {
			t.Fatalf("PUT %d want %d: %s", rec.Code, tc.status, rec.Body.String())
		}
	}
	get := multipartConditionRequest(t, router, http.MethodGet, url, "", nil)
	if get.Code != http.StatusOK || get.Body.String() != "second" {
		t.Fatalf("single-pool GET: %d %q", get.Code, get.Body.String())
	}
}

// An internal replica callback without an addressed version is not a public
// condition. Preserve its availability when another pool is unreadable. An
// addressed replica already requires all pools for lock/tag reconciliation.
func TestPoolsConditionalPutReplicaAvailability(t *testing.T) {
	for _, addressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("addressed=%t", addressed), func(t *testing.T) {
			z, _ := consistencyPools(t)
			mode := "unversioned"
			if addressed {
				mode = "versioned"
			}
			bucket, router := conditionalPutBucket(t, z, mode)
			object := "replica-availability"
			oi := putConsistencyObject(t, z, bucket, object, 0, "old", ObjectOptions{Versioned: addressed, MTime: UTCNow().Add(-time.Minute)})
			defer conditionalPutPool(t, z, object, 0)()
			restoreFault := conditionalPutSwapDisks(z.serverPools[1], object, func(disk StorageAPI) StorageAPI {
				return consistencyReadFaultDisk{StorageAPI: disk, bucket: bucket, object: object}
			})
			defer restoreFault()
			headers := map[string]string{
				xhttp.MinIOSourceReplicationRequest: "true",
				xhttp.AmzBucketReplicationStatus:    "REPLICA",
				xhttp.MinIOSourceETag:               fmt.Sprintf("%x", md5.Sum([]byte("replacement"))),
			}
			url := getPutObjectURL("", bucket, object)
			wantStatus, wantBody := http.StatusOK, "replacement"
			if addressed {
				url += "?versionId=" + oi.VersionID
				wantStatus, wantBody = http.StatusServiceUnavailable, "old"
			}
			put := multipartConditionRequest(t, router, http.MethodPut, url, "replacement", headers)
			if put.Code != wantStatus {
				t.Fatalf("replica PUT: %d want %d: %s", put.Code, wantStatus, put.Body.String())
			}
			restoreFault()
			get := multipartConditionRequest(t, router, http.MethodGet, url, "", nil)
			if get.Code != http.StatusOK || get.Body.String() != wantBody {
				t.Fatalf("replica GET: %d %q", get.Code, get.Body.String())
			}
		})
	}
}

// A public client cannot address a destination version, with or without a
// precondition; only trusted replication may (SN-2026-016).
func TestPoolsConditionalPutDestinationVersionHTTP(t *testing.T) {
	z, _ := consistencyPools(t)
	bucket, router := conditionalPutBucket(t, z, "versioned")
	object := "client-version"
	old := putConsistencyObject(t, z, bucket, object, 0, "old", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour)})
	current := putConsistencyObject(t, z, bucket, object, 1, "current", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Minute)})
	defer conditionalPutPool(t, z, object, 0)()
	url := getPutObjectURL("", bucket, object) + "?versionId=" + old.VersionID
	for _, tag := range []string{old.ETag, current.ETag} {
		put := multipartConditionRequest(t, router, http.MethodPut, url, "replacement", map[string]string{xhttp.IfMatch: fmt.Sprintf("%q", tag)})
		if put.Code != http.StatusForbidden {
			t.Fatalf("version-addressed public PUT: %d want 403: %s", put.Code, put.Body.String())
		}
	}
	get := multipartConditionRequest(t, router, http.MethodGet, url, "", nil)
	if get.Code != http.StatusOK || get.Body.String() != "old" {
		t.Fatalf("addressed GET: %d %q", get.Code, get.Body.String())
	}
}

func TestPoolsConditionalPutDeleteMarkerTie(t *testing.T) {
	for markerPool := range 2 {
		t.Run(fmt.Sprintf("marker-pool=%d", markerPool), func(t *testing.T) {
			z, _ := consistencyPools(t)
			bucket, router := conditionalPutBucket(t, z, "versioned")
			object := "marker-tie"
			mtime := UTCNow().Add(-time.Minute)
			putConsistencyObject(t, z, bucket, object, 1-markerPool, "live", ObjectOptions{Versioned: true, MTime: mtime})
			if _, err := z.serverPools[markerPool].DeleteObject(t.Context(), bucket, object, ObjectOptions{Versioned: true, VersionID: mustGetUUID(), DeleteMarker: true, MTime: mtime}); err != nil {
				t.Fatal(err)
			}
			defer conditionalPutPool(t, z, object, 0)()
			url := getPutObjectURL("", bucket, object)
			before := multipartConditionRequest(t, router, http.MethodGet, url, "", nil)
			want := http.StatusPreconditionFailed
			if markerPool == 0 {
				want = http.StatusOK
				if before.Code != http.StatusNotFound {
					t.Fatalf("GET tie: %d", before.Code)
				}
			} else if before.Code != http.StatusOK {
				t.Fatalf("GET tie: %d", before.Code)
			}
			put := multipartConditionRequest(t, router, http.MethodPut, url, "replacement", map[string]string{xhttp.IfNoneMatch: "*"})
			if put.Code != want {
				t.Fatalf("PUT tie: %d want %d: %s", put.Code, want, put.Body.String())
			}
		})
	}
}

// Overlap fixture changes with the real IAM Walk reader instead of relying on
// its periodic refresh timer to expose an unsynchronized disk-adapter swap.
func TestPoolsConditionalPutFixtureConcurrentIAM(t *testing.T) {
	z, _ := consistencyPools(t)
	conditionalPutBucket(t, z, "unversioned")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	started, finished := make(chan struct{}), make(chan error, 1)
	iam := globalIAMSys
	go func() {
		close(started)
		for range 20 {
			if err := iam.Load(ctx, false); err != nil {
				finished <- err
				return
			}
		}
		finished <- nil
	}()
	<-started
	for i := range 5000 {
		restore := conditionalPutPool(t, z, "fixture-concurrent-iam", i%2)
		restore()
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
