// Copyright (c) 2026 Denis Babchuk
// Copyright (c) 2026 Feng Ruohang
//
// This file is part of Silo Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	xhttp "github.com/minio/minio/internal/http"
)

// multipartInitiateUploads returns the number of pending uploads of object in
// each pool.
func multipartInitiateUploads(t *testing.T, z *erasureServerPools, bucket, object string) []int {
	t.Helper()
	counts := make([]int, len(z.serverPools))
	for i, pool := range z.serverPools {
		res, err := pool.listMultipartUploadsExact(t.Context(), bucket, object)
		if err != nil {
			t.Fatal(err)
		}
		counts[i] = len(res.Uploads)
	}
	return counts
}

// A multi-pool NewMultipartUpload goes to the pool of a pending upload of the
// key or, without one, to the pool chosen by capacity. Neither has to hold the
// current object, so a condition sent with the initiate must be evaluated
// against the current object across pools, as for PUT and completion.
// Routing itself does not change: an accepted upload lands in the same pool.
// Allocation follows a current delete marker to its pool, so a stale version
// under a marker in another pool is reached only through a pending upload.
func TestPoolsMultipartConditionalInitiateHTTP(t *testing.T) {
	const wrongETag = "ffffffffffffffffffffffffffffffff"
	for _, mode := range []string{"unversioned", "versioned"} {
		t.Run(mode, func(t *testing.T) {
			z, _ := consistencyPools(t)
			bucket, router := conditionalPutBucket(t, z, mode)
			versioned := mode == "versioned"
			for _, route := range []string{"pending-upload", "allocation"} {
				for target := range 2 {
					for _, layout := range []string{"current-in-other-pool", "stale-copy-in-target", "marker-in-other-pool", "control-current-in-target"} {
						if layout == "marker-in-other-pool" && (!versioned || route == "allocation") {
							continue
						}
						for _, cond := range []string{"if-match-current", "if-match-any", "if-match-stale", "if-none-match-any"} {
							t.Run(fmt.Sprintf("%s/target=%d/%s/%s", route, target, layout, cond), func(t *testing.T) {
								object := fmt.Sprintf("%s-%d-%s-%s", route, target, layout, cond)
								other := 1 - target
								opts := func(age time.Duration) ObjectOptions {
									return ObjectOptions{Versioned: versioned, MTime: UTCNow().Add(-age)}
								}
								present, staleETag := true, wrongETag
								var current ObjectInfo
								switch layout {
								case "current-in-other-pool":
									current = putConsistencyObject(t, z, bucket, object, other, "current", opts(time.Minute))
								case "stale-copy-in-target":
									staleETag = putConsistencyObject(t, z, bucket, object, target, "stale", opts(time.Hour)).ETag
									current = putConsistencyObject(t, z, bucket, object, other, "current", opts(time.Minute))
								case "marker-in-other-pool":
									// The client knows the version under the marker.
									current = putConsistencyObject(t, z, bucket, object, target, "deleted", opts(time.Hour))
									if _, err := z.serverPools[other].DeleteObject(t.Context(), bucket, object, ObjectOptions{Versioned: true, VersionID: mustGetUUID(), DeleteMarker: true, MTime: UTCNow().Add(-time.Minute)}); err != nil {
										t.Fatal(err)
									}
									present = false
								case "control-current-in-target":
									staleETag = putConsistencyObject(t, z, bucket, object, other, "stale", opts(time.Hour)).ETag
									current = putConsistencyObject(t, z, bucket, object, target, "current", opts(time.Minute))
								}

								before := make([]int, len(z.serverPools))
								if route == "pending-upload" {
									if _, err := z.serverPools[target].NewMultipartUpload(t.Context(), bucket, object, ObjectOptions{Versioned: versioned}); err != nil {
										t.Fatal(err)
									}
									before[target] = 1
								} else {
									defer conditionalPutPool(t, z, object, target)()
									if idx, err := z.getWritePoolIdx(t.Context(), bucket, object, -1, false); err != nil || idx != target {
										t.Fatalf("allocation target=%d: idx=%d err=%v", target, idx, err)
									}
								}

								var headers map[string]string
								switch cond {
								case "if-match-current":
									headers = map[string]string{xhttp.IfMatch: fmt.Sprintf("%q", current.ETag)}
								case "if-match-any":
									headers = map[string]string{xhttp.IfMatch: "*"}
								case "if-match-stale":
									headers = map[string]string{xhttp.IfMatch: fmt.Sprintf("%q", staleETag)}
								case "if-none-match-any":
									headers = map[string]string{xhttp.IfNoneMatch: "*"}
								}
								want := http.StatusOK
								switch {
								case !present && strings.HasPrefix(cond, "if-match"):
									want = http.StatusNotFound
								case !present:
								case cond == "if-match-stale", cond == "if-none-match-any":
									want = http.StatusPreconditionFailed
								}

								rec := multipartConditionRequest(t, router, http.MethodPost, getNewMultipartURL("", bucket, object), "", headers)
								after := multipartInitiateUploads(t, z, bucket, object)
								t.Logf("initiate %v: HTTP %d, uploads per pool %v -> %v", headers, rec.Code, before, after)
								if rec.Code != want {
									t.Errorf("initiate HTTP %d, want %d: %s", rec.Code, want, rec.Body.String())
								}
								wantAfter := slices.Clone(before)
								if want == http.StatusOK {
									wantAfter[target]++
								}
								if !slices.Equal(after, wantAfter) {
									t.Errorf("uploads per pool %v, want %v", after, wantAfter)
								}
								if rec.Code != want {
									return
								}
								switch want {
								case http.StatusPreconditionFailed:
									multipartConditionError(t, rec, "PreconditionFailed")
									if etag := multipartConditionResponseETag(rec); etag != current.ETag {
										t.Errorf("412 describes ETag %s, want the current %s", etag, current.ETag)
									}
								case http.StatusNotFound:
									multipartConditionError(t, rec, "NoSuchKey")
								}
							})
						}
					}
				}
			}
		})
	}
}

// A pool that cannot be read may hold the newest object, so the condition
// cannot be evaluated even when the upload goes to a readable pool.
func TestPoolsMultipartConditionalInitiateUnreadable(t *testing.T) {
	z, _ := consistencyPools(t)
	bucket, router := conditionalPutBucket(t, z, "unversioned")
	for faultPool := range 2 {
		for _, match := range []bool{false, true} {
			t.Run(fmt.Sprintf("fault-pool=%d/match=%t", faultPool, match), func(t *testing.T) {
				object := fmt.Sprintf("unreadable-%d-%t", faultPool, match)
				putConsistencyObject(t, z, bucket, object, 0, "stale", ObjectOptions{MTime: UTCNow().Add(-time.Hour)})
				putConsistencyObject(t, z, bucket, object, 1, "current", ObjectOptions{MTime: UTCNow().Add(-time.Minute)})
				defer conditionalPutPool(t, z, object, 0)()
				defer conditionalPutSwapDisks(z.serverPools[faultPool], object, func(disk StorageAPI) StorageAPI {
					return consistencyReadFaultDisk{StorageAPI: disk, bucket: bucket, object: object}
				})()
				headers := map[string]string{xhttp.IfNoneMatch: "*"}
				if match {
					headers = map[string]string{xhttp.IfMatch: "*"}
				}
				rec := multipartConditionRequest(t, router, http.MethodPost, getNewMultipartURL("", bucket, object), "", headers)
				if rec.Code != http.StatusServiceUnavailable {
					t.Errorf("unverified initiate must fail: HTTP %d: %s", rec.Code, rec.Body.String())
				}
				called := 0
				_, err := z.NewMultipartUpload(t.Context(), bucket, object, ObjectOptions{HasIfMatch: match, CheckPrecondFn: func(ObjectInfo) bool { called++; return false }})
				if !isErrReadQuorum(err) || called != 0 {
					t.Errorf("initiate error=%v, callback calls=%d", err, called)
				}
				if n := multipartInitiateUploads(t, z, bucket, object); !slices.Equal(n, []int{0, 0}) {
					t.Errorf("uploads per pool %v after failed initiates", n)
				}
			})
		}
	}
}

type multipartInitiateMetadataGate struct {
	entered, resume chan struct{}
	once            sync.Once
}

type multipartInitiateMetadataDisk struct {
	StorageAPI
	gate *multipartInitiateMetadataGate
}

func (d multipartInitiateMetadataDisk) WriteMetadata(ctx context.Context, orig, volume, path string, fi FileInfo) error {
	if volume == minioMetaMultipartBucket {
		d.gate.once.Do(func() { close(d.gate.entered) })
		select {
		case <-d.gate.resume:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return d.StorageAPI.WriteMetadata(ctx, orig, volume, path, fi)
}

// The pools-layer lock must cover placement of the upload, not just reading
// the current object. Pause the metadata write after the condition passed and
// require a concurrent public overwrite or delete to wait for that placement.
func TestPoolsMultipartConditionalInitiateHoldsLockThroughPersistence(t *testing.T) {
	for _, mutation := range []string{"overwrite", "delete"} {
		t.Run(mutation, func(t *testing.T) {
			z, bucket := consistencyPools(t)
			object := "locked-initiate"
			current := putConsistencyObject(t, z, bucket, object, 1, "current", ObjectOptions{})
			if _, err := z.serverPools[0].NewMultipartUpload(t.Context(), bucket, object, ObjectOptions{}); err != nil {
				t.Fatal(err)
			}
			gate := &multipartInitiateMetadataGate{entered: make(chan struct{}), resume: make(chan struct{})}
			restoreDisks := conditionalPutSwapDisks(z.serverPools[0], object, func(d StorageAPI) StorageAPI {
				return multipartInitiateMetadataDisk{StorageAPI: d, gate: gate}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			var workers sync.WaitGroup
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(gate.resume) }) }
			defer func() {
				release()
				cancel()
				workers.Wait()
				restoreDisks()
			}()

			initiated := make(chan error, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				_, err := z.NewMultipartUpload(ctx, bucket, object, ObjectOptions{
					HasIfMatch: true,
					CheckPrecondFn: func(oi ObjectInfo) bool {
						return oi.ETag != current.ETag
					},
				})
				initiated <- err
			}()
			select {
			case <-gate.entered:
			case err := <-initiated:
				t.Fatalf("initiate returned before persistence: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}

			mutated := make(chan error, 1)
			started := make(chan struct{})
			reader := mustGetPutObjReader(t, strings.NewReader("new"), 3, "", "")
			workers.Add(1)
			go func() {
				defer workers.Done()
				close(started)
				var err error
				if mutation == "delete" {
					_, err = z.DeleteObject(ctx, bucket, object, ObjectOptions{})
				} else {
					_, err = z.PutObject(ctx, bucket, object, reader, ObjectOptions{})
				}
				mutated <- err
			}()
			<-started
			select {
			case err := <-mutated:
				t.Fatalf("mutation escaped initiate lock: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			release()
			for _, result := range []<-chan error{initiated, mutated} {
				select {
				case err := <-result:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
		})
	}
}

// Initiate only checks the current state; it does not reserve the object or
// persist a condition for completion. Completion must carry its own condition,
// compares ETags rather than object generations, and leaves parts available
// for retry when a condition fails.
func TestPoolsMultipartConditionalInitiateLifecycle(t *testing.T) {
	z, _ := consistencyPools(t)
	bucket, router := conditionalPutBucket(t, z, "unversioned")
	for _, change := range []string{"overwrite", "delete", "recreate-same-etag", "omit-complete-condition"} {
		t.Run(change, func(t *testing.T) {
			object := "lifecycle-" + change
			current := putConsistencyObject(t, z, bucket, object, 1, "original", ObjectOptions{})
			defer conditionalPutPool(t, z, object, 0)()
			headers := map[string]string{xhttp.IfMatch: fmt.Sprintf("%q", current.ETag)}
			initiate := multipartConditionRequest(t, router, http.MethodPost, getNewMultipartURL("", bucket, object), "", headers)
			if initiate.Code != http.StatusOK {
				t.Fatalf("initiate: %d %s", initiate.Code, initiate.Body.String())
			}
			var upload InitiateMultipartUploadResponse
			if err := xml.Unmarshal(initiate.Body.Bytes(), &upload); err != nil || upload.UploadID == "" {
				t.Fatalf("upload ID: %v %s", err, initiate.Body.String())
			}
			const finalBody = "multipart-final"
			part, err := z.PutObjectPart(t.Context(), bucket, object, upload.UploadID, 1,
				mustGetPutObjReader(t, strings.NewReader(finalBody), int64(len(finalBody)), "", ""), ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if change == "delete" || change == "recreate-same-etag" {
				if _, err := z.DeleteObject(t.Context(), bucket, object, ObjectOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			if change != "delete" {
				body := "concurrent"
				if change == "recreate-same-etag" {
					body = "original"
				}
				if _, err := z.PutObject(t.Context(), bucket, object,
					mustGetPutObjReader(t, strings.NewReader(body), int64(len(body)), "", ""), ObjectOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			if change == "omit-complete-condition" {
				headers = nil
			}
			url := getCompleteMultipartUploadURL("", bucket, object, upload.UploadID)
			body := multipartConditionCompleteBody([]CompletePart{{PartNumber: 1, ETag: part.ETag}})
			complete := multipartConditionRequest(t, router, http.MethodPost, url, body, headers)
			want := http.StatusOK
			if change == "overwrite" {
				want = http.StatusPreconditionFailed
			}
			if change == "delete" {
				want = http.StatusNotFound
			}
			if complete.Code != want {
				t.Fatalf("complete: %d, want %d: %s", complete.Code, want, complete.Body.String())
			}
			if want != http.StatusOK {
				parts, err := z.ListObjectParts(t.Context(), bucket, object, upload.UploadID, 0, 100, ObjectOptions{})
				if err != nil || len(parts.Parts) != 1 || parts.Parts[0].ETag != part.ETag {
					t.Fatalf("failed condition consumed upload: %v %+v", err, parts)
				}
				if change == "overwrite" {
					oi, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{})
					if err != nil {
						t.Fatal(err)
					}
					headers = map[string]string{xhttp.IfMatch: fmt.Sprintf("%q", oi.ETag)}
				} else {
					headers = map[string]string{xhttp.IfNoneMatch: "*"}
				}
				complete = multipartConditionRequest(t, router, http.MethodPost, url, body, headers)
				if complete.Code != http.StatusOK {
					t.Fatalf("retry with new condition: %d %s", complete.Code, complete.Body.String())
				}
			}
			get := multipartConditionRequest(t, router, http.MethodGet, getGetObjectURL("", bucket, object), "", nil)
			if get.Code != http.StatusOK || get.Body.String() != finalBody {
				t.Fatalf("committed body: %d %q", get.Code, get.Body.String())
			}
		})
	}
}
