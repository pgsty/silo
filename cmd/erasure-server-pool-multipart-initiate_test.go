// Copyright (c) 2026 Denis Babchuk
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
	"fmt"
	"net/http"
	"slices"
	"strings"
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
