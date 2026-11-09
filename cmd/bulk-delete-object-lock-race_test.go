// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio/internal/bucket/replication"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/mux"
)

// Schedule a protection update immediately before the storage mutation. Both
// public delete entry points are gated so the test is independent of whether
// the handler batches a version or uses the single-object deletion path.
type bulkDeleteLockBarrier struct {
	ObjectLayer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *bulkDeleteLockBarrier) DeleteObjects(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions) ([]DeletedObject, []error) {
	g.wait()
	return g.ObjectLayer.DeleteObjects(ctx, bucket, objects, opts)
}

func (g *bulkDeleteLockBarrier) wait() {
	g.once.Do(func() { close(g.entered); <-g.release })
}

func (g *bulkDeleteLockBarrier) DeleteObject(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	g.wait()
	return g.ObjectLayer.DeleteObject(ctx, bucket, object, opts)
}

func bulkDeleteLockRequest(t *testing.T, bucket, key, version string) *http.Request {
	t.Helper()
	body := encodeResponse(DeleteObjectsRequest{Objects: []ObjectToDelete{{ObjectV: ObjectV{ObjectName: key, VersionID: version}}}})
	req, err := newTestSignedRequestV4(http.MethodPost, getDeleteMultipleObjectsURL("", bucket), int64(len(body)), bytes.NewReader(body), globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	return mux.SetURLVars(req, map[string]string{"bucket": bucket})
}

func TestBulkDeleteObjectLockInterleaving(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, directory := range []bool{false, true} {
			for _, kind := range []string{"legal-hold", "retention"} {
				t.Run(fmt.Sprintf("pools=%d/directory=%v/%s", pools, directory, kind), func(t *testing.T) {
					z, _ := bulkDeletePools(t, pools)
					bucket, router, err := initAPIHandlerTest(t.Context(), z, nil, MakeBucketOptions{VersioningEnabled: true, LockEnabled: true})
					if err != nil {
						t.Fatal(err)
					}
					key := "protection-update"
					if directory {
						key += "/"
					}
					var oi ObjectInfo
					if directory {
						oi, err = z.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewReader(nil), 0, "", ""), ObjectOptions{Versioned: true, VersionID: nullVersionID})
						if err != nil {
							t.Fatal(err)
						}
					} else {
						oi = batchPutVersion(t, z, bucket, key, nil)
					}
					gate := &bulkDeleteLockBarrier{ObjectLayer: z, entered: make(chan struct{}), release: make(chan struct{})}
					api := objectAPIHandlers{ObjectAPI: func() ObjectLayer { return gate }}
					requestVersion := oi.VersionID
					if directory {
						requestVersion = ""
					}
					req := bulkDeleteLockRequest(t, bucket, key, requestVersion)
					rec := httptest.NewRecorder()
					done := make(chan struct{})
					go func() { defer close(done); api.DeleteMultipleObjectsHandler(rec, req) }()
					var release sync.Once
					unblock := func() { release.Do(func() { close(gate.release) }) }
					defer func() {
						unblock()
						select {
						case <-done:
						case <-time.After(10 * time.Second):
							t.Error("delete did not finish")
						}
					}()
					select {
					case <-gate.entered:
					case <-time.After(10 * time.Second):
						t.Fatal("bulk handler did not reach deletion after validation")
					}
					body := []byte(`<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>ON</Status></LegalHold>`)
					if kind == "retention" {
						body = retentionBody("COMPLIANCE", UTCNow().Add(24*time.Hour))
					}
					holdReq, err := newTestSignedRequestV4(http.MethodPut, "/"+bucket+"/"+key+"?"+kind+"&versionId="+url.QueryEscape(oi.VersionID), int64(len(body)), bytes.NewReader(body), globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
					if err != nil {
						t.Fatal(err)
					}
					holdRec := httptest.NewRecorder()
					router.ServeHTTP(holdRec, holdReq)
					protected, getErr := z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: oi.VersionID})
					unblock()
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Fatal("delete did not finish")
					}
					if holdRec.Code != http.StatusOK || getErr != nil {
						t.Fatalf("protection setup failed: status=%d body=%s err=%v", holdRec.Code, holdRec.Body.String(), getErr)
					}
					if kind == "legal-hold" && protected.UserDefined[strings.ToLower(xhttp.AmzObjectLockLegalHold)] != "ON" {
						t.Fatal("legal hold was not stored")
					}
					if kind == "retention" && protected.UserDefined[strings.ToLower(xhttp.AmzObjectLockMode)] != "COMPLIANCE" {
						t.Fatal("retention was not stored")
					}
					var response DeleteObjectsResponse
					if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					exists := batchVersionExists(t, z, bucket, key, oi.VersionID)
					t.Logf("protection PUT=%d; delete POST=%d response=%s; protected_version_exists=%v", holdRec.Code, rec.Code, rec.Body.String(), exists)
					if rec.Code != http.StatusOK || !exists || len(response.Errors) != 1 || len(response.DeletedObjects) != 0 {
						t.Errorf("bulk deletion removed a version after its protection update succeeded")
					}
				})
			}
		}
	}
}

func TestBulkDeleteObjectLockPoolCopies(t *testing.T) {
	for _, kind := range []string{"COMPLIANCE", "LEGALHOLD"} {
		t.Run(kind, func(t *testing.T) {
			z, _ := bulkDeletePools(t, 2)
			bucket, router, err := initAPIHandlerTest(t.Context(), z, nil, MakeBucketOptions{VersioningEnabled: true, LockEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			for _, bulk := range []bool{false, true} {
				key := "single-control"
				if bulk {
					key = "bulk"
				}
				id := mustGetUUID()
				mtime := UTCNow().Add(-time.Hour)
				putConsistencyObject(t, z, bucket, key, 0, "same-data", ObjectOptions{Versioned: true, VersionID: id, MTime: mtime, UserDefined: nil})
				putConsistencyObject(t, z, bucket, key, 1, "same-data", ObjectOptions{Versioned: true, VersionID: id, MTime: mtime, UserDefined: batchLockMeta(kind)})
				selected, err := z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: id})
				if err != nil {
					t.Fatal(err)
				}
				if selected.UserDefined[strings.ToLower(xhttp.AmzObjectLockMode)] != "" || selected.UserDefined[strings.ToLower(xhttp.AmzObjectLockLegalHold)] != "" {
					t.Fatal("fixture did not select the unprotected pool copy")
				}
				req := bulkDeleteLockRequest(t, bucket, key, id)
				if !bulk {
					req, err = newTestSignedRequestV4(http.MethodDelete, getDeleteObjectURL("", bucket, key)+"?versionId="+id, 0, nil, globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
					if err != nil {
						t.Fatal(err)
					}
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if !strings.Contains(rec.Body.String(), "Object is WORM protected") {
					t.Fatalf("expected Object Lock refusal: HTTP %d: %s", rec.Code, rec.Body.String())
				}
				remaining := 0
				for _, pool := range z.serverPools {
					_, err := pool.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: id})
					if err == nil {
						remaining++
					} else if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
						t.Fatal(err)
					}
				}
				t.Logf("bulk=%v HTTP=%d response=%s remaining_pool_copies=%d", bulk, rec.Code, rec.Body.String(), remaining)
				if remaining != 2 {
					t.Errorf("protected version copies removed by bulk=%v", bulk)
				}
			}
		})
	}
}

// One response must retain the identity and outcome of every requested item,
// even when physical version removals and marker creation take different paths.
func TestBulkDeleteObjectLockMixedResponse(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, quiet := range []bool{false, true} {
			t.Run(fmt.Sprintf("pools=%d/quiet=%v", pools, quiet), func(t *testing.T) {
				z, _ := bulkDeletePools(t, pools)
				bucket, router, err := initAPIHandlerTest(t.Context(), z, nil, MakeBucketOptions{VersioningEnabled: true, LockEnabled: true})
				if err != nil {
					t.Fatal(err)
				}
				locked := batchPutVersion(t, z, bucket, "locked", batchLockMeta("COMPLIANCE"))
				free := batchPutVersion(t, z, bucket, "free", nil)
				marker := batchPutVersion(t, z, bucket, "marker", batchLockMeta("LEGALHOLD"))
				if _, err := z.PutObject(t.Context(), bucket, "directory/", mustGetPutObjReader(t, bytes.NewReader(nil), 0, "", ""), ObjectOptions{Versioned: true, VersionID: nullVersionID}); err != nil {
					t.Fatal(err)
				}
				missing := mustGetUUID()
				objects := []ObjectToDelete{
					{ObjectV: ObjectV{ObjectName: "locked", VersionID: locked.VersionID}},
					{ObjectV: ObjectV{ObjectName: "free", VersionID: free.VersionID}},
					{ObjectV: ObjectV{ObjectName: "missing", VersionID: missing}},
					{ObjectV: ObjectV{ObjectName: "marker"}},
					{ObjectV: ObjectV{ObjectName: "directory/"}},
					{ObjectV: ObjectV{ObjectName: "directory/", VersionID: nullVersionID}},
					{ObjectV: ObjectV{ObjectName: "invalid", VersionID: "invalid"}},
				}
				objects = append(objects, objects[0], objects[1])
				body := encodeResponse(DeleteObjectsRequest{Quiet: quiet, Objects: objects})
				rec := r5Request(t, router, globalActiveCred, http.MethodPost, getDeleteMultipleObjectsURL("", bucket), string(body), nil)
				var response DeleteObjectsResponse
				if rec.Code != http.StatusOK || xml.Unmarshal(rec.Body.Bytes(), &response) != nil {
					t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
				}
				wantErrors := []ObjectV{objects[0].ObjectV, objects[6].ObjectV, objects[0].ObjectV}
				if len(response.Errors) != len(wantErrors) {
					t.Fatalf("errors: %+v", response.Errors)
				}
				for i, e := range response.Errors {
					if e.Key != wantErrors[i].ObjectName || e.VersionID != wantErrors[i].VersionID {
						t.Errorf("error identity %d: %+v", i, e)
					}
				}
				if quiet {
					if len(response.DeletedObjects) != 0 {
						t.Errorf("quiet successes: %+v", response.DeletedObjects)
					}
				} else {
					want := []ObjectV{objects[1].ObjectV, objects[2].ObjectV, objects[3].ObjectV, objects[4].ObjectV, objects[5].ObjectV, objects[1].ObjectV}
					if len(response.DeletedObjects) != len(want) {
						t.Fatalf("successes: %+v", response.DeletedObjects)
					}
					for i, d := range response.DeletedObjects {
						if d.ObjectName != want[i].ObjectName || d.VersionID != want[i].VersionID {
							t.Errorf("success identity %d: %+v", i, d)
						}
						if i == 2 && (!d.DeleteMarker || d.DeleteMarkerVersionID == "") {
							t.Errorf("missing delete marker: %+v", d)
						}
					}
				}
				if !batchVersionExists(t, z, bucket, "locked", locked.VersionID) || !batchVersionExists(t, z, bucket, "marker", marker.VersionID) || batchVersionExists(t, z, bucket, "free", free.VersionID) || batchVersionExists(t, z, bucket, "directory/", nullVersionID) {
					t.Fatal("unexpected stored versions after mixed deletion")
				}
			})
		}
	}
}

func TestBulkDeleteObjectLockGovernance(t *testing.T) {
	for _, pools := range []int{1, 2} {
		t.Run(fmt.Sprintf("pools=%d", pools), func(t *testing.T) {
			z, _ := bulkDeletePools(t, pools)
			bucket, router, err := initAPIHandlerTest(t.Context(), z, nil, MakeBucketOptions{VersioningEnabled: true, LockEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			deleteOnly := newObjectAttributesAuthzUser(t, "bulk-governance", bucket, `"s3:DeleteObjectVersion"`)
			for _, allowed := range []bool{false, true} {
				for _, bypass := range []bool{false, true} {
					key := fmt.Sprintf("allowed-%v-bypass-%v", allowed, bypass)
					oi := batchPutVersion(t, z, bucket, key, batchLockMeta("GOVERNANCE"))
					cred := deleteOnly
					if allowed {
						cred = globalActiveCred
					}
					body := encodeResponse(DeleteObjectsRequest{Objects: []ObjectToDelete{{ObjectV: ObjectV{ObjectName: key, VersionID: oi.VersionID}}}})
					header := map[string]string{}
					if bypass {
						header[xhttp.AmzObjectLockBypassGovernance] = "true"
					}
					rec := r5Request(t, router, cred, http.MethodPost, getDeleteMultipleObjectsURL("", bucket), string(body), header)
					var response DeleteObjectsResponse
					if rec.Code != http.StatusOK || xml.Unmarshal(rec.Body.Bytes(), &response) != nil {
						t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
					}
					deleted := allowed && bypass
					if batchVersionExists(t, z, bucket, key, oi.VersionID) == deleted || (len(response.Errors) == 0) != deleted {
						t.Fatalf("%s: %s", key, rec.Body.String())
					}
				}
			}
		})
	}
}

// The locked path computes replication decisions while holding the mutation
// lock. Keep pending purges and their queue entries, including duplicate input.
func TestBulkDeleteObjectLockReplication(t *testing.T) {
	for _, pools := range []int{1, 2} {
		t.Run(fmt.Sprintf("pools=%d", pools), func(t *testing.T) {
			z, _ := bulkDeletePools(t, pools)
			bucket, router, err := initAPIHandlerTest(t.Context(), z, nil, MakeBucketOptions{VersioningEnabled: true, LockEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			client, err := minio.New("localhost:1", &minio.Options{Region: "us-east-1", MaxRetries: 1})
			if err != nil {
				t.Fatal(err)
			}
			worker, cleanup := r5ReplicationFixture(t, z, bucket, client)
			defer cleanup()
			free := batchPutVersion(t, z, bucket, "free", nil)
			locked := batchPutVersion(t, z, bucket, "locked", batchLockMeta("LEGALHOLD"))
			objects := []ObjectToDelete{{ObjectV: ObjectV{ObjectName: "free", VersionID: free.VersionID}}, {ObjectV: ObjectV{ObjectName: "locked", VersionID: locked.VersionID}}}
			objects = append(objects, objects[0])
			body := encodeResponse(DeleteObjectsRequest{Objects: objects})
			rec := r5Request(t, router, globalActiveCred, http.MethodPost, getDeleteMultipleObjectsURL("", bucket), string(body), nil)
			var response DeleteObjectsResponse
			if rec.Code != http.StatusOK || xml.Unmarshal(rec.Body.Bytes(), &response) != nil || len(response.Errors) != 1 || len(response.DeletedObjects) != 2 {
				t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
			}
			if len(worker) != 1 {
				t.Fatalf("want one purge queued, got %d", len(worker))
			}
			op, ok := (<-worker).(DeletedObjectReplicationInfo)
			if !ok || op.ObjectName != "free" || op.VersionID != free.VersionID || op.VersionPurgeStatus() != replication.VersionPurgePending || op.ReplicationState.ReplicateDecisionStr == "" {
				t.Fatalf("lost purge identity/state: %+v", op)
			}
			if !batchVersionExists(t, z, bucket, "locked", locked.VersionID) {
				t.Fatal("protected version was deleted")
			}
		})
	}
}
