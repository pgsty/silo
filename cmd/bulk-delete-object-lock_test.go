// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minio/minio/internal/auth"
)

// A directory object always has the null version, and a bulk delete without a
// version ID removes it. The retention check must read that version's lock.
func TestBulkDeleteDirectoryObjectLock(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, endpoints: []string{"DeleteMultipleObjects"},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			enableBucketObjectLock(t, bucket)
			for _, kind := range append([]string{"unlocked"}, batchLockKinds...) {
				key := "dir-" + kind + "/"
				if _, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewReader(nil), 0, "", ""),
					ObjectOptions{Versioned: true, VersionID: nullVersionID, UserDefined: batchLockMeta(kind)}); err != nil {
					t.Fatal(err)
				}
				body := encodeResponse(DeleteObjectsRequest{Objects: []ObjectToDelete{{ObjectV: ObjectV{ObjectName: key}}}})
				req, err := newTestSignedRequestV4(http.MethodPost, getDeleteMultipleObjectsURL("", bucket), int64(len(body)), bytes.NewReader(body),
					cred.AccessKey, cred.SecretKey, nil)
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				var resp DeleteObjectsResponse
				if rec.Code != http.StatusOK || xml.Unmarshal(rec.Body.Bytes(), &resp) != nil {
					t.Fatalf("%s: %s: status %d: %s", instance, key, rec.Code, rec.Body.String())
				}
				exists := batchVersionExists(t, obj, bucket, key, nullVersionID)
				if kind == "unlocked" {
					if exists || len(resp.DeletedObjects) != 1 {
						t.Errorf("%s: %s: unlocked directory object was not deleted: %s", instance, key, rec.Body.String())
					}
					continue
				}
				if !exists || len(resp.Errors) != 1 || len(resp.DeletedObjects) != 0 ||
					resp.Errors[0].Key != key || !strings.Contains(resp.Errors[0].Message, "WORM") {
					t.Errorf("%s: %s: want the WORM error and the object kept (exists=%v): %s", instance, key, exists, rec.Body.String())
				}
			}
		},
	})
}
