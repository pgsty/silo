// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/minio/minio/internal/auth"
)

// A bulk delete joins each name to the request bucket on the drives, so a name
// with a ".." segment names a path in another bucket or in the meta bucket.
// Such a name is the error of its own entry and reaches no drive, and the
// other entries of the request are deleted as usual. This holds for the one
// bulk lock of a single node, for a pool that locks per set, and for more than
// one pool.
func TestPoolsBulkDeleteInvalidNames(t *testing.T) {
	for _, topology := range []struct {
		name string
		new  func(t *testing.T) (*erasureServerPools, string)
	}{
		{"single node", func(t *testing.T) (*erasureServerPools, string) { return bulkDeletePools(t, 1) }},
		{"set locks", func(t *testing.T) (*erasureServerPools, string) { return ldPool(t, ldLocal) }},
		{"two pools", func(t *testing.T) (*erasureServerPools, string) { return bulkDeletePools(t, 2) }},
	} {
		t.Run(topology.name, func(t *testing.T) {
			z, bucket := topology.new(t)
			ctx := t.Context()
			other := "bulk-delete-other"
			if err := z.MakeBucket(ctx, other, MakeBucketOptions{VersioningEnabled: true}); err != nil {
				t.Fatal(err)
			}
			old := batchPutVersion(t, z, other, "kept", nil)
			latest := batchPutVersion(t, z, other, "kept", nil)
			batchPutVersion(t, z, other, "visible", nil)
			metaKey := pathJoin(bucketMetaPrefix, other, bucketMetadataFile)
			if !batchVersionExists(t, z, minioMetaBucket, metaKey, "") {
				t.Fatal("the bucket metadata is not an object of the meta bucket")
			}
			for _, key := range []string{"own", "dir/"} {
				if _, err := z.PutObject(ctx, bucket, key, mustGetPutObjReader(t, bytes.NewReader(nil), 0, "", ""), ObjectOptions{}); err != nil {
					t.Fatal(err)
				}
			}

			names := []ObjectToDelete{
				{ObjectV: ObjectV{ObjectName: "../" + other + "/kept", VersionID: old.VersionID}}, // purge in another bucket
				{ObjectV: ObjectV{ObjectName: "own"}},
				{ObjectV: ObjectV{ObjectName: "a/../../" + other + "/visible"}},         // marker in another bucket
				{ObjectV: ObjectV{ObjectName: "../" + minioMetaBucket + "/" + metaKey}}, // marker on bucket metadata
				{ObjectV: ObjectV{ObjectName: "dir/"}},
				{ObjectV: ObjectV{ObjectName: ""}},
			}
			invalid := map[int]bool{0: true, 2: true, 3: true, 5: true}
			// Without a version ID these options ask for a delete marker, the
			// one write a bulk delete makes.
			deleted, errs := z.DeleteObjects(ctx, bucket, slices.Clone(names), ObjectOptions{Versioned: true})
			for i, name := range names {
				_, rejected := errs[i].(ObjectNameInvalid)
				if rejected != invalid[i] || !invalid[i] && errs[i] != nil {
					t.Errorf("%d %q: error = %v, rejected as invalid = %v, want %v", i, name.ObjectName, errs[i], rejected, invalid[i])
				}
				if deleted[i].ObjectName != name.ObjectName || deleted[i].found == invalid[i] {
					t.Errorf("%d %q: result = %+v", i, name.ObjectName, deleted[i])
				}
			}

			for _, version := range []string{old.VersionID, latest.VersionID} {
				if !batchVersionExists(t, z, other, "kept", version) {
					t.Errorf("version %q of the object in the other bucket was removed", version)
				}
			}
			if !batchVersionExists(t, z, other, "visible", "") {
				t.Error("the object of the other bucket is hidden by a marker")
			}
			if !batchVersionExists(t, z, minioMetaBucket, metaKey, "") {
				t.Error("the metadata of the other bucket is hidden by a marker")
			}
			for _, key := range []string{"own", "dir/"} {
				if batchVersionExists(t, z, bucket, key, "") {
					t.Errorf("%q of the request bucket was not deleted", key)
				}
			}
		})
	}
}

// The names of an S3 DeleteObjects request come from its body, which the path
// checks of the request URL do not see. A user allowed to delete in one bucket
// reaches nothing outside it through such a name: a version under COMPLIANCE
// retention in another bucket stays, and no delete marker lands on that object
// or on the stored metadata of its bucket.
func TestBulkDeleteObjectLockNameOutsideBucket(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, endpoints: []string{"DeleteMultipleObjects"},
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
			ctx := t.Context()
			user := newObjectAttributesAuthzUser(t, instance, bucket, `"s3:DeleteObject","s3:DeleteObjectVersion"`)
			locked := getRandomBucketName()
			if err := obj.MakeBucket(ctx, locked, MakeBucketOptions{VersioningEnabled: true, LockEnabled: true}); err != nil {
				t.Fatal(err)
			}
			enableBucketObjectLock(t, locked)
			worm := batchPutVersion(t, obj, locked, "secret", batchLockMeta("COMPLIANCE"))
			batchPutVersion(t, obj, bucket, "own", nil)
			metaKey := pathJoin(bucketMetaPrefix, locked, bucketMetadataFile)

			outside := []ObjectToDelete{
				{ObjectV: ObjectV{ObjectName: "../" + locked + "/secret", VersionID: worm.VersionID}},
				{ObjectV: ObjectV{ObjectName: "../" + locked + "/secret"}},
				{ObjectV: ObjectV{ObjectName: "../" + minioMetaBucket + "/" + metaKey}},
			}
			body := encodeResponse(DeleteObjectsRequest{Objects: append(slices.Clone(outside), ObjectToDelete{ObjectV: ObjectV{ObjectName: "own"}})})
			req, err := newTestSignedRequestV4(http.MethodPost, getDeleteMultipleObjectsURL("", bucket), int64(len(body)), bytes.NewReader(body),
				user.AccessKey, user.SecretKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			var resp DeleteObjectsResponse
			if rec.Code != http.StatusOK || xml.Unmarshal(rec.Body.Bytes(), &resp) != nil {
				t.Fatalf("%s: status %d: %s", instance, rec.Code, rec.Body.String())
			}

			if len(resp.DeletedObjects) != 1 || resp.DeletedObjects[0].ObjectName != "own" || len(resp.Errors) != len(outside) {
				t.Errorf("%s: want the three names outside the bucket refused and \"own\" deleted: %s", instance, rec.Body.String())
			}
			for _, e := range resp.Errors {
				if e.Code != errorCodes[ErrInvalidObjectName].Code {
					t.Errorf("%s: %q: code %s, want %s", instance, e.Key, e.Code, errorCodes[ErrInvalidObjectName].Code)
				}
			}
			if !batchVersionExists(t, obj, locked, "secret", worm.VersionID) {
				t.Errorf("%s: the version under COMPLIANCE retention in the other bucket was removed", instance)
			}
			if !batchVersionExists(t, obj, locked, "secret", "") {
				t.Errorf("%s: a delete marker hides the object of the other bucket", instance)
			}
			if !batchVersionExists(t, obj, minioMetaBucket, metaKey, "") {
				t.Errorf("%s: a delete marker hides the stored metadata of the other bucket", instance)
			}
			if batchVersionExists(t, obj, bucket, "own", "") {
				t.Errorf("%s: the object of the request bucket was not deleted", instance)
			}
		},
	})
}
