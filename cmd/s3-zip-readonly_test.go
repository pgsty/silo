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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"archive/zip"
	"bytes"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/minio/minio/internal/auth"
)

func TestAPIArchiveReadsDoNotPersistMetadata(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, makeBucketOptions: MakeBucketOptions{LockEnabled: true},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			var archive bytes.Buffer
			zw := zip.NewWriter(&archive)
			file, err := zw.Create("entry.txt")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.Write([]byte("archive content")); err != nil {
				t.Fatal(err)
			}
			if err = zw.Close(); err != nil {
				t.Fatal(err)
			}
			reader := newObjectAttributesAuthzUser(t, backend, bucket, `"s3:GetObject","s3:ListBucket"`)
			policy := fmt.Appendf(nil, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/*"]}]}`, bucket, bucket)
			if _, err = globalBucketMetadataSys.Update(t.Context(), bucket, bucketPolicyConfig, policy); err != nil {
				t.Fatal(err)
			}
			for _, anonymous := range []bool{false, true} {
				for _, method := range []string{http.MethodGet, http.MethodHead, "LIST"} {
					key := fmt.Sprintf("archive-%v-%s.zip", anonymous, method)
					before, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewReader(archive.Bytes()), int64(archive.Len()), "", ""), ObjectOptions{Versioned: true, UserDefined: batchLockMeta("COMPLIANCE")})
					if err != nil {
						t.Fatal(err)
					}
					before, err = obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: before.VersionID})
					if err != nil {
						t.Fatal(err)
					}
					url := getGetObjectURL("", bucket, key+"/entry.txt")
					verb := method
					if method == "LIST" {
						verb = http.MethodGet
						url = "/" + bucket + "?list-type=2&prefix=" + key + "/"
					}
					req, err := newTestSignedRequestV4(verb, url, 0, nil, reader.AccessKey, reader.SecretKey, map[string]string{xMinIOExtract: "true"})
					if err != nil {
						t.Fatal(err)
					}
					if anonymous {
						req.Header.Del("Authorization")
					}
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					if rec.Code != http.StatusOK {
						t.Fatalf("%s anonymous=%v %s: %d %s", backend, anonymous, method, rec.Code, rec.Body.String())
					}
					if method == http.MethodGet && rec.Body.String() != "archive content" {
						t.Fatalf("wrong archive entry: %s", rec.Body.String())
					}
					if method == "LIST" && !bytes.Contains(rec.Body.Bytes(), []byte("entry.txt")) {
						t.Fatal("archive listing omitted entry")
					}
					after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: before.VersionID})
					if err != nil || !maps.Equal(before.UserDefined, after.UserDefined) || !after.ModTime.Equal(before.ModTime) || after.ETag != before.ETag {
						t.Fatalf("%s anonymous=%v %s changed stored metadata: before=%v after=%v err=%v", backend, anonymous, method, before.UserDefined, after.UserDefined, err)
					}
				}
			}
			// Explicit extraction during an authorized upload still builds and
			// persists the index for subsequent reads.
			req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucket, "indexed.zip"), int64(archive.Len()), bytes.NewReader(archive.Bytes()), cred.AccessKey, cred.SecretKey, map[string]string{xMinIOExtract: "true"})
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			oi, err := obj.GetObjectInfo(t.Context(), bucket, "indexed.zip", ObjectOptions{})
			if rec.Code != http.StatusOK || err != nil || len(oi.ArchiveInfo(nil)) == 0 {
				t.Fatalf("explicit extraction lost index: %d %s %v", rec.Code, rec.Body.String(), err)
			}
		},
	})
}
