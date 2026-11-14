// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
)

func TestAPIAttributesAndArchiveStoredTags(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, makeBucketOptions: MakeBucketOptions{VersioningEnabled: true},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
			_, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
			if err != nil {
				t.Fatal(err)
			}
			var archive bytes.Buffer
			zw := zip.NewWriter(&archive)
			entry, err := zw.Create("entry.txt")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = entry.Write([]byte("private entry")); err != nil {
				t.Fatal(err)
			}
			if err = zw.Close(); err != nil {
				t.Fatal(err)
			}
			for _, indexed := range []bool{false, true} {
				key := fmt.Sprintf("tagged-%v.zip", indexed)
				put := func(tag string) ObjectInfo {
					oi, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewReader(archive.Bytes()), int64(archive.Len()), "", ""), ObjectOptions{Versioned: true, UserDefined: map[string]string{xhttp.AmzObjectTagging: "tier=" + tag}})
					if err != nil {
						t.Fatal(err)
					}
					return oi
				}
				old := put("public")
				latest := put("restricted")
				if indexed {
					if _, err := updateObjectMetadataWithZipInfo(t.Context(), obj, bucket, key, ObjectOptions{VersionID: latest.VersionID}); err != nil {
						t.Fatal(err)
					}
				}
				for _, anonymous := range []bool{false, true} {
					for _, effect := range []string{"Allow", "Deny"} {
						actions := `"s3:GetObject","s3:GetObjectAttributes","s3:GetObjectVersion","s3:GetObjectVersionAttributes"`
						condition := `"Condition":{"StringEquals":{"s3:ExistingObjectTag/tier":"restricted"}}`
						statement := fmt.Sprintf(`{"Effect":"%s","Action":[%s],"Resource":["arn:aws:s3:::%s/*"],%s}`, effect, actions, bucket, condition)
						if effect == "Deny" {
							statement += fmt.Sprintf(`,{"Effect":"Allow","Action":[%s],"Resource":["arn:aws:s3:::%s/*"]}`, actions, bucket)
						}
						statement += fmt.Sprintf(`,{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::%s"]}`, bucket)
						creds := newDeleteAuthzPolicyUser(t, backend, bucket, "["+statement+"]")
						if anonymous {
							document := `{"Version":"2012-10-17","Statement":[` + strings.ReplaceAll(statement, `"Effect":`, `"Principal":"*","Effect":`) + `]}`
							if _, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketPolicyConfig, []byte(document)); err != nil {
								t.Fatal(err)
							}
						}
						for _, operation := range []string{"attributes", "version-attributes", http.MethodGet, http.MethodHead, "LIST"} {
							t.Run(fmt.Sprintf("%s/indexed=%v/anonymous=%v/%s/%s", backend, indexed, anonymous, effect, operation), func(t *testing.T) {
								verb := http.MethodGet
								target := getGetObjectURL("", bucket, key+"/entry.txt")
								headers := map[string]string{xMinIOExtract: "true", xhttp.AmzObjectTagging: "tier=public"}
								want := http.StatusOK
								if effect == "Deny" {
									want = http.StatusForbidden
								}
								switch operation {
								case "attributes", "version-attributes":
									q := url.Values{"attributes": {""}}
									if operation == "version-attributes" {
										q.Set("versionId", old.VersionID)
										if effect == "Allow" {
											want = http.StatusForbidden
										} else {
											want = http.StatusOK
										}
									}
									target = makeTestTargetURL("", bucket, key, q)
									headers[xhttp.AmzObjectAttributes] = "ETag,ObjectSize"
								case http.MethodHead:
									verb = http.MethodHead
								case "LIST":
									target = "/" + bucket + "?list-type=2&prefix=" + key + "/"
								}
								req, err := newTestSignedRequestV4(verb, target, 0, nil, creds.AccessKey, creds.SecretKey, headers)
								if err != nil {
									t.Fatal(err)
								}
								if anonymous {
									req.Header.Del("Authorization")
								}
								rec := httptest.NewRecorder()
								router.ServeHTTP(rec, req)
								if rec.Code != want {
									t.Fatalf("status %d, want %d: %s", rec.Code, want, rec.Body.String())
								}
								if rec.Code == http.StatusOK && operation == http.MethodGet && rec.Body.String() != "private entry" {
									t.Fatalf("wrong extracted content: %s", rec.Body.String())
								}
								if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "private entry") {
									t.Fatal("denied response disclosed content")
								}
							})
						}
					}
				}
			}
			// Each Attributes action is necessary; a conditional Deny on either
			// action must win even when the other action is unconditionally allowed.
			for _, versioned := range []bool{false, true} {
				for _, deniedAction := range []string{"GetObject", "GetObjectAttributes"} {
					actions := `"s3:GetObject","s3:GetObjectAttributes"`
					if versioned {
						actions = `"s3:GetObjectVersion","s3:GetObjectVersionAttributes"`
						deniedAction = strings.Replace(deniedAction, "GetObject", "GetObjectVersion", 1)
					}
					statements := fmt.Sprintf(`[{"Effect":"Allow","Action":[%s],"Resource":["arn:aws:s3:::%s/*"]},{"Effect":"Deny","Action":["s3:%s"],"Resource":["arn:aws:s3:::%s/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/tier":"restricted"}}}]`, actions, bucket, deniedAction, bucket)
					creds := newDeleteAuthzPolicyUser(t, backend, bucket, statements)
					q := url.Values{"attributes": {""}}
					if versioned {
						oi, err := obj.GetObjectInfo(t.Context(), bucket, "tagged-true.zip", ObjectOptions{})
						if err != nil {
							t.Fatal(err)
						}
						q.Set("versionId", oi.VersionID)
					}
					req, err := newTestSignedRequestV4(http.MethodGet, makeTestTargetURL("", bucket, "tagged-true.zip", q), 0, nil, creds.AccessKey, creds.SecretKey, map[string]string{xhttp.AmzObjectAttributes: "ETag"})
					if err != nil {
						t.Fatal(err)
					}
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					if rec.Code != http.StatusForbidden {
						t.Fatalf("%s Deny: %d %s", deniedAction, rec.Code, rec.Body.String())
					}
				}
			}
			listOnly := newDeleteAuthzPolicyUser(t, backend, bucket, fmt.Sprintf(`[{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::%s"]}]`, bucket))
			for _, extract := range []bool{false, true} {
				req, err := newTestSignedRequestV4(http.MethodGet, "/"+bucket+"?list-type=2&prefix=tagged-true.zip/", 0, nil, listOnly.AccessKey, listOnly.SecretKey, map[string]string{xMinIOExtract: fmt.Sprint(extract)})
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				want := http.StatusOK
				if extract {
					want = http.StatusForbidden
				}
				if rec.Code != want {
					t.Fatalf("list-only extract=%v: %d %s", extract, rec.Code, rec.Body.String())
				}
			}
		},
	})
}
