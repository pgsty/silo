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
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

func TestAPIReplicaPreservesProtectedContent(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, makeBucketOptions: MakeBucketOptions{LockEnabled: true},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			oldTLS, oldKMS := globalIsTLS, GlobalKMS
			globalIsTLS, GlobalKMS = true, kms.NewStub("replica-content")
			defer func() { globalIsTLS, GlobalKMS = oldTLS, oldKMS }()
			restoreCompression := disableCompression()
			defer restoreCompression()
			request := func(method, url string, data []byte, headers map[string]string) *httptest.ResponseRecorder {
				t.Helper()
				req, err := newTestSignedRequestV4(method, url, int64(len(data)), bytes.NewReader(data), cred.AccessKey, cred.SecretKey, headers)
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				return rec
			}
			for _, encryption := range []string{"plain", "sse-s3", "sse-kms", "sse-c", "plain-compressed", "sse-s3-compressed"} {
				restore := func() {}
				if strings.HasSuffix(encryption, "-compressed") {
					restore = setCopyChecksumCompression(true)
				}
				for _, multipart := range []bool{false, true} {
					for _, protection := range []string{"COMPLIANCE", "LEGALHOLD", "GOVERNANCE"} {
						key := fmt.Sprintf("protected/%s/%v/%s.txt", encryption, multipart, protection)
						enc := map[string]string{}
						switch encryption {
						case "sse-s3", "sse-s3-compressed":
							enc[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionAES
						case "sse-kms":
							enc[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionKMS
							enc[xhttp.AmzServerSideEncryptionKmsID] = "replica-content"
						case "sse-c":
							enc = ssecKeyHeaders(bytes.Repeat([]byte{0x37}, 32), false)
						}
						headers := maps.Clone(enc)
						maps.Copy(headers, batchLockMeta(protection))
						// Both inline and disk-backed writes are exercised.
						body := bytes.Repeat([]byte("immutable content "), 20000)
						switch protection {
						case "LEGALHOLD":
							body = body[:64]
						case "GOVERNANCE":
							body = nil
						}
						if !multipart {
							putCopyChecksumSource(t, router, cred, bucket, key, body, headers)
						} else {
							initRec := request(http.MethodPost, getNewMultipartURL("", bucket, key), nil, headers)
							if initRec.Code != http.StatusOK {
								t.Fatalf("source initiate: %d %s", initRec.Code, initRec.Body.String())
							}
							var init InitiateMultipartUploadResponse
							if err := xml.Unmarshal(initRec.Body.Bytes(), &init); err != nil {
								t.Fatal(err)
							}
							part := request(http.MethodPut, getPutObjectPartURL("", bucket, key, init.UploadID, "1"), body, enc)
							if part.Code != http.StatusOK {
								t.Fatalf("source part: %d %s", part.Code, part.Body.String())
							}
							complete, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{{PartNumber: 1, ETag: canonicalizeETag(part.Header()[xhttp.ETag][0])}}})
							if err != nil {
								t.Fatal(err)
							}
							rec := request(http.MethodPost, getCompleteMultipartUploadURL("", bucket, key, init.UploadID), complete, enc)
							if rec.Code != http.StatusOK {
								t.Fatalf("source complete: %d %s", rec.Code, rec.Body.String())
							}
						}
						gr, err := obj.GetObjectNInfo(t.Context(), bucket, key, nil, http.Header{}, ObjectOptions{ReplicationRequest: true})
						if err != nil {
							t.Fatal(err)
						}
						src := gr.ObjInfo
						wire, err := io.ReadAll(gr)
						gr.Close()
						if err != nil {
							t.Fatal(err)
						}
						for _, altered := range []bool{true, false} {
							data := bytes.Clone(wire)
							if altered {
								if len(data) == 0 {
									data = []byte("x")
								} else {
									data[len(data)-1] ^= 0x20
								}
							}
							opts, _, err := putReplicationOpts(t.Context(), "", src)
							if err != nil {
								t.Fatal(err)
							}
							hdrs := map[string]string{}
							for k, vs := range opts.Header() {
								if len(vs) > 0 {
									hdrs[k] = vs[0]
								}
							}
							hdrs[xhttp.MinIOSourceReplicationRequest] = "true"
							hdrs[xhttp.AmzBucketReplicationStatus] = "REPLICA"
							// Forge the old ETag and size along with a newer tag revision:
							// the body comparison must still reject different bytes.
							hdrs[xhttp.MinIOSourceETag] = src.ETag
							hdrs[xhttp.MinIOSourceTaggingTimestamp] = UTCNow().Add(time.Minute).Format(time.RFC3339Nano)
							hdrs[xhttp.AmzObjectTagging] = "replica=updated"
							var rec *httptest.ResponseRecorder
							if !multipart {
								rec = request(http.MethodPut, getPutObjectURL("", bucket, key)+"?versionId="+src.VersionID, data, hdrs)
							} else {
								initRec := request(http.MethodPost, getNewMultipartURL("", bucket, key)+"&versionId="+src.VersionID, nil, hdrs)
								if initRec.Code != http.StatusOK {
									t.Fatalf("%s %s initiate: %d %s", backend, key, initRec.Code, initRec.Body.String())
								}
								var init InitiateMultipartUploadResponse
								if err := xml.Unmarshal(initRec.Body.Bytes(), &init); err != nil {
									t.Fatal(err)
								}
								partHdrs := map[string]string{xhttp.MinIOSourceReplicationRequest: "true"}
								partRec := request(http.MethodPut, getPutObjectPartURL("", bucket, key, init.UploadID, "1"), data, partHdrs)
								if partRec.Code != http.StatusOK && (!altered || !strings.Contains(partRec.Body.String(), "XMinioObjectTampered")) {
									t.Fatalf("%s %s part: %d %s", backend, key, partRec.Code, partRec.Body.String())
								}
								if partRec.Code != http.StatusOK {
									rec = partRec
								} else {
									complete, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{{PartNumber: 1, ETag: canonicalizeETag(partRec.Header()[xhttp.ETag][0])}}})
									if err != nil {
										t.Fatal(err)
									}
									actual, err := src.GetActualSize()
									if err != nil {
										t.Fatal(err)
									}
									partHdrs[xhttp.MinIOReplicationActualObjectSize] = strconv.FormatInt(actual, 10)
									rec = request(http.MethodPost, getCompleteMultipartUploadURL("", bucket, key, init.UploadID), complete, partHdrs)
								}
							}
							if altered {
								if rec.Code < 400 || !strings.Contains(rec.Body.String(), "WORM") && !strings.Contains(rec.Body.String(), "XMinioObjectTampered") {
									t.Fatalf("%s %s: different content not refused: %d %s", backend, key, rec.Code, rec.Body.String())
								}
							} else if rec.Code != http.StatusOK {
								t.Fatalf("%s %s: same content refused: %d %s", backend, key, rec.Code, rec.Body.String())
							}
							getHdrs := map[string]string{}
							if encryption == "sse-c" {
								getHdrs = enc
							}
							got := request(http.MethodGet, getGetObjectURL("", bucket, key)+"?versionId="+src.VersionID, nil, getHdrs)
							if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), body) {
								t.Fatalf("%s %s: protected content changed or became unreadable: %d", backend, key, got.Code)
							}
						}
					}
				}
				restore()
			}
		},
	})
}

func TestPoolsReplicaProtectedContentAcrossPools(t *testing.T) {
	z, bucket := consistencyPools(t)
	const key = "protected-across-pools"
	id := mustGetUUID()
	stamp := UTCNow().Add(-time.Hour)
	putConsistencyObject(t, z, bucket, key, 0, "original", ObjectOptions{Versioned: true, VersionID: id, MTime: stamp})
	putConsistencyObject(t, z, bucket, key, 1, "original", ObjectOptions{Versioned: true, VersionID: id, MTime: stamp, UserDefined: batchLockMeta("COMPLIANCE")})
	_, err := z.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, strings.NewReader("tampered"), 8, "", ""), ObjectOptions{Versioned: true, VersionID: id, ReplicationRequest: true, ReplicaLockReconcile: true, UserDefined: map[string]string{}})
	if _, ok := err.(ObjectLocked); !ok {
		t.Fatalf("protected pool copy allowed overwrite: %v", err)
	}
	for i, pool := range z.serverPools {
		gr, err := pool.GetObjectNInfo(t.Context(), bucket, key, nil, http.Header{}, ObjectOptions{VersionID: id})
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(gr)
		gr.Close()
		if err != nil || string(data) != "original" {
			t.Fatalf("pool %d: changed protected data: %q %v", i, data, err)
		}
	}
}

func TestLockedSSECReplicaRejectsChangedSeal(t *testing.T) {
	stored := ObjectInfo{Bucket: "bucket", Name: "key", Size: 0, UserDefined: batchLockMeta("LEGALHOLD")}
	stored.UserDefined[crypto.MetaSealedKeySSEC] = "stored-seal"
	incoming := stored
	incoming.UserDefined = maps.Clone(stored.UserDefined)
	incoming.UserDefined[crypto.MetaSealedKeySSEC] = "changed-seal"
	open := func() (*GetObjectReader, error) {
		t.Fatal("changed seal must be rejected before reading")
		return nil, nil
	}
	if err := verifyLockedReplica(t.Context(), incoming, stored, open, open); err == nil {
		t.Fatal("changed SSE-C seal accepted")
	}
}

func TestAPIReplicaCopyPreservesProtectedVersion(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, makeBucketOptions: MakeBucketOptions{LockEnabled: true},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			const key = "copy-protected-version"
			original := batchPutVersion(t, obj, bucket, key, batchLockMeta("COMPLIANCE"))
			data := []byte("different source version")
			source, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{Versioned: true})
			if err != nil {
				t.Fatal(err)
			}
			headers := map[string]string{
				xhttp.AmzCopySource:                 url.QueryEscape("/"+bucket+"/"+key) + "?versionId=" + source.VersionID,
				xhttp.MinIOSourceReplicationRequest: "true", xhttp.AmzBucketReplicationStatus: "REPLICA",
				xhttp.AmzMetadataDirective: replaceDirective,
			}
			req, err := newTestSignedRequestV4(http.MethodPut, getCopyObjectURL("", bucket, key)+"?versionId="+original.VersionID, 0, nil, cred.AccessKey, cred.SecretKey, headers)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code < 400 || !strings.Contains(rec.Body.String(), "WORM") {
				t.Fatalf("%s: copy replaced protected version: %d %s", backend, rec.Code, rec.Body.String())
			}
			gr, err := obj.GetObjectNInfo(t.Context(), bucket, key, nil, http.Header{}, ObjectOptions{VersionID: original.VersionID})
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(gr)
			gr.Close()
			if err != nil || string(got) != "batch lock "+key {
				t.Fatalf("%s: protected body changed: %q %v", backend, got, err)
			}
		},
	})
}

func TestAPIReplicaCannotWeakenCompliance(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, makeBucketOptions: MakeBucketOptions{LockEnabled: true},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			const key = "compliance-removal"
			oi := batchPutVersion(t, obj, bucket, key, batchLockMeta("COMPLIANCE"))
			until := oi.UserDefined[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)]
			for _, copyRequest := range []bool{false, true} {
				headers := map[string]string{xhttp.MinIOSourceReplicationRequest: "true", xhttp.AmzBucketReplicationStatus: "REPLICA", xhttp.MinIOSourceObjectRetentionTimestamp: UTCNow().Add(time.Hour).Format(time.RFC3339Nano)}
				body := []byte("batch lock " + key)
				if copyRequest {
					headers[xhttp.AmzCopySource] = url.QueryEscape("/"+bucket+"/"+key) + "?versionId=" + oi.VersionID
					headers[xhttp.AmzMetadataDirective] = replaceDirective
					body = nil
				}
				req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucket, key)+"?versionId="+oi.VersionID, int64(len(body)), bytes.NewReader(body), cred.AccessKey, cred.SecretKey, headers)
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s copy=%v: %d %s", backend, copyRequest, rec.Code, rec.Body.String())
				}
				stored, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: oi.VersionID})
				if err != nil || stored.UserDefined[strings.ToLower(xhttp.AmzObjectLockMode)] != "COMPLIANCE" || stored.UserDefined[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] != until {
					t.Fatalf("%s copy=%v: a replica cleared COMPLIANCE: %+v %v", backend, copyRequest, stored.UserDefined, err)
				}
			}
		},
	})
}
