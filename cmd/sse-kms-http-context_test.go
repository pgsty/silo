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
	"encoding/base64"
	"encoding/xml"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

// A successful encrypted write must stay readable. Malformed context must be
// rejected before replacing an existing object or creating a multipart upload.
func TestAPISSEKMSHTTPContext(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t,
		// Specific PUT routes must precede the generic PutObject route.
		endpoints: []string{"CopyObject", "NewMultipart", "PutObjectPart", "CompleteMultipart", "PutObject", "GetObject"},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			previousKMS, previousTLS := GlobalKMS, globalIsTLS
			var err error
			GlobalKMS, err = kms.NewBuiltin("context-key", bytes.Repeat([]byte{0x42}, 32))
			if err != nil {
				t.Fatal(err)
			}
			globalIsTLS = true
			defer func() { GlobalKMS, globalIsTLS = previousKMS, previousTLS }()
			request := func(t *testing.T, method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
				t.Helper()
				req, err := newTestSignedRequestV4(method, target, int64(len(body)), bytes.NewReader(body), cred.AccessKey, cred.SecretKey, headers)
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				return rec
			}
			expectStatus := func(t *testing.T, rec *httptest.ResponseRecorder, want int) {
				t.Helper()
				if rec.Code != want {
					t.Fatalf("status=%d, want %d: %s", rec.Code, want, rec.Body.String())
				}
				if want == http.StatusBadRequest {
					var response APIErrorResponse
					if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Code != "InvalidArgument" {
						t.Fatalf("expected InvalidArgument: %s (decode: %v)", rec.Body.String(), err)
					}
				}
			}
			encryption := func(raw string) map[string]string {
				return map[string]string{
					xhttp.AmzServerSideEncryption:           xhttp.AmzEncryptionKMS,
					xhttp.AmzServerSideEncryptionKmsID:      "context-key",
					xhttp.AmzServerSideEncryptionKmsContext: base64.StdEncoding.EncodeToString([]byte(raw)),
				}
			}
			for _, operation := range []string{"put", "self-copy", "copy-replace", "cross-key-copy", "multipart"} {
				for _, tc := range []struct {
					name, raw string
					invalid   bool
				}{
					{"unicode", `{"区域":"杭州","emoji":"🔑","�":"replacement"}`, false},
					{"invalid-key", "{\"\xff\":\"value\"}", true},
					{"invalid-value", "{\"tenant\":\"\xff\"}", true},
					{"colliding-keys", "{\"\xff\":\"a\",\"\xfe\":\"b\"}", true},
				} {
					t.Run(backend+"/"+operation+"/"+tc.name, func(t *testing.T) {
						key := operation + "-" + tc.name
						original, replacement := []byte("original encrypted object"), []byte("updated encrypted object")
						seed := request(t, http.MethodPut, getPutObjectURL("", bucket, key), original, encryption(`{"tenant":"original"}`))
						expectStatus(t, seed, http.StatusOK)
						before, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{})
						if err != nil {
							t.Fatal(err)
						}
						headers := encryption(tc.raw)
						wantData := replacement
						var rec *httptest.ResponseRecorder
						switch operation {
						case "put":
							rec = request(t, http.MethodPut, getPutObjectURL("", bucket, key), replacement, headers)
						case "self-copy", "copy-replace", "cross-key-copy":
							source := key
							if operation == "cross-key-copy" {
								source += "-source"
								seed = request(t, http.MethodPut, getPutObjectURL("", bucket, source), replacement, encryption(`{"tenant":"source"}`))
								expectStatus(t, seed, http.StatusOK)
							} else {
								wantData = original
							}
							if operation == "copy-replace" {
								headers[xhttp.AmzMetadataDirective] = "REPLACE"
							}
							headers[xhttp.AmzCopySource] = "/" + bucket + "/" + source
							rec = request(t, http.MethodPut, getCopyObjectURL("", bucket, key), nil, headers)
						case "multipart":
							rec = request(t, http.MethodPost, getNewMultipartURL("", bucket, key), nil, headers)
							if !tc.invalid {
								expectStatus(t, rec, http.StatusOK)
								var upload InitiateMultipartUploadResponse
								if err := xml.Unmarshal(rec.Body.Bytes(), &upload); err != nil || upload.UploadID == "" {
									t.Fatalf("missing upload ID: %s (decode: %v)", rec.Body.String(), err)
								}
								part := request(t, http.MethodPut, getPutObjectPartURL("", bucket, key, upload.UploadID, "1"), replacement, nil)
								expectStatus(t, part, http.StatusOK)
								// The in-process recorder retains the handler's literal
								// ETag key; Header.Get would canonicalize it to Etag.
								etags := part.Header()[xhttp.ETag]
								if len(etags) != 1 || etags[0] == "" {
									t.Fatalf("missing part ETag: %v", part.Header())
								}
								body, err := xml.Marshal(CompleteMultipartUpload{Parts: []CompletePart{{PartNumber: 1, ETag: strings.Trim(etags[0], "\"")}}})
								if err != nil {
									t.Fatal(err)
								}
								rec = request(t, http.MethodPost, getCompleteMultipartUploadURL("", bucket, key, upload.UploadID), body, nil)
							}
						}
						wantStatus := http.StatusOK
						if tc.invalid {
							wantStatus, wantData = http.StatusBadRequest, original
						}
						expectStatus(t, rec, wantStatus)
						get := request(t, http.MethodGet, getGetObjectURL("", bucket, key), nil, nil)
						expectStatus(t, get, http.StatusOK)
						if !bytes.Equal(get.Body.Bytes(), wantData) {
							t.Fatalf("GET returned %q, want %q", get.Body.Bytes(), wantData)
						}
						after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{})
						if err != nil {
							t.Fatal(err)
						}
						if tc.invalid {
							if !maps.Equal(before.UserDefined, after.UserDefined) || !before.ModTime.Equal(after.ModTime) {
								t.Fatal("rejected context changed existing object metadata")
							}
						} else {
							_, _, _, got, err := crypto.S3KMS.ParseMetadata(after.UserDefined)
							want := kms.Context{"区域": "杭州", "emoji": "🔑", "�": "replacement"}
							if err != nil || !maps.Equal(got, want) {
								t.Fatalf("stored context=%v error=%v, want %v", got, err, want)
							}
						}
					})
				}
			}
		},
	})
}
