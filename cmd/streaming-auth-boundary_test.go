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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
)

func TestAPIStreamingAuthenticationBoundaries(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, endpoints: []string{"PutObject"},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			data := []byte("authenticated streaming payload")
			for _, mode := range []string{"valid", "missing-algorithm", "wrong-algorithm", "wrong-signature", "invalid-credential"} {
				req, err := newStreamingUnsignedTrailerRequest(http.MethodPut, getPutObjectURL("", bucket, mode), data, UTCNow())
				if err != nil {
					t.Fatal(err)
				}
				if err := signRequestV4(req, cred.AccessKey, cred.SecretKey); err != nil {
					t.Fatal(err)
				}
				authorization := req.Header.Get(xhttp.Authorization)
				switch mode {
				case "missing-algorithm":
					authorization = strings.TrimPrefix(authorization, signV4Algorithm+" ")
				case "wrong-algorithm":
					authorization = strings.Replace(authorization, signV4Algorithm, "INVALID", 1)
				case "wrong-signature":
					prefix, _, found := strings.Cut(authorization, "Signature=")
					if !found {
						t.Fatal("signed request has no signature")
					}
					authorization = prefix + "Signature=" + strings.Repeat("0", 64)
				case "invalid-credential":
					authorization = strings.Replace(authorization, cred.AccessKey, strings.Repeat("A", len(cred.AccessKey)), 1)
				}
				req.Header.Set(xhttp.Authorization, authorization)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				_, stored := obj.GetObjectInfo(t.Context(), bucket, mode, ObjectOptions{})
				if mode == "valid" {
					if rec.Code != http.StatusOK || stored != nil {
						t.Fatalf("%s %s: %d %s, object: %v", backend, mode, rec.Code, rec.Body.String(), stored)
					}
				} else if rec.Code < 400 || stored == nil {
					t.Errorf("%s %s: malformed authentication wrote an object: %d %s", backend, mode, rec.Code, rec.Body.String())
				}
			}
			for _, trailers := range []bool{false, true} {
				req, err := newTestStreamingSignedRequest(http.MethodPut, getPutObjectURL("", bucket, "tagged"), int64(len(data)), 64*1024, bytes.NewReader(data), cred.AccessKey, cred.SecretKey)
				if err != nil {
					t.Fatal(err)
				}
				if trailers {
					req.Header.Set(xhttp.AmzContentSha256, streamingContentSHA256Trailer)
					req.Header.Set(awsTrailerHeader, "x-amz-checksum-crc32")
					if err := signRequestV4(req, cred.AccessKey, cred.SecretKey); err != nil {
						t.Fatal(err)
					}
				}
				getRequestAuthType(req)
				if _, _, _, _, code := calculateSeedSignature(req, trailers); code != ErrNone {
					t.Fatalf("%s trailers=%v: valid seed rejected: %v", backend, trailers, code)
				}
				req.Header.Set(xhttp.AmzObjectTagging, "unsigned=injected")
				if _, code := newSignV4ChunkedReader(req, trailers); code != ErrUnsignedHeaders {
					t.Errorf("%s trailers=%v: unsigned tags accepted: %v", backend, trailers, code)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if _, err := obj.GetObjectInfo(t.Context(), bucket, "tagged", ObjectOptions{}); rec.Code < 400 || err == nil {
					t.Errorf("%s trailers=%v: injected metadata stored: %d", backend, trailers, rec.Code)
				}
			}
			// A public bucket can still use the unsigned trailer decoder without
			// claiming credentials; authorization remains the handler's job.
			req, err := newStreamingUnsignedTrailerRequest(http.MethodPut, "/public/key", data, UTCNow())
			if err != nil {
				t.Fatal(err)
			}
			rd, code := newUnsignedV4ChunkedReader(req, true)
			if code != ErrNone {
				t.Fatal(code)
			}
			got, err := io.ReadAll(rd)
			rd.Close()
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("anonymous decoder: %q %v", got, err)
			}
		},
	})
}

func TestStreamingTrailerConditionValues(t *testing.T) {
	tests := []struct {
		name, payload, authorization string
		wantVersion, wantAuthType    string
	}{
		{
			name:          "signed trailer",
			payload:       streamingContentSHA256Trailer,
			authorization: "AWS4-HMAC-SHA256 Credential=test",
			wantVersion:   signV4Algorithm,
			wantAuthType:  "REST-HEADER",
		},
		{
			name:          "authenticated unsigned trailer",
			payload:       unsignedPayloadTrailer,
			authorization: "AWS4-HMAC-SHA256 Credential=test",
			wantVersion:   signV4Algorithm,
			wantAuthType:  "REST-HEADER",
		},
		{
			name:         "anonymous unsigned trailer",
			payload:      unsignedPayloadTrailer,
			wantVersion:  "",
			wantAuthType: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "http://minio.local/bucket/object", nil)
			r.Header.Set(xhttp.AmzContentSha256, tc.payload)
			if tc.authorization != "" {
				r.Header.Set(xhttp.Authorization, tc.authorization)
			}
			values := getConditionValues(r, "", auth.Credentials{})
			if got := strings.Join(values["signatureversion"], ""); got != tc.wantVersion {
				t.Fatalf("signatureversion = %q, want %q", got, tc.wantVersion)
			}
			if got := strings.Join(values["authType"], ""); got != tc.wantAuthType {
				t.Fatalf("authType = %q, want %q", got, tc.wantAuthType)
			}
		})
	}
}

func TestStreamingUnsignedTrailerDateGate(t *testing.T) {
	tests := []struct {
		name       string
		date       string
		authorized bool
		wantCall   bool
	}{
		{name: "anonymous without date", authorized: false, wantCall: true},
		{name: "authenticated current", date: UTCNow().Format(iso8601Format), authorized: true, wantCall: true},
		{name: "authenticated missing", authorized: true, wantCall: false},
		{name: "authenticated malformed", date: "not-a-date", authorized: true, wantCall: false},
		{name: "authenticated old", date: UTCNow().Add(-globalMaxSkewTime - time.Second).Format(iso8601Format), authorized: true, wantCall: false},
		{name: "authenticated future", date: UTCNow().Add(globalMaxSkewTime + time.Second).Format(iso8601Format), authorized: true, wantCall: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "http://minio.local/bucket/object", nil)
			r.Header.Set(xhttp.AmzContentSha256, unsignedPayloadTrailer)
			if tc.authorized {
				r.Header.Set(xhttp.Authorization, "AWS4-HMAC-SHA256 Credential=test")
			}
			if tc.date != "" {
				r.Header.Set(xhttp.AmzDate, tc.date)
			}

			called := false
			h := setAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if called != tc.wantCall {
				t.Fatalf("handler called = %v, want %v; status=%d body=%q", called, tc.wantCall, rec.Code, rec.Body.String())
			}
		})
	}
}
