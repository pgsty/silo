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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
)

func TestReplicationControlsRequireSignedHeaders(t *testing.T) {
	for _, header := range replicationRequestHeaders {
		t.Run(header, func(t *testing.T) {
			req, err := newTestSignedRequestV4(http.MethodGet, "http://localhost/bucket/key", 0, nil, "access-key", "secret-key", nil)
			if err != nil {
				t.Fatal(err)
			}
			// Membership matters even for a present-empty internal header.
			req.Header.Set(header, "")
			if replicationHeadersSigned(req) {
				t.Fatal("unsigned control granted replication trust")
			}
			if err := signRequestV4(req, "access-key", "secret-key"); err != nil {
				t.Fatal(err)
			}
			if !replicationHeadersSigned(req) {
				t.Fatal("signed control rejected")
			}
		})
	}
	for _, authorization := range []string{"", "AWS access-key:signature", "Credential=access-key"} {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		req.Header.Set(xhttp.Authorization, authorization)
		req.Header.Set(xhttp.MinIOSourceReplicationRequest, "true")
		if replicationHeadersSigned(req) {
			t.Fatalf("non-SigV4 authorization granted trust: %q", authorization)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	req.Header.Set(xhttp.MinIOSourceReplicationRequest, "true")
	presignBoundaryRequest(t, req, UTCNow(), []string{"host", "x-minio-source-replication-request"}, auth.Credentials{AccessKey: "access-key", SecretKey: "secret-key"})
	getRequestAuthType(req)
	if replicationHeadersSigned(req) {
		t.Fatal("presigned request granted peer trust")
	}
}

func TestAPIUnsignedReplicationControlsAreIgnored(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, endpoints: []string{"PutObject"},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			for _, signedMarker := range []bool{false, true} {
				headers := map[string]string{}
				if signedMarker {
					headers[xhttp.MinIOSourceReplicationRequest] = "true"
				}
				body := []byte("replication controls are authenticated")
				req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucket, "key"), int64(len(body)), bytes.NewReader(body), cred.AccessKey, cred.SecretKey, headers)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set(xhttp.MinIOSourceReplicationRequest, "true")
				req.Header.Set(xhttp.MinIOSourceMTime, "2100-01-01T00:00:00Z")
				req.Header.Set(xhttp.MinIOSourceETag, "forged-source-etag")
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				oi, err := obj.GetObjectInfo(t.Context(), bucket, "key", ObjectOptions{})
				if rec.Code != http.StatusOK || err != nil || oi.ModTime.Year() == 2100 || oi.ETag == "forged-source-etag" {
					t.Fatalf("%s signedMarker=%v: unsigned replication state was accepted: HTTP=%d info=%+v err=%v", backend, signedMarker, rec.Code, oi, err)
				}
			}
		},
	})
}
