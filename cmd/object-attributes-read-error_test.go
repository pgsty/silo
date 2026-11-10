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
	"bytes"
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
)

// GetObjectAttributes answers NoSuchKey with AccessDenied to a caller without
// s3:ListBucket on the bucket, as S3 does, so that a missing object cannot be
// told apart from a forbidden one. A server error, such as lost read quorum,
// must reach a caller allowed to read the object as the error it is.
func TestGetObjectAttributesReadQuorumLost(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	obj, dirs, err := prepareErasure16(ctx)
	if err != nil {
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	defer func() {
		z.Shutdown(context.Background())
		removeRoots(dirs)
		setObjectLayer(previous)
	}()
	bucket, router, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const object, missing = "object", "missing"
	if _, err := z.PutObject(ctx, bucket, object, mustGetPutObjReader(t, bytes.NewReader([]byte("data")), 4, "", ""), ObjectOptions{}); err != nil {
		t.Fatal(err)
	}

	read := `{"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectAttributes"], "Resource": ["arn:aws:s3:::` + bucket + `/*"]}`
	withoutList := newDeleteAuthzPolicyUser(t, "", bucket, "["+read+"]")
	withList := newDeleteAuthzPolicyUser(t, "", bucket, "["+read+
		`, {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::`+bucket+`"]}]`)

	check := func(stage, user string, creds auth.Credentials, key string, want int) {
		t.Helper()
		target := makeTestTargetURL("", bucket, key, url.Values{"attributes": []string{""}})
		req, err := newTestSignedRequestV4(http.MethodGet, target, 0, nil, creds.AccessKey, creds.SecretKey,
			map[string]string{xhttp.AmzObjectAttributes: "ETag"})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != want {
			var apiErr APIErrorResponse
			_ = xml.Unmarshal(rec.Body.Bytes(), &apiErr)
			t.Errorf("%s: GetObjectAttributes %s by %s: status %d %s, want %d", stage, key, user, rec.Code, apiErr.Code, want)
		}
	}

	check("healthy", "withoutList", withoutList, object, http.StatusOK)
	check("healthy", "withList", withList, object, http.StatusOK)
	check("healthy", "withoutList", withoutList, missing, http.StatusForbidden)
	check("healthy", "withList", withList, missing, http.StatusNotFound)

	defer objectReadFault(z, bucket, object, 10)()
	check("read quorum lost", "withoutList", withoutList, object, http.StatusServiceUnavailable)
	check("read quorum lost", "withList", withList, object, http.StatusServiceUnavailable)
}
