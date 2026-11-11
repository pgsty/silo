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

package crypto

import (
	"encoding/base64"
	"errors"
	"maps"
	"net/http"
	"testing"

	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

func TestKMSParseHTTPContext(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      kms.Context
		invalid   bool
	}{
		{name: "absent"},
		{name: "empty", raw: `{}`, want: kms.Context{}},
		{name: "null", raw: `null`},
		{name: "unicode", raw: `{"区域":"杭州","emoji":"🔑","�":"replacement"}`, want: kms.Context{"区域": "杭州", "emoji": "🔑", "�": "replacement"}},
		{name: "array", raw: `[]`, invalid: true},
		{name: "invalid-json", raw: `not-json`, invalid: true},
		{name: "trailing-json", raw: `{"tenant":"ok"} {}`, invalid: true},
		{name: "number-value", raw: `{"tenant":1}`, invalid: true},
		{name: "invalid-base64", invalid: true},
		{name: "empty-header", invalid: true},
		{name: "nil-header-values", invalid: true},
		{name: "invalid-key", raw: "{\"\xff\":\"value\"}", invalid: true},
		{name: "invalid-value", raw: "{\"tenant\":\"\xff\"}", invalid: true},
		{name: "colliding-keys", raw: "{\"\xff\":\"a\",\"\xfe\":\"b\"}", invalid: true},
		{name: "replacement-key", raw: "{\"\xff\":\"a\",\"�\":\"b\"}", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			header.Set(xhttp.AmzServerSideEncryption, xhttp.AmzEncryptionKMS)
			header.Set(xhttp.AmzServerSideEncryptionKmsID, "context-key")
			if tc.raw != "" {
				header.Set(xhttp.AmzServerSideEncryptionKmsContext, base64.StdEncoding.EncodeToString([]byte(tc.raw)))
			}
			switch tc.name {
			case "invalid-base64":
				header.Set(xhttp.AmzServerSideEncryptionKmsContext, "not-base64!")
			case "empty-header":
				header.Set(xhttp.AmzServerSideEncryptionKmsContext, "")
			case "nil-header-values":
				header[xhttp.AmzServerSideEncryptionKmsContext] = nil
			}
			key, context, err := S3KMS.ParseHTTP(header)
			if tc.invalid {
				var apiErr kms.Error
				if !errors.As(err, &apiErr) || apiErr.Code != http.StatusBadRequest || apiErr.APICode != "InvalidArgument" {
					t.Fatalf("invalid context: got %v, want 400 InvalidArgument", err)
				}
				return
			}
			if err != nil || key != "context-key" || !maps.Equal(context, tc.want) {
				t.Fatalf("key=%q context=%v error=%v; want context=%v", key, context, err, tc.want)
			}
		})
	}
}
