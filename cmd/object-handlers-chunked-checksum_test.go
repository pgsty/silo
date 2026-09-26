// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/minio/minio/internal/auth"
)

func crc32Checksum(data []byte) string {
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], crc32.ChecksumIEEE(data))
	return base64.StdEncoding.EncodeToString(c[:])
}

// TestAPIPutObjectChunkedChecksum exercises PutObject with aws-chunked streaming
// transfer encoding combined with a CRC32 checksum. It reproduces issue #107:
// the AWS Java SDK v2, with chunked encoding enabled, sends a non-trailer signed
// chunked body (x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD), places
// the precomputed checksum in the x-amz-checksum-crc32 header, yet still advertises
// it in x-amz-trailer even though no trailer is ever sent. Before the fix the
// server treated the checksum as trailing (empty value) and returned HTTP 400
// XAmzContentChecksumMismatch.
func TestAPIPutObjectChunkedChecksum(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPIPutObjectChunkedChecksum,
		endpoints:  []string{"PutObject", "GetObject"},
	})
}

func testAPIPutObjectChunkedChecksum(obj ObjectLayer, instanceType, bucketName string, apiRouter http.Handler,
	credentials auth.Credentials, t *testing.T,
) {
	data := bytes.Repeat([]byte("a"), 4096)
	goodCRC := crc32Checksum(data)
	// A well-formed 4-byte value that does not match the content.
	wrongCRC := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04})

	apiErrOf := func(rec *httptest.ResponseRecorder) APIErrorResponse {
		var apiErr APIErrorResponse
		b, _ := io.ReadAll(rec.Body)
		_ = xml.Unmarshal(b, &apiErr)
		return apiErr
	}
	apiCode := func(rec *httptest.ResponseRecorder) string { return apiErrOf(rec).Code }

	// newChunkedJavaForm builds a non-trailer signed chunked PutObject request that
	// mirrors the AWS Java SDK v2 wire form: the checksum value sits in the header
	// while x-amz-trailer still advertises it (no trailer is actually sent). The
	// checksum headers are set BEFORE signing so they are part of the signed
	// headers, exactly as the captured Java SDK request sends them.
	newChunkedJavaForm := func(object, crc string) *http.Request {
		body := bytes.NewReader(data)
		req, err := newTestStreamingRequest(http.MethodPut,
			getPutObjectURL("", bucketName, object),
			int64(len(data)), int64(len(data)), body)
		if err != nil {
			t.Fatalf("Failed to create streaming request: %v", err)
		}
		req.Header.Set("x-amz-checksum-crc32", crc)
		req.Header.Set("x-amz-trailer", "x-amz-checksum-crc32")
		req.Header.Set("x-amz-sdk-checksum-algorithm", "CRC32")
		currTime := UTCNow()
		signature, err := signStreamingRequest(req, credentials.AccessKey, credentials.SecretKey, currTime)
		if err != nil {
			t.Fatalf("Failed to sign streaming request: %v", err)
		}
		req, err = assembleStreamingChunks(req, body, int64(len(data)), credentials.SecretKey, signature, currTime)
		if err != nil {
			t.Fatalf("Failed to assemble streaming chunks: %v", err)
		}
		return req
	}

	// 1. Correct checksum: must succeed and echo the checksum on the response.
	{
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, newChunkedJavaForm("chunked-ok", goodCRC))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: chunked+CRC32 PutObject: expected 200, got %d (%s)", instanceType, rec.Code, apiCode(rec))
		}
		if got := rec.Header().Get("x-amz-checksum-crc32"); got != goodCRC {
			t.Fatalf("%s: response checksum echo = %q, want %q", instanceType, got, goodCRC)
		}

		// Read the stored checksum back via GetObject with checksum mode enabled.
		greq, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, "chunked-ok"),
			0, nil, credentials.AccessKey, credentials.SecretKey, map[string]string{"x-amz-checksum-mode": "ENABLED"})
		if err != nil {
			t.Fatalf("Failed to create GET request: %v", err)
		}
		grec := httptest.NewRecorder()
		apiRouter.ServeHTTP(grec, greq)
		if grec.Code != http.StatusOK {
			t.Fatalf("%s: GetObject: expected 200, got %d", instanceType, grec.Code)
		}
		if got := grec.Header().Get("x-amz-checksum-crc32"); got != goodCRC {
			t.Fatalf("%s: stored checksum read back = %q, want %q", instanceType, got, goodCRC)
		}
	}

	// 2. Wrong checksum over the same chunked form: must still be rejected.
	{
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, newChunkedJavaForm("chunked-wrong", wrongCRC))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: chunked+wrong CRC32: expected 400, got %d", instanceType, rec.Code)
		}
		gotErr := apiErrOf(rec)
		if gotErr.Code != "XAmzContentChecksumMismatch" {
			t.Fatalf("%s: chunked+wrong CRC32: want XAmzContentChecksumMismatch, got %q", instanceType, gotErr.Code)
		}
		if gotErr.Message != "The CRC32 you specified did not match the calculated checksum." {
			t.Fatalf("%s: chunked+wrong CRC32: message = %q, want S3 algorithm-specific wording", instanceType, gotErr.Message)
		}
	}
}
