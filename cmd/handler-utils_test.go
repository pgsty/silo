// Copyright (c) 2015-2021 MinIO, Inc.
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
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/minio/minio/internal/config"
	xhttp "github.com/minio/minio/internal/http"
)

// Tests validate bucket LocationConstraint.
func TestIsValidLocationConstraint(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	obj, fsDir, err := prepareFS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(fsDir)
	if err = newTestConfig(globalMinioDefaultRegion, obj); err != nil {
		t.Fatal(err)
	}

	// Corrupted XML
	malformedReq := &http.Request{
		Body:          io.NopCloser(bytes.NewReader([]byte("<>"))),
		ContentLength: int64(len("<>")),
	}

	// Not an XML
	badRequest := &http.Request{
		Body:          io.NopCloser(bytes.NewReader([]byte("garbage"))),
		ContentLength: int64(len("garbage")),
	}

	// generates the input request with XML bucket configuration set to the request body.
	createExpectedRequest := func(req *http.Request, location string) *http.Request {
		createBucketConfig := createBucketLocationConfiguration{}
		createBucketConfig.Location = location
		createBucketConfigBytes, _ := xml.Marshal(createBucketConfig)
		createBucketConfigBuffer := bytes.NewReader(createBucketConfigBytes)
		req.Body = io.NopCloser(createBucketConfigBuffer)
		req.ContentLength = int64(createBucketConfigBuffer.Len())
		return req
	}

	testCases := []struct {
		request            *http.Request
		serverConfigRegion string
		expectedCode       APIErrorCode
	}{
		// Test case - 1.
		{createExpectedRequest(&http.Request{}, "eu-central-1"), globalMinioDefaultRegion, ErrNone},
		// Test case - 2.
		// In case of empty request body ErrNone is returned.
		{createExpectedRequest(&http.Request{}, ""), globalMinioDefaultRegion, ErrNone},
		// Test case - 3
		// In case of garbage request body ErrMalformedXML is returned.
		{badRequest, globalMinioDefaultRegion, ErrMalformedXML},
		// Test case - 4
		// In case of invalid XML request body ErrMalformedXML is returned.
		{malformedReq, globalMinioDefaultRegion, ErrMalformedXML},
	}

	for i, testCase := range testCases {
		config.SetRegion(globalServerConfig, testCase.serverConfigRegion)
		_, actualCode := parseLocationConstraint(testCase.request)
		if testCase.expectedCode != actualCode {
			t.Errorf("Test %d: Expected the APIErrCode to be %d, but instead found %d", i+1, testCase.expectedCode, actualCode)
		}
	}
}

// Tests validate metadata extraction from http headers.
func TestExtractMetadataHeaders(t *testing.T) {
	testCases := []struct {
		header     http.Header
		metadata   map[string]string
		shouldFail bool
	}{
		// Validate if there a known 'content-type'.
		{
			header: http.Header{
				"Content-Type": []string{"image/png"},
			},
			metadata: map[string]string{
				"content-type": "image/png",
			},
			shouldFail: false,
		},
		// Validate if there are no keys to extract.
		{
			header: http.Header{
				"Test-1": []string{"123"},
			},
			metadata:   map[string]string{},
			shouldFail: false,
		},
		// Validate that there are all headers extracted
		{
			header: http.Header{
				"X-Amz-Meta-Appid":   []string{"amz-meta"},
				"X-Minio-Meta-Appid": []string{"minio-meta"},
			},
			metadata: map[string]string{
				"X-Amz-Meta-Appid":   "amz-meta",
				"X-Minio-Meta-Appid": "minio-meta",
			},
			shouldFail: false,
		},
		// Fail if header key is not in canonicalized form
		{
			header: http.Header{
				"x-amz-meta-appid": []string{"amz-meta"},
			},
			metadata: map[string]string{
				"x-amz-meta-appid": "amz-meta",
			},
			shouldFail: false,
		},
		// Support multiple values
		{
			header: http.Header{
				"x-amz-meta-key": []string{"amz-meta1", "amz-meta2"},
			},
			metadata: map[string]string{
				"x-amz-meta-key": "amz-meta1,amz-meta2",
			},
			shouldFail: false,
		},
		// Replication-only headers must not be accepted on ordinary requests.
		{
			header: http.Header{
				"Content-Type": []string{"image/png"},
				"X-Minio-Replication-Server-Side-Encryption-Sealed-Key":     []string{"sealed-key"},
				"X-Minio-Replication-Server-Side-Encryption-Seal-Algorithm": []string{"DAREv2-HMAC-SHA256"},
				"X-Minio-Replication-Server-Side-Encryption-Iv":             []string{"iv"},
				"X-Minio-Replication-Encrypted-Multipart":                   []string{""},
				"X-Minio-Replication-Actual-Object-Size":                    []string{"1"},
				ReplicationSsecChecksumHeader:                               []string{"checksum"},
			},
			metadata: map[string]string{
				"content-type": "image/png",
			},
			shouldFail: false,
		},
		// Empty header input returns empty metadata.
		{
			header:     nil,
			metadata:   nil,
			shouldFail: true,
		},
	}

	// Validate if the extracting headers.
	for i, testCase := range testCases {
		metadata := make(map[string]string)
		err := extractMetadataFromMime(t.Context(), textproto.MIMEHeader(testCase.header), metadata)
		if err != nil && !testCase.shouldFail {
			t.Fatalf("Test %d failed to extract metadata: %v", i+1, err)
		}
		if err == nil && testCase.shouldFail {
			t.Fatalf("Test %d should fail, but it passed", i+1)
		}
		if err == nil && !reflect.DeepEqual(metadata, testCase.metadata) {
			t.Fatalf("Test %d failed: Expected \"%#v\", got \"%#v\"", i+1, testCase.metadata, metadata)
		}
	}
}

func TestExtractMetadataFromRequestUsesHeaderPrecedence(t *testing.T) {
	query := make(url.Values)
	query.Set(strings.ToLower(xhttp.AmzStorageClass), "QUERY-CLASS")
	query.Set(strings.ToLower(xhttp.AmzObjectTagging), "source=query")
	req, err := http.NewRequest(http.MethodGet, "http://localhost/test?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(xhttp.AmzStorageClass, "HEADER-CLASS")
	req.Header.Set(xhttp.AmzObjectTagging, "source=header")
	if err = req.ParseForm(); err != nil {
		t.Fatal(err)
	}

	metadata, err := extractMetadataFromReq(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got := metadata[xhttp.AmzStorageClass]; got != "HEADER-CLASS" {
		t.Fatalf("storage class: expected header, got %q", got)
	}
	if got := metadata[xhttp.AmzObjectTagging]; got != "source=header" {
		t.Fatalf("tagging: expected header, got %q", got)
	}

	// Presence, rather than a non-empty value, establishes precedence. This
	// prevents a query value from taking over when a signed header is empty.
	req.Header[xhttp.AmzObjectTagging] = []string{""}
	if got, ok := getRequestHeaderOrQueryValue(req, xhttp.AmzObjectTagging); !ok || got != "" {
		t.Fatalf("empty header did not override query: value=%q present=%v", got, ok)
	}
}

func TestExtractMetadataFromRequestKeepsQueryCompatibility(t *testing.T) {
	query := make(url.Values)
	query.Set(strings.ToLower(xhttp.AmzStorageClass), "REDUCED_REDUNDANCY")
	query.Set(strings.ToLower(xhttp.AmzObjectTagging), "security=public")
	req, err := http.NewRequest(http.MethodGet, "http://localhost/test?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = req.ParseForm(); err != nil {
		t.Fatal(err)
	}

	metadata, err := extractMetadataFromReq(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got := metadata[xhttp.AmzStorageClass]; got != "REDUCED_REDUNDANCY" {
		t.Fatalf("storage class query value lost: %q", got)
	}
	if got := metadata[xhttp.AmzObjectTagging]; got != "security=public" {
		t.Fatalf("tagging query value lost: %q", got)
	}
}

func TestExtractReplicationMetadataHeaders(t *testing.T) {
	header := http.Header{
		"Content-Type":      []string{"application/wasm"},
		"Content-Encoding":  []string{"aws-chunked"},
		"X-Amz-Meta-Source": []string{"client"},
		"X-Minio-Replication-Server-Side-Encryption-Sealed-Key":     []string{"sealed-key"},
		"X-Minio-Replication-Server-Side-Encryption-Seal-Algorithm": []string{"DAREv2-HMAC-SHA256"},
		"X-Minio-Replication-Server-Side-Encryption-Iv":             []string{"iv"},
		"X-Minio-Replication-Encrypted-Multipart":                   []string{""},
		"X-Minio-Replication-Actual-Object-Size":                    []string{"1"},
		ReplicationSsecChecksumHeader:                               []string{"checksum"},
	}

	metadata := map[string]string{
		"content-type":      "application/wasm",
		"x-amz-meta-source": "client",
	}
	if err := extractReplicationMetadataFromMime(t.Context(), textproto.MIMEHeader(header), metadata); err != nil {
		t.Fatalf("failed to extract replication metadata: %v", err)
	}

	expected := map[string]string{
		"content-type":      "application/wasm",
		"x-amz-meta-source": "client",
		"X-Minio-Internal-Server-Side-Encryption-Sealed-Key":     "sealed-key",
		"X-Minio-Internal-Server-Side-Encryption-Seal-Algorithm": "DAREv2-HMAC-SHA256",
		"X-Minio-Internal-Server-Side-Encryption-Iv":             "iv",
		"X-Minio-Internal-Encrypted-Multipart":                   "",
		"X-Minio-Internal-Actual-Object-Size":                    "1",
		ReplicationSsecChecksumHeader:                            "checksum",
	}

	if !reflect.DeepEqual(metadata, expected) {
		t.Fatalf("unexpected replication metadata: expected %#v, got %#v", expected, metadata)
	}
	if _, ok := metadata["content-encoding"]; ok {
		t.Fatalf("replication metadata restored transport content-encoding: %#v", metadata)
	}
}

func TestGetCopyObjectMetadataFromHeaderReplication(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "http://localhost/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Header.Set("X-Amz-Metadata-Directive", replaceDirective)
	req.Header.Set("X-Minio-Replication-Server-Side-Encryption-Sealed-Key", "sealed-key")

	metadata, err := getCpObjMetadataFromHeader(t.Context(), req, nil, false)
	if err != nil {
		t.Fatalf("copy metadata extraction failed: %v", err)
	}
	if _, ok := metadata["X-Minio-Internal-Server-Side-Encryption-Sealed-Key"]; ok {
		t.Fatalf("unexpected replication metadata without validation: %#v", metadata)
	}

	metadata, err = getCpObjMetadataFromHeader(t.Context(), req, nil, true)
	if err != nil {
		t.Fatalf("copy metadata extraction with replication failed: %v", err)
	}
	if got := metadata["X-Minio-Internal-Server-Side-Encryption-Sealed-Key"]; got != "sealed-key" {
		t.Fatalf("expected restored replication metadata, got %#v", metadata)
	}
}

func TestCloneRequestWithoutReplicationHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "http://localhost/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(xhttp.MinIOSourceReplicationRequest, "true")
	req.Header.Set(xhttp.MinIOSourceETag, "etag")
	req.Header.Set(xhttp.MinIOSourceMTime, "2026-04-15T10:00:00Z")
	req.Header.Set(xhttp.MinIOSourceTaggingTimestamp, "2026-04-15T10:00:00Z")
	req.Header.Set(xhttp.MinIOSourceObjectRetentionTimestamp, "2026-04-15T10:00:00Z")
	req.Header.Set(xhttp.MinIOSourceObjectLegalHoldTimestamp, "2026-04-15T10:00:00Z")
	req.Header.Set(xhttp.MinIOReplicationActualObjectSize, "123")
	req.Header.Set(ReplicationSsecChecksumHeader, "checksum")
	req.Header.Set(xhttp.AmzBucketReplicationStatus, "REPLICA")
	req.Header.Set(xhttp.MinIOSourceDeleteMarker, "true")
	req.Header.Set("X-Minio-Replication-Server-Side-Encryption-Sealed-Key", "sealed")
	req.Header.Set("Content-Type", "application/octet-stream")

	clone := cloneRequestWithoutReplicationHeaders(t.Context(), req)
	if clone == req {
		t.Fatal("expected cloned request")
	}

	for _, header := range []string{
		xhttp.MinIOSourceReplicationRequest,
		xhttp.MinIOSourceETag,
		xhttp.MinIOSourceMTime,
		xhttp.MinIOSourceTaggingTimestamp,
		xhttp.MinIOSourceObjectRetentionTimestamp,
		xhttp.MinIOSourceObjectLegalHoldTimestamp,
		xhttp.MinIOReplicationActualObjectSize,
		ReplicationSsecChecksumHeader,
		xhttp.AmzBucketReplicationStatus,
		xhttp.MinIOSourceDeleteMarker,
		"X-Minio-Replication-Server-Side-Encryption-Sealed-Key",
	} {
		if got := clone.Header.Get(header); got != "" {
			t.Fatalf("expected %s to be stripped, got %q", header, got)
		}
		if got := req.Header.Get(header); got == "" {
			t.Fatalf("expected original request to preserve %s", header)
		}
	}

	if got := clone.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("expected non-replication headers to be preserved, got %q", got)
	}
}

// Test getResource()
func TestGetResource(t *testing.T) {
	testCases := []struct {
		p                string
		host             string
		domains          []string
		expectedResource string
	}{
		{"/a/b/c", "test.mydomain.com", []string{"mydomain.com"}, "/test/a/b/c"},
		{"/a/b/c", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:17000", []string{"mydomain.com"}, "/a/b/c"},
		{"/a/b/c", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]", []string{"mydomain.com"}, "/a/b/c"},
		{"/a/b/c", "192.168.1.1:9000", []string{"mydomain.com"}, "/a/b/c"},
		{"/a/b/c", "test.mydomain.com", []string{"notmydomain.com"}, "/a/b/c"},
		{"/a/b/c", "test.mydomain.com", nil, "/a/b/c"},
	}
	for i, test := range testCases {
		gotResource, err := getResource(test.p, test.host, test.domains)
		if err != nil {
			t.Fatal(err)
		}
		if gotResource != test.expectedResource {
			t.Fatalf("test %d: expected %s got %s", i+1, test.expectedResource, gotResource)
		}
	}
}
