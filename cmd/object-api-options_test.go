// Copyright (c) 2015-2024 MinIO, Inc.
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
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	xhttp "github.com/minio/minio/internal/http"
)

// TestGetAndValidateAttributesOpts is currently minimal and covers a subset of getAndValidateAttributesOpts(),
// it is intended to be expanded when the function is worked on in the future.
func TestGetAndValidateAttributesOpts(t *testing.T) {
	globalBucketVersioningSys = &BucketVersioningSys{}
	bucket := minioMetaBucket
	ctx := t.Context()
	testCases := []struct {
		name            string
		headers         http.Header
		wantObjectAttrs map[string]struct{}
	}{
		{
			name:            "empty header",
			headers:         http.Header{},
			wantObjectAttrs: map[string]struct{}{},
		},
		{
			name: "single header line",
			headers: http.Header{
				xhttp.AmzObjectAttributes: []string{"test1,test2"},
			},
			wantObjectAttrs: map[string]struct{}{
				"test1": {}, "test2": {},
			},
		},
		{
			name: "multiple header lines with some duplicates",
			headers: http.Header{
				xhttp.AmzObjectAttributes: []string{"test1,test2", "test3,test4", "test4,test3"},
			},
			wantObjectAttrs: map[string]struct{}{
				"test1": {}, "test2": {}, "test3": {}, "test4": {},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header = testCase.headers

			opts, _ := getAndValidateAttributesOpts(ctx, rec, req, bucket, "testobject")

			if !reflect.DeepEqual(opts.ObjectAttributes, testCase.wantObjectAttrs) {
				t.Errorf("want opts %v, got %v", testCase.wantObjectAttrs, opts.ObjectAttributes)
			}
		})
	}
}

// TestGetAndValidateAttributesOptsPartsRange asserts that GetObjectAttributes
// range checks the ObjectParts pagination headers the way ListObjectParts
// does: a negative value is rejected with the same API error, an absent or
// zero x-amz-max-parts means the default page size, and in-range values are
// passed through unchanged.
func TestGetAndValidateAttributesOptsPartsRange(t *testing.T) {
	globalBucketVersioningSys = &BucketVersioningSys{}
	bucket := minioMetaBucket
	ctx := t.Context()

	testCases := []struct {
		name         string
		maxParts     string
		marker       string
		wantValid    bool
		wantErr      APIErrorCode
		wantArgument string
		wantValue    string
		wantMaxParts int
		wantMarker   int
	}{
		{
			name:         "defaults",
			wantValid:    true,
			wantMaxParts: maxPartsList,
		},
		{
			name:         "zero max-parts means the default page size",
			maxParts:     "0",
			wantValid:    true,
			wantMaxParts: maxPartsList,
		},
		{
			name:         "in range values pass through",
			maxParts:     "10",
			marker:       "3",
			wantValid:    true,
			wantMaxParts: 10,
			wantMarker:   3,
		},
		{
			name:         "negative max-parts is rejected",
			maxParts:     "-1",
			wantValid:    false,
			wantErr:      ErrInvalidMaxParts,
			wantArgument: strings.ToLower(xhttp.AmzMaxParts),
			wantValue:    "-1",
		},
		{
			name:         "negative part-number-marker is rejected",
			marker:       "-1",
			wantValid:    false,
			wantErr:      ErrInvalidPartNumberMarker,
			wantArgument: strings.ToLower(xhttp.AmzPartNumberMarker),
			wantValue:    "-1",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/testbucket/testobject?attributes", nil)
			req.Header.Set(xhttp.AmzObjectAttributes, "ObjectParts")
			if testCase.maxParts != "" {
				req.Header.Set(xhttp.AmzMaxParts, testCase.maxParts)
			}
			if testCase.marker != "" {
				req.Header.Set(xhttp.AmzPartNumberMarker, testCase.marker)
			}

			opts, valid := getAndValidateAttributesOpts(ctx, rec, req, bucket, "testobject")
			if valid != testCase.wantValid {
				t.Fatalf("want valid %v, got %v (%s)", testCase.wantValid, valid, rec.Body.String())
			}

			if testCase.wantValid {
				if opts.MaxParts != testCase.wantMaxParts {
					t.Errorf("want MaxParts %d, got %d", testCase.wantMaxParts, opts.MaxParts)
				}
				if opts.PartNumberMarker != testCase.wantMarker {
					t.Errorf("want PartNumberMarker %d, got %d", testCase.wantMarker, opts.PartNumberMarker)
				}
				return
			}

			wantErr := errorCodes.ToAPIErr(testCase.wantErr)
			if rec.Code != wantErr.HTTPStatusCode {
				t.Errorf("want HTTP status %d, got %d", wantErr.HTTPStatusCode, rec.Code)
			}
			var errResp objectAttributesErrorResponse
			if err := xml.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("decode error response: %v (%s)", err, rec.Body.String())
			}
			if errResp.Code != wantErr.Code || errResp.Message != wantErr.Description {
				t.Errorf("want error %s/%q, got %s/%q", wantErr.Code, wantErr.Description, errResp.Code, errResp.Message)
			}
			if errResp.ArgumentName == nil || *errResp.ArgumentName != testCase.wantArgument {
				t.Errorf("want ArgumentName %q, got %v", testCase.wantArgument, errResp.ArgumentName)
			}
			if errResp.ArgumentValue == nil || *errResp.ArgumentValue != testCase.wantValue {
				t.Errorf("want ArgumentValue %q, got %v", testCase.wantValue, errResp.ArgumentValue)
			}
		})
	}
}
