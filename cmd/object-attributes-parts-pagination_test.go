// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
)

type attributesPartsPage struct {
	ObjectParts struct {
		IsTruncated          bool
		MaxParts             int
		NextPartNumberMarker int
		PartNumberMarker     int
		PartsCount           int
		Parts                []struct {
			PartNumber int
			Size       int64
		} `xml:"Part"`
	}
}

// TestAPIGetObjectAttributesPartsPagination asserts that ObjectParts pagination
// terminates for sparse part numbers: truncation is decided by whether parts
// remain, not by comparing the last part number with the part count.
func TestAPIGetObjectAttributesPartsPagination(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPIGetObjectAttributesPartsPagination,
	})
}

func testAPIGetObjectAttributesPartsPagination(_ ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	signedRequest := func(method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		req, err := newTestSignedRequestV4(method, target, int64(len(body)), bytes.NewReader(body),
			credentials.AccessKey, credentials.SecretKey, headers)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return rec
	}

	const partSize = 5 * 1024 * 1024

	// upload completes a multipart object with the given part numbers. Part
	// numbers must be strictly increasing, but gaps are allowed, so the last
	// part number need not equal the number of parts.
	upload := func(object string, partNumbers []int) {
		t.Helper()
		initRec := signedRequest(http.MethodPost, getNewMultipartURL("", bucketName, object), nil, nil)
		if initRec.Code != http.StatusOK {
			t.Fatalf("%s INIT: %d %s", instanceType, initRec.Code, initRec.Body.String())
		}
		var initiated struct {
			UploadID string `xml:"UploadId"`
		}
		if err := xml.Unmarshal(initRec.Body.Bytes(), &initiated); err != nil {
			t.Fatal(err)
		}
		var complete bytes.Buffer
		complete.WriteString("<CompleteMultipartUpload>")
		for i, number := range partNumbers {
			body := bytes.Repeat([]byte("abcd"), partSize/4)
			if i == len(partNumbers)-1 {
				body = bytes.Repeat([]byte("12345"), 103)
			}
			put := signedRequest(http.MethodPut,
				getPutObjectPartURL("", bucketName, object, initiated.UploadID, strconv.Itoa(number)), body, nil)
			if put.Code != http.StatusOK {
				t.Fatalf("%s PART %d: %d %s", instanceType, number, put.Code, put.Body.String())
			}
			fmt.Fprintf(&complete, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
				number, put.Header()[xhttp.ETag][0])
		}
		complete.WriteString("</CompleteMultipartUpload>")
		finish := signedRequest(http.MethodPost,
			getCompleteMultipartUploadURL("", bucketName, object, initiated.UploadID), complete.Bytes(), nil)
		if finish.Code != http.StatusOK {
			t.Fatalf("%s COMPLETE: %d %s", instanceType, finish.Code, finish.Body.String())
		}
	}

	attributes := func(object string, marker, maxParts int) attributesPartsPage {
		t.Helper()
		headers := map[string]string{xhttp.AmzObjectAttributes: "ObjectParts"}
		if marker > 0 {
			headers[xhttp.AmzPartNumberMarker] = strconv.Itoa(marker)
		}
		if maxParts > 0 {
			headers[xhttp.AmzMaxParts] = strconv.Itoa(maxParts)
		}
		rec := signedRequest(http.MethodGet, getGetObjectURL("", bucketName, object)+"?attributes", nil, headers)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s ATTRIBUTES marker=%d max=%d: %d %s", instanceType, marker, maxParts, rec.Code, rec.Body.String())
		}
		var page attributesPartsPage
		if err := xml.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		return page
	}

	check := func(name string, page attributesPartsPage, wantParts []int, wantTruncated bool, wantNext, wantCount int) {
		t.Helper()
		got := make([]int, 0, len(page.ObjectParts.Parts))
		for _, p := range page.ObjectParts.Parts {
			got = append(got, p.PartNumber)
		}
		if fmt.Sprint(got) != fmt.Sprint(wantParts) {
			t.Errorf("%s %s: parts=%v want=%v", instanceType, name, got, wantParts)
		}
		if page.ObjectParts.IsTruncated != wantTruncated {
			t.Errorf("%s %s: IsTruncated=%v want=%v", instanceType, name, page.ObjectParts.IsTruncated, wantTruncated)
		}
		if page.ObjectParts.NextPartNumberMarker != wantNext {
			t.Errorf("%s %s: NextPartNumberMarker=%d want=%d", instanceType, name,
				page.ObjectParts.NextPartNumberMarker, wantNext)
		}
		if page.ObjectParts.PartsCount != wantCount {
			t.Errorf("%s %s: PartsCount=%d want=%d", instanceType, name, page.ObjectParts.PartsCount, wantCount)
		}
	}

	sparse := "review/attributes-pagination-sparse"
	upload(sparse, []int{1, 3, 5})

	// A single page holding every sparse part is complete.
	check("sparse full page", attributes(sparse, 0, 0), []int{1, 3, 5}, false, 0, 3)

	// One part per page walks 1, 3, 5 and stops. Page 2 returns part 3,
	// whose number equals the part count, and must still be truncated:
	// the old comparison declared that page final and silently dropped
	// part 5.
	check("sparse max-parts=1 page 1", attributes(sparse, 0, 1), []int{1}, true, 1, 3)
	check("sparse max-parts=1 page 2", attributes(sparse, 1, 1), []int{3}, true, 3, 3)
	check("sparse max-parts=1 page 3", attributes(sparse, 3, 1), []int{5}, false, 0, 3)

	// A page that exactly holds the remainder is not truncated, so no
	// empty trailing page is requested.
	check("sparse max-parts=2 page 2", attributes(sparse, 1, 2), []int{3, 5}, false, 0, 3)

	// A marker at or past the last part ends the listing instead of
	// looping back through NextPartNumberMarker=0.
	check("sparse marker at last part", attributes(sparse, 5, 0), nil, false, 0, 3)
	check("sparse marker past last part", attributes(sparse, 9, 0), nil, false, 0, 3)

	// Contiguous numbering is affected too: the empty page past the end
	// used to report IsTruncated=true with NextPartNumberMarker=0.
	contiguous := "review/attributes-pagination-contiguous"
	upload(contiguous, []int{1, 2})
	check("contiguous full page", attributes(contiguous, 0, 0), []int{1, 2}, false, 0, 2)
	check("contiguous max-parts=1 page 1", attributes(contiguous, 0, 1), []int{1}, true, 1, 2)
	check("contiguous max-parts=1 page 2", attributes(contiguous, 1, 1), []int{2}, false, 0, 2)
	check("contiguous marker at last part", attributes(contiguous, 2, 0), nil, false, 0, 2)
}
