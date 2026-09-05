// Copyright (c) 2015-2026 MinIO, Inc.
// Copyright (c) 2026 PGSTY
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
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
)

// attributesPartsResponse is the subset of the GetObjectAttributes response
// the ObjectParts tests assert on.
type attributesPartsResponse struct {
	ObjectSize  int64
	ObjectParts struct {
		IsTruncated          bool
		NextPartNumberMarker int
		PartsCount           int
		Parts                []struct {
			PartNumber int
			Size       int64
		} `xml:"Part"`
	}
}

func attributesPartsSSECHeaders(key []byte) map[string]string {
	digest := md5.Sum(key)
	return map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(digest[:]),
	}
}

func attributesPartsSignedRequest(t *testing.T, apiRouter http.Handler, credentials auth.Credentials,
	method, target string, body []byte, headers map[string]string,
) *httptest.ResponseRecorder {
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

// attributesPartsUpload completes a multipart upload of bodies under
// partNumbers and returns the concatenated plaintext.
func attributesPartsUpload(t *testing.T, apiRouter http.Handler, credentials auth.Credentials,
	bucketName, object string, headers map[string]string, bodies [][]byte, partNumbers []int,
) []byte {
	t.Helper()
	initRec := attributesPartsSignedRequest(t, apiRouter, credentials, http.MethodPost,
		getNewMultipartURL("", bucketName, object), nil, headers)
	if initRec.Code != http.StatusOK {
		t.Fatalf("NewMultipart %s: %d %s", object, initRec.Code, initRec.Body.String())
	}
	var initiated struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(initRec.Body.Bytes(), &initiated); err != nil {
		t.Fatal(err)
	}

	var complete bytes.Buffer
	complete.WriteString("<CompleteMultipartUpload>")
	var data []byte
	for i, body := range bodies {
		data = append(data, body...)
		put := attributesPartsSignedRequest(t, apiRouter, credentials, http.MethodPut,
			getPutObjectPartURL("", bucketName, object, initiated.UploadID, strconv.Itoa(partNumbers[i])), body, headers)
		if put.Code != http.StatusOK {
			t.Fatalf("PutObjectPart %s part %d: %d %s", object, partNumbers[i], put.Code, put.Body.String())
		}
		fmt.Fprintf(&complete, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
			partNumbers[i], put.Header()[xhttp.ETag][0])
	}
	complete.WriteString("</CompleteMultipartUpload>")

	finish := attributesPartsSignedRequest(t, apiRouter, credentials, http.MethodPost,
		getCompleteMultipartUploadURL("", bucketName, object, initiated.UploadID), complete.Bytes(), headers)
	if finish.Code != http.StatusOK {
		t.Fatalf("CompleteMultipartUpload %s: %d %s", object, finish.Code, finish.Body.String())
	}
	return data
}

// attributesPartsFetch issues GetObjectAttributes for ObjectSize and
// ObjectParts and decodes the response.
func attributesPartsFetch(t *testing.T, apiRouter http.Handler, credentials auth.Credentials,
	bucketName, object string, headers map[string]string,
) attributesPartsResponse {
	t.Helper()
	attributeHeaders := maps.Clone(headers)
	if attributeHeaders == nil {
		attributeHeaders = make(map[string]string)
	}
	attributeHeaders[xhttp.AmzObjectAttributes] = "ObjectSize,ObjectParts"
	rec := attributesPartsSignedRequest(t, apiRouter, credentials, http.MethodGet,
		getGetObjectURL("", bucketName, object)+"?attributes", nil, attributeHeaders)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetObjectAttributes %s: %d %s", object, rec.Code, rec.Body.String())
	}
	var response attributesPartsResponse
	if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode GetObjectAttributes response: %v (%s)", err, rec.Body.String())
	}
	return response
}

// enableAttributesPartsCompression turns on compression for ".txt" objects,
// including encrypted ones, for the duration of the test.
func enableAttributesPartsCompression(t *testing.T) {
	t.Helper()
	globalCompressConfigMu.Lock()
	previous := globalCompressConfig
	globalCompressConfig.Enabled = true
	globalCompressConfig.Extensions = []string{".txt"}
	globalCompressConfig.MimeTypes = nil
	globalCompressConfig.AllowEncrypted = true
	globalCompressConfigMu.Unlock()
	t.Cleanup(func() {
		globalCompressConfigMu.Lock()
		globalCompressConfig = previous
		globalCompressConfigMu.Unlock()
	})
}

// TestAPIGetObjectAttributesMultipartLogicalPartSize asserts that ObjectPart.Size
// reports the uploaded plaintext length of every part, not the transformed
// length stored on disk. Compressed parts must report the pre-compression
// length and encrypted parts the pre-encryption length, for consecutive as
// well as sparse part numbering.
func TestAPIGetObjectAttributesMultipartLogicalPartSize(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPIGetObjectAttributesMultipartLogicalPartSize,
	})
}

func testAPIGetObjectAttributesMultipartLogicalPartSize(_ ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()
	enableAttributesPartsCompression(t)

	for _, variant := range []struct {
		name      string
		extension string
		encrypted bool
	}{
		{name: "plain", extension: ".bin"},
		{name: "compressed", extension: ".txt"},
		{name: "ssec", extension: ".bin", encrypted: true},
		{name: "compressed-ssec", extension: ".txt", encrypted: true},
	} {
		for _, numbering := range []struct {
			name        string
			partNumbers []int
		}{
			{name: "consecutive", partNumbers: []int{1, 2}},
			{name: "sparse", partNumbers: []int{1, 3}},
		} {
			t.Run(variant.name+"/"+numbering.name, func(t *testing.T) {
				var headers map[string]string
				if variant.encrypted {
					headers = attributesPartsSSECHeaders(bytes.Repeat([]byte{0x19}, 32))
				}
				object := "attributes/parts-" + variant.name + "-" + numbering.name + variant.extension
				bodies := [][]byte{
					bytes.Repeat([]byte("abcd"), 5*1024*1024/4),
					bytes.Repeat([]byte("12345"), 103),
				}
				data := attributesPartsUpload(t, apiRouter, credentials, bucketName, object, headers, bodies, numbering.partNumbers)

				get := attributesPartsSignedRequest(t, apiRouter, credentials, http.MethodGet,
					getGetObjectURL("", bucketName, object), nil, headers)
				if get.Code != http.StatusOK || !bytes.Equal(get.Body.Bytes(), data) {
					t.Fatalf("%s GET: %d bytes=%d want=%d", instanceType, get.Code, get.Body.Len(), len(data))
				}

				response := attributesPartsFetch(t, apiRouter, credentials, bucketName, object, headers)
				if response.ObjectSize != int64(len(data)) {
					t.Errorf("%s ObjectSize=%d want=%d", instanceType, response.ObjectSize, len(data))
				}
				if len(response.ObjectParts.Parts) != len(bodies) {
					t.Fatalf("%s part count=%d want=%d", instanceType, len(response.ObjectParts.Parts), len(bodies))
				}
				if response.ObjectParts.IsTruncated {
					t.Errorf("%s lists all %d parts %v, but IsTruncated=true NextPartNumberMarker=%d",
						instanceType, len(bodies), numbering.partNumbers, response.ObjectParts.NextPartNumberMarker)
				}
				var total int64
				for i, part := range response.ObjectParts.Parts {
					if part.PartNumber != numbering.partNumbers[i] {
						t.Errorf("%s part %d number=%d want=%d", instanceType, i, part.PartNumber, numbering.partNumbers[i])
					}
					if part.Size != int64(len(bodies[i])) {
						t.Errorf("%s part %d size=%d want logical size=%d",
							instanceType, part.PartNumber, part.Size, len(bodies[i]))
					}
					total += part.Size
				}
				if total != response.ObjectSize {
					t.Errorf("%s part sizes sum to %d, ObjectSize=%d", instanceType, total, response.ObjectSize)
				}
			})
		}
	}
}

// TestAPIGetObjectAttributesCompressedEmptyTrailingPart pins the reported
// size of a compressed part carrying no payload. Such a part stores
// Size 0 and ActualSize 0, so it exercises the lower bound of the
// ActualSize guard and must keep reporting 0.
func TestAPIGetObjectAttributesCompressedEmptyTrailingPart(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPIGetObjectAttributesCompressedEmptyTrailingPart,
	})
}

func testAPIGetObjectAttributesCompressedEmptyTrailingPart(_ ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	enableAttributesPartsCompression(t)

	object := "attributes/parts-compressed-empty-tail.txt"
	bodies := [][]byte{bytes.Repeat([]byte("abcd"), 5*1024*1024/4), {}}
	data := attributesPartsUpload(t, apiRouter, credentials, bucketName, object, nil, bodies, []int{1, 2})

	response := attributesPartsFetch(t, apiRouter, credentials, bucketName, object, nil)
	if response.ObjectSize != int64(len(data)) {
		t.Errorf("%s ObjectSize=%d want=%d", instanceType, response.ObjectSize, len(data))
	}
	if len(response.ObjectParts.Parts) != len(bodies) {
		t.Fatalf("%s part count=%d want=%d", instanceType, len(response.ObjectParts.Parts), len(bodies))
	}
	for i, part := range response.ObjectParts.Parts {
		if part.Size != int64(len(bodies[i])) {
			t.Errorf("%s part %d size=%d want logical size=%d",
				instanceType, part.PartNumber, part.Size, len(bodies[i]))
		}
	}
}

// TestAPIGetObjectAttributesEncryptedPartLengths pins how a part length that
// cannot be a valid encrypted stream is reported, for both encrypted layouts.
// Parts of an encrypted multipart object are separate streams, so an
// unconvertible one is corrupt and must fail the request. DecryptObjectInfo
// does not catch that: ObjectInfo.isMultipart gives up on the first part that
// fails sio.DecryptedSize, after which ObjectInfo.DecryptedSize validates only
// the object total. A legacy encrypted object carries no multipart marker and
// is one continuous stream that the erasure writer split into storage
// fragments; those fragments are not independently decryptable, so they must
// keep their stored size rather than fail an intact object. Both fixtures use
// part lengths 5245473 and 1, whose sum 5245474 is a valid stream length while
// the second part alone is not.
func TestAPIGetObjectAttributesEncryptedPartLengths(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPIGetObjectAttributesEncryptedPartLengths,
	})
}

func testAPIGetObjectAttributesEncryptedPartLengths(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	ctx := t.Context()
	partLengths := []int64{5245473, 1}

	// The marker alone is enough for crypto.IsEncrypted to report an encrypted
	// object, which keeps both fixtures free of a sealed key while still
	// driving the handler down the encrypted branch. A trusted SSE-C
	// replication upload reaches the multipart state with real metadata,
	// because it stores whatever part lengths the peer sends.
	for _, variant := range []struct {
		name     string
		metadata map[string]string
		tampered bool
	}{
		{
			name:     "separately-encrypted-parts",
			metadata: map[string]string{crypto.MetaMultipart: ""},
			tampered: true,
		},
		{
			name:     "legacy-single-stream",
			metadata: map[string]string{crypto.MetaIV: "legacy"},
		},
	} {
		t.Run(variant.name, func(t *testing.T) {
			object := "attributes/parts-encrypted-" + variant.name
			upload, err := obj.NewMultipartUpload(ctx, bucketName, object,
				ObjectOptions{UserDefined: maps.Clone(variant.metadata)})
			if err != nil {
				t.Fatal(err)
			}
			parts := make([]CompletePart, 0, len(partLengths))
			for i, length := range partLengths {
				body := bytes.Repeat([]byte("z"), int(length))
				reader, err := hash.NewReader(ctx, bytes.NewReader(body), length, "", "", length)
				if err != nil {
					t.Fatal(err)
				}
				info, err := obj.PutObjectPart(ctx, bucketName, object, upload.UploadID, i+1,
					NewPutObjReader(reader), ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				parts = append(parts, CompletePart{PartNumber: i + 1, ETag: info.ETag})
			}
			if _, err = obj.CompleteMultipartUpload(ctx, bucketName, object, upload.UploadID, parts, ObjectOptions{}); err != nil {
				t.Fatal(err)
			}

			rec := attributesPartsSignedRequest(t, apiRouter, credentials, http.MethodGet,
				getGetObjectURL("", bucketName, object)+"?attributes", nil,
				map[string]string{xhttp.AmzObjectAttributes: "ObjectParts"})

			if variant.tampered {
				wantErr := errorCodes.ToAPIErr(ErrObjectTampered)
				if rec.Code != wantErr.HTTPStatusCode {
					t.Fatalf("%s status %d, want %d: %s", instanceType, rec.Code, wantErr.HTTPStatusCode, rec.Body.String())
				}
				var errResp APIErrorResponse
				if err = xml.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
					t.Fatalf("decode error response: %v (%s)", err, rec.Body.String())
				}
				if errResp.Code != wantErr.Code {
					t.Errorf("%s error code %q, want %q", instanceType, errResp.Code, wantErr.Code)
				}
				return
			}

			if rec.Code != http.StatusOK {
				t.Fatalf("%s status %d, want %d: %s", instanceType, rec.Code, http.StatusOK, rec.Body.String())
			}
			var response attributesPartsResponse
			if err = xml.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode GetObjectAttributes response: %v (%s)", err, rec.Body.String())
			}
			if len(response.ObjectParts.Parts) != len(partLengths) {
				t.Fatalf("%s part count=%d want=%d", instanceType, len(response.ObjectParts.Parts), len(partLengths))
			}
			for i, part := range response.ObjectParts.Parts {
				if part.Size != partLengths[i] {
					t.Errorf("%s part %d size=%d, want the stored fragment size %d",
						instanceType, part.PartNumber, part.Size, partLengths[i])
				}
			}
		})
	}
}
