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
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/sio"
)

// TestAPISSECReplicaPartNumberReads replicates a three-part SSE-C multipart
// object through the trusted-replication write path and compares what
// GET ?partNumber=N returns before and after the replica overwrite.
func TestAPISSECReplicaPartNumberReads(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPISSECReplicaPartNumberReads,
	})
}

func testAPISSECReplicaPartNumberReads(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject","s3:GetObject","s3:ReplicateObject"`)
	key := bytes.Repeat([]byte{0x42}, 32)
	keyMD5 := md5.Sum(key)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}

	const mib = 1024 * 1024
	partLens := []int{5 * mib, 5 * mib, 1 * mib}
	plaintext := make([]byte, 0, 11*mib)
	partData := make([][]byte, len(partLens))
	for i, n := range partLens {
		b := make([]byte, n)
		for j := range b {
			// Distinct, position-dependent bytes so an off-by-N shift is visible.
			b[j] = byte(i*7 + j%251)
		}
		partData[i] = b
		plaintext = append(plaintext, b...)
	}

	object := "ssec-mp-3part"

	// ---- 1. Build the source: a real three-part SSE-C multipart object. ----
	newRec := httptest.NewRecorder()
	newReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	apiRouter.ServeHTTP(newRec, newReq)
	if newRec.Code != http.StatusOK {
		t.Fatalf("source NewMultipart status %d: %s", newRec.Code, newRec.Body.String())
	}
	var srcInit InitiateMultipartUploadResponse
	if err = xmlDecoder(newRec.Body, &srcInit, int64(newRec.Body.Len())); err != nil {
		t.Fatal(err)
	}

	srcParts := make([]CompletePart, len(partLens))
	for i, b := range partData {
		pn := strconv.Itoa(i + 1)
		partReq, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectPartURL("", bucketName, object, srcInit.UploadID, pn),
			int64(len(b)), bytes.NewReader(b), credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, partReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("source PutPart %s status %d: %s", pn, rec.Code, rec.Body.String())
		}
		srcParts[i] = CompletePart{PartNumber: i + 1, ETag: canonicalizeETag(rec.Header()[xhttp.ETag][0])}
	}
	srcCompleteBody, err := xml.Marshal(CompleteMultipartUpload{Parts: srcParts})
	if err != nil {
		t.Fatal(err)
	}
	completeReq, err := newTestSignedRequestV4(http.MethodPost,
		getCompleteMultipartUploadURL("", bucketName, object, srcInit.UploadID), int64(len(srcCompleteBody)),
		bytes.NewReader(srcCompleteBody), credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	completeRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(completeRec, completeReq)
	if completeRec.Code != http.StatusOK {
		t.Fatalf("source Complete status %d: %s", completeRec.Code, completeRec.Body.String())
	}

	// ---- 2. Record the source's per-part metadata and per-part GET answers. ----
	srcOI, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[%s] SOURCE parts:", instanceType)
	for _, p := range srcOI.Parts {
		t.Logf("  part %d Size=%d ActualSize=%d", p.Number, p.Size, p.ActualSize)
	}
	srcActual, err := srcOI.GetActualSize()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[%s] SOURCE object Size=%d GetActualSize=%d actual-size-meta=%q",
		instanceType, srcOI.Size, srcActual, srcOI.UserDefined[ReservedMetadataPrefix+"actual-size"])

	type getResult struct {
		status int
		clen   string
		crange string
		body   []byte
	}
	doGet := func(query string, extra map[string]string) getResult {
		hdrs := map[string]string{}
		for k, v := range sseHeaders {
			hdrs[k] = v
		}
		for k, v := range extra {
			hdrs[k] = v
		}
		u := getGetObjectURL("", bucketName, object) + query
		req, err := newTestSignedRequestV4(http.MethodGet, u, 0, nil, credentials.AccessKey, credentials.SecretKey, hdrs)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return getResult{
			status: rec.Code,
			clen:   rec.Header().Get(xhttp.ContentLength),
			crange: rec.Header().Get(xhttp.ContentRange),
			body:   append([]byte(nil), rec.Body.Bytes()...),
		}
	}

	doHead := func(query string) getResult {
		u := getGetObjectURL("", bucketName, object) + query
		req, err := newTestSignedRequestV4(http.MethodHead, u, 0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return getResult{
			status: rec.Code,
			clen:   rec.Header().Get(xhttp.ContentLength),
			crange: rec.Header().Get(xhttp.ContentRange),
		}
	}

	queries := []string{"?partNumber=1", "?partNumber=2", "?partNumber=3"}
	srcGets := make([]getResult, len(queries))
	for i, q := range queries {
		srcGets[i] = doGet(q, nil)
		t.Logf("[%s] SOURCE GET %s -> status=%d Content-Length=%s Content-Range=%s len(body)=%d",
			instanceType, q, srcGets[i].status, srcGets[i].clen, srcGets[i].crange, len(srcGets[i].body))
	}
	// Range GET crossing the part1/part2 boundary.
	boundaryRange := fmt.Sprintf("bytes=%d-%d", 5*mib-16, 5*mib+15)
	srcRange := doGet("", map[string]string{"Range": boundaryRange})
	t.Logf("[%s] SOURCE GET Range %s -> status=%d Content-Length=%s len(body)=%d",
		instanceType, boundaryRange, srcRange.status, srcRange.clen, len(srcRange.body))

	// Sanity: the source must return exactly the part bytes.
	for i := range partData {
		if !bytes.Equal(srcGets[i].body, partData[i]) {
			t.Fatalf("[%s] SOURCE partNumber=%d returned wrong bytes (len %d want %d)",
				instanceType, i+1, len(srcGets[i].body), len(partData[i]))
		}
	}

	// ---- 3. Read the raw ciphertext the replication worker would ship. ----
	gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{ReplicationRequest: true})
	if err != nil {
		t.Fatal(err)
	}
	sourceInfo := gr.ObjInfo
	rawAll, err := io.ReadAll(gr)
	gr.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rawAll, plaintext) {
		t.Fatal("source replication read did not return encrypted bytes")
	}
	rawParts := make([][]byte, len(sourceInfo.Parts))
	off := int64(0)
	for i, p := range sourceInfo.Parts {
		rawParts[i] = rawAll[off : off+p.Size]
		off += p.Size
	}
	if off != int64(len(rawAll)) {
		t.Fatalf("raw ciphertext length %d != sum of part sizes %d", len(rawAll), off)
	}

	// ---- 4. Replicate onto the same key through the trusted write path. ----
	replicationOpts, isMP, err := putReplicationOpts(t.Context(), "", sourceInfo)
	if err != nil {
		t.Fatal(err)
	}
	if !isMP {
		t.Fatal("SSE-C multipart source was not recognized as multipart")
	}
	replicationOpts.Internal.SourceMTime = time.Time{}
	replicationHeaders := make(map[string]string)
	for name, values := range replicationOpts.Header() {
		if len(values) > 0 {
			replicationHeaders[name] = values[0]
		}
	}
	replNewReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
		0, nil, replicator.AccessKey, replicator.SecretKey, replicationHeaders)
	if err != nil {
		t.Fatal(err)
	}
	replNewRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(replNewRec, replNewReq)
	if replNewRec.Code != http.StatusOK {
		t.Fatalf("replica NewMultipart status %d: %s", replNewRec.Code, replNewRec.Body.String())
	}
	var replInit InitiateMultipartUploadResponse
	if err = xmlDecoder(replNewRec.Body, &replInit, int64(replNewRec.Body.Len())); err != nil {
		t.Fatal(err)
	}

	replParts := make([]CompletePart, len(rawParts))
	for i, raw := range rawParts {
		pn := strconv.Itoa(i + 1)
		req, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectPartURL("", bucketName, object, replInit.UploadID, pn),
			int64(len(raw)), bytes.NewReader(raw), replicator.AccessKey, replicator.SecretKey,
			map[string]string{xhttp.MinIOSourceReplicationRequest: "true"})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("replica PutPart %s status %d: %s", pn, rec.Code, rec.Body.String())
		}
		replParts[i] = CompletePart{PartNumber: i + 1, ETag: canonicalizeETag(rec.Header()[xhttp.ETag][0])}
	}
	replCompleteBody, err := xml.Marshal(CompleteMultipartUpload{Parts: replParts})
	if err != nil {
		t.Fatal(err)
	}
	srcActualSize, err := sourceInfo.GetActualSize()
	if err != nil {
		t.Fatal(err)
	}
	replCompleteHeaders := map[string]string{
		xhttp.MinIOSourceReplicationRequest:    "true",
		xhttp.MinIOSourceMTime:                 sourceInfo.ModTime.Format(time.RFC3339Nano),
		xhttp.MinIOSourceETag:                  sourceInfo.ETag,
		xhttp.MinIOReplicationActualObjectSize: strconv.FormatInt(srcActualSize, 10),
	}
	replCompleteReq, err := newTestSignedRequestV4(http.MethodPost,
		getCompleteMultipartUploadURL("", bucketName, object, replInit.UploadID), int64(len(replCompleteBody)),
		bytes.NewReader(replCompleteBody), replicator.AccessKey, replicator.SecretKey, replCompleteHeaders)
	if err != nil {
		t.Fatal(err)
	}
	replCompleteRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(replCompleteRec, replCompleteReq)
	if replCompleteRec.Code != http.StatusOK {
		t.Fatalf("replica Complete status %d: %s", replCompleteRec.Code, replCompleteRec.Body.String())
	}

	// ---- 5. Same reads against the replica. ----
	repOI, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[%s] REPLICA parts:", instanceType)
	for _, p := range repOI.Parts {
		t.Logf("  part %d Size=%d ActualSize=%d", p.Number, p.Size, p.ActualSize)
	}
	repActual, err := repOI.GetActualSize()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[%s] REPLICA object Size=%d GetActualSize=%d actual-size-meta=%q",
		instanceType, repOI.Size, repActual, repOI.UserDefined[ReservedMetadataPrefix+"actual-size"])

	// Whole-object GET must still be byte-identical.
	whole := doGet("", nil)
	if whole.status != http.StatusOK || !bytes.Equal(whole.body, plaintext) {
		t.Errorf("[%s] REPLICA whole-object GET: status=%d len=%d want %d, equal=%v",
			instanceType, whole.status, len(whole.body), len(plaintext), bytes.Equal(whole.body, plaintext))
	} else {
		t.Logf("[%s] REPLICA whole-object GET: OK, %d bytes identical", instanceType, len(whole.body))
	}

	// Fresh replica parts must record the plaintext lengths, not the
	// ciphertext lengths the sender shipped.
	if len(repOI.Parts) != len(partLens) {
		t.Fatalf("[%s] REPLICA has %d parts, want %d", instanceType, len(repOI.Parts), len(partLens))
	}
	for i, p := range repOI.Parts {
		if p.ActualSize != int64(partLens[i]) {
			t.Errorf("[%s] REPLICA part %d ActualSize=%d, want the uploaded length %d",
				instanceType, p.Number, p.ActualSize, partLens[i])
		}
	}

	// Expected framing from independent prefix sums of the uploaded lengths.
	total := len(plaintext)
	start := 0
	for i, q := range queries {
		wantLen := partLens[i]
		wantRange := fmt.Sprintf("bytes %d-%d/%d", start, start+wantLen-1, total)
		start += wantLen

		got := doGet(q, nil)
		want := srcGets[i]
		if got.status != want.status || got.status != http.StatusPartialContent {
			t.Errorf("[%s] REPLICA GET %s status=%d, source=%d, want 206", instanceType, q, got.status, want.status)
		}
		if got.clen != strconv.Itoa(wantLen) || got.crange != wantRange {
			t.Errorf("[%s] REPLICA GET %s Content-Length=%s Content-Range=%s, want %d and %q",
				instanceType, q, got.clen, got.crange, wantLen, wantRange)
		}
		if want.clen != strconv.Itoa(wantLen) || want.crange != wantRange {
			t.Errorf("[%s] SOURCE GET %s Content-Length=%s Content-Range=%s, want %d and %q",
				instanceType, q, want.clen, want.crange, wantLen, wantRange)
		}
		if len(got.body) != wantLen {
			t.Errorf("[%s] REPLICA GET %s body is %d bytes, want %d", instanceType, q, len(got.body), wantLen)
		}
		if !bytes.Equal(got.body, want.body) {
			firstDiff := -1
			for k := 0; k < len(got.body) && k < len(want.body); k++ {
				if got.body[k] != want.body[k] {
					firstDiff = k
					break
				}
			}
			t.Errorf("[%s] REPLICA partNumber=%d returned DIFFERENT bytes than the source: got %d bytes (Content-Range %q), want %d bytes (Content-Range %q), first differing byte at %d",
				instanceType, i+1, len(got.body), got.crange, len(want.body), want.crange, firstDiff)
		}

		head := doHead(q)
		if head.status != http.StatusPartialContent || head.clen != strconv.Itoa(wantLen) || head.crange != wantRange {
			t.Errorf("[%s] REPLICA HEAD %s status=%d Content-Length=%s Content-Range=%s, want 206, %d and %q",
				instanceType, q, head.status, head.clen, head.crange, wantLen, wantRange)
		}
	}

	repRange := doGet("", map[string]string{"Range": boundaryRange})
	sameRange := bytes.Equal(repRange.body, srcRange.body)
	t.Logf("[%s] REPLICA GET Range %s -> status=%d Content-Length=%s len(body)=%d | source len=%d | bytes-equal=%v",
		instanceType, boundaryRange, repRange.status, repRange.clen, len(repRange.body), len(srcRange.body), sameRange)
	if !sameRange {
		t.Errorf("[%s] REPLICA boundary Range GET returned different bytes", instanceType)
	}
}

// TestSSECReplicaPartActualSizeDataMovement reproduces what a decommission or
// rebalance does to a replica whose parts already carry the ciphertext length in
// ActualSize: it replays the object through the object layer exactly the way
// decommissionObject does (cmd/erasure-server-pool-decom.go:605-667), passing the
// stale ActualSize to PutObjectPart and completing without ReplicationRequest, so
// CompleteMultipartUpload recomputes the object-level actual-size from the sum of
// part ActualSizes (cmd/erasure-multipart.go:1365,1440).
func TestSSECReplicaPartActualSizeDataMovement(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testSSECReplicaPartActualSizeDataMovement,
	})
}

func testSSECReplicaPartActualSizeDataMovement(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	key := bytes.Repeat([]byte{0x37}, 32)
	keyMD5 := md5.Sum(key)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}

	const mib = 1024 * 1024
	partLens := []int{5 * mib, 5 * mib, 1 * mib}
	plaintext := make([]byte, 0, 11*mib)
	partData := make([][]byte, len(partLens))
	for i, n := range partLens {
		b := make([]byte, n)
		for j := range b {
			b[j] = byte(i*13 + j%241)
		}
		partData[i] = b
		plaintext = append(plaintext, b...)
	}
	object := "ssec-mp-datamovement"

	newRec := httptest.NewRecorder()
	newReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	apiRouter.ServeHTTP(newRec, newReq)
	if newRec.Code != http.StatusOK {
		t.Fatalf("NewMultipart status %d: %s", newRec.Code, newRec.Body.String())
	}
	var init InitiateMultipartUploadResponse
	if err = xmlDecoder(newRec.Body, &init, int64(newRec.Body.Len())); err != nil {
		t.Fatal(err)
	}
	srcParts := make([]CompletePart, len(partLens))
	for i, b := range partData {
		req, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectPartURL("", bucketName, object, init.UploadID, strconv.Itoa(i+1)),
			int64(len(b)), bytes.NewReader(b), credentials.AccessKey, credentials.SecretKey, sseHeaders)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("PutPart %d status %d: %s", i+1, rec.Code, rec.Body.String())
		}
		srcParts[i] = CompletePart{PartNumber: i + 1, ETag: canonicalizeETag(rec.Header()[xhttp.ETag][0])}
	}
	body, err := xml.Marshal(CompleteMultipartUpload{Parts: srcParts})
	if err != nil {
		t.Fatal(err)
	}
	cReq, err := newTestSignedRequestV4(http.MethodPost,
		getCompleteMultipartUploadURL("", bucketName, object, init.UploadID), int64(len(body)),
		bytes.NewReader(body), credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	cRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(cRec, cReq)
	if cRec.Code != http.StatusOK {
		t.Fatalf("Complete status %d: %s", cRec.Code, cRec.Body.String())
	}

	// Replay it the way decommissionObject does, but hand PutObjectPart the STALE
	// ActualSize an already-written SSE-C replica carries: the ciphertext length.
	gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{},
		ObjectOptions{NoDecryption: true, NoLock: true, NoAuditLog: true})
	if err != nil {
		t.Fatal(err)
	}
	oi := gr.ObjInfo
	res, err := obj.NewMultipartUpload(t.Context(), bucketName, object, ObjectOptions{
		UserDefined:  oi.UserDefined,
		DataMovement: true,
		NoAuditLog:   true,
	})
	if err != nil {
		gr.Close()
		t.Fatal(err)
	}
	moved := make([]CompletePart, len(oi.Parts))
	for i, part := range oi.Parts {
		staleActual := part.Size // what a bad replica records
		hr, herr := hash.NewReader(t.Context(), io.LimitReader(gr, part.Size), part.Size, "", "", staleActual)
		if herr != nil {
			gr.Close()
			t.Fatal(herr)
		}
		pi, perr := obj.PutObjectPart(t.Context(), bucketName, object, res.UploadID, part.Number,
			NewPutObjReader(hr), ObjectOptions{
				PreserveETag: part.ETag,
				IndexCB:      func() []byte { return part.Index },
				NoAuditLog:   true,
			})
		if perr != nil {
			gr.Close()
			t.Fatalf("data-movement PutObjectPart part %d: %v", part.Number, perr)
		}
		moved[i] = CompletePart{ETag: pi.ETag, PartNumber: pi.PartNumber}
	}
	gr.Close()

	// decommissionObject/rebalanceObject complete WITHOUT ReplicationRequest, so
	// the object-level actual-size is recomputed from the part ActualSizes.
	if _, err = obj.CompleteMultipartUpload(t.Context(), bucketName, object, res.UploadID, moved,
		ObjectOptions{DataMovement: true, MTime: oi.ModTime, NoAuditLog: true}); err != nil {
		t.Fatalf("data-movement CompleteMultipartUpload: %v", err)
	}

	after, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[%s] AFTER DATA MOVEMENT parts:", instanceType)
	for _, p := range after.Parts {
		t.Logf("  part %d Size=%d ActualSize=%d", p.Number, p.Size, p.ActualSize)
	}
	gotActual, err := after.GetActualSize()
	if err != nil {
		t.Fatalf("GetActualSize after data movement: %v", err)
	}
	t.Logf("[%s] AFTER DATA MOVEMENT object Size=%d GetActualSize=%d actual-size-meta=%q",
		instanceType, after.Size, gotActual, after.UserDefined[ReservedMetadataPrefix+"actual-size"])

	wantActual := int64(len(plaintext))
	if gotActual != wantActual {
		t.Errorf("[%s] object-level actual size after data movement = %d, want %d",
			instanceType, gotActual, wantActual)
	}
	for i, p := range after.Parts {
		if p.ActualSize != int64(partLens[i]) {
			t.Errorf("[%s] part %d ActualSize after data movement = %d, want %d",
				instanceType, p.Number, p.ActualSize, partLens[i])
		}
	}

	getReq, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", bucketName, object),
		0, nil, credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	getRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK || !bytes.Equal(getRec.Body.Bytes(), plaintext) {
		t.Errorf("[%s] whole-object GET after data movement: status=%d len=%d want %d equal=%v",
			instanceType, getRec.Code, getRec.Body.Len(), len(plaintext), bytes.Equal(getRec.Body.Bytes(), plaintext))
	}
	// The advertised length must be the body length: a poisoned object-level
	// actual-size shows up here as a Content-Length larger than the body.
	if clen := getRec.Header().Get(xhttp.ContentLength); clen != strconv.Itoa(len(plaintext)) || clen != strconv.Itoa(getRec.Body.Len()) {
		t.Errorf("[%s] whole-object GET after data movement advertises Content-Length=%s for a %d-byte body (plaintext %d)",
			instanceType, clen, getRec.Body.Len(), len(plaintext))
	}
}

// TestPartNumberToRangeSpecEncryptedParts pins the read-side repair: for an
// encrypted, uncompressed object the part range is derived from the stored
// ciphertext length, so a replica whose parts still record the ciphertext
// length in ActualSize reads correctly, while plaintext and compressed objects
// keep using ActualSize, and a part whose length cannot be a valid encrypted
// stream is reported as tampered by both callers. See pgsty/silo#119.
func TestPartNumberToRangeSpecEncryptedParts(t *testing.T) {
	const mib = 1024 * 1024
	plain := []int64{5 * mib, 5 * mib, 1024}
	cipher := make([]int64, len(plain))
	for i, n := range plain {
		c, err := sio.EncryptedSize(uint64(n))
		if err != nil {
			t.Fatal(err)
		}
		cipher[i] = int64(c)
	}
	sum := func(v []int64) (s int64) {
		for _, n := range v {
			s += n
		}
		return s
	}
	encMeta := map[string]string{
		crypto.MetaSealedKeySSEC: "sealed-key",
		crypto.MetaIV:            "iv",
		crypto.MetaAlgorithm:     crypto.InsecureSealAlgorithm,
	}
	compressedEncMeta := map[string]string{ReservedMetadataPrefix + "compression": compressionAlgorithmV2}
	for k, v := range encMeta {
		compressedEncMeta[k] = v
	}
	mkParts := func(sizes, actual []int64) []ObjectPartInfo {
		parts := make([]ObjectPartInfo, len(sizes))
		for i := range sizes {
			parts[i] = ObjectPartInfo{Number: i + 1, Size: sizes[i], ActualSize: actual[i]}
		}
		return parts
	}

	// A compressed part's ActualSize is the uploaded length before compression,
	// which bears no relation to the ciphertext length: use lengths whose
	// decrypted size differs from ActualSize so that dropping the compression
	// exclusion is detectable.
	uploaded := []int64{2 * plain[0], 2 * plain[1], 2 * plain[2]}
	wantRangeOf := func(lens []int64, pn int) (start, end int64) {
		for i := 0; i < pn-1; i++ {
			start += lens[i]
		}
		return start, start + lens[pn-1] - 1
	}
	for _, tc := range []struct {
		name string
		oi   ObjectInfo
		lens []int64
	}{
		{"encrypted, stale ciphertext ActualSize", ObjectInfo{Size: sum(cipher), UserDefined: encMeta, Parts: mkParts(cipher, cipher)}, plain},
		{"encrypted, correct ActualSize", ObjectInfo{Size: sum(cipher), UserDefined: encMeta, Parts: mkParts(cipher, plain)}, plain},
		{"plaintext", ObjectInfo{Size: sum(plain), UserDefined: map[string]string{}, Parts: mkParts(plain, plain)}, plain},
		{"compressed and encrypted keeps ActualSize", ObjectInfo{Size: sum(cipher), UserDefined: compressedEncMeta, Parts: mkParts(cipher, uploaded)}, uploaded},
	} {
		for pn := 1; pn <= len(plain); pn++ {
			rs, err := partNumberToRangeSpec(tc.oi, pn)
			if err != nil {
				t.Fatalf("%s: partNumber=%d: %v", tc.name, pn, err)
			}
			start, end := wantRangeOf(tc.lens, pn)
			if rs == nil || rs.Start != start || rs.End != end {
				t.Errorf("%s: partNumber=%d range %+v, want %d-%d", tc.name, pn, rs, start, end)
			}
		}
	}

	// A 31-byte part cannot be a sio stream: both callers report it as tampered.
	bad := ObjectInfo{
		Size:        31 + cipher[1] + cipher[2],
		UserDefined: encMeta,
		Parts:       mkParts([]int64{31, cipher[1], cipher[2]}, []int64{31, plain[1], plain[2]}),
	}
	for pn := 1; pn <= 2; pn++ {
		if _, err := partNumberToRangeSpec(bad, pn); err != errObjectTampered {
			t.Errorf("malformed part: partNumber=%d err=%v, want errObjectTampered", pn, err)
		}
	}
	if _, _, _, err := NewGetObjectReader(nil, bad, ObjectOptions{PartNumber: 1}, http.Header{}); err != errObjectTampered {
		t.Errorf("NewGetObjectReader on a malformed part: err=%v, want errObjectTampered", err)
	}
	if err := setObjectHeaders(t.Context(), httptest.NewRecorder(), bad, nil, ObjectOptions{PartNumber: 1}); err != errObjectTampered {
		t.Errorf("setObjectHeaders on a malformed part: err=%v, want errObjectTampered", err)
	}

	// A zero-length trailing part is a valid (empty) stream and stays accepted.
	zero := ObjectInfo{Size: cipher[0], UserDefined: encMeta, Parts: mkParts([]int64{cipher[0], 0}, []int64{cipher[0], 0})}
	rs, err := partNumberToRangeSpec(zero, 2)
	if err != nil || rs == nil || rs.Start != plain[0] {
		t.Errorf("zero-length trailing part: range %+v err=%v, want start %d", rs, err, plain[0])
	}
}

// TestAPISSECReplicaMalformedPartIsRejected asserts that a trusted SSE-C replica
// part whose ciphertext length cannot be a valid encrypted stream is rejected
// as tampered before the part is committed. See pgsty/silo#119.
func TestAPISSECReplicaMalformedPartIsRejected(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPISSECReplicaMalformedPartIsRejected})
}

func testAPISSECReplicaMalformedPartIsRejected(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, credentials auth.Credentials, t *testing.T,
) {
	previousTLS := globalIsTLS
	globalIsTLS = true
	defer func() { globalIsTLS = previousTLS }()

	replicator := newObjectAttributesAuthzUser(t, instanceType, bucketName, `"s3:PutObject","s3:GetObject","s3:ReplicateObject"`)
	key := bytes.Repeat([]byte{0x45}, 32)
	keyMD5 := md5.Sum(key)
	sseHeaders := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: xhttp.AmzEncryptionAES,
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(key),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}
	object := "ssec-replica-malformed"
	data := bytes.Repeat([]byte("malformed-part-"), 1024)

	putReq, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, object), int64(len(data)),
		bytes.NewReader(data), credentials.AccessKey, credentials.SecretKey, sseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	putRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("%s: source PUT %d: %s", instanceType, putRec.Code, putRec.Body.String())
	}
	gr, err := obj.GetObjectNInfo(t.Context(), bucketName, object, nil, http.Header{}, ObjectOptions{ReplicationRequest: true})
	if err != nil {
		t.Fatal(err)
	}
	sourceInfo := gr.ObjInfo
	raw, err := io.ReadAll(gr)
	gr.Close()
	if err != nil {
		t.Fatal(err)
	}
	replicationOpts, _, err := putReplicationOpts(t.Context(), "", sourceInfo)
	if err != nil {
		t.Fatal(err)
	}
	replicationOpts.Internal.SourceMTime = time.Time{}
	replicationHeaders := make(map[string]string)
	for name, values := range replicationOpts.Header() {
		if len(values) > 0 {
			replicationHeaders[name] = values[0]
		}
	}
	newReq, err := newTestSignedRequestV4(http.MethodPost, getNewMultipartURL("", bucketName, object),
		0, nil, replicator.AccessKey, replicator.SecretKey, replicationHeaders)
	if err != nil {
		t.Fatal(err)
	}
	newRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(newRec, newReq)
	if newRec.Code != http.StatusOK {
		t.Fatalf("%s: replica NewMultipart %d: %s", instanceType, newRec.Code, newRec.Body.String())
	}
	var init InitiateMultipartUploadResponse
	if err = xmlDecoder(newRec.Body, &init, int64(newRec.Body.Len())); err != nil {
		t.Fatal(err)
	}
	partHeaders := map[string]string{xhttp.MinIOSourceReplicationRequest: "true"}

	// 31 bytes cannot be a sio stream (the package header plus its
	// authentication tag occupy 32 bytes).
	badReq, err := newTestSignedRequestV4(http.MethodPut, getPutObjectPartURL("", bucketName, object, init.UploadID, "1"),
		31, bytes.NewReader(raw[:31]), replicator.AccessKey, replicator.SecretKey, partHeaders)
	if err != nil {
		t.Fatal(err)
	}
	badRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(badRec, badReq)
	if badRec.Code == http.StatusOK || !strings.Contains(badRec.Body.String(), "XMinioObjectTampered") {
		t.Fatalf("%s: malformed replica part answered %d: %s", instanceType, badRec.Code, badRec.Body.String())
	}
	lpi, err := obj.ListObjectParts(t.Context(), bucketName, object, init.UploadID, 0, 10, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(lpi.Parts) != 0 {
		t.Fatalf("%s: malformed replica part was committed: %+v", instanceType, lpi.Parts)
	}

	// Control: the real ciphertext still uploads on the same upload.
	goodReq, err := newTestSignedRequestV4(http.MethodPut, getPutObjectPartURL("", bucketName, object, init.UploadID, "1"),
		int64(len(raw)), bytes.NewReader(raw), replicator.AccessKey, replicator.SecretKey, partHeaders)
	if err != nil {
		t.Fatal(err)
	}
	goodRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(goodRec, goodReq)
	if goodRec.Code != http.StatusOK {
		t.Fatalf("%s: valid replica part answered %d: %s", instanceType, goodRec.Code, goodRec.Body.String())
	}
	lpi, err = obj.ListObjectParts(t.Context(), bucketName, object, init.UploadID, 0, 10, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(lpi.Parts) != 1 || lpi.Parts[0].ActualSize != int64(len(data)) {
		t.Fatalf("%s: valid replica part recorded %+v, want one part with ActualSize %d", instanceType, lpi.Parts, len(data))
	}
}
