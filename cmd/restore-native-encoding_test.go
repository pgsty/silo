// Copyright (c) 2026 Feng Ruohang
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
	"github.com/minio/minio/internal/pubsub"
	"github.com/minio/mux"
)

// Exercise the stored representation produced by real S3 uploads. Native
// restore copies encoded bytes, but must retain logical sizes and identity.
func TestNativeRestoreEncodedObjects(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, encoding := range []string{"plain", "compressed", "ssec", "s3-compressed"} {
			for _, layout := range []string{"single", "multipart", "sparse-one-part"} {
				t.Run(fmt.Sprintf("pools=%d/%s/%s", pools, encoding, layout), func(t *testing.T) {
					r := newRestoreSafetyTest(t, pools, versioning.Enabled)
					initConfigSubsystem(t.Context(), r.z)
					r.object = "restore-encoded.txt"
					previousKMS, previousTLS := GlobalKMS, globalIsTLS
					t.Cleanup(func() { GlobalKMS, globalIsTLS = previousKMS, previousTLS })
					globalIsTLS = true
					headers := make(map[string]string)
					readHeaders := make(map[string]string)
					if encoding == "compressed" || encoding == "s3-compressed" {
						enableAttributesPartsCompression(t)
					}
					if encoding == "ssec" {
						headers = ssecTestHeaders(0x53)
						readHeaders = ssecTestHeaders(0x53)
					}
					if encoding == "s3-compressed" {
						var err error
						GlobalKMS, err = kms.NewBuiltin("restore-test-key", bytes.Repeat([]byte{0x59}, 32))
						if err != nil {
							t.Fatal(err)
						}
						headers[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionAES
					}
					previousObjectAPI := newObjectLayerFn()
					t.Cleanup(func() { setObjectLayer(previousObjectAPI) })
					router := initTestAPIEndPoints(r.z, []string{"NewMultipart", "PutObjectPart", "CompleteMultipart", "PutObject", "GetObject"})
					bodies := [][]byte{bytes.Repeat([]byte("encoded-restore-"), compMinIndexSize/16+1)}
					partNumbers := []int{1}
					switch layout {
					case "multipart":
						bodies = append(bodies, []byte("last encoded part"))
						partNumbers = []int{1, 2}
					case "sparse-one-part":
						partNumbers = []int{5}
					}
					want := bytes.Join(bodies, nil)
					if layout == "single" {
						headers[xhttp.AmzChecksumCRC32] = mustChecksum(t, hash.ChecksumCRC32, want)
						putCopyChecksumSource(t, router, globalActiveCred, r.bucket, r.object, want, headers)
					} else {
						attributesPartsUpload(t, router, globalActiveCred, r.bucket, r.object, headers, bodies, partNumbers)
					}
					before, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, ObjectOptions{})
					if err != nil {
						t.Fatal(err)
					}
					if before.IsCompressed() != (encoding == "compressed" || encoding == "s3-compressed") {
						t.Fatalf("unexpected compression state: %v", before.IsCompressed())
					}
					if before.IsCompressed() && len(before.Parts[0].Index) == 0 {
						t.Fatal("fixture must have a compression index")
					}
					if layout == "single" && len(before.Checksum) == 0 {
						t.Fatal("fixture must have a stored checksum")
					}
					objectURL := getGetObjectURL("", r.bucket, r.object) + "?versionId=" + url.QueryEscape(before.VersionID)
					beforeGet := attributesPartsSignedRequest(t, router, globalActiveCred, http.MethodGet, objectURL, nil, readHeaders)
					if beforeGet.Code != http.StatusOK || !bytes.Equal(beforeGet.Body.Bytes(), want) {
						t.Fatalf("fixture GET: %d bytes=%d want=%d", beforeGet.Code, beforeGet.Body.Len(), len(want))
					}
					beforeRaw := nativeRestoreSnapshot(t, r)
					topts := r.opts(before.VersionID)
					topts.MTime = before.ModTime
					topts.Transition = TransitionOptions{Tier: "WARM", ETag: before.ETag}
					if err := r.z.TransitionObject(t.Context(), r.bucket, r.object, topts); err != nil {
						t.Fatal(err)
					}
					observed := nativeRestoreHTTPObserver{r.z, make(chan nativeRestoreHTTPResult, 1)}
					api := objectAPIHandlers{ObjectAPI: func() ObjectLayer { return observed }}
					events, done := make(chan event.Event, 1), make(chan struct{})
					defer close(done)
					if err := globalHTTPListen.Subscribe(pubsub.MaskFromMaskable(event.ObjectRestoreCompleted), events, done, nil); err != nil {
						t.Fatal(err)
					}
					restoreXML := []byte(`<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>1</Days></RestoreRequest>`)
					req, err := newTestSignedRequestV4(http.MethodPost, objectURL+"&restore", int64(len(restoreXML)), bytes.NewReader(restoreXML), globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := req.ParseForm(); err != nil {
						t.Fatal(err)
					}
					req = mux.SetURLVars(req, map[string]string{"bucket": r.bucket, "object": r.object})
					rec := httptest.NewRecorder()
					api.PostRestoreObjectHandler(rec, req)
					if rec.Code != http.StatusOK {
						t.Fatalf("restore POST: %d %s", rec.Code, rec.Body.String())
					}
					select {
					case result := <-observed.done:
						if result.err != nil {
							t.Fatalf("background restore: %v", result.err)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("restore did not finish")
					}
					select {
					case <-events:
					case <-time.After(5 * time.Second):
						t.Fatal("restore completion event missing")
					}
					after, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(before.VersionID))
					if err != nil {
						t.Fatal(err)
					}
					if after.ETag != before.ETag || after.Size != before.Size || !after.ModTime.Equal(before.ModTime) {
						t.Error("restore changed content identity")
					}
					afterRaw := nativeRestoreSnapshot(t, r)
					for pool := range beforeRaw {
						if len(afterRaw[pool]) != len(beforeRaw[pool]) {
							t.Fatalf("pool %d version count changed", pool)
						}
						for i, fi := range beforeRaw[pool] {
							if !bytes.Equal(fi.Checksum, afterRaw[pool][i].Checksum) {
								t.Error("restore lost stored checksum")
							}
						}
					}
					if len(after.Parts) != len(before.Parts) {
						t.Fatal("restore changed part count")
					}
					for i, part := range after.Parts {
						old := before.Parts[i]
						if part.Number != old.Number || part.Size != old.Size || part.ActualSize != old.ActualSize || !bytes.Equal(part.Index, old.Index) {
							t.Errorf("part %d layout or compression index changed", i)
						}
					}
					tier := globalTierConfigMgr.drivercache["WARM"].(*restoreTestTier)
					reads := tier.gets.Load()
					got := attributesPartsSignedRequest(t, router, globalActiveCred, http.MethodGet, objectURL, nil, readHeaders)
					if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), want) {
						t.Errorf("restored GET: %d bytes=%d want=%d", got.Code, got.Body.Len(), len(want))
					}
					if got.Header().Get(xhttp.ETag) != beforeGet.Header().Get(xhttp.ETag) {
						t.Error("restore changed client ETag")
					}
					for i, number := range partNumbers {
						part := attributesPartsSignedRequest(t, router, globalActiveCred, http.MethodGet, objectURL+fmt.Sprintf("&partNumber=%d", number), nil, readHeaders)
						if part.Code != http.StatusPartialContent || !bytes.Equal(part.Body.Bytes(), bodies[i]) {
							t.Errorf("restored part %d: %d bytes=%d want=%d", number, part.Code, part.Body.Len(), len(bodies[i]))
						}
					}
					if tier.gets.Load() != reads {
						t.Error("restored GET still used remote tier")
					}
				})
			}
		}
	}
}
