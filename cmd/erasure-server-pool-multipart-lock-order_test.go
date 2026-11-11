// Copyright (c) 2026 PGSTY
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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	xhttp "github.com/minio/minio/internal/http"
)

type copyPartSourceContextKey struct{}

// Pause the HTTP copy after the real reader has acquired its source lock.
// IAM and other background readers do not carry the request's context key.
type copyPartSourceGate struct {
	ObjectLayer
	opened, release chan struct{}
}

func (a *copyPartSourceGate) GetObjectNInfo(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, opts ObjectOptions) (*GetObjectReader, error) {
	gr, err := a.ObjectLayer.GetObjectNInfo(ctx, bucket, object, rs, h, opts)
	if err != nil || ctx.Value(copyPartSourceContextKey{}) != true {
		return gr, err
	}
	close(a.opened)
	select {
	case <-a.release:
		return gr, nil
	case <-ctx.Done():
		gr.Close()
		return nil, ctx.Err()
	}
}

func copyPartLockRefs(l *localLockInstance) int32 {
	l.ns.lockMapMutex.Lock()
	defer l.ns.lockMapMutex.Unlock()
	if lock := l.ns.lockMap[pathJoin(l.volume, l.paths[0])]; lock != nil {
		return lock.ref
	}
	return 0
}

// A copy from the upload's own key holds object RLock before asking for the
// upload RLock. Complete must wait for that reader without holding upload
// Lock, on both single- and multi-pool backends. Cancellation of either
// request must release its locks and let the other request finish.
func TestUploadPartCopyConcurrentComplete(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, action := range []string{"complete", "cancel-copy", "cancel-complete"} {
			t.Run(fmt.Sprintf("pools=%d/%s", pools, action), func(t *testing.T) {
				z, _ := bulkDeletePools(t, pools)
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				var workers sync.WaitGroup
				defer func() { cancel(); workers.Wait() }()
				api := &copyPartSourceGate{ObjectLayer: z, opened: make(chan struct{}), release: make(chan struct{})}
				bucket, router, err := initAPIHandlerTest(ctx, api, nil, MakeBucketOptions{})
				if err != nil {
					t.Fatal(err)
				}
				setObjectLayer(api)
				const key = "copy-part-self"
				data := bytes.Repeat([]byte("existing source bytes"), 32768)
				oi, err := z.PutObject(ctx, bucket, key, mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if oi.Inlined {
					t.Fatal("the source must retain its read lock until its reader closes")
				}
				upload, err := z.NewMultipartUpload(ctx, bucket, key, ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				first := []byte("the completed part")
				part, err := z.PutObjectPart(ctx, bucket, key, upload.UploadID, 1, mustGetPutObjReader(t, bytes.NewReader(first), int64(len(first)), "", ""), ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}

				objectLock := z.NewObjectNSLock(bucket, key).(*localLockInstance)
				uploadLock := z.uploadIDNSLock(bucket, key, upload.UploadID).(*localLockInstance)
				copyCtx, cancelCopy := context.WithCancel(context.WithValue(ctx, copyPartSourceContextKey{}, true))
				defer cancelCopy()
				req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectPartURL("", bucket, key, upload.UploadID, "2"), 0, nil, globalActiveCred.AccessKey, globalActiveCred.SecretKey, map[string]string{xhttp.AmzCopySource: "/" + bucket + "/" + key})
				if err != nil {
					t.Fatal(err)
				}
				copyDone := make(chan *httptest.ResponseRecorder, 1)
				workers.Go(func() {
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req.WithContext(copyCtx))
					copyDone <- rec
				})
				select {
				case <-api.opened:
				case <-ctx.Done():
					t.Fatal("COPY did not open its source")
				}
				if refs := copyPartLockRefs(objectLock); refs != 1 {
					t.Fatalf("COPY object lock references = %d, want 1", refs)
				}

				completeCtx, cancelComplete := context.WithCancel(ctx)
				defer cancelComplete()
				completeDone := make(chan error, 1)
				workers.Go(func() {
					_, err := z.CompleteMultipartUpload(completeCtx, bucket, key, upload.UploadID, []CompletePart{{PartNumber: 1, ETag: part.ETag}}, ObjectOptions{})
					completeDone <- err
				})
				// One reference belongs to COPY, the second to Complete waiting
				// for it. Check the actual lock resources, not elapsed time.
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for copyPartLockRefs(objectLock) != 2 {
					select {
					case err := <-completeDone:
						t.Fatalf("Complete exited before waiting for COPY: %v", err)
					case <-ctx.Done():
						t.Fatal("Complete did not wait for the source object lock")
					case <-ticker.C:
					}
				}
				if refs := copyPartLockRefs(uploadLock); refs != 0 {
					t.Fatalf("Complete holds the upload lock while waiting for COPY's object lock: refs=%d", refs)
				}

				if action == "cancel-complete" {
					cancelComplete()
					select {
					case err := <-completeDone:
						if !errors.Is(err, context.Canceled) {
							t.Fatalf("canceled Complete: %v", err)
						}
					case <-ctx.Done():
						t.Fatal("Complete did not cancel while COPY held the source")
					}
				}
				if action == "cancel-copy" {
					cancelCopy()
				} else {
					close(api.release)
				}
				select {
				case rec := <-copyDone:
					want := http.StatusOK
					if action == "cancel-copy" {
						want = 499
					}
					if rec.Code != want {
						t.Fatalf("COPY: %d, want %d: %s", rec.Code, want, rec.Body.String())
					}
				case <-ctx.Done():
					t.Fatal("COPY did not finish")
				}
				if action != "cancel-complete" {
					select {
					case err := <-completeDone:
						if err != nil {
							t.Fatalf("Complete after source release: %v", err)
						}
					case <-ctx.Done():
						t.Fatal("Complete did not finish after source release")
					}
				}
				if copyPartLockRefs(objectLock) != 0 || copyPartLockRefs(uploadLock) != 0 {
					t.Fatal("request left an object or upload lock behind")
				}
				wantBody := string(first)
				if action == "cancel-complete" {
					wantBody = string(data)
					if _, err := z.GetMultipartInfo(ctx, bucket, key, upload.UploadID, ObjectOptions{}); err != nil {
						t.Fatalf("canceled completion lost the upload: %v", err)
					}
				}
				if body := bulkDeleteBody(t, z, bucket, key, ""); body != wantBody {
					t.Fatalf("object body length = %d, want %d", len(body), len(wantBody))
				}
			})
		}
	}
}
