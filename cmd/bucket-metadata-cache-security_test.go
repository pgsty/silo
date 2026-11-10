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

package cmd

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
)

type metadataCacheLoadBarrier struct {
	ObjectLayer
	key          string
	read, resume chan struct{}
	once         sync.Once
}

func (b *metadataCacheLoadBarrier) GetObjectNInfo(ctx context.Context, bucket, key string, rs *HTTPRangeSpec, h http.Header, opts ObjectOptions) (*GetObjectReader, error) {
	r, err := b.ObjectLayer.GetObjectNInfo(ctx, bucket, key, rs, h, opts)
	if bucket == minioMetaBucket && key == b.key {
		b.once.Do(func() { close(b.read); <-b.resume })
	}
	return r, err
}

func TestBucketMetadataLoadPreservesConcurrentPublication(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t,
		objAPITest: func(obj ObjectLayer, backend, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
			// Disk has the old unlocked config; a concurrent publication enables
			// lock and versioning after the cache miss has started loading it.
			enableBucketObjectLock(t, bucket)
			newer, err := globalBucketMetadataSys.Get(bucket)
			if err != nil {
				t.Fatal(err)
			}
			globalBucketMetadataSys.Remove(bucket)
			barrier := &metadataCacheLoadBarrier{ObjectLayer: obj, key: pathJoin(bucketMetaPrefix, bucket, bucketMetadataFile), read: make(chan struct{}), resume: make(chan struct{})}
			previous := newObjectLayerFn()
			setObjectLayer(barrier)
			defer setObjectLayer(previous)
			release := sync.OnceFunc(func() { close(barrier.resume) })
			defer release()
			type result struct {
				meta     BucketMetadata
				reloaded bool
				err      error
			}
			done := make(chan result, 1)
			go func() {
				meta, reloaded, err := globalBucketMetadataSys.GetConfig(t.Context(), bucket)
				done <- result{meta, reloaded, err}
			}()
			select {
			case <-barrier.read:
			case <-time.After(10 * time.Second):
				t.Fatal("metadata load did not reach disk")
			}
			globalBucketMetadataSys.Set(bucket, newer)
			release()
			select {
			case got := <-done:
				if got.err != nil || got.reloaded || got.meta.objectLockConfig == nil || got.meta.objectLockConfig.ObjectLockEnabled != "Enabled" {
					t.Fatalf("%s: stale load replaced the publication: %+v", backend, got)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("metadata load did not finish")
			}
			cached, err := globalBucketMetadataSys.Get(bucket)
			if err != nil || cached.objectLockConfig == nil || cached.objectLockConfig.ObjectLockEnabled != "Enabled" {
				t.Fatalf("cached lock lost: %+v %v", cached, err)
			}
		},
	})
}

func TestBulkDeleteVersionLockWithStaleBucketCache(t *testing.T) {
	for _, pools := range []int{1, 2} {
		z, _ := bulkDeletePools(t, pools)
		bucket, router, err := initAPIHandlerTest(t.Context(), z, nil, MakeBucketOptions{LockEnabled: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, protection := range batchLockKinds {
			oi := batchPutVersion(t, z, bucket, protection, batchLockMeta(protection))
			saved, err := globalBucketMetadataSys.Get(bucket)
			if err != nil {
				t.Fatal(err)
			}
			globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, bulkDeleteLockRequest(t, bucket, protection, oi.VersionID))
			globalBucketMetadataSys.Set(bucket, saved)
			var response DeleteObjectsResponse
			if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusOK || len(response.Errors) != 1 || len(response.DeletedObjects) != 0 || !batchVersionExists(t, z, bucket, protection, oi.VersionID) {
				t.Fatalf("pools=%d %s: stale bucket cache bypassed version lock: %s", pools, protection, rec.Body.String())
			}
		}
	}
}
