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
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
)

// createDeletedBucketTombstone simulates the site-replication deletion marker
// a replicated delete leaves behind for a bucket.
func createDeletedBucketTombstone(ctx context.Context, t *testing.T, obj ObjectLayer, bucket string) {
	t.Helper()
	z, ok := obj.(*erasureServerPools)
	if !ok {
		t.Skip("erasure pool required")
	}
	if err := z.s3Peer.MakeBucket(ctx, pathJoin(minioMetaBucket, bucketMetaPrefix, deletedBucketsPrefix, bucket), MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
}

func deletedBucketTombstoneTime(ctx context.Context, t *testing.T, obj ObjectLayer, bucket string) (found bool, at time.Time) {
	t.Helper()
	bi, err := obj.GetBucketInfo(ctx, bucket, BucketOptions{Deleted: true, NoMetadata: true})
	if err != nil {
		return false, time.Time{}
	}
	return !bi.Deleted.IsZero(), bi.Deleted
}

func TestSRStaleBucketCreateRejected(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testSRStaleBucketCreateRejected,
	})
}

func testSRStaleBucketCreateRejected(obj ObjectLayer, instanceType, bucket string, _ http.Handler, creds auth.Credentials, t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start from a deleted bucket: the harness bucket is removed without a
	// tombstone, then a replicated-delete tombstone is added.
	if err := obj.DeleteBucket(ctx, bucket, DeleteBucketOptions{Force: true}); err != nil {
		t.Fatalf("%s: removing harness bucket failed: %v", instanceType, err)
	}
	createDeletedBucketTombstone(ctx, t, obj, bucket)
	found, deletedAt := deletedBucketTombstoneTime(ctx, t, obj, bucket)
	if !found {
		t.Fatalf("%s: tombstone missing", instanceType)
	}

	for _, tc := range []struct {
		name      string
		createdAt time.Time
	}{
		{"older-lineage", deletedAt.Add(-time.Hour)},
		{"zero-lineage", time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := globalSiteReplicationSys.PeerBucketMakeWithVersioningHandler(ctx, bucket, MakeBucketOptions{CreatedAt: tc.createdAt})
			if !errors.Is(err, errSRStaleBucketCreate) {
				t.Fatalf("%s: stale make %q: err = %v, want errSRStaleBucketCreate", instanceType, tc.name, err)
			}
			// The bucket must not have been resurrected and the tombstone
			// must survive for the heal loop.
			if _, err := obj.GetBucketInfo(ctx, bucket, BucketOptions{}); !isErrBucketNotFound(err) {
				t.Fatalf("%s: stale make resurrected the bucket: %v", instanceType, err)
			}
			if found, _ := deletedBucketTombstoneTime(ctx, t, obj, bucket); !found {
				t.Fatalf("%s: tombstone lost after stale make", instanceType)
			}
		})
	}
}

func TestSRNewerBucketCreateClearsTombstone(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testSRNewerBucketCreateClearsTombstone,
	})
}

func testSRNewerBucketCreateClearsTombstone(obj ObjectLayer, instanceType, bucket string, _ http.Handler, creds auth.Credentials, t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := obj.DeleteBucket(ctx, bucket, DeleteBucketOptions{Force: true}); err != nil {
		t.Fatalf("%s: removing harness bucket failed: %v", instanceType, err)
	}
	createDeletedBucketTombstone(ctx, t, obj, bucket)
	found, deletedAt := deletedBucketTombstoneTime(ctx, t, obj, bucket)
	if !found {
		t.Fatalf("%s: tombstone missing", instanceType)
	}

	// A re-creation newer than the recorded deletion is legitimate and must
	// clear the obsolete tombstone so bucket state stays unambiguous.
	if err := globalSiteReplicationSys.PeerBucketMakeWithVersioningHandler(ctx, bucket, MakeBucketOptions{
		CreatedAt:         deletedAt.Add(time.Hour),
		VersioningEnabled: true,
	}); err != nil {
		t.Fatalf("%s: newer re-creation rejected: %v", instanceType, err)
	}
	if found, _ := deletedBucketTombstoneTime(ctx, t, obj, bucket); found {
		t.Fatalf("%s: obsolete tombstone kept after newer re-creation", instanceType)
	}
	if _, err := obj.GetBucketInfo(ctx, bucket, BucketOptions{}); err != nil {
		t.Fatalf("%s: re-created bucket missing: %v", instanceType, err)
	}
}

// TestSRGetBucketInfoReportsTombstone verifies that GetBucketInfo with
// Deleted reports a tombstone that outlives a re-created bucket volume,
// matching listBucketsLocal.
func TestSRGetBucketInfoReportsTombstone(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testSRGetBucketInfoReportsTombstone,
	})
}

func testSRGetBucketInfoReportsTombstone(obj ObjectLayer, instanceType, bucket string, _ http.Handler, creds auth.Credentials, t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// The harness bucket is live; adding a tombstone must be visible even
	// though the volume exists.
	createDeletedBucketTombstone(ctx, t, obj, bucket)
	bi, err := obj.GetBucketInfo(ctx, bucket, BucketOptions{Deleted: true, NoMetadata: true})
	if err != nil {
		t.Fatalf("%s: GetBucketInfo(deleted) failed: %v", instanceType, err)
	}
	if bi.Created.IsZero() || bi.Deleted.IsZero() {
		t.Fatalf("%s: live bucket with tombstone: created=%v deleted=%v", instanceType, bi.Created, bi.Deleted)
	}
}

// TestSRDeleteRefreshesTombstone verifies that re-deleting a bucket records a
// fresh deletion time instead of silently keeping the stale tombstone.
func TestSRDeleteRefreshesTombstone(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testSRDeleteRefreshesTombstone,
	})
}

func testSRDeleteRefreshesTombstone(obj ObjectLayer, instanceType, bucket string, _ http.Handler, creds auth.Credentials, t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// A stale tombstone from an earlier lineage.
	createDeletedBucketTombstone(ctx, t, obj, bucket)
	found, firstDeletedAt := deletedBucketTombstoneTime(ctx, t, obj, bucket)
	if !found {
		t.Fatalf("%s: tombstone missing", instanceType)
	}

	time.Sleep(50 * time.Millisecond)

	if err := obj.DeleteBucket(ctx, bucket, DeleteBucketOptions{Force: true, SRDeleteOp: MarkDelete}); err != nil {
		t.Fatalf("%s: delete failed: %v", instanceType, err)
	}
	found, secondDeletedAt := deletedBucketTombstoneTime(ctx, t, obj, bucket)
	if !found {
		t.Fatalf("%s: tombstone missing after delete", instanceType)
	}
	if !secondDeletedAt.After(firstDeletedAt) {
		t.Fatalf("%s: tombstone not refreshed: first=%v second=%v", instanceType, firstDeletedAt, secondDeletedAt)
	}
}
