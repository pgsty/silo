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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/replication"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/once"
)

// ilmDeleteTarget models one replication destination for ILM expiry tests.
type ilmDeleteTarget struct {
	arn, bucket string
	deletes     atomic.Int32
}

func newILMTestTarget(t *testing.T) *ilmDeleteTarget {
	return &ilmDeleteTarget{arn: "arn:minio:replication::" + mustGetUUID() + ":bucket", bucket: getRandomBucketName()}
}

func registerILMTestTarget(t *testing.T, obj ObjectLayer, bucket string, target *ilmDeleteTarget, handler http.HandlerFunc) {
	t.Helper()
	if err := obj.MakeBucket(t.Context(), target.bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewServer(handler)
	t.Cleanup(remote.Close)
	client, err := minio.New(strings.TrimPrefix(remote.URL, "http://"), &minio.Options{Region: "us-east-1", MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	globalBucketTargetSys.Lock()
	globalBucketTargetSys.arnRemotesMap[target.arn] = arnTarget{Client: &TargetClient{Client: client, ARN: target.arn, Bucket: target.bucket}, lastRefresh: UTCNow()}
	globalBucketTargetSys.targetsMap[bucket] = append(globalBucketTargetSys.targetsMap[bucket], madmin.BucketTarget{Arn: target.arn, TargetBucket: target.bucket})
	globalBucketTargetSys.Unlock()
	globalBucketTargetSys.hMutex.Lock()
	globalBucketTargetSys.hc[client.EndpointURL().Host] = epHealth{Online: true}
	globalBucketTargetSys.hMutex.Unlock()
}

func setILMTestReplicationConfig(t *testing.T, bucket, arn, targetBucket string) {
	t.Helper()
	cfg := replication.Config{}
	rule := configs[0].Rules[0]
	rule.Priority = 1
	rule.Destination = replication.Destination{ARN: arn, Bucket: targetBucket}
	cfg.Rules = append(cfg.Rules, rule)
	cfg.RoleArn = arn
	meta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	meta.replicationConfig = &cfg
	globalBucketMetadataSys.Set(bucket, meta)
}

func newILMTestReplicationPool(ctx context.Context, obj ObjectLayer, stats *ReplicationStats) (restore func(), receive func() DeletedObjectReplicationInfo) {
	old := globalReplicationPool
	p := &ReplicationPool{ctx: ctx, objLayer: obj, workers: []chan ReplicationWorkerOperation{make(chan ReplicationWorkerOperation, 8)}, stats: stats, mrfSaveCh: make(chan MRFReplicateEntry, 8)}
	globalReplicationPool = once.NewSingleton[ReplicationPool]()
	globalReplicationPool.Set(p)
	return func() { globalReplicationPool = old }, func() DeletedObjectReplicationInfo {
		select {
		case op := <-p.workers[0]:
			d, ok := op.(DeletedObjectReplicationInfo)
			if !ok {
				return DeletedObjectReplicationInfo{}
			}
			return d
		case <-time.After(3 * time.Second):
			return DeletedObjectReplicationInfo{}
		}
	}
}

// TestReplicateILMExpiryDeleteMarker verifies that a delete marker created by
// ILM expiry carries delete replication state and is queued for replication,
// exactly like a marker created through the S3 DELETE API.
func TestReplicateILMExpiryDeleteMarker(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testReplicateILMExpiryDeleteMarker,
	})
}

func testReplicateILMExpiryDeleteMarker(obj ObjectLayer, instanceType, bucket string, _ http.Handler, creds auth.Credentials, t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stats := NewReplicationStats(ctx, nil)
	oldStats := globalReplicationStats.Swap(stats)
	defer globalReplicationStats.Store(oldStats)

	const name = "ilm-object"
	if _, err := globalBucketMetadataSys.Update(ctx, bucket, bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatal(err)
	}
	// DeleteObject refuses ILM expiry (Expiration.Expire) without lifecycle
	// rules; a date in the past makes every version eligible immediately.
	ilmXML := []byte(`<LifecycleConfiguration><Rule><ID>ilm-expire</ID><Status>Enabled</Status><Filter/><Expiration><Date>2020-01-01T00:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>`)
	if _, err := globalBucketMetadataSys.Update(ctx, bucket, bucketLifecycleConfig, ilmXML); err != nil {
		t.Fatal(err)
	}
	oi, err := obj.PutObject(ctx, bucket, name, mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{Versioned: true})
	if err != nil {
		t.Fatal(err)
	}

	target := newILMTestTarget(t)
	registerILMTestTarget(t, obj, bucket, target, func(w http.ResponseWriter, r *http.Request) {
		topts := ObjectOptions{VersionID: r.URL.Query().Get("versionId"), Versioned: true}
		switch r.Method {
		case http.MethodHead:
			roi, rerr := obj.GetObjectInfo(r.Context(), target.bucket, name, topts)
			if roi.DeleteMarker {
				w.Header().Set(xhttp.AmzDeleteMarker, "true")
				w.Header().Set(xhttp.AmzVersionID, roi.VersionID)
			}
			if rerr != nil {
				writeErrorResponseHeadersOnly(w, toAPIError(r.Context(), rerr))
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			target.deletes.Add(1)
			if topts.VersionID == "" {
				t.Error("missing remote versionId")
			}
			topts.DeleteMarker = r.Header.Get(xhttp.MinIOSourceDeleteMarker) == "true"
			topts.ReplicationRequest = true
			topts.SetReplicaStatus(replication.Replica)
			if _, err := obj.DeleteObject(r.Context(), target.bucket, name, topts); err != nil && !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
				writeErrorResponse(r.Context(), w, toAPIError(r.Context(), err), r.URL)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected remote method %s", r.Method)
		}
	})
	setILMTestReplicationConfig(t, bucket, target.arn, target.bucket)
	restorePool, receive := newILMTestReplicationPool(ctx, obj, stats)
	defer restorePool()

	if ok := applyExpiryOnNonTransitionedObjects(ctx, obj, oi, lifecycle.Event{Action: lifecycle.DeleteAction}, lcEventSrc_Scanner); !ok {
		t.Fatalf("%s: ILM expiry did not apply", instanceType)
	}

	deletion := receive()
	if deletion.ObjectName == "" {
		t.Fatalf("%s: ILM delete marker was not queued for replication", instanceType)
	}
	if !deletion.DeleteMarker || deletion.VersionID != "" || deletion.DeleteMarkerVersionID == "" {
		t.Fatalf("%s: unexpected queued delete: %+v", instanceType, deletion)
	}
	if deletion.EventType != ReplicateILMDelete {
		t.Fatalf("%s: queued event type = %q, want %q", instanceType, deletion.EventType, ReplicateILMDelete)
	}

	// The ILM-created marker must carry pending replication state.
	markerVID := deletion.DeleteMarkerVersionID
	moi, merr := obj.GetObjectInfo(ctx, bucket, name, ObjectOptions{VersionID: markerVID, Versioned: true})
	if !isErrMethodNotAllowed(merr) || !moi.DeleteMarker {
		t.Fatalf("%s: ILM marker missing: %v %v", instanceType, moi, merr)
	}
	if moi.ReplicationStatus != replication.Pending {
		t.Fatalf("%s: ILM marker replication status = %q, want PENDING", instanceType, moi.ReplicationStatus)
	}

	result := replicateDelete(ctx, deletion, obj)
	if result.ReplicationStatus() != replication.Completed {
		t.Fatalf("%s: marker replication result: %+v", instanceType, result)
	}
	if target.deletes.Load() != 1 {
		t.Fatalf("%s: target saw %d deletes, want 1", instanceType, target.deletes.Load())
	}
	// The marker must exist on the target.
	roi, rerr := obj.GetObjectInfo(ctx, target.bucket, name, ObjectOptions{VersionID: markerVID, Versioned: true})
	if !isErrMethodNotAllowed(rerr) || !roi.DeleteMarker {
		t.Fatalf("%s: target marker missing: %v %v", instanceType, roi, rerr)
	}
	// The source marker records the completed replication per target. The
	// composite ReplicationStatus field is unreliable on read-back for
	// markers carrying a replication timestamp, so assert the raw state.
	moi, merr = obj.GetObjectInfo(ctx, bucket, name, ObjectOptions{VersionID: markerVID})
	if !isErrMethodNotAllowed(merr) || !strings.Contains(moi.ReplicationStatusInternal, "=COMPLETED;") {
		t.Fatalf("%s: source marker state = %q (err %v), want COMPLETED", instanceType, moi.ReplicationStatusInternal, merr)
	}
}

// TestReplicateILMExpiryNoncurrentPurge verifies that a noncurrent version
// removed by ILM carries a pending version purge state, is queued for delete
// replication and converges on the target.
func TestReplicateILMExpiryNoncurrentPurge(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testReplicateILMExpiryNoncurrentPurge,
	})
}

func testReplicateILMExpiryNoncurrentPurge(obj ObjectLayer, instanceType, bucket string, _ http.Handler, creds auth.Credentials, t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stats := NewReplicationStats(ctx, nil)
	oldStats := globalReplicationStats.Swap(stats)
	defer globalReplicationStats.Store(oldStats)

	const name = "ilm-object"
	if _, err := globalBucketMetadataSys.Update(ctx, bucket, bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatal(err)
	}
	v1Info, err := obj.PutObject(ctx, bucket, name, mustGetPutObjReader(t, strings.NewReader("v1"), 2, "", ""), ObjectOptions{Versioned: true})
	if err != nil {
		t.Fatal(err)
	}
	v1 := v1Info.VersionID
	if v1 == "" {
		t.Fatalf("%s: missing version ID on first version", instanceType)
	}
	if _, err := obj.PutObject(ctx, bucket, name, mustGetPutObjReader(t, strings.NewReader("v2"), 2, "", ""), ObjectOptions{Versioned: true}); err != nil {
		t.Fatal(err)
	}

	target := newILMTestTarget(t)
	registerILMTestTarget(t, obj, bucket, target, func(w http.ResponseWriter, r *http.Request) {
		topts := ObjectOptions{VersionID: r.URL.Query().Get("versionId"), Versioned: true}
		switch r.Method {
		case http.MethodDelete:
			target.deletes.Add(1)
			if topts.VersionID == "" {
				t.Error("missing remote versionId")
			}
			topts.DeleteMarker = r.Header.Get(xhttp.MinIOSourceDeleteMarker) == "true"
			topts.ReplicationRequest = true
			topts.SetReplicaStatus(replication.Replica)
			if _, err := obj.DeleteObject(r.Context(), target.bucket, name, topts); err != nil && !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
				writeErrorResponse(r.Context(), w, toAPIError(r.Context(), err), r.URL)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected remote method %s", r.Method)
		}
	})
	// Pre-create a marker version on the target with the same version ID as
	// the noncurrent version being purged, so the purge can be observed.
	if _, err := obj.DeleteObject(ctx, target.bucket, name, ObjectOptions{VersionID: v1, Versioned: true, DeleteMarker: true, ReplicationRequest: true}); err != nil {
		t.Fatal(err)
	}
	setILMTestReplicationConfig(t, bucket, target.arn, target.bucket)
	restorePool, receive := newILMTestReplicationPool(ctx, obj, stats)
	defer restorePool()

	// The scanner evaluates noncurrent version expiry per version; build the
	// delete entry exactly the way the scanner does for the oldest version.
	vi, verr := obj.GetObjectInfo(ctx, bucket, name, ObjectOptions{VersionID: v1, Versioned: true})
	if verr != nil {
		t.Fatalf("%s: missing noncurrent version: %v", instanceType, verr)
	}
	otd := ilmPurgeToDelete(ctx, bucket, vi, true)
	if otd.VersionPurgeStatus != replication.VersionPurgePending || otd.VersionPurgeStatuses == "" || otd.ReplicateDecisionStr == "" {
		t.Fatalf("%s: ILM purge entry carries no replication state: %+v", instanceType, otd)
	}
	if plain := ilmPurgeToDelete(ctx, bucket, vi, false); plain.VersionPurgeStatus != "" || plain.ReplicateDecisionStr != "" {
		t.Fatalf("%s: non-replicating purge entry carries state: %+v", instanceType, plain)
	}

	deleteObjectVersions(ctx, obj, bucket, []ObjectToDelete{otd}, []lifecycle.Event{{Action: lifecycle.DeleteVersionAction}})

	// The version must remain locally as a tombstone with pending purge
	// state until replication completes.
	pi, perr := obj.GetObjectInfo(ctx, bucket, name, ObjectOptions{VersionID: v1, Versioned: true})
	if !isErrMethodNotAllowed(perr) {
		t.Fatalf("%s: purged version metadata lost: %v", instanceType, perr)
	}
	if pi.VersionPurgeStatus != replication.VersionPurgePending {
		t.Fatalf("%s: purged version state = %q, want PENDING", instanceType, pi.VersionPurgeStatus)
	}

	deletion := receive()
	if deletion.ObjectName == "" {
		t.Fatalf("%s: ILM noncurrent purge was not queued for replication", instanceType)
	}
	if deletion.VersionID != v1 || deletion.DeleteMarkerVersionID != "" || deletion.DeleteMarker {
		t.Fatalf("%s: unexpected queued purge: %+v", instanceType, deletion)
	}

	result := replicateDelete(ctx, deletion, obj)
	if result.VersionPurgeStatus() != replication.VersionPurgeComplete {
		t.Fatalf("%s: purge replication result: %+v", instanceType, result)
	}
	if target.deletes.Load() != 1 {
		t.Fatalf("%s: target saw %d deletes, want 1", instanceType, target.deletes.Load())
	}
	// The purge must have converged on the target.
	if _, terr := obj.GetObjectInfo(ctx, target.bucket, name, ObjectOptions{VersionID: v1, Versioned: true}); !isErrVersionNotFound(terr) && !isErrObjectNotFound(terr) {
		t.Fatalf("%s: target version still present: %v", instanceType, terr)
	}
	// Once the purge completes the local tombstone is freed and the version
	// is gone on both sides.
	if _, terr := obj.GetObjectInfo(ctx, bucket, name, ObjectOptions{VersionID: v1}); !isErrVersionNotFound(terr) && !isErrObjectNotFound(terr) {
		t.Fatalf("%s: purged version still present locally: %v", instanceType, terr)
	}
}
