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
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/replication"
	"github.com/minio/minio/internal/bucket/versioning"
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
	oldPool := globalReplicationPool
	p := &ReplicationPool{ctx: ctx, objLayer: obj, workers: []chan ReplicationWorkerOperation{make(chan ReplicationWorkerOperation, 8)}, stats: stats, mrfSaveCh: make(chan MRFReplicateEntry, 8)}
	globalReplicationPool = once.NewSingleton[ReplicationPool]()
	globalReplicationPool.Set(p)
	return func() { globalReplicationPool = oldPool }, func() DeletedObjectReplicationInfo {
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

// Lifecycle deletes are not replicated: a delete marker or a version purge
// that ILM makes stays on the source, as in S3. The replication heal still
// sends an empty-state marker when existing-object replication applies to
// it, as it always did; that path is pinned here too.

// ilmTestTarget registers a target that applies the deletes it receives and
// records the requests, and the replication configuration of bucket with
// existing-object replication set as given.
func ilmTestTarget(t *testing.T, obj ObjectLayer, bucket, name string, existing bool) (*ilmDeleteTarget, *atomic.Int32) {
	t.Helper()
	target := newILMTestTarget(t)
	var requests atomic.Int32
	registerILMTestTarget(t, obj, bucket, target, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
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
	if !existing {
		meta, err := globalBucketMetadataSys.Get(bucket)
		if err != nil {
			t.Fatal(err)
		}
		cfg := *meta.replicationConfig
		cfg.Rules = slices.Clone(cfg.Rules)
		cfg.Rules[0].ExistingObjectReplication = replication.ExistingObjectReplication{Status: replication.Disabled}
		meta.replicationConfig = &cfg
		globalBucketMetadataSys.Set(bucket, meta)
	}
	return target, &requests
}

// ilmTestReplicationConfig is the replication configuration the scanner and
// the replication heal use for bucket.
func ilmTestReplicationConfig(t *testing.T, bucket string) replicationConfig {
	t.Helper()
	cfg, err := getReplicationConfig(t.Context(), bucket)
	if err != nil || cfg == nil {
		t.Fatalf("replication config: %v", err)
	}
	remotes, err := globalBucketTargetSys.ListBucketTargets(t.Context(), bucket)
	if err != nil {
		t.Fatalf("bucket targets: %v", err)
	}
	return replicationConfig{Config: cfg, remotes: remotes}
}

// An ILM delete marker carries no replication state and is not queued; with
// existing-object replication off, the replication heal leaves it too.
func TestILMExpiryDeleteMarkerNotReplicated(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testILMExpiryDeleteMarkerNotReplicated})
}

func testILMExpiryDeleteMarkerNotReplicated(obj ObjectLayer, instanceType, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ilmMarkerReplicationCase(obj, instanceType, bucket, t, false)
}

// The inherited exception: with existing-object replication on, the
// replication heal sends an empty-state ILM delete marker, as it did before
// lifecycle deletes were ever replication-aware.
func TestILMExpiryDeleteMarkerExistingObjectResync(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testILMExpiryDeleteMarkerExistingObjectResync})
}

func testILMExpiryDeleteMarkerExistingObjectResync(obj ObjectLayer, instanceType, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ilmMarkerReplicationCase(obj, instanceType, bucket, t, true)
}

func ilmMarkerReplicationCase(obj ObjectLayer, instanceType, bucket string, t *testing.T, existing bool) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stats := NewReplicationStats(ctx, nil)
	oldStats := globalReplicationStats.Swap(stats)
	defer globalReplicationStats.Store(oldStats)

	const name = "ilm-object"
	if _, err := globalBucketMetadataSys.Update(ctx, bucket, bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatal(err)
	}
	ilmXML := []byte(`<LifecycleConfiguration><Rule><ID>ilm-expire</ID><Status>Enabled</Status><Filter/><Expiration><Date>2020-01-01T00:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>`)
	if _, err := globalBucketMetadataSys.Update(ctx, bucket, bucketLifecycleConfig, ilmXML); err != nil {
		t.Fatal(err)
	}
	oi, err := obj.PutObject(ctx, bucket, name, mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{Versioned: true})
	if err != nil {
		t.Fatal(err)
	}
	target, requests := ilmTestTarget(t, obj, bucket, name, existing)
	restorePool, _ := newILMTestReplicationPool(ctx, obj, stats)
	defer restorePool()
	queue := globalReplicationPool.Get().workers[0]

	if ok := applyExpiryOnNonTransitionedObjects(ctx, obj, oi, lifecycle.Event{Action: lifecycle.DeleteAction}, lcEventSrc_Scanner); !ok {
		t.Fatalf("%s: ILM expiry did not apply", instanceType)
	}
	if n := len(queue); n != 0 {
		t.Fatalf("%s: ILM expiry queued %d replication tasks", instanceType, n)
	}
	marker, err := obj.GetObjectInfo(ctx, bucket, name, ObjectOptions{Versioned: true})
	if !isErrMethodNotAllowed(err) && !isErrObjectNotFound(err) || !marker.DeleteMarker || marker.VersionID == "" {
		t.Fatalf("%s: latest after expiry: %+v %v", instanceType, marker, err)
	}
	marker.Bucket, marker.Name = bucket, name
	if !marker.ReplicationStatus.Empty() || marker.ReplicationStatusInternal != "" {
		t.Fatalf("%s: ILM marker carries replication state %q / %q", instanceType, marker.ReplicationStatus, marker.ReplicationStatusInternal)
	}

	// The replication heal, as the scanner runs it for the marker.
	queueReplicationHeal(ctx, bucket, marker, ilmTestReplicationConfig(t, bucket), 0)
	if !existing {
		if n := len(queue); n != 0 {
			t.Fatalf("%s: replication heal queued %d tasks for an ILM marker", instanceType, n)
		}
		if n := requests.Load(); n != 0 {
			t.Fatalf("%s: the target saw %d requests", instanceType, n)
		}
		return
	}
	// The test harness reuses the bucket name for each object layer type, so
	// targets registered for earlier ones are still listed: expect a task for
	// at least the target of this run. Existing-object replication may also
	// resync the data version; only the marker's tasks matter here.
	markerTasks := 0
	for n := len(queue); n > 0; n-- {
		op := <-queue
		deletion, ok := op.(DeletedObjectReplicationInfo)
		if !ok {
			continue
		}
		if !deletion.DeleteMarker || deletion.DeleteMarkerVersionID != marker.VersionID {
			t.Fatalf("%s: unexpected resync task %+v", instanceType, deletion)
		}
		markerTasks++
		replicateDelete(ctx, deletion, obj)
	}
	if markerTasks == 0 {
		t.Fatalf("%s: existing-object resync queued no task for the marker", instanceType)
	}
	if target.deletes.Load() == 0 {
		t.Fatalf("%s: the target saw no delete", instanceType)
	}
}

// An API delete of a version still carries a purge decision and is queued:
// only lifecycle deletes are left out of replication.
func TestAPIVersionDeleteStillReplicated(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPIVersionDeleteStillReplicated})
}

func testAPIVersionDeleteStillReplicated(obj ObjectLayer, instanceType, bucket string, router http.Handler, creds auth.Credentials, t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stats := NewReplicationStats(ctx, nil)
	oldStats := globalReplicationStats.Swap(stats)
	defer globalReplicationStats.Store(oldStats)

	const name = "api-object"
	if _, err := globalBucketMetadataSys.Update(ctx, bucket, bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := obj.PutObject(ctx, bucket, name, mustGetPutObjReader(t, strings.NewReader("v1"), 2, "", ""), ObjectOptions{Versioned: true}); err != nil {
		t.Fatal(err)
	}
	v1, err := obj.PutObject(ctx, bucket, name, mustGetPutObjReader(t, strings.NewReader("v2"), 2, "", ""), ObjectOptions{Versioned: true})
	if err != nil {
		t.Fatal(err)
	}
	ilmTestTarget(t, obj, bucket, name, false)
	restorePool, receive := newILMTestReplicationPool(ctx, obj, stats)
	defer restorePool()

	req, err := newTestSignedRequestV4(http.MethodDelete, getDeleteObjectURL("", bucket, name)+"?versionId="+v1.VersionID, 0, nil, creds.AccessKey, creds.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("%s: DELETE: %d %s", instanceType, rec.Code, rec.Body.String())
	}
	deletion := receive()
	if deletion.VersionID != v1.VersionID || deletion.VersionPurgeStatus() != replication.VersionPurgePending {
		t.Fatalf("%s: API version delete not queued for replication: %+v", instanceType, deletion)
	}
}

// The scanner's noncurrent expiry deletes the version at once: no pending
// purge tombstone, nothing queued, the target untouched.
func TestILMNoncurrentPurgeNotReplicatedThroughScanner(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	ctx := t.Context()
	stats := NewReplicationStats(ctx, nil)
	oldStats := globalReplicationStats.Swap(stats)
	t.Cleanup(func() { globalReplicationStats.Store(oldStats) })

	const key = "ncv-scanner-replicated"
	s.write(key, splitAt("old", 5, 0))
	s.write(key, splitAt("new", 3, 0))
	old := s.ids[key+" old"]
	target, requests := ilmTestTarget(t, s.z, s.bucket, key, false)
	putConsistencyObject(t, s.z, target.bucket, key, 0, "replica", ObjectOptions{Versioned: true, VersionID: old})
	restorePool, _ := newILMTestReplicationPool(ctx, s.z, stats)
	t.Cleanup(restorePool)
	s.replication = ilmTestReplicationConfig(t, s.bucket)

	s.scan(0)

	if _, err := s.z.GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: old}); !isErrVersionNotFound(err) {
		t.Fatalf("expired version: %v, want it gone (no pending purge tombstone)", err)
	}
	if n := len(globalReplicationPool.Get().workers[0]); n != 0 {
		t.Fatalf("noncurrent expiry queued %d replication tasks", n)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("the target saw %d requests", n)
	}
	if _, err := s.z.GetObjectInfo(ctx, target.bucket, key, ObjectOptions{VersionID: old}); err != nil {
		t.Fatalf("target copy changed: %v", err)
	}
}
