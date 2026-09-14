// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/bucket/replication"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/once"
)

// Exercise the actual single-object DELETE handler and erasure metadata. A
// marker purge must delete the target version and finish the source purge;
// merely seeing a 405 on HEAD is not evidence of a completed permanent delete.
func TestReplicateDeleteMarkerPurge(t *testing.T) {
	defer DetectTestLeak(t)()
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("recover_legacy_%v", legacy), func(t *testing.T) {
			ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
				t: t, endpoints: []string{"DeleteObject"},
				objAPITest: func(obj ObjectLayer, instanceType, bucket string, router http.Handler, creds auth.Credentials, t *testing.T) {
					testReplicateDeleteMarkerPurge(obj, instanceType, bucket, router, creds, t, legacy)
				},
			})
		})
	}
}

func TestReplicateDeleteMarkerTargetSemantics(t *testing.T) {
	for _, tt := range []struct {
		name       string
		purge      bool
		legacy     bool
		deleteCode int
		wantDelete bool
		wantFailed bool
	}{
		{name: "existing marker is idempotent"},
		{name: "purge removes an existing marker", purge: true, deleteCode: 204, wantDelete: true},
		{name: "purge forbidden", purge: true, deleteCode: 403, wantDelete: true, wantFailed: true},
		{name: "purge method rejected", purge: true, deleteCode: 405, wantDelete: true, wantFailed: true},
		{name: "purge unavailable", purge: true, deleteCode: 503, wantDelete: true, wantFailed: true},
		// A purge that rides the delete-marker path (version-tracked purge
		// state on the marker) must neither be short-circuited by the
		// marker's creation status nor record its outcome in that status.
		{name: "marker-path purge removes an existing marker", legacy: true, deleteCode: 204, wantDelete: true},
		{name: "marker-path purge forbidden", legacy: true, deleteCode: 403, wantDelete: true, wantFailed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var deletes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.Header().Set(xhttp.AmzDeleteMarker, "true")
					w.Header().Set(xhttp.AmzVersionID, r.URL.Query().Get("versionId"))
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				deletes.Add(1)
				w.WriteHeader(tt.deleteCode)
				if tt.wantFailed {
					code := map[int]string{403: "AccessDenied", 405: "MethodNotAllowed", 503: "ServiceUnavailable"}[tt.deleteCode]
					fmt.Fprintf(w, `<Error><Code>%s</Code><Message>injected delete rejection</Message></Error>`, code)
				}
			}))
			defer server.Close()
			client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{Region: "us-east-1", MaxRetries: 1})
			if err != nil {
				t.Fatal(err)
			}
			old := globalBucketTargetSys
			globalBucketTargetSys = &BucketTargetSys{hc: map[string]epHealth{client.EndpointURL().Host: {Online: true}}}
			defer func() { globalBucketTargetSys = old }()
			deletion := DeletedObjectReplicationInfo{Bucket: "source", DeletedObject: DeletedObject{
				ObjectName: "marker", DeleteMarker: true, DeleteMarkerVersionID: mustGetUUID(),
			}}
			switch {
			case tt.legacy:
				// The marker itself was already replicated (creation status
				// COMPLETED); only its purge is still pending.
				deletion.ReplicationState.Targets = map[string]replication.StatusType{"arn1": replication.Completed}
				deletion.ReplicationState.PurgeTargets = map[string]VersionPurgeStatusType{"arn1": replication.VersionPurgePending}
			case tt.purge:
				deletion.VersionID = deletion.DeleteMarkerVersionID
				deletion.DeleteMarkerVersionID = ""
				deletion.ReplicationState.PurgeTargets = map[string]VersionPurgeStatusType{"arn1": replication.VersionPurgePending}
			}
			result := replicateDeleteToTarget(t.Context(), deletion, &TargetClient{Client: client, ARN: "arn1", Bucket: "target"})
			if (deletes.Load() != 0) != tt.wantDelete {
				t.Fatalf("remote DELETE count = %d, want delete %v", deletes.Load(), tt.wantDelete)
			}
			if tt.purge || tt.legacy {
				want := replication.VersionPurgeComplete
				if tt.wantFailed {
					want = replication.VersionPurgeFailed
				}
				if result.VersionPurgeStatus != want || (result.Err != nil) != tt.wantFailed {
					t.Errorf("purge result = %+v, want %s", result, want)
				}
				if tt.legacy && result.ReplicationStatus != replication.Completed {
					t.Errorf("marker-path purge clobbered the creation status: %+v", result)
				}
			} else if result.ReplicationStatus != replication.Completed {
				t.Errorf("existing marker result = %+v, want Completed", result)
			}
		})
	}
}

func testReplicateDeleteMarkerPurge(obj ObjectLayer, instanceType, bucket string, router http.Handler, creds auth.Credentials, t *testing.T, legacy bool) {
	ctx := t.Context()
	const arn = "arn:minio:replication::af470089-d354-4473-934c-9e1f52f6da89:bucket"
	const name = "marker"
	version := mustGetUUID()
	remoteBucket := getRandomBucketName()
	if err := obj.MakeBucket(ctx, remoteBucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := globalBucketMetadataSys.Update(ctx, bucket, bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{bucket, remoteBucket} {
		if _, err := obj.PutObject(ctx, b, name, mustGetPutObjReader(t, bytes.NewReader([]byte("data")), 4, "", ""), ObjectOptions{Versioned: true}); err != nil {
			t.Fatal(err)
		}
		opts := ObjectOptions{VersionID: version, Versioned: true, DeleteMarker: true, ReplicationRequest: true, MTime: UTCNow()}
		opts.SetReplicaStatus(replication.Replica)
		if _, err := obj.DeleteObject(ctx, b, name, opts); err != nil {
			t.Fatalf("%s: seed marker in %s: %v", instanceType, b, err)
		}
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		opts := ObjectOptions{VersionID: r.URL.Query().Get("versionId"), Versioned: true}
		switch r.Method {
		case http.MethodHead:
			oi, err := obj.GetObjectInfo(r.Context(), remoteBucket, name, opts)
			if oi.DeleteMarker {
				w.Header().Set(xhttp.AmzDeleteMarker, "true")
				w.Header().Set(xhttp.AmzVersionID, oi.VersionID)
			}
			if err != nil {
				writeErrorResponseHeadersOnly(w, toAPIError(r.Context(), err))
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			opts.DeleteMarker = r.Header.Get(xhttp.MinIOSourceDeleteMarker) == "true"
			opts.SetReplicaStatus(replication.Replica)
			_, err := obj.DeleteObject(r.Context(), remoteBucket, name, opts)
			if err != nil && !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
				writeErrorResponse(r.Context(), w, toAPIError(r.Context(), err), r.URL)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected remote method %s", r.Method)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer remote.Close()
	client, err := minio.New(strings.TrimPrefix(remote.URL, "http://"), &minio.Options{Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	target := &TargetClient{Client: client, ARN: arn, Bucket: remoteBucket}
	globalBucketTargetSys.Lock()
	globalBucketTargetSys.arnRemotesMap[arn] = arnTarget{Client: target, lastRefresh: UTCNow()}
	globalBucketTargetSys.targetsMap[bucket] = []madmin.BucketTarget{{Arn: arn, TargetBucket: remoteBucket}}
	globalBucketTargetSys.Unlock()
	globalBucketTargetSys.hMutex.Lock()
	globalBucketTargetSys.hc[client.EndpointURL().Host] = epHealth{Online: true}
	globalBucketTargetSys.hMutex.Unlock()
	meta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	cfg := configs[0]
	cfg.RoleArn = arn
	meta.replicationConfig = &cfg
	globalBucketMetadataSys.Set(bucket, meta)
	worker := make(chan ReplicationWorkerOperation, 1)
	p := &ReplicationPool{
		ctx:       ctx,
		objLayer:  obj,
		workers:   []chan ReplicationWorkerOperation{worker},
		stats:     globalReplicationStats.Load(),
		mrfSaveCh: make(chan MRFReplicateEntry, 1),
	}
	oldPool := globalReplicationPool
	globalReplicationPool = once.NewSingleton[ReplicationPool]()
	globalReplicationPool.Set(p)
	defer func() { globalReplicationPool = oldPool }()

	req, err := newTestSignedRequestV4(http.MethodDelete, "/"+bucket+"/"+name+"?versionId="+version, 0, nil, creds.AccessKey, creds.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE status %d: %s", w.Code, w.Body.String())
	}
	var deletion DeletedObjectReplicationInfo
	select {
	case op := <-worker:
		deletion = op.(DeletedObjectReplicationInfo)
	case <-time.After(time.Second):
		t.Fatal("DELETE did not schedule replication")
	}
	if deletion.VersionID != version || deletion.DeleteMarkerVersionID != "" {
		t.Errorf("purge scheduled as marker creation: version=%q marker=%q", deletion.VersionID, deletion.DeleteMarkerVersionID)
	}
	if legacy {
		// Reproduce the legacy producer's shape: the purge rides the
		// delete-marker path (VersionID empty, marker version in
		// DeleteMarkerVersionID) with pending purge state on the marker.
		// The replication path must classify it from the purge state and
		// finish the source cleanup in this attempt, instead of leaving the
		// source PENDING for a later heal.
		deletion.VersionID, deletion.DeleteMarkerVersionID = "", version
		result := replicateDelete(ctx, deletion, obj)
		if result.VersionPurgeStatus() != replication.VersionPurgeComplete {
			t.Errorf("legacy marker purge result = %s, want COMPLETE", result.VersionPurgeStatus())
		}
		for _, b := range []string{bucket, remoteBucket} {
			oi, err := obj.GetObjectInfo(ctx, b, name, ObjectOptions{VersionID: version, Versioned: true})
			if !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
				t.Errorf("legacy purge left the marker in %s: %+v, err=%v", b, oi, err)
			}
		}
		// Converged: nothing further may be scheduled for healing.
		select {
		case op := <-worker:
			t.Fatalf("unexpected heal scheduled after legacy purge converged: %v", op)
		case <-time.After(500 * time.Millisecond):
		}
		return
	}
	result := replicateDelete(context.Background(), deletion, obj)
	if result.VersionPurgeStatus() != replication.VersionPurgeComplete {
		t.Errorf("remote purge result = %s, want COMPLETE", result.VersionPurgeStatus())
	}
	for _, b := range []string{bucket, remoteBucket} {
		oi, err := obj.GetObjectInfo(ctx, b, name, ObjectOptions{VersionID: version, Versioned: true})
		if !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
			t.Errorf("%s: marker remains in %s: %+v, err=%v", instanceType, b, oi, err)
		}
	}
}
