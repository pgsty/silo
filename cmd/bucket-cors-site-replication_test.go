// Copyright (c) 2015-2021 MinIO, Inc.
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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/mux"
)

const testSiteReplicationCORSDoc = `<CORSConfiguration><CORSRule><AllowedOrigin>https://app.example.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`

const testSiteReplicationAlternateCORSDoc = `<CORSConfiguration><CORSRule><AllowedOrigin>https://admin.example.com</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>`

func TestPeerBucketCorsReplicationOrdering(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testPeerBucketCorsReplicationOrdering,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testPeerBucketCorsReplicationOrdering(_ ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	encoded := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	initialMeta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	putAt := initialMeta.Created.Add(time.Second)
	deleteAt := putAt.Add(time.Second)

	// Use a JSON-decoded event for the first apply so the wire representation
	// and the real metadata apply path meet in one regression test.
	wireData, err := json.Marshal(madmin.SRBucketMeta{
		Type:      madmin.SRBucketMetaTypeCorsConfig,
		Bucket:    bucket,
		Cors:      &encoded,
		UpdatedAt: putAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	var item madmin.SRBucketMeta
	if err = json.Unmarshal(wireData, &item); err != nil {
		t.Fatal(err)
	}
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, item.Bucket, item.Cors, item.UpdatedAt); err != nil {
		t.Fatalf("peer PUT failed: %v", err)
	}

	meta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if string(meta.CorsConfigXML) != testSiteReplicationCORSDoc {
		t.Fatalf("peer PUT stored %q, want %q", meta.CorsConfigXML, testSiteReplicationCORSDoc)
	}
	if !meta.CorsConfigUpdatedAt.Equal(putAt) {
		t.Fatalf("peer PUT timestamp = %v, want source time %v", meta.CorsConfigUpdatedAt, putAt)
	}
	cfg, cfgAt, err := globalBucketMetadataSys.GetResidentCorsConfig(bucket)
	if err != nil {
		t.Fatalf("peer PUT stored raw XML but no parsed config: %v", err)
	}
	if cfg == nil || !cfgAt.Equal(putAt) {
		t.Fatalf("peer PUT parsed config = %#v at %v, want config at %v", cfg, cfgAt, putAt)
	}
	if _, _, ok := cfg.MatchRule("https://app.example.com", http.MethodGet); !ok {
		t.Fatal("peer PUT parsed config does not enforce its origin and method")
	}

	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, nil, deleteAt); err != nil {
		t.Fatalf("newer peer DELETE failed: %v", err)
	}
	meta, err = globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.CorsConfigXML) != 0 || meta.corsConfig != nil {
		t.Fatalf("newer peer DELETE left a live config: %q", meta.CorsConfigXML)
	}
	if !meta.CorsConfigUpdatedAt.Equal(deleteAt) {
		t.Fatalf("peer DELETE timestamp = %v, want source time %v", meta.CorsConfigUpdatedAt, deleteAt)
	}

	// A delayed older PUT must not resurrect the newer deletion tombstone.
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, &encoded, putAt); err != nil {
		t.Fatalf("stale peer PUT failed: %v", err)
	}
	meta, err = globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.CorsConfigXML) != 0 || !meta.CorsConfigUpdatedAt.Equal(deleteAt) {
		t.Fatalf("stale peer PUT changed tombstone: xml=%q timestamp=%v", meta.CorsConfigXML, meta.CorsConfigUpdatedAt)
	}

	// Duplicate delivery at the same timestamp is idempotent.
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, nil, deleteAt); err != nil {
		t.Fatalf("duplicate peer DELETE failed: %v", err)
	}
	meta, err = globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.CorsConfigXML) != 0 || !meta.CorsConfigUpdatedAt.Equal(deleteAt) {
		t.Fatalf("duplicate peer DELETE changed tombstone: xml=%q timestamp=%v", meta.CorsConfigXML, meta.CorsConfigUpdatedAt)
	}

	// DELETE wins a same-timestamp conflict deterministically.
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, &encoded, deleteAt); err != nil {
		t.Fatalf("same-timestamp peer PUT failed: %v", err)
	}
	meta, err = globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.CorsConfigXML) != 0 || !meta.CorsConfigUpdatedAt.Equal(deleteAt) {
		t.Fatalf("same-timestamp peer PUT replaced tombstone: xml=%q timestamp=%v", meta.CorsConfigXML, meta.CorsConfigUpdatedAt)
	}

	missingBucket := bucket + "-missing"
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, missingBucket, &encoded, UTCNow()); err == nil {
		t.Fatal("peer CORS event for missing bucket metadata unexpectedly succeeded")
	}
	if _, err = globalBucketMetadataSys.Get(missingBucket); !errors.Is(err, errConfigNotFound) {
		t.Fatalf("peer CORS event created metadata for missing bucket: %v", err)
	}
}

func TestSiteReplicationMetaInfoPreservesCorsTombstone(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testSiteReplicationMetaInfoPreservesCorsTombstone,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testSiteReplicationMetaInfoPreservesCorsTombstone(obj ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	if _, err := updateLocalBucketCORSMetadata(ctx, obj, bucket, []byte(testSiteReplicationCORSDoc)); err != nil {
		t.Fatal(err)
	}
	deleteAt, err := updateLocalBucketCORSMetadata(ctx, obj, bucket, nil)
	if err != nil {
		t.Fatal(err)
	}

	globalSiteReplicationSys.Lock()
	wasEnabled := globalSiteReplicationSys.enabled
	globalSiteReplicationSys.enabled = true
	globalSiteReplicationSys.Unlock()
	defer func() {
		globalSiteReplicationSys.Lock()
		globalSiteReplicationSys.enabled = wasEnabled
		globalSiteReplicationSys.Unlock()
	}()

	info, err := globalSiteReplicationSys.SiteReplicationMetaInfo(ctx, obj, madmin.SRStatusOptions{Buckets: true})
	if err != nil {
		t.Fatal(err)
	}
	got := info.Buckets[bucket]
	if got.CorsConfig != nil {
		t.Fatalf("deleted CORS config reported live payload %q", *got.CorsConfig)
	}
	if !got.CorsConfigUpdatedAt.Equal(deleteAt) {
		t.Fatalf("reported tombstone timestamp = %v, want %v", got.CorsConfigUpdatedAt, deleteAt)
	}

	// Model metadata written before the CORS timestamp field existed.
	meta, err := readBucketMetadata(ctx, obj, bucket)
	if err != nil {
		t.Fatal(err)
	}
	meta.CorsConfigXML = nil
	meta.CorsConfigUpdatedAt = time.Time{}
	if err = globalBucketMetadataSys.save(ctx, meta); err != nil {
		t.Fatal(err)
	}

	info, err = globalSiteReplicationSys.SiteReplicationMetaInfo(ctx, obj, madmin.SRStatusOptions{Buckets: true})
	if err != nil {
		t.Fatal(err)
	}
	got = info.Buckets[bucket]
	if !got.CorsConfigUpdatedAt.IsZero() {
		t.Fatalf("never-configured CORS timestamp = %v, want zero baseline", got.CorsConfigUpdatedAt)
	}
}

func TestHealCorsMetadataPrefersNewerTombstone(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testHealCorsMetadataPrefersNewerTombstone,
		endpoints:  []string{"GetBucketCors"},
	})
}

func TestLatestCORSConfigIgnoresBaseline(t *testing.T) {
	created := UTCNow().Add(-time.Hour)
	configuredAt := created.Add(time.Minute)
	laterCreated := configuredAt.Add(time.Minute)
	encoded := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))

	bs := map[string]srBucketStatsSummary{
		"configured": {
			meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{
				CorsConfig:          &encoded,
				CorsConfigUpdatedAt: configuredAt,
				CreatedAt:           created,
			}},
		},
		"never-configured": {
			meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{
				CorsConfig:          nil,
				CorsConfigUpdatedAt: time.Time{},
				CreatedAt:           laterCreated,
			}},
		},
	}

	latestID, latest, ok := latestCORSConfig(bs)
	if !ok {
		t.Fatal("expected live config to be selected")
	}
	latestConfig := latest.encodedPayload()
	if latestID != "configured" || !latest.updatedAt.Equal(configuredAt) || latestConfig == nil || *latestConfig != encoded {
		t.Fatalf("latest = (%q, %v, %v), want configured live config at %v", latestID, latest.updatedAt, latestConfig, configuredAt)
	}
}

func testHealCorsMetadataPrefersNewerTombstone(obj ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := readBucketMetadata(ctx, obj, bucket)
	if err != nil {
		t.Fatal(err)
	}
	oldAt := meta.Created.Add(time.Second)
	deleteAt := oldAt.Add(time.Second)
	meta.CorsConfigXML = []byte(testSiteReplicationCORSDoc)
	meta.CorsConfigUpdatedAt = oldAt
	if err = globalBucketMetadataSys.save(ctx, meta); err != nil {
		t.Fatal(err)
	}

	localID := globalDeploymentID()
	remoteID := "remote-cors-tombstone"
	encoded := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	info := srStatusInfo{
		Sites: map[string]madmin.PeerInfo{
			localID:  {Name: "local", DeploymentID: localID},
			remoteID: {Name: "remote", DeploymentID: remoteID},
		},
		BucketStats: map[string]map[string]srBucketStatsSummary{
			bucket: {
				localID: {
					SRBucketStatsSummary: madmin.SRBucketStatsSummary{CorsCfgMismatch: true},
					meta: srBucketMetaInfo{
						SRBucketInfo: madmin.SRBucketInfo{
							Bucket:              bucket,
							CorsConfig:          &encoded,
							CorsConfigUpdatedAt: oldAt,
							CreatedAt:           meta.Created,
						},
						DeploymentID: localID,
					},
				},
				remoteID: {
					SRBucketStatsSummary: madmin.SRBucketStatsSummary{CorsCfgMismatch: true},
					meta: srBucketMetaInfo{
						SRBucketInfo: madmin.SRBucketInfo{
							Bucket:              bucket,
							CorsConfig:          nil,
							CorsConfigUpdatedAt: deleteAt,
							CreatedAt:           meta.Created,
						},
						DeploymentID: remoteID,
					},
				},
			},
		},
	}

	globalSiteReplicationSys.Lock()
	wasEnabled := globalSiteReplicationSys.enabled
	globalSiteReplicationSys.enabled = true
	globalSiteReplicationSys.Unlock()
	defer func() {
		globalSiteReplicationSys.Lock()
		globalSiteReplicationSys.enabled = wasEnabled
		globalSiteReplicationSys.Unlock()
	}()

	if err = globalSiteReplicationSys.healCORSMetadata(ctx, obj, bucket, info); err != nil {
		t.Fatal(err)
	}
	meta, err = globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.CorsConfigXML) != 0 || meta.corsConfig != nil {
		t.Fatalf("heal retained stale CORS config %q", meta.CorsConfigXML)
	}
	if !meta.CorsConfigUpdatedAt.Equal(deleteAt) {
		t.Fatalf("heal tombstone timestamp = %v, want %v", meta.CorsConfigUpdatedAt, deleteAt)
	}
}

func TestPeerBucketCorsEqualTimestampOrderIndependent(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testPeerBucketCorsEqualTimestampOrderIndependent,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testPeerBucketCorsEqualTimestampOrderIndependent(obj ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := readBucketMetadata(ctx, obj, bucket)
	if err != nil {
		t.Fatal(err)
	}
	at := meta.Created.Add(time.Second)
	first := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	second := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationAlternateCORSDoc))

	reset := func() {
		t.Helper()
		meta.CorsConfigXML = nil
		meta.CorsConfigUpdatedAt = meta.Created
		if err := globalBucketMetadataSys.save(ctx, meta); err != nil {
			t.Fatal(err)
		}
	}
	apply := func(encoded *string) {
		t.Helper()
		if err := globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, encoded, at); err != nil {
			t.Fatal(err)
		}
	}
	readPayload := func() string {
		t.Helper()
		got, err := globalBucketMetadataSys.Get(bucket)
		if err != nil {
			t.Fatal(err)
		}
		return string(got.CorsConfigXML)
	}

	reset()
	apply(&first)
	apply(&second)
	forward := readPayload()

	reset()
	apply(&second)
	apply(&first)
	reverse := readPayload()

	if forward != reverse {
		t.Fatalf("equal-timestamp result depends on arrival order: forward=%q reverse=%q", forward, reverse)
	}
	want := testSiteReplicationCORSDoc
	if bytes.Compare([]byte(testSiteReplicationAlternateCORSDoc), []byte(want)) > 0 {
		want = testSiteReplicationAlternateCORSDoc
	}
	if forward != want {
		t.Fatalf("equal-timestamp live winner = %q, want lexicographic maximum %q", forward, want)
	}
}

func TestAdversarialHealCorsPropagatesNewerEqualValueTimestamp(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAdversarialHealCorsPropagatesNewerEqualValueTimestamp,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testAdversarialHealCorsPropagatesNewerEqualValueTimestamp(obj ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := readBucketMetadata(ctx, obj, bucket)
	if err != nil {
		t.Fatal(err)
	}
	older := meta.Created.Add(time.Second)
	newer := older.Add(time.Second)
	meta.CorsConfigXML = []byte(testSiteReplicationCORSDoc)
	meta.CorsConfigUpdatedAt = older
	if err = globalBucketMetadataSys.save(ctx, meta); err != nil {
		t.Fatal(err)
	}

	localID := globalDeploymentID()
	remoteID := "remote-cors-newer-barrier"
	encoded := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	info := srStatusInfo{
		Sites: map[string]madmin.PeerInfo{
			localID:  {Name: "local", DeploymentID: localID},
			remoteID: {Name: "remote", DeploymentID: remoteID},
		},
		BucketStats: map[string]map[string]srBucketStatsSummary{
			bucket: {
				localID: {
					SRBucketStatsSummary: madmin.SRBucketStatsSummary{CorsCfgMismatch: true},
					meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{
						Bucket: bucket, CorsConfig: &encoded, CorsConfigUpdatedAt: older, CreatedAt: meta.Created,
					}, DeploymentID: localID},
				},
				remoteID: {
					SRBucketStatsSummary: madmin.SRBucketStatsSummary{CorsCfgMismatch: true},
					meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{
						Bucket: bucket, CorsConfig: &encoded, CorsConfigUpdatedAt: newer, CreatedAt: meta.Created,
					}, DeploymentID: remoteID},
				},
			},
		},
	}

	globalSiteReplicationSys.Lock()
	wasEnabled := globalSiteReplicationSys.enabled
	globalSiteReplicationSys.enabled = true
	globalSiteReplicationSys.Unlock()
	defer func() {
		globalSiteReplicationSys.Lock()
		globalSiteReplicationSys.enabled = wasEnabled
		globalSiteReplicationSys.Unlock()
	}()

	if err = globalSiteReplicationSys.healCORSMetadata(ctx, obj, bucket, info); err != nil {
		t.Fatal(err)
	}
	got, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if !got.CorsConfigUpdatedAt.Equal(newer) {
		t.Fatalf("heal retained source barrier %v, want %v", got.CorsConfigUpdatedAt, newer)
	}
}

func TestSiteReplicationStatusDetectsCorsTimestampMismatch(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testSiteReplicationStatusDetectsCorsTimestampMismatch,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testSiteReplicationStatusDetectsCorsTimestampMismatch(obj ObjectLayer, _ string, bucket string, _ http.Handler, credentials auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := readBucketMetadata(ctx, obj, bucket)
	if err != nil {
		t.Fatal(err)
	}
	older := meta.Created.Add(time.Second)
	newer := older.Add(time.Second)
	meta.CorsConfigXML = []byte(testSiteReplicationCORSDoc)
	meta.CorsConfigUpdatedAt = older
	if err = globalBucketMetadataSys.save(ctx, meta); err != nil {
		t.Fatal(err)
	}

	localID := globalDeploymentID()
	remoteID := "remote-cors-status"
	encoded := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	remoteInfo := madmin.SRInfo{
		DeploymentID: remoteID,
		Buckets: map[string]madmin.SRBucketInfo{
			bucket: {
				Bucket:              bucket,
				CreatedAt:           meta.Created,
				CorsConfig:          &encoded,
				CorsConfigUpdatedAt: newer,
			},
		},
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(remoteInfo); err != nil {
			t.Errorf("encode remote metadata: %v", err)
		}
	}))
	defer remote.Close()

	serviceCred, _, err := globalIAMSys.NewServiceAccount(ctx, credentials.AccessKey, nil, newServiceAccountOpts{
		accessKey: "cors-status-service",
		secretKey: "cors-status-service-secret-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer globalIAMSys.DeleteServiceAccount(ctx, serviceCred.AccessKey, false)

	globalSiteReplicationSys.Lock()
	oldEnabled := globalSiteReplicationSys.enabled
	oldState := globalSiteReplicationSys.state
	globalSiteReplicationSys.enabled = true
	globalSiteReplicationSys.state = srState{
		Name:                    "cors-status-test",
		ServiceAccountAccessKey: serviceCred.AccessKey,
		Peers: map[string]madmin.PeerInfo{
			localID:  {Name: "local", DeploymentID: localID},
			remoteID: {Name: "remote", DeploymentID: remoteID, Endpoint: remote.URL},
		},
	}
	globalSiteReplicationSys.Unlock()
	defer func() {
		globalSiteReplicationSys.Lock()
		globalSiteReplicationSys.enabled = oldEnabled
		globalSiteReplicationSys.state = oldState
		globalSiteReplicationSys.Unlock()
	}()

	status, err := globalSiteReplicationSys.siteReplicationStatus(ctx, obj, madmin.SRStatusOptions{Buckets: true})
	if err != nil {
		t.Fatal(err)
	}
	localStatus, ok := status.BucketStats[bucket][localID]
	if !ok {
		t.Fatalf("status omitted local bucket entry: %#v", status.BucketStats[bucket])
	}
	if !localStatus.CorsCfgMismatch {
		t.Fatalf("status treated source timestamps %v and %v as converged", older, newer)
	}
}

func TestSiteReplicationStatusCountsCorsPerSite(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testSiteReplicationStatusCountsCorsPerSite,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testSiteReplicationStatusCountsCorsPerSite(obj ObjectLayer, _ string, bucket string, _ http.Handler, credentials auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := readBucketMetadata(ctx, obj, bucket)
	if err != nil {
		t.Fatal(err)
	}
	localID := globalDeploymentID()
	remoteID := "remote-cors-count"
	encoded := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	remoteInfo := madmin.SRInfo{
		DeploymentID: remoteID,
		Buckets: map[string]madmin.SRBucketInfo{
			bucket: {Bucket: bucket, CreatedAt: meta.Created},
		},
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(remoteInfo); err != nil {
			t.Errorf("encode remote metadata: %v", err)
		}
	}))
	defer remote.Close()

	serviceCred, _, err := globalIAMSys.NewServiceAccount(ctx, credentials.AccessKey, nil, newServiceAccountOpts{
		accessKey: "cors-count-service",
		secretKey: "cors-count-service-secret-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer globalIAMSys.DeleteServiceAccount(ctx, serviceCred.AccessKey, false)

	globalSiteReplicationSys.Lock()
	oldEnabled := globalSiteReplicationSys.enabled
	oldState := globalSiteReplicationSys.state
	globalSiteReplicationSys.enabled = true
	globalSiteReplicationSys.state = srState{
		Name:                    "cors-count-test",
		ServiceAccountAccessKey: serviceCred.AccessKey,
		Peers: map[string]madmin.PeerInfo{
			localID:  {Name: "local", DeploymentID: localID},
			remoteID: {Name: "remote", DeploymentID: remoteID, Endpoint: remote.URL},
		},
	}
	globalSiteReplicationSys.Unlock()
	defer func() {
		globalSiteReplicationSys.Lock()
		globalSiteReplicationSys.enabled = oldEnabled
		globalSiteReplicationSys.state = oldState
		globalSiteReplicationSys.Unlock()
	}()

	check := func(name string, wantLocal, wantRemote int, wantMismatch, wantReplicated bool) {
		t.Helper()
		status, err := globalSiteReplicationSys.siteReplicationStatus(ctx, obj, madmin.SRStatusOptions{Buckets: true})
		if err != nil {
			t.Fatal(err)
		}
		if got := status.StatsSummary[localID].TotalCorsConfigCount; got != wantLocal {
			t.Fatalf("%s: local TotalCorsConfigCount = %d, want %d", name, got, wantLocal)
		}
		if got := status.StatsSummary[remoteID].TotalCorsConfigCount; got != wantRemote {
			t.Fatalf("%s: remote TotalCorsConfigCount = %d, want %d", name, got, wantRemote)
		}
		for _, id := range []string{localID, remoteID} {
			bucketStatus := status.BucketStats[bucket][id]
			wantSet := wantLocal != 0
			if id == remoteID {
				wantSet = wantRemote != 0
			}
			if bucketStatus.HasCorsCfgSet != wantSet {
				t.Fatalf("%s: %s HasCorsCfgSet = %v, want %v", name, id, bucketStatus.HasCorsCfgSet, wantSet)
			}
			if bucketStatus.CorsCfgMismatch != wantMismatch {
				t.Fatalf("%s: %s CorsCfgMismatch = %v, want %v", name, id, bucketStatus.CorsCfgMismatch, wantMismatch)
			}
			gotReplicated := status.StatsSummary[id].ReplicatedCorsConfig != 0
			if gotReplicated != wantReplicated {
				t.Fatalf("%s: %s ReplicatedCorsConfig = %d, want replicated %v", name, id, status.StatsSummary[id].ReplicatedCorsConfig, wantReplicated)
			}
		}
	}

	check("neither site", 0, 0, false, false)
	t1 := meta.Created.Add(time.Second)
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, &encoded, t1); err != nil {
		t.Fatal(err)
	}
	check("local site only", 1, 0, true, false)

	t2 := t1.Add(time.Second)
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, nil, t2); err != nil {
		t.Fatal(err)
	}
	remoteInfo.Buckets[bucket] = madmin.SRBucketInfo{
		Bucket: bucket, CreatedAt: meta.Created, CorsConfig: &encoded,
	}
	check("live remote without timestamp", 0, 0, true, false)

	invalidXML := base64.StdEncoding.EncodeToString([]byte(`not xml`))
	remoteInfo.Buckets[bucket] = madmin.SRBucketInfo{
		Bucket: bucket, CreatedAt: meta.Created, CorsConfig: &invalidXML, CorsConfigUpdatedAt: t2,
	}
	check("invalid remote XML", 0, 0, true, false)

	remoteInfo.Buckets[bucket] = madmin.SRBucketInfo{
		Bucket: bucket, CreatedAt: meta.Created, CorsConfig: &encoded, CorsConfigUpdatedAt: t2,
	}
	check("remote site only", 0, 1, true, false)

	t3 := t2.Add(time.Second)
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, &encoded, t3); err != nil {
		t.Fatal(err)
	}
	remoteInfo.Buckets[bucket] = madmin.SRBucketInfo{
		Bucket: bucket, CreatedAt: meta.Created, CorsConfig: &encoded, CorsConfigUpdatedAt: t3,
	}
	check("both sites", 1, 1, false, true)
}

func TestCORSReplicationStateOrdering(t *testing.T) {
	at := UTCNow()
	baseline := newCORSReplicationState(nil, time.Time{})
	liveA := newCORSReplicationState([]byte("a"), at)
	liveB := newCORSReplicationState([]byte("b"), at)
	tombstone := newCORSReplicationState(nil, at)

	ordered := []corsReplicationState{baseline, liveA, liveB, tombstone}
	for i := 1; i < len(ordered); i++ {
		if compareCORSReplicationStates(ordered[i-1], ordered[i]) >= 0 {
			t.Fatalf("state %d is not lower than state %d", i-1, i)
		}
	}
	for _, state := range ordered {
		if !equalCORSReplicationStates(state, state) {
			t.Fatalf("state is not equal to itself: %#v", state)
		}
	}
}

func TestCORSReplicationStatusStateEquality(t *testing.T) {
	at := UTCNow()
	payload := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	otherPayload := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationAlternateCORSDoc))
	sites := []srBucketMetaInfo{
		{DeploymentID: "a", SRBucketInfo: madmin.SRBucketInfo{}},
		{DeploymentID: "b", SRBucketInfo: madmin.SRBucketInfo{}},
	}
	if !areCORSReplicationStatesEqual(sites) {
		t.Fatal("two baselines should be converged")
	}

	sites[0].CorsConfigUpdatedAt = at
	sites[1].CorsConfigUpdatedAt = at
	if !areCORSReplicationStatesEqual(sites) {
		t.Fatal("matching tombstones should be converged")
	}
	sites[1].CorsConfigUpdatedAt = at.Add(time.Nanosecond)
	if areCORSReplicationStatesEqual(sites) {
		t.Fatal("different tombstone barriers should be mismatched")
	}

	sites[0].CorsConfig = &payload
	sites[1].CorsConfig = &payload
	sites[1].CorsConfigUpdatedAt = at
	if !areCORSReplicationStatesEqual(sites) {
		t.Fatal("matching live states should be converged")
	}
	sites[1].CorsConfig = &otherPayload
	if areCORSReplicationStatesEqual(sites) {
		t.Fatal("different live payloads should be mismatched")
	}
}

func TestLatestCORSConfigEqualTimestampDeterministic(t *testing.T) {
	at := UTCNow()
	encodedA := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	encodedB := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationAlternateCORSDoc))
	bs := map[string]srBucketStatsSummary{
		"site-a": {meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CorsConfig: &encodedA, CorsConfigUpdatedAt: at}}},
		"site-b": {meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CorsConfig: &encodedB, CorsConfigUpdatedAt: at}}},
		"site-c": {meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CorsConfigUpdatedAt: at}}},
	}
	for i := 0; i < 100; i++ {
		id, state, ok := latestCORSConfig(bs)
		if !ok || id != "site-c" || state.kind != corsReplicationTombstone || !state.updatedAt.Equal(at) {
			t.Fatalf("iteration %d selected (%q, %#v, %v), want site-c tombstone", i, id, state, ok)
		}
	}
}

func TestNewBucketCORSReplicationEvent(t *testing.T) {
	meta := newBucketMetadata("bucket")
	if _, ok := newBucketCORSReplicationEvent(meta.Name, meta); ok {
		t.Fatal("baseline unexpectedly produced an initial-sync event")
	}

	at := UTCNow()
	meta.CorsConfigXML = []byte(testSiteReplicationCORSDoc)
	meta.CorsConfigUpdatedAt = at
	live, ok := newBucketCORSReplicationEvent(meta.Name, meta)
	if !ok || live.Cors == nil || !live.UpdatedAt.Equal(at) {
		t.Fatalf("live initial-sync event = %#v, %v", live, ok)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(*live.Cors)
	if err != nil || string(decoded) != testSiteReplicationCORSDoc {
		t.Fatalf("live initial-sync payload = %q, %v", decoded, err)
	}

	meta.CorsConfigXML = nil
	tombstone, ok := newBucketCORSReplicationEvent(meta.Name, meta)
	if !ok || tombstone.Cors != nil || !tombstone.UpdatedAt.Equal(at) {
		t.Fatalf("tombstone initial-sync event = %#v, %v", tombstone, ok)
	}
}

func TestPeerBucketCorsRejectsNonCanonicalBase64(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testPeerBucketCorsRejectsNonCanonicalBase64,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testPeerBucketCorsRejectsNonCanonicalBase64(_ ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	at := meta.Created.Add(time.Second)
	inputs := []string{"AB==", "Q\nQ==", "!!!!"}
	for _, encoded := range inputs {
		if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, &encoded, at); err == nil {
			t.Fatalf("non-canonical base64 %q was accepted", encoded)
		}
		if err = globalSiteReplicationSys.PeerBucketMetadataUpdateHandler(ctx, madmin.SRBucketMeta{
			Bucket: bucket, Cors: &encoded, UpdatedAt: at,
		}); err == nil {
			t.Fatalf("legacy bulk path accepted non-canonical base64 %q", encoded)
		}
	}
	got, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.CorsConfigXML) != 0 || !got.CorsConfigUpdatedAt.IsZero() {
		t.Fatalf("rejected payload changed metadata: xml=%q timestamp=%v", got.CorsConfigXML, got.CorsConfigUpdatedAt)
	}
}

func TestPeerBucketCorsRejectsInvalidConfiguration(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testPeerBucketCorsRejectsInvalidConfiguration,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testPeerBucketCorsRejectsInvalidConfiguration(_ ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	at := meta.Created.Add(time.Second)
	invalidDocs := []string{
		`<CORSConfiguration><CORSRule><AllowedOrigin>https://?.example.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`,
		`not xml`,
	}
	for _, doc := range invalidDocs {
		encoded := base64.StdEncoding.EncodeToString([]byte(doc))
		if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, &encoded, at); err == nil {
			t.Fatalf("invalid CORS config %q was accepted", doc)
		}
		if err = globalSiteReplicationSys.PeerBucketMetadataUpdateHandler(ctx, madmin.SRBucketMeta{
			Bucket: bucket, Cors: &encoded, UpdatedAt: at,
		}); err == nil {
			t.Fatalf("legacy bulk path accepted invalid CORS config %q", doc)
		}
	}
	got, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.CorsConfigXML) != 0 || !got.CorsConfigUpdatedAt.IsZero() {
		t.Fatalf("rejected config changed metadata: xml=%q timestamp=%v", got.CorsConfigXML, got.CorsConfigUpdatedAt)
	}
}

func TestPeerBucketCorsCreatedAtFloor(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testPeerBucketCorsCreatedAtFloor,
		endpoints:  []string{"GetBucketCors"},
	})
}

func TestLegacyInvalidCorsMetadataCanBeDeleted(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testLegacyInvalidCorsMetadataCanBeDeleted,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testLegacyInvalidCorsMetadataCanBeDeleted(obj ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := readBucketMetadata(ctx, obj, bucket)
	if err != nil {
		t.Fatal(err)
	}
	legacyAt := meta.Created.Add(time.Second)
	meta.CorsConfigXML = []byte(`<CORSConfiguration><CORSRule><AllowedOrigin>https://app.example.com</AllowedOrigin><AllowedMethod>get</AllowedMethod></CORSRule></CORSConfiguration>`)
	meta.CorsConfigUpdatedAt = legacyAt

	data := make([]byte, 4, meta.Msgsize()+4)
	binary.LittleEndian.PutUint16(data[0:2], bucketMetadataFormat)
	binary.LittleEndian.PutUint16(data[2:4], bucketMetadataVersion)
	data, err = meta.MarshalMsg(data)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveConfig(ctx, obj, pathJoin(bucketMetaPrefix, bucket, bucketMetadataFile), data); err != nil {
		t.Fatal(err)
	}

	globalBucketMetadataSys.Remove(bucket)
	loaded, err := globalBucketMetadataSys.GetConfigFromDisk(ctx, bucket)
	if err != nil {
		t.Fatalf("strict load made all bucket metadata unavailable: %v", err)
	}
	if loaded.corsConfigErr == nil || loaded.corsConfig != nil {
		t.Fatalf("legacy CORS state = (%#v, %v), want fail-closed parse error", loaded.corsConfig, loaded.corsConfigErr)
	}
	globalBucketMetadataSys.Set(bucket, loaded)
	if _, gotAt, err := globalBucketMetadataSys.GetResidentCorsConfig(bucket); err == nil || !gotAt.Equal(legacyAt) {
		t.Fatalf("GetResidentCorsConfig = timestamp %v, error %v; want legacy timestamp and error", gotAt, err)
	}
	if _, gotAt, err := globalBucketMetadataSys.GetCorsConfigXML(bucket); err == nil || !gotAt.Equal(legacyAt) {
		t.Fatalf("GetCorsConfigXML = timestamp %v, error %v; want legacy timestamp and error", gotAt, err)
	}

	deleteAt, err := updateLocalBucketCORSMetadata(ctx, obj, bucket, nil)
	if err != nil {
		t.Fatalf("DELETE could not repair legacy invalid CORS: %v", err)
	}
	globalBucketMetadataSys.Remove(bucket)
	repaired, err := globalBucketMetadataSys.GetConfigFromDisk(ctx, bucket)
	if err != nil {
		t.Fatal(err)
	}
	if repaired.corsConfigErr != nil || repaired.corsConfig != nil || len(repaired.CorsConfigXML) != 0 || !repaired.CorsConfigUpdatedAt.Equal(deleteAt) {
		t.Fatalf("repaired CORS state = (%q, %#v, %v, %v), want tombstone at %v", repaired.CorsConfigXML, repaired.corsConfig, repaired.corsConfigErr, repaired.CorsConfigUpdatedAt, deleteAt)
	}
}

func testPeerBucketCorsCreatedAtFloor(_ ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, &encoded, meta.Created.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.CorsConfigXML) != 0 || !got.CorsConfigUpdatedAt.IsZero() {
		t.Fatalf("pre-creation event changed metadata: xml=%q timestamp=%v", got.CorsConfigXML, got.CorsConfigUpdatedAt)
	}

	fresh := meta.Created.Add(time.Second)
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, &encoded, fresh); err != nil {
		t.Fatal(err)
	}
	got, err = globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.CorsConfigXML) != testSiteReplicationCORSDoc || !got.CorsConfigUpdatedAt.Equal(fresh) {
		t.Fatalf("post-creation event state = (%q, %v), want live at %v", got.CorsConfigXML, got.CorsConfigUpdatedAt, fresh)
	}
}

func TestLocalBucketCorsUpdateAdvancesFutureBarrier(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testLocalBucketCorsUpdateAdvancesFutureBarrier,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testLocalBucketCorsUpdateAdvancesFutureBarrier(obj ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	future := UTCNow().Add(time.Hour)
	if !future.After(meta.Created) {
		future = meta.Created.Add(time.Hour)
	}
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, nil, future); err != nil {
		t.Fatal(err)
	}
	updatedAt, err := updateLocalBucketCORSMetadata(ctx, obj, bucket, []byte(testSiteReplicationCORSDoc))
	if err != nil {
		t.Fatal(err)
	}
	if !updatedAt.After(future) {
		t.Fatalf("local update timestamp = %v, want after future barrier %v", updatedAt, future)
	}
	got, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.CorsConfigXML) != testSiteReplicationCORSDoc || !got.CorsConfigUpdatedAt.Equal(updatedAt) {
		t.Fatalf("local update state = (%q, %v), want live payload at %v", got.CorsConfigXML, got.CorsConfigUpdatedAt, updatedAt)
	}
}

func TestLocalBucketCorsConcurrentUpdatesAreMonotonic(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testLocalBucketCorsConcurrentUpdatesAreMonotonic,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testLocalBucketCorsConcurrentUpdatesAreMonotonic(obj ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	type result struct {
		payload []byte
		at      time.Time
		err     error
	}
	payloads := [][]byte{
		[]byte(testSiteReplicationCORSDoc),
		[]byte(testSiteReplicationAlternateCORSDoc),
		nil,
	}
	start := make(chan struct{})
	results := make(chan result, 24)
	var wg sync.WaitGroup
	for i := 0; i < cap(results); i++ {
		payload := bytes.Clone(payloads[i%len(payloads)])
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			at, err := updateLocalBucketCORSMetadata(t.Context(), obj, bucket, payload)
			results <- result{payload: payload, at: at, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	seen := make(map[int64]struct{}, cap(results))
	var latest result
	for got := range results {
		if got.err != nil {
			t.Fatal(got.err)
		}
		key := got.at.UnixNano()
		if _, ok := seen[key]; ok {
			t.Fatalf("concurrent local updates reused timestamp %v", got.at)
		}
		seen[key] = struct{}{}
		if latest.at.IsZero() || got.at.After(latest.at) {
			latest = got
		}
	}

	meta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.CorsConfigUpdatedAt.Equal(latest.at) || !bytes.Equal(meta.CorsConfigXML, latest.payload) {
		t.Fatalf("final state = (%q, %v), want last serialized local update (%q, %v)", meta.CorsConfigXML, meta.CorsConfigUpdatedAt, latest.payload, latest.at)
	}
}

func TestPeerBucketCorsConcurrentConvergence(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testPeerBucketCorsConcurrentConvergence,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testPeerBucketCorsConcurrentConvergence(_ ObjectLayer, _ string, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	base := meta.Created.Add(time.Second)
	encodedA := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	encodedB := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationAlternateCORSDoc))
	events := []struct {
		payload *string
		at      time.Time
	}{
		{payload: &encodedA, at: base},
		{payload: &encodedB, at: base},
		{payload: nil, at: base},
		{payload: &encodedA, at: base.Add(time.Second)},
		{payload: &encodedB, at: base.Add(2 * time.Second)},
		{payload: nil, at: base.Add(2 * time.Second)},
	}

	start := make(chan struct{})
	errCh := make(chan error, len(events)*8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		for j, event := range events {
			event := event
			useBulkPath := event.payload != nil && (i+j)%2 == 0
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if useBulkPath {
					errCh <- globalSiteReplicationSys.PeerBucketMetadataUpdateHandler(ctx, madmin.SRBucketMeta{
						Bucket: bucket, Cors: event.payload, UpdatedAt: event.at,
					})
					return
				}
				errCh <- globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, event.payload, event.at)
			}()
		}
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	got, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.CorsConfigXML) != 0 || !got.CorsConfigUpdatedAt.Equal(base.Add(2*time.Second)) {
		t.Fatalf("concurrent final state = (%q, %v), want newest equal-time tombstone", got.CorsConfigXML, got.CorsConfigUpdatedAt)
	}
}

func TestCorsReplicationDispatchStatusHealReload(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testCorsReplicationDispatchStatusHealReload,
		endpoints:  []string{"GetBucketCors"},
	})
}

func testCorsReplicationDispatchStatusHealReload(obj ObjectLayer, _ string, bucket string, _ http.Handler, credentials auth.Credentials, t *testing.T) {
	ctx := t.Context()
	meta, err := readBucketMetadata(ctx, obj, bucket)
	if err != nil {
		t.Fatal(err)
	}
	putAt := meta.Created.Add(time.Second)
	deleteAt := putAt.Add(time.Second)
	encoded := base64.StdEncoding.EncodeToString([]byte(testSiteReplicationCORSDoc))
	item, err := json.Marshal(madmin.SRBucketMeta{
		Type:      madmin.SRBucketMetaTypeCorsConfig,
		Bucket:    bucket,
		Cors:      &encoded,
		UpdatedAt: putAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	adminRouter := mux.NewRouter()
	registerAdminRouter(adminRouter, true)
	path := adminPathPrefix + adminAPIVersionPrefix + "/site-replication/peer/bucket-meta"
	req, err := newTestSignedRequestV4(http.MethodPut, path, int64(len(item)), bytes.NewReader(item), credentials.AccessKey, credentials.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	adminRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin dispatch returned %d: %s", rec.Code, rec.Body.String())
	}

	localID := globalDeploymentID()
	remoteID := "remote-cors-integration"
	remoteInfo := madmin.SRInfo{
		DeploymentID: remoteID,
		Buckets: map[string]madmin.SRBucketInfo{
			bucket: {
				Bucket:              bucket,
				CreatedAt:           meta.Created,
				CorsConfig:          nil,
				CorsConfigUpdatedAt: deleteAt,
			},
		},
	}
	remoteApplies := make(chan madmin.SRBucketMeta, 1)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var applied madmin.SRBucketMeta
			if err := json.NewDecoder(r.Body).Decode(&applied); err != nil {
				t.Errorf("decode remote apply: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			remoteApplies <- applied
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(remoteInfo); err != nil {
			t.Errorf("encode remote metadata: %v", err)
		}
	}))
	defer remote.Close()

	serviceCred, _, err := globalIAMSys.NewServiceAccount(ctx, credentials.AccessKey, nil, newServiceAccountOpts{
		accessKey: "cors-integration-svc",
		secretKey: "cors-integration-service-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer globalIAMSys.DeleteServiceAccount(ctx, serviceCred.AccessKey, false)

	globalSiteReplicationSys.Lock()
	oldEnabled := globalSiteReplicationSys.enabled
	oldState := globalSiteReplicationSys.state
	globalSiteReplicationSys.enabled = true
	globalSiteReplicationSys.state = srState{
		Name:                    "cors-integration-test",
		ServiceAccountAccessKey: serviceCred.AccessKey,
		Peers: map[string]madmin.PeerInfo{
			localID:  {Name: "local", DeploymentID: localID},
			remoteID: {Name: "remote", DeploymentID: remoteID, Endpoint: remote.URL},
		},
	}
	globalSiteReplicationSys.Unlock()
	defer func() {
		globalSiteReplicationSys.Lock()
		globalSiteReplicationSys.enabled = oldEnabled
		globalSiteReplicationSys.state = oldState
		globalSiteReplicationSys.Unlock()
	}()

	status, err := globalSiteReplicationSys.siteReplicationStatus(ctx, obj, madmin.SRStatusOptions{Buckets: true})
	if err != nil {
		t.Fatal(err)
	}
	if !status.BucketStats[bucket][localID].CorsCfgMismatch {
		t.Fatal("status did not expose the missed DELETE")
	}
	if err = globalSiteReplicationSys.healCORSMetadata(ctx, obj, bucket, status); err != nil {
		t.Fatal(err)
	}

	globalBucketMetadataSys.Remove(bucket)
	reloaded, err := globalBucketMetadataSys.GetConfigFromDisk(ctx, bucket)
	if err != nil {
		t.Fatal(err)
	}
	globalBucketMetadataSys.Set(bucket, reloaded)
	if len(reloaded.CorsConfigXML) != 0 || reloaded.corsConfig != nil || !reloaded.CorsConfigUpdatedAt.Equal(deleteAt) {
		t.Fatalf("reloaded state = (%q, %#v, %v), want tombstone at %v", reloaded.CorsConfigXML, reloaded.corsConfig, reloaded.CorsConfigUpdatedAt, deleteAt)
	}
	metaInfo, err := globalSiteReplicationSys.SiteReplicationMetaInfo(ctx, obj, madmin.SRStatusOptions{Buckets: true})
	if err != nil {
		t.Fatal(err)
	}
	got := metaInfo.Buckets[bucket]
	if got.CorsConfig != nil || !got.CorsConfigUpdatedAt.Equal(deleteAt) {
		t.Fatalf("post-reload status = (%v, %v), want tombstone at %v", got.CorsConfig, got.CorsConfigUpdatedAt, deleteAt)
	}

	// Make the local site the winner and exercise heal's remote dispatch branch.
	newerAt := deleteAt.Add(time.Second)
	if err = globalSiteReplicationSys.PeerBucketCorsConfigHandler(ctx, bucket, &encoded, newerAt); err != nil {
		t.Fatal(err)
	}
	status, err = globalSiteReplicationSys.siteReplicationStatus(ctx, obj, madmin.SRStatusOptions{Buckets: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = globalSiteReplicationSys.healCORSMetadata(ctx, obj, bucket, status); err != nil {
		t.Fatal(err)
	}
	select {
	case applied := <-remoteApplies:
		if applied.Type != madmin.SRBucketMetaTypeCorsConfig || applied.Bucket != bucket || applied.Cors == nil || !applied.UpdatedAt.Equal(newerAt) {
			t.Fatalf("remote heal apply = %#v, want live CORS at %v", applied, newerAt)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(*applied.Cors)
		if err != nil || string(decoded) != testSiteReplicationCORSDoc {
			t.Fatalf("remote heal payload = %q, %v", decoded, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("remote heal did not dispatch CORS state")
	}
}
