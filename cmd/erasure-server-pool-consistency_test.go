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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	madmin "github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/bucket/replication"
	xhttp "github.com/minio/minio/internal/http"
)

func consistencyPools(t *testing.T) (*erasureServerPools, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	obj, dirs, err := prepareErasurePoolsWithContext(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	t.Cleanup(func() { cancel(); z.Shutdown(context.Background()); removeRoots(dirs); setObjectLayer(previous) })
	bucket := "pool-consistency"
	if err := z.MakeBucket(t.Context(), bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	return z, bucket
}

func putConsistencyObject(t *testing.T, z *erasureServerPools, bucket, object string, pool int, body string, opts ObjectOptions) ObjectInfo {
	t.Helper()
	oi, err := z.serverPools[pool].PutObject(t.Context(), bucket, object,
		mustGetPutObjReader(t, bytes.NewBufferString(body), int64(len(body)), "", ""), opts)
	if err != nil {
		t.Fatal(err)
	}
	return oi
}

func consistencyRequest(t *testing.T, router http.Handler, method, bucket, object, version string) *httptest.ResponseRecorder {
	t.Helper()
	url := getGetObjectURL("", bucket, object)
	if version != "" {
		url += "?versionId=" + version
	}
	req, err := newTestSignedRequestV4(method, url, 0, nil, globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// Exercise the handler's real replication/retention callbacks, including the
// MethodNotAllowed metadata returned for an explicitly addressed delete marker.
func TestPoolsDeleteVersionAPI(t *testing.T) {
	z, _ := consistencyPools(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bucket, router, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{VersioningEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"uuid", "null", "marker"} {
		for primary := range 2 {
			t.Run(fmt.Sprintf("%s/primary=%d", kind, primary), func(t *testing.T) {
				object := fmt.Sprintf("%s-%d", kind, primary)
				opts := ObjectOptions{Versioned: kind != "null", MTime: UTCNow().Add(-time.Hour)}
				var addressed ObjectInfo
				if kind == "marker" {
					opts.VersionID, opts.DeleteMarker = mustGetUUID(), true
					addressed, err = z.serverPools[primary].DeleteObject(ctx, bucket, object, opts)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					addressed = putConsistencyObject(t, z, bucket, object, primary, "payload", opts)
				}
				version := addressed.VersionID
				if version == "" {
					version = nullVersionID
				}
				opts.VersionID = version
				opts.MTime = addressed.ModTime.Add(-time.Minute)
				if kind == "marker" {
					opts.DeleteMarker = true
					if _, err := z.serverPools[1-primary].DeleteObject(ctx, bucket, object, opts); err != nil {
						t.Fatal(err)
					}
				} else {
					putConsistencyObject(t, z, bucket, object, 1-primary, "payload", opts)
				}
				latest := putConsistencyObject(t, z, bucket, object, 1-primary, "keep-latest", ObjectOptions{Versioned: true})
				rec := consistencyRequest(t, router, http.MethodDelete, bucket, object, version)
				if rec.Code != http.StatusNoContent {
					t.Fatalf("DELETE: %d %s", rec.Code, rec.Body.String())
				}
				if kind == "marker" && (strings.Join(rec.Header()[xhttp.AmzDeleteMarker], "") != "true" || strings.Join(rec.Header()[xhttp.AmzVersionID], "") != version) {
					t.Errorf("lost deleted marker response headers: %v", rec.Header())
				}
				for i, pool := range z.serverPools {
					if _, err := pool.GetObjectInfo(ctx, bucket, object, ObjectOptions{VersionID: version}); !isErrVersionNotFound(err) {
						t.Errorf("pool %d retained addressed version: %v", i, err)
					}
				}
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					if rec := consistencyRequest(t, router, method, bucket, object, version); rec.Code != http.StatusNotFound {
						t.Errorf("%s after DELETE: %d %s", method, rec.Code, rec.Body.String())
					}
				}
				if got, err := z.GetObjectInfo(ctx, bucket, object, ObjectOptions{}); err != nil || got.VersionID != latest.VersionID {
					t.Errorf("DELETE changed another version: %+v, %v", got, err)
				}
				if rec := consistencyRequest(t, router, http.MethodDelete, bucket, object, version); rec.Code != http.StatusNoContent {
					t.Errorf("idempotent retry: %d %s", rec.Code, rec.Body.String())
				}
			})
		}
	}
	if rec := consistencyRequest(t, router, http.MethodDelete, bucket, "absent-key", mustGetUUID()); rec.Code != http.StatusNoContent {
		t.Errorf("absent key: %d %s", rec.Code, rec.Body.String())
	}
}

type consistencyReadFaultDisk struct {
	StorageAPI
	bucket, object string
}

func (d consistencyReadFaultDisk) ReadVersion(ctx context.Context, origvolume, volume, path, version string, opts ReadOptions) (FileInfo, error) {
	if volume == d.bucket && path == d.object {
		return FileInfo{}, errDiskNotFound
	}
	return d.StorageAPI.ReadVersion(ctx, origvolume, volume, path, version, opts)
}

func (d consistencyReadFaultDisk) ReadXL(ctx context.Context, volume, path string, readData bool) (RawFileInfo, error) {
	if volume == d.bucket && path == d.object {
		return RawFileInfo{}, errDiskNotFound
	}
	return d.StorageAPI.ReadXL(ctx, volume, path, readData)
}

func TestPoolsDeleteVersionUnreadablePool(t *testing.T) {
	z, _ := consistencyPools(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bucket, router, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{VersioningEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, holding := range []bool{false, true} {
		for failed := range 2 {
			t.Run(fmt.Sprintf("holding=%t/pool=%d", holding, failed), func(t *testing.T) {
				object := fmt.Sprintf("unreadable-%t-%d", holding, failed)
				oi := putConsistencyObject(t, z, bucket, object, 1-failed, "payload", ObjectOptions{Versioned: true})
				if holding {
					putConsistencyObject(t, z, bucket, object, failed, "payload", ObjectOptions{Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime})
				}
				set := z.serverPools[failed].getHashedSet(object)
				getDisks := set.getDisks
				faulty := append([]StorageAPI(nil), getDisks()...)
				for i := range faulty {
					faulty[i] = consistencyReadFaultDisk{StorageAPI: faulty[i], bucket: bucket, object: object}
				}
				set.getDisks = func() []StorageAPI { return faulty }
				defer func() { set.getDisks = getDisks }()
				if rec := consistencyRequest(t, router, http.MethodDelete, bucket, object, oi.VersionID); rec.Code != http.StatusServiceUnavailable {
					t.Errorf("unreadable pool DELETE: %d %s", rec.Code, rec.Body.String())
				}
				if _, err := z.serverPools[1-failed].GetObjectInfo(ctx, bucket, object, ObjectOptions{VersionID: oi.VersionID}); err != nil {
					t.Errorf("DELETE lost the readable copy: %v", err)
				}
				set.getDisks = getDisks
				if rec := consistencyRequest(t, router, http.MethodDelete, bucket, object, oi.VersionID); rec.Code != http.StatusNoContent {
					t.Errorf("recovered pool retry: %d %s", rec.Code, rec.Body.String())
				}
				for i, pool := range z.serverPools {
					if _, err := pool.GetObjectInfo(ctx, bucket, object, ObjectOptions{VersionID: oi.VersionID}); !isErrVersionNotFound(err) {
						t.Errorf("pool %d retained version after retry: %v", i, err)
					}
				}
			})
		}
	}
}

type consistencyDeleteCountDisk struct {
	StorageAPI
	bucket, object         string
	metadataReads, deletes *atomic.Int32
}

func (d consistencyDeleteCountDisk) ReadVersion(ctx context.Context, origvolume, volume, path, version string, opts ReadOptions) (FileInfo, error) {
	if volume == d.bucket && path == d.object {
		d.metadataReads.Add(1)
	}
	return d.StorageAPI.ReadVersion(ctx, origvolume, volume, path, version, opts)
}

func (d consistencyDeleteCountDisk) DeleteVersion(ctx context.Context, volume, path string, fi FileInfo, force bool, opts DeleteOptions) error {
	if volume == d.bucket && path == d.object {
		d.deletes.Add(1)
	}
	return d.StorageAPI.DeleteVersion(ctx, volume, path, fi, force, opts)
}

func TestPoolsDeleteVersionSingleCopy(t *testing.T) {
	z, bucket := consistencyPools(t)
	for primary := range 2 {
		t.Run(fmt.Sprintf("pool=%d", primary), func(t *testing.T) {
			object := fmt.Sprintf("single-copy-%d", primary)
			oi := putConsistencyObject(t, z, bucket, object, primary, "payload", ObjectOptions{Versioned: true})
			var metadataReads, deletes [2]atomic.Int32
			for i, pool := range z.serverPools {
				set := pool.getHashedSet(object)
				getDisks := set.getDisks
				disks := append([]StorageAPI(nil), getDisks()...)
				for j := range disks {
					disks[j] = consistencyDeleteCountDisk{StorageAPI: disks[j], bucket: bucket, object: object, metadataReads: &metadataReads[i], deletes: &deletes[i]}
				}
				set.getDisks = func() []StorageAPI { return disks }
				defer func() { set.getDisks = getDisks }()
			}
			metadata, retention := 0, 0
			_, err := z.DeleteObject(t.Context(), bucket, object, ObjectOptions{
				Versioned: true, VersionID: oi.VersionID,
				EvalMetadataFn: func(current *ObjectInfo, err error) (ReplicateDecision, error) {
					metadata++
					if err != nil || current.VersionID != oi.VersionID {
						t.Errorf("metadata callback: %+v, %v", current, err)
					}
					// Count preflight reads before the physical delete reads its own metadata.
					for i := range metadataReads {
						if got := metadataReads[i].Load(); got != 16 {
							t.Errorf("pool %d metadata reads before callbacks = %d; want once per disk (16)", i, got)
						}
					}
					return ReplicateDecision{}, nil
				},
				EvalRetentionBypassFn: func(current ObjectInfo, err error) error {
					retention++
					return err
				},
			})
			if err != nil || metadata != 1 || retention != 1 {
				t.Fatalf("DELETE: %v, metadata=%d retention=%d", err, metadata, retention)
			}
			if deletes[primary].Load() != 16 || deletes[1-primary].Load() != 0 {
				t.Errorf("physical deletes per pool = %d, %d; want once per holding disk only", deletes[0].Load(), deletes[1].Load())
			}
		})
	}
}

func TestPoolsDeleteVersionReplicationPurge(t *testing.T) {
	z, bucket := consistencyPools(t)
	for _, marker := range []bool{false, true} {
		t.Run(fmt.Sprintf("marker=%t", marker), func(t *testing.T) {
			object := fmt.Sprintf("local-replication-purge-%t", marker)
			version := mustGetUUID()
			for _, pool := range z.serverPools {
				opts := ObjectOptions{Versioned: true, VersionID: version, DeleteMarker: marker}
				var err error
				if marker {
					_, err = pool.DeleteObject(t.Context(), bucket, object, opts)
				} else {
					_, err = pool.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader("payload"), 7, "", ""), opts)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			dsc := ReplicateDecision{}
			dsc.Set(newReplicateTargetDecision("arn1", true, false))
			opts := ObjectOptions{Versioned: true, VersionID: version}
			for attempt := range 2 {
				calls := 0
				opts.EvalMetadataFn = func(current *ObjectInfo, gerr error) (ReplicateDecision, error) {
					calls++
					wantMethodNotAllowed := marker || attempt > 0
					if (wantMethodNotAllowed && !isErrMethodNotAllowed(gerr)) || (!wantMethodNotAllowed && gerr != nil) {
						t.Errorf("pending purge callback lost set-layer read error: %v", gerr)
					}
					return dsc, nil
				}
				got, err := z.DeleteObject(t.Context(), bucket, object, opts)
				if err != nil || calls != 1 || got.VersionPurgeStatus != replication.VersionPurgePending || got.replicationDecision != dsc.String() {
					t.Fatalf("replication scheduling result: %+v, %v, calls=%d", got, err, calls)
				}
				for i, pool := range z.serverPools {
					got, err := pool.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: version})
					if (err != nil && (!got.DeleteMarker || !isErrMethodNotAllowed(err))) || got.VersionPurgeStatus != replication.VersionPurgePending {
						t.Errorf("pool %d lost pending purge: %+v, %v", i, got, err)
					}
				}
			}
			// The local worker completes the purge without ReplicationRequest.
			// Both pending copies must be removed, including a pending marker purge.
			opts.EvalMetadataFn = nil
			opts.DeleteReplication = ReplicationState{
				VersionPurgeStatusInternal: "arn1=COMPLETED;",
				PurgeTargets:               map[string]VersionPurgeStatusType{"arn1": replication.VersionPurgeComplete},
			}
			if _, err := z.DeleteObject(t.Context(), bucket, object, opts); err != nil {
				t.Fatal(err)
			}
			for i, pool := range z.serverPools {
				if _, err := pool.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: version}); !isErrVersionNotFound(err) {
					t.Errorf("pool %d retained completed replication purge: %v", i, err)
				}
			}
		})
	}
}

func TestPoolsDeleteVersionCleanupFailure(t *testing.T) {
	z, bucket := consistencyPools(t)
	for primary := range 2 {
		t.Run(fmt.Sprintf("primary=%d", primary), func(t *testing.T) {
			object := fmt.Sprintf("cleanup-failure-%d", primary)
			oi := putConsistencyObject(t, z, bucket, object, primary, "payload", ObjectOptions{Versioned: true})
			putConsistencyObject(t, z, bucket, object, 1-primary, "payload", ObjectOptions{
				Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime.Add(-time.Minute),
			})
			set := z.serverPools[1-primary].getHashedSet(object)
			getDisks := set.getDisks
			faulty := append([]StorageAPI(nil), getDisks()...)
			for i := range faulty {
				faulty[i] = consistencyDeleteFaultDisk{StorageAPI: faulty[i], bucket: bucket, object: object, version: oi.VersionID}
			}
			set.getDisks = func() []StorageAPI { return faulty }
			defer func() { set.getDisks = getDisks }()
			opts := ObjectOptions{Versioned: true, VersionID: oi.VersionID}
			if _, err := z.DeleteObject(t.Context(), bucket, object, opts); err == nil {
				t.Error("acknowledged DELETE despite failed secondary cleanup")
			}
			if got, err := z.serverPools[primary].GetObjectInfo(t.Context(), bucket, object, opts); err != nil || got.ETag != oi.ETag {
				t.Errorf("lost authoritative copy after secondary failure: %+v, %v", got, err)
			}
			set.getDisks = getDisks
			if _, err := z.DeleteObject(t.Context(), bucket, object, opts); err != nil {
				t.Fatal(err)
			}
			for i, pool := range z.serverPools {
				if _, err := pool.GetObjectInfo(t.Context(), bucket, object, opts); !isErrVersionNotFound(err) {
					t.Errorf("pool %d retained version after retry: %v", i, err)
				}
			}
		})
	}
}

func TestPoolsDeleteVersionCallbacks(t *testing.T) {
	z, bucket := consistencyPools(t)
	for _, marker := range []bool{false, true} {
		t.Run(fmt.Sprintf("marker=%t", marker), func(t *testing.T) {
			object := fmt.Sprintf("callbacks-%t", marker)
			old, recent := "2026-09-09T09:00:00Z", "2026-09-09T10:00:00Z"
			oi := putConsistencyObject(t, z, bucket, object, 0, "payload", ObjectOptions{
				Versioned: true, UserDefined: poolLockMetadata("GOVERNANCE", "OFF", recent, old),
			})
			putConsistencyObject(t, z, bucket, object, 1, "payload", ObjectOptions{
				Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime,
				UserDefined: poolLockMetadata("", "ON", old, recent),
			})
			if marker {
				markerOpts := ObjectOptions{Versioned: true, VersionID: mustGetUUID(), DeleteMarker: true, MTime: UTCNow()}
				for _, pool := range z.serverPools {
					var err error
					oi, err = pool.DeleteObject(t.Context(), bucket, object, markerOpts)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			check := func(current ObjectInfo, err error) {
				t.Helper()
				if current.VersionID != oi.VersionID || current.DeleteMarker != marker || (marker && !isErrMethodNotAllowed(err)) || (!marker && err != nil) {
					t.Errorf("wrong callback version or read error: %+v, %v", current, err)
				}
				if !marker {
					state := storedObjectLockState(current.UserDefined)
					if state.mode != "GOVERNANCE" || state.legalHold != "ON" {
						t.Errorf("callback did not reconcile independently ordered lock state: %+v", state)
					}
				}
			}
			for _, reject := range []string{"retention", "metadata", "none"} {
				metadata, retention := 0, 0
				denied := errors.New("callback denied deletion")
				opts := ObjectOptions{
					Versioned: true, VersionID: oi.VersionID,
					EvalRetentionBypassFn: func(current ObjectInfo, err error) error {
						retention++
						check(current, err)
						if reject == "retention" {
							return denied
						}
						return nil
					},
					EvalMetadataFn: func(current *ObjectInfo, err error) (ReplicateDecision, error) {
						metadata++
						check(*current, err)
						if reject == "metadata" {
							return ReplicateDecision{}, denied
						}
						return ReplicateDecision{}, nil
					},
				}
				_, err := z.DeleteObject(t.Context(), bucket, object, opts)
				if reject == "none" {
					if err != nil || metadata != 1 || retention != 1 {
						t.Fatalf("DELETE: %v, metadata=%d retention=%d", err, metadata, retention)
					}
				} else if !errors.Is(err, denied) {
					t.Fatalf("%s rejection was lost: %v", reject, err)
				}
				for i, pool := range z.serverPools {
					current, err := pool.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: oi.VersionID})
					if reject == "none" {
						if !isErrVersionNotFound(err) {
							t.Errorf("pool %d retained deleted version: %v", i, err)
						}
					} else if current.VersionID != oi.VersionID || (err != nil && (!marker || !isErrMethodNotAllowed(err))) {
						t.Errorf("pool %d changed despite %s rejection: %+v, %v", i, reject, current, err)
					}
				}
			}
		})
	}
}

func TestPoolsDeleteVersionSpecialCalls(t *testing.T) {
	z, bucket := consistencyPools(t)
	t.Run("incoming-marker-replication", func(t *testing.T) {
		const object = "incoming-marker"
		opts := ObjectOptions{Versioned: true, VersionID: mustGetUUID(), DeleteMarker: true, ReplicationRequest: true}
		opts.SetReplicaStatus(replication.Replica)
		if _, err := z.DeleteObject(t.Context(), bucket, object, opts); err != nil {
			t.Fatalf("replication could not create an absent marker: %v", err)
		}
		if got, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: opts.VersionID}); !isErrMethodNotAllowed(err) || !got.DeleteMarker {
			t.Fatalf("replicated marker missing: %+v, %v", got, err)
		}
	})
	for _, rebalance := range []bool{false, true} {
		t.Run(fmt.Sprintf("movement/rebalance=%t", rebalance), func(t *testing.T) {
			object := fmt.Sprintf("movement-%t", rebalance)
			putConsistencyObject(t, z, bucket, object, 1, "destination", ObjectOptions{Versioned: true})
			opts := ObjectOptions{Versioned: true, VersionID: mustGetUUID(), DeleteMarker: true, MTime: UTCNow()}
			if _, err := z.serverPools[0].DeleteObject(t.Context(), bucket, object, opts); err != nil {
				t.Fatal(err)
			}
			if rebalance {
				z.rebalMu.Lock()
				z.rebalMeta = &rebalanceMeta{PoolStats: []*rebalanceStats{{Participating: true, Info: rebalanceInfo{Status: rebalStarted}}, {}}}
				z.rebalMu.Unlock()
				defer func() { z.rebalMu.Lock(); z.rebalMeta = nil; z.rebalMu.Unlock() }()
			} else {
				z.poolMetaMutex.Lock()
				z.poolMeta.Pools[0].Decommission = &PoolDecommissionInfo{}
				z.poolMetaMutex.Unlock()
				defer func() { z.poolMetaMutex.Lock(); z.poolMeta.Pools[0].Decommission = nil; z.poolMetaMutex.Unlock() }()
			}
			// These are the marker-copy options used by rebalance/decommission;
			// Source cleanup belongs to the mover.
			opts.DataMovement, opts.SrcPoolIdx = true, 0
			opts.SkipRebalancing, opts.SkipDecommissioned = rebalance, !rebalance
			if _, err := z.DeleteObject(t.Context(), bucket, object, opts); err != nil {
				t.Fatal(err)
			}
			for i, pool := range z.serverPools {
				if got, err := pool.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: opts.VersionID}); !isErrMethodNotAllowed(err) || !got.DeleteMarker {
					t.Errorf("movement lost marker in pool %d: %+v, %v", i, got, err)
				}
			}
		})
	}
	for _, expiration := range []bool{false, true} {
		t.Run(fmt.Sprintf("scanner/expiration=%t", expiration), func(t *testing.T) {
			object := fmt.Sprintf("scanner-%t", expiration)
			oi := putConsistencyObject(t, z, bucket, object, 0, "payload", ObjectOptions{Versioned: true})
			set := z.serverPools[1].getHashedSet(object)
			getDisks := set.getDisks
			faulty := append([]StorageAPI(nil), getDisks()...)
			for i := range faulty {
				faulty[i] = consistencyReadFaultDisk{StorageAPI: faulty[i], bucket: bucket, object: object}
			}
			set.getDisks = func() []StorageAPI { return faulty }
			defer func() { set.getDisks = getDisks }()
			opts := ObjectOptions{Versioned: true, VersionID: oi.VersionID, InclFreeVersions: !expiration, Expiration: ExpirationOptions{Expire: expiration}}
			_, err := z.DeleteObject(t.Context(), bucket, object, opts)
			if expiration {
				// No lifecycle rule authorizes expiration. Preserve its existing
				// version-not-found result, even with an unrelated unreadable pool.
				if !isErrVersionNotFound(err) {
					t.Errorf("expiration changed its scanner contract: %v", err)
				}
			} else if err != nil {
				t.Errorf("free-version cleanup was forced through all-pool resolution: %v", err)
			}
		})
	}
}

func TestPoolsDeleteUnversionedFanout(t *testing.T) {
	z, bucket := consistencyPools(t)
	const object = "unversioned-fanout"
	for i := range z.serverPools {
		putConsistencyObject(t, z, bucket, object, i, "payload", ObjectOptions{})
	}
	if _, err := z.DeleteObject(t.Context(), bucket, object, ObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	for i, pool := range z.serverPools {
		if _, err := pool.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); !isErrObjectNotFound(err) {
			t.Errorf("unversioned fanout left pool %d readable: %v", i, err)
		}
	}
}

func TestPoolsConditionalDeleteVersionSelection(t *testing.T) {
	z, bucket := consistencyPools(t)
	const object = "split-versions"
	old := putConsistencyObject(t, z, bucket, object, 1, "old", ObjectOptions{Versioned: true, MTime: time.Now().Add(-time.Hour)})
	latest := putConsistencyObject(t, z, bucket, object, 0, "latest", ObjectOptions{Versioned: true})
	_, err := z.DeleteObject(t.Context(), bucket, object, ObjectOptions{
		Versioned: true, VersionID: old.VersionID, HasIfMatch: true,
		CheckPrecondFn: func(oi ObjectInfo) bool { return oi.ETag != old.ETag },
	})
	if err != nil {
		t.Fatalf("delete addressed version in pool 1: %v", err)
	}
	if _, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: old.VersionID}); !isErrVersionNotFound(err) {
		t.Errorf("addressed version survived: %v", err)
	}
	if oi, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); err != nil || oi.VersionID != latest.VersionID {
		t.Errorf("delete changed the latest version: %+v, %v", oi, err)
	}
}

func TestPoolsConditionalDeleteDuplicateVersion(t *testing.T) {
	z, bucket := consistencyPools(t)
	const object = "duplicate-version"
	oi := putConsistencyObject(t, z, bucket, object, 0, "payload", ObjectOptions{Versioned: true})
	putConsistencyObject(t, z, bucket, object, 1, "payload", ObjectOptions{Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime})
	_, err := z.DeleteObject(t.Context(), bucket, object, ObjectOptions{
		Versioned: true, VersionID: oi.VersionID, HasIfMatch: true,
		CheckPrecondFn: func(current ObjectInfo) bool { return current.ETag != oi.ETag },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: oi.VersionID}); !isErrVersionNotFound(err) {
		t.Fatalf("success left a readable duplicate version: %v", err)
	}
}

func TestPoolsConditionalDeleteReportsOtherPoolFailure(t *testing.T) {
	z, bucket := consistencyPools(t)
	const object = "delete-failure"
	putConsistencyObject(t, z, bucket, object, 1, "older", ObjectOptions{MTime: time.Now().Add(-time.Hour)})
	oi := putConsistencyObject(t, z, bucket, object, 0, "latest", ObjectOptions{})
	set := z.serverPools[1].getHashedSet(object)
	getDisks := set.getDisks
	faulty := append([]StorageAPI(nil), getDisks()...)
	for i := range faulty {
		faulty[i] = consistencyDeleteFaultDisk{StorageAPI: faulty[i], bucket: bucket, object: object}
	}
	set.getDisks = func() []StorageAPI { return faulty }
	defer func() { set.getDisks = getDisks }()
	_, err := z.DeleteObject(t.Context(), bucket, object, ObjectOptions{
		HasIfMatch: true, CheckPrecondFn: func(current ObjectInfo) bool { return current.ETag != oi.ETag },
	})
	if err == nil {
		t.Fatal("delete reported success despite the other pool's write failure")
	}
}

func TestPoolsConditionalDeleteSerializesPut(t *testing.T) {
	testPoolsConditionalDeleteWriter(t, false)
}

func TestPoolsConditionalDeleteSerializesCompletion(t *testing.T) {
	testPoolsConditionalDeleteWriter(t, true)
}

func testPoolsConditionalDeleteWriter(t *testing.T, multipart bool) {
	z, bucket := consistencyPools(t)
	const object = "concurrent-put"
	initial := putConsistencyObject(t, z, bucket, object, 1, "before", ObjectOptions{})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reader := mustGetPutObjReader(t, bytes.NewBufferString("after"), 5, "", "")
	write := func() error {
		_, err := z.PutObject(ctx, bucket, object, reader, ObjectOptions{})
		return err
	}
	if multipart {
		mp, err := z.serverPools[1].NewMultipartUpload(ctx, bucket, object, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		part, err := z.serverPools[1].PutObjectPart(ctx, bucket, object, mp.UploadID, 1, reader, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		write = func() error {
			_, err := z.CompleteMultipartUpload(ctx, bucket, object, mp.UploadID,
				[]CompletePart{{PartNumber: 1, ETag: part.ETag}}, ObjectOptions{})
			return err
		}
	}
	checked, resume := make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	release := func() { resumeOnce.Do(func() { close(resume) }) }
	defer release()
	deleted := make(chan error, 1)
	go func() {
		_, err := z.DeleteObject(ctx, bucket, object, ObjectOptions{
			HasIfMatch: true,
			CheckPrecondFn: func(oi ObjectInfo) bool {
				close(checked)
				<-resume
				return oi.ETag != initial.ETag
			},
		})
		deleted <- err
	}()
	select {
	case <-checked:
	case err := <-deleted:
		t.Fatalf("delete did not evaluate the precondition: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	written := make(chan error, 1)
	go func() { written <- write() }()
	var early bool
	select {
	case err := <-written:
		early = true
		if err != nil {
			t.Errorf("concurrent PUT: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
	}
	release()
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if !early {
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
	if early {
		t.Error("PUT committed while DELETE was between its comparison and removal")
	}
	if _, err := z.GetObjectInfo(ctx, bucket, object, ObjectOptions{}); err != nil {
		t.Errorf("matching the old ETag removed the concurrent replacement: %v", err)
	}
}

type consistencyGateReader struct {
	io.Reader
	entered, resume chan struct{}
	once            sync.Once
	release         sync.Once
}

func (r *consistencyGateReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered); <-r.resume })
	return r.Reader.Read(p)
}

func TestPoolsReplicaSerializesMetadataAndHealing(t *testing.T) {
	for _, heal := range []bool{false, true} {
		t.Run(fmt.Sprintf("heal=%t", heal), func(t *testing.T) {
			z, bucket := consistencyPools(t)
			const object = "metadata-race"
			old, recent := "2026-09-09T09:00:00Z", "2026-09-09T10:00:00Z"
			meta := poolLockMetadata("GOVERNANCE", "OFF", old, old)
			oi := putConsistencyObject(t, z, bucket, object, 1, "data", ObjectOptions{Versioned: true, UserDefined: meta})
			z.poolMetaMutex.Lock()
			z.poolMeta.Pools[0].Decommission = &PoolDecommissionInfo{}
			z.poolMetaMutex.Unlock()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate := &consistencyGateReader{Reader: strings.NewReader("data"), entered: make(chan struct{}), resume: make(chan struct{})}
			release := func() { gate.release.Do(func() { close(gate.resume) }) }
			defer release()
			reader := mustGetPutObjReader(t, gate, 4, "", "")
			written := make(chan error, 1)
			go func() {
				_, err := z.PutObject(ctx, bucket, object, reader, ObjectOptions{
					Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime,
					ReplicaLockReconcile: true, UserDefined: maps.Clone(meta),
				})
				written <- err
			}()
			select {
			case <-gate.entered:
			case err := <-written:
				t.Fatalf("write failed before consuming the body: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			mutated := make(chan error, 1)
			go func() {
				var err error
				if heal {
					_, err = z.healObjectInPool(ctx, z.serverPools[1].getHashedSet(object), bucket, object, oi.VersionID, madmin.HealOpts{})
				} else {
					_, err = z.PutObjectMetadata(ctx, bucket, object, ObjectOptions{
						VersionID: oi.VersionID, MTime: oi.ModTime,
						EvalMetadataFn: func(current *ObjectInfo, _ error) (ReplicateDecision, error) {
							current.UserDefined[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = "ON"
							current.UserDefined[ReservedMetadataPrefixLower+ObjectLockLegalHoldTimestamp] = recent
							return ReplicateDecision{}, nil
						},
					})
				}
				mutated <- err
			}()
			var early bool
			select {
			case err := <-mutated:
				early = true
				t.Errorf("mutation completed during the paused replica write: %v", err)
			case <-time.After(250 * time.Millisecond):
			}
			release()
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !early {
				if err := <-mutated; err != nil {
					t.Fatal(err)
				}
			}
			got, err := z.GetObjectInfo(ctx, bucket, object, ObjectOptions{VersionID: oi.VersionID})
			if err != nil {
				t.Fatal(err)
			}
			if !heal && storedObjectLockState(got.UserDefined).legalHold != "ON" {
				t.Error("replica write rolled back the newer metadata update")
			}
		})
	}
}

func TestPoolsConditionalDeletePreservesVersionHistory(t *testing.T) {
	z, bucket := consistencyPools(t)
	const object = "conditional-marker"
	older := putConsistencyObject(t, z, bucket, object, 1, "older", ObjectOptions{Versioned: true, MTime: time.Now().Add(-time.Hour)})
	latest := putConsistencyObject(t, z, bucket, object, 0, "latest", ObjectOptions{Versioned: true})
	_, err := z.DeleteObject(t.Context(), bucket, object, ObjectOptions{
		Versioned:      true,
		CheckPrecondFn: func(oi ObjectInfo) bool { return oi.ETag != older.ETag },
	})
	if !isErrPreconditionFailed(err) {
		t.Fatalf("wrong latest ETag: %v", err)
	}
	marker, err := z.DeleteObject(t.Context(), bucket, object, ObjectOptions{
		Versioned:      true,
		CheckPrecondFn: func(oi ObjectInfo) bool { return oi.ETag != latest.ETag },
	})
	if err != nil || !marker.DeleteMarker {
		t.Fatalf("logical delete did not create a marker: %+v, %v", marker, err)
	}
	if got, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); !isErrObjectNotFound(err) || !got.DeleteMarker {
		t.Errorf("delete marker did not hide the split object: %+v, %v", got, err)
	}
	for _, version := range []string{older.VersionID, latest.VersionID} {
		if _, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: version}); err != nil {
			t.Errorf("conditional marker removed history %s: %v", version, err)
		}
	}
}

func poolLockMetadata(retention, hold, retentionTime, holdTime string) map[string]string {
	return map[string]string{
		strings.ToLower(xhttp.AmzObjectLockMode):                   retention,
		strings.ToLower(xhttp.AmzObjectLockRetainUntilDate):        "2030-01-01T00:00:00Z",
		strings.ToLower(xhttp.AmzObjectLockLegalHold):              hold,
		ReservedMetadataPrefixLower + ObjectLockRetentionTimestamp: retentionTime,
		ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: holdTime,
	}
}

func TestPoolsReplicaIndependentLockWinners(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		multipart, rebalance bool
	}{
		{"put-decommission", false, false},
		{"put-rebalance", false, true},
		{"multipart-decommission", true, false},
		{"multipart-rebalance", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z, bucket := consistencyPools(t)
			const object = "split-lock-state"
			old, recent := "2026-09-09T09:00:00Z", "2026-09-09T10:00:00Z"
			first := poolLockMetadata("GOVERNANCE", "OFF", recent, old)
			second := poolLockMetadata("", "ON", old, recent)
			oi := putConsistencyObject(t, z, bucket, object, 0, "data", ObjectOptions{Versioned: true, UserDefined: first})
			putConsistencyObject(t, z, bucket, object, 1, "data", ObjectOptions{
				Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime, UserDefined: second,
			})
			opts := ObjectOptions{
				Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime,
				ReplicaLockReconcile: true, UserDefined: poolLockMetadata("", "OFF", old, old),
			}
			var uploadID string
			var parts []CompletePart
			if tc.multipart {
				mp, err := z.serverPools[1].NewMultipartUpload(t.Context(), bucket, object, opts)
				if err != nil {
					t.Fatal(err)
				}
				uploadID = mp.UploadID
				part, err := z.serverPools[1].PutObjectPart(t.Context(), bucket, object, uploadID, 1,
					mustGetPutObjReader(t, bytes.NewBufferString("data"), 4, "", ""), ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				parts = []CompletePart{{PartNumber: 1, ETag: part.ETag}}
			}
			// The upload and both versions predate the routing change. Retention's
			// winner remains in the draining pool; legal hold's winner is in pool 1.
			if tc.rebalance {
				z.rebalMu.Lock()
				z.rebalMeta = &rebalanceMeta{PoolStats: []*rebalanceStats{
					{Participating: true, Info: rebalanceInfo{Status: rebalStarted}}, {},
				}}
				z.rebalMu.Unlock()
			} else {
				z.poolMetaMutex.Lock()
				z.poolMeta.Pools[0].Decommission = &PoolDecommissionInfo{}
				z.poolMetaMutex.Unlock()
			}
			var err error
			if tc.multipart {
				_, err = z.CompleteMultipartUpload(t.Context(), bucket, object, uploadID, parts,
					ObjectOptions{Versioned: true, MTime: oi.ModTime, ReplicaLockReconcile: true})
			} else {
				_, err = z.PutObject(t.Context(), bucket, object,
					mustGetPutObjReader(t, bytes.NewBufferString("data"), 4, "", ""), opts)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: oi.VersionID})
			if err != nil {
				t.Fatal(err)
			}
			state := storedObjectLockState(got.UserDefined)
			if state.mode != "GOVERNANCE" || state.retentionTimestamp != recent || state.legalHold != "ON" || state.legalHoldTimestamp != recent {
				t.Errorf("pooled read lost independently ordered lock state: %+v", state)
			}
			if _, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: oi.VersionID}); !isErrVersionNotFound(err) {
				t.Errorf("successful replacement left its stale competing copy: %v", err)
			}
		})
	}
}

func TestPoolsReplicaSoleDrainingOwner(t *testing.T) {
	for _, rebalance := range []bool{false, true} {
		for _, null := range []bool{false, true} {
			t.Run(fmt.Sprintf("rebalance=%t/null=%t", rebalance, null), func(t *testing.T) {
				z, bucket := consistencyPools(t)
				const object = "sole-owner"
				old, recent := "2026-09-09T09:00:00Z", "2026-09-09T10:00:00Z"
				meta := poolLockMetadata("", "ON", recent, recent)
				delete(meta, strings.ToLower(xhttp.AmzObjectLockRetainUntilDate))
				oi := putConsistencyObject(t, z, bucket, object, 0, "data", ObjectOptions{Versioned: !null, UserDefined: meta})
				versionID := oi.VersionID
				if null {
					versionID = nullVersionID
					// A different latest version must not donate its lock to the null version.
					putConsistencyObject(t, z, bucket, object, 1, "other-version", ObjectOptions{Versioned: true})
				}
				if rebalance {
					z.rebalMu.Lock()
					z.rebalMeta = &rebalanceMeta{PoolStats: []*rebalanceStats{
						{Participating: true, Info: rebalanceInfo{Status: rebalStarted}}, {},
					}}
					z.rebalMu.Unlock()
				} else {
					z.poolMetaMutex.Lock()
					z.poolMeta.Pools[0].Decommission = &PoolDecommissionInfo{}
					z.poolMetaMutex.Unlock()
				}
				_, err := z.PutObject(t.Context(), bucket, object,
					mustGetPutObjReader(t, bytes.NewBufferString("data"), 4, "", ""), ObjectOptions{
						Versioned: !null, VersionSuspended: null, VersionID: versionID, MTime: oi.ModTime,
						ReplicaLockReconcile: true, UserDefined: poolLockMetadata("GOVERNANCE", "OFF", old, old),
					})
				if err != nil {
					t.Fatal(err)
				}
				got, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: versionID})
				if err != nil {
					t.Fatal(err)
				}
				state := storedObjectLockState(got.UserDefined)
				if state.mode != "" || state.retainUntil != "" || state.retentionTimestamp != recent || state.legalHold != "ON" {
					t.Errorf("lost a removal or legal hold from the sole draining owner: %+v", state)
				}
			})
		}
	}
}

func TestPoolsMetadataUpdateUsesMergedVersion(t *testing.T) {
	z, bucket := consistencyPools(t)
	const object = "metadata-update"
	old, recent := "2026-09-09T09:00:00Z", "2026-09-09T10:00:00Z"
	oi := putConsistencyObject(t, z, bucket, object, 0, "data", ObjectOptions{
		Versioned: true, UserDefined: poolLockMetadata("GOVERNANCE", "OFF", recent, old),
	})
	putConsistencyObject(t, z, bucket, object, 1, "data", ObjectOptions{
		Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime, UserDefined: poolLockMetadata("", "ON", old, recent),
	})
	latest := putConsistencyObject(t, z, bucket, object, 1, "latest", ObjectOptions{Versioned: true})
	called := 0
	_, err := z.PutObjectMetadata(t.Context(), bucket, object, ObjectOptions{
		VersionID: oi.VersionID, MTime: oi.ModTime,
		EvalMetadataFn: func(current *ObjectInfo, _ error) (ReplicateDecision, error) {
			called++
			state := storedObjectLockState(current.UserDefined)
			if state.mode != "GOVERNANCE" || state.legalHold != "ON" {
				return ReplicateDecision{}, fmt.Errorf("metadata policy evaluated stale state: %+v", state)
			}
			current.UserDefined["custom-update"] = "preserved"
			return ReplicateDecision{}, nil
		},
	})
	if err != nil || called != 1 {
		t.Fatalf("metadata update: %v; callback count %d", err, called)
	}
	for i, pool := range z.serverPools {
		got, err := pool.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: oi.VersionID})
		if err != nil {
			t.Fatal(err)
		}
		state := storedObjectLockState(got.UserDefined)
		if state.mode != "GOVERNANCE" || state.legalHold != "ON" || got.UserDefined["custom-update"] != "preserved" {
			t.Errorf("pool %d did not receive the merged update: %+v", i, got.UserDefined)
		}
	}
	if current, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); err != nil || current.VersionID != latest.VersionID {
		t.Errorf("updating an older version changed the latest: %+v, %v", current, err)
	}
}

func TestPoolsReplicaMetadataCopyReconcilesLockAndTags(t *testing.T) {
	z, bucket := consistencyPools(t)
	const object = "replica-metadata-copy"
	old, recent := "2026-09-09T09:00:00Z", "2026-09-09T10:00:00Z"
	meta := poolLockMetadata("GOVERNANCE", "OFF", recent, old)
	meta[xhttp.AmzObjectTagging] = "key=new"
	meta[ReservedMetadataPrefixLower+TaggingTimestamp] = recent
	oi := putConsistencyObject(t, z, bucket, object, 0, "data", ObjectOptions{Versioned: true, UserDefined: meta})
	putConsistencyObject(t, z, bucket, object, 1, "data", ObjectOptions{
		Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime, UserDefined: poolLockMetadata("", "ON", old, recent),
	})
	stale := oi
	stale.metadataOnly = true
	stale.UserDefined = maps.Clone(oi.UserDefined)
	stale.UserDefined[xhttp.AmzObjectTagging] = "key=old"
	stale.UserDefined[ReservedMetadataPrefixLower+TaggingTimestamp] = old
	_, err := z.CopyObject(t.Context(), bucket, object, bucket, object, stale,
		ObjectOptions{VersionID: oi.VersionID}, ObjectOptions{
			Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime, ReplicaLockReconcile: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	got, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: oi.VersionID})
	if err != nil {
		t.Fatal(err)
	}
	state := storedObjectLockState(got.UserDefined)
	if state.mode != "GOVERNANCE" || state.legalHold != "ON" || got.UserTags != "key=new" {
		t.Errorf("metadata replication rolled back a newer field: %+v", got.UserDefined)
	}
}

func TestPoolsReplicaCleanupFailureCanRetry(t *testing.T) {
	z, bucket := consistencyPools(t)
	const object = "replica-cleanup-failure"
	old, recent := "2026-09-09T09:00:00Z", "2026-09-09T10:00:00Z"
	oi := putConsistencyObject(t, z, bucket, object, 0, "data", ObjectOptions{
		Versioned: true, UserDefined: poolLockMetadata("GOVERNANCE", "ON", recent, recent),
	})
	z.poolMetaMutex.Lock()
	z.poolMeta.Pools[0].Decommission = &PoolDecommissionInfo{}
	z.poolMetaMutex.Unlock()
	set := z.serverPools[0].getHashedSet(object)
	getDisks := set.getDisks
	faulty := append([]StorageAPI(nil), getDisks()...)
	for i := range faulty {
		faulty[i] = consistencyDeleteFaultDisk{StorageAPI: faulty[i], bucket: bucket, object: object, version: oi.VersionID}
	}
	set.getDisks = func() []StorageAPI { return faulty }
	defer func() { set.getDisks = getDisks }()
	write := func() error {
		_, err := z.PutObject(t.Context(), bucket, object,
			mustGetPutObjReader(t, bytes.NewBufferString("data"), 4, "", ""), ObjectOptions{
				Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime, ReplicaLockReconcile: true,
				UserDefined: poolLockMetadata("", "OFF", old, old),
			})
		return err
	}
	if err := write(); err == nil {
		t.Fatal("replica replacement hid a competing-copy cleanup failure")
	}
	if got, err := z.serverPools[1].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: oi.VersionID}); err != nil || storedObjectLockState(got.UserDefined).legalHold != "ON" {
		t.Fatalf("cleanup failure lost the committed reconciled version: %+v, %v", got, err)
	}
	set.getDisks = getDisks
	if err := write(); err != nil {
		t.Fatalf("retry could not finish cleanup: %v", err)
	}
	if _, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: oi.VersionID}); !isErrVersionNotFound(err) {
		t.Errorf("retry left the competing version: %v", err)
	}
}

func TestPoolsRetiringCopyPreservesSharedTierObject(t *testing.T) {
	for _, test := range []struct {
		name              string
		deleting          bool
		failPrimaryDelete bool
		differentRemote   bool
		restored          bool
		unconditional     bool
		skipFreeVersion   bool
		bulk              bool
		unversioned       bool
	}{
		{name: "metadata-copy"},
		{name: "restored-metadata-copy", restored: true},
		{name: "metadata-copy-distinct-reference", differentRemote: true},
		{name: "failed-primary-delete", deleting: true, failPrimaryDelete: true},
		{name: "failed-primary-delete-distinct-reference", deleting: true, failPrimaryDelete: true, differentRemote: true},
		{name: "successful-delete", deleting: true},
		{name: "ordinary-failed-primary-delete", deleting: true, unconditional: true, failPrimaryDelete: true},
		{name: "ordinary-successful-delete", deleting: true, unconditional: true},
		{name: "ordinary-skip-free-version", deleting: true, unconditional: true, skipFreeVersion: true},
		{name: "bulk-failed-primary-delete", deleting: true, bulk: true, failPrimaryDelete: true},
		{name: "bulk-restored-failed-primary-delete", deleting: true, bulk: true, restored: true, failPrimaryDelete: true},
		{name: "bulk-successful-delete", deleting: true, bulk: true},
		{name: "bulk-distinct-reference", deleting: true, bulk: true, differentRemote: true},
		{name: "bulk-skip-free-version", deleting: true, bulk: true, skipFreeVersion: true},
		{name: "unversioned-failed-primary-delete", deleting: true, unconditional: true, unversioned: true, failPrimaryDelete: true},
		{name: "unversioned-successful-delete", deleting: true, unconditional: true, unversioned: true},
		{name: "bulk-unversioned-failed-primary-delete", deleting: true, bulk: true, unversioned: true, failPrimaryDelete: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			z, bucket := consistencyPools(t)
			const object = "shared-tier-object"
			metadata := map[string]string{
				ReservedMetadataPrefixLower + TransitionStatus:       "complete",
				ReservedMetadataPrefixLower + TransitionTier:         "TEST-TIER",
				ReservedMetadataPrefixLower + TransitionedObjectName: "shared-remote-object",
				ReservedMetadataPrefixLower + TransitionedVersionID:  "shared-remote-version",
			}
			if test.restored {
				metadata[xhttp.AmzRestore] = completedRestoreObj(time.Now().Add(time.Hour)).String()
			}
			oi := putConsistencyObject(t, z, bucket, object, 0, "data", ObjectOptions{Versioned: !test.unversioned, UserDefined: metadata})
			secondaryMetadata := maps.Clone(metadata)
			if test.differentRemote {
				secondaryMetadata[ReservedMetadataPrefixLower+TransitionedObjectName] = "other-remote-object"
			}
			putConsistencyObject(t, z, bucket, object, 1, "data", ObjectOptions{
				Versioned: !test.unversioned, VersionID: oi.VersionID, MTime: oi.ModTime, UserDefined: secondaryMetadata,
			})
			current, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: oi.VersionID})
			if err != nil || current.TransitionedObject.Status != "complete" || current.IsRemote() == test.restored {
				t.Fatalf("fixture did not persist the tier reference: %+v, %v", current.TransitionedObject, err)
			}
			if test.failPrimaryDelete {
				// The authoritative copy remains readable if its deletion fails.
				// Retiring a secondary copy must not schedule its shared remote
				// contents for garbage collection in that case.
				set := z.serverPools[0].getHashedSet(object)
				getDisks := set.getDisks
				faulty := append([]StorageAPI(nil), getDisks()...)
				var failed, attempted atomic.Int32
				for i := range faulty {
					if test.bulk {
						faulty[i] = bulkDeleteFaultDisk{StorageAPI: faulty[i], bucket: bucket, object: object, mode: "eio", fail: true, failed: &failed, attempted: &attempted}
					}
					faulty[i] = consistencyDeleteFaultDisk{StorageAPI: faulty[i], bucket: bucket, object: object, version: oi.VersionID}
				}
				set.getDisks = func() []StorageAPI { return faulty }
				defer func() { set.getDisks = getDisks }()
			}
			if test.deleting {
				opts := ObjectOptions{
					Versioned: !test.unversioned, VersionID: oi.VersionID, SkipFreeVersion: test.skipFreeVersion,
					CheckPrecondFn: func(info ObjectInfo) bool { return info.ETag != current.ETag },
				}
				if test.unconditional {
					opts.CheckPrecondFn = nil
				}
				var err error
				if test.bulk {
					opts.CheckPrecondFn = nil
					_, errs := z.DeleteObjects(t.Context(), bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: object, VersionID: oi.VersionID}}}, opts)
					err = errs[0]
				} else {
					_, err = z.DeleteObject(t.Context(), bucket, object, opts)
				}
				if (err != nil) != test.failPrimaryDelete {
					t.Fatalf("unexpected authoritative delete result: %v", err)
				}
			} else {
				current.metadataOnly = true
				current.UserDefined["metadata-update"] = "new"
				_, err := z.CopyObject(t.Context(), bucket, object, bucket, object, current,
					ObjectOptions{VersionID: oi.VersionID}, ObjectOptions{
						Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime, ReplicaLockReconcile: true,
					})
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err = z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: oi.VersionID})
			primaryDeleted := test.deleting && !test.failPrimaryDelete
			if primaryDeleted {
				if !isErrVersionNotFound(err) && (!test.unversioned || !isErrObjectNotFound(err)) {
					t.Fatalf("authoritative copy survived successful delete: %v", err)
				}
			} else if err != nil {
				t.Fatalf("lost retained authoritative copy: %v", err)
			}
			for pool, wantFree := range []bool{primaryDeleted, test.differentRemote} {
				wantFree = wantFree && !test.skipFreeVersion
				for _, disk := range z.serverPools[pool].getHashedSet(object).getDisks() {
					data, err := disk.ReadAll(t.Context(), bucket, pathJoin(object, xlStorageFormatFile))
					if errors.Is(err, errFileNotFound) && !wantFree {
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					versions, err := getFileInfoVersions(data, bucket, object, false)
					if err != nil {
						t.Fatal(err)
					}
					wantCount := 0
					if wantFree {
						wantCount = 1
					}
					if len(versions.FreeVersions) != wantCount {
						t.Fatalf("pool %d has %d tier GC markers, want %d", pool, len(versions.FreeVersions), wantCount)
					}
				}
			}
		})
	}
}

// Fault injection shared by general multi-pool regressions.
type consistencyDeleteFaultDisk struct {
	StorageAPI
	bucket, object, version string
}

func (d consistencyDeleteFaultDisk) DeleteVersion(ctx context.Context, volume, path string, fi FileInfo, forceDelMarker bool, opts DeleteOptions) error {
	if volume == d.bucket && path == d.object && fi.VersionID == d.version {
		return errDiskFull
	}
	return d.StorageAPI.DeleteVersion(ctx, volume, path, fi, forceDelMarker, opts)
}

// Exercise the surviving production rebalance copy, then interrupt the workflow
// before its later source cleanup. Repeated versions are reachable without the
// retired access-tier mover, and an API delete must remove both copies.
func TestPoolsDeleteVersionAfterInterruptedRebalance(t *testing.T) {
	z, _ := consistencyPools(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bucket, router, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{VersioningEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for source := range 2 {
		t.Run(fmt.Sprintf("source=%d", source), func(t *testing.T) {
			object := fmt.Sprintf("interrupted-rebalance-%d", source)
			original := putConsistencyObject(t, z, bucket, object, source, "original", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour)})
			stats := []*rebalanceStats{{}, {}}
			stats[source] = &rebalanceStats{Participating: true, Info: rebalanceInfo{Status: rebalStarted}}
			z.rebalMu.Lock()
			z.rebalMeta = &rebalanceMeta{PoolStats: stats}
			z.rebalMu.Unlock()
			defer func() { z.rebalMu.Lock(); z.rebalMeta = nil; z.rebalMu.Unlock() }()
			gr, err := z.serverPools[source].GetObjectNInfo(ctx, bucket, object, nil, nil, ObjectOptions{VersionID: original.VersionID, NoLock: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := z.rebalanceObject(ctx, source, bucket, gr); err != nil {
				t.Fatalf("rebalance copy: %v", err)
			}
			// Simulate interruption after rebalanceObject, before the enclosing loop
			// removes the source version stack. Stop rebalance before the API request.
			z.rebalMu.Lock()
			z.rebalMeta = nil
			z.rebalMu.Unlock()
			for i, pool := range z.serverPools {
				got, err := pool.GetObjectInfo(ctx, bucket, object, ObjectOptions{VersionID: original.VersionID})
				if err != nil || got.VersionID != original.VersionID || !got.ModTime.Equal(original.ModTime) {
					t.Fatalf("copy missing/changed in pool %d: %+v, %v", i, got, err)
				}
			}
			later, err := z.PutObject(ctx, bucket, object, mustGetPutObjReader(t, bytes.NewBufferString("later"), 5, "", ""), ObjectOptions{Versioned: true})
			if err != nil {
				t.Fatal(err)
			}
			rec := consistencyRequest(t, router, http.MethodDelete, bucket, object, original.VersionID)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("DELETE: %d %s", rec.Code, rec.Body.String())
			}
			for i, pool := range z.serverPools {
				if _, err := pool.GetObjectInfo(ctx, bucket, object, ObjectOptions{VersionID: original.VersionID}); !isErrVersionNotFound(err) {
					t.Errorf("pool %d retained old version: %v", i, err)
				}
			}
			if got, err := z.GetObjectInfo(ctx, bucket, object, ObjectOptions{}); err != nil || got.VersionID != later.VersionID {
				t.Fatalf("other version changed: %+v, %v", got, err)
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				if rec := consistencyRequest(t, router, method, bucket, object, original.VersionID); rec.Code != http.StatusNotFound {
					t.Errorf("%s returned %d", method, rec.Code)
				}
			}
		})
	}
}

func TestPoolsDeleteDirectoryMarker(t *testing.T) {
	z, _ := consistencyPools(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bucket, router, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{VersioningEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for holding := range 2 {
		for _, unreadable := range []bool{false, true} {
			t.Run(fmt.Sprintf("holding=%d/unreadable=%t", holding, unreadable), func(t *testing.T) {
				object := fmt.Sprintf("directory-%d-%t/", holding, unreadable)
				encoded := encodeDirObject(object)
				putConsistencyObject(t, z, bucket, encoded, holding, "", ObjectOptions{})
				set := z.serverPools[1-holding].getHashedSet(encoded)
				getDisks := set.getDisks
				defer func() { set.getDisks = getDisks }()
				if unreadable {
					disks := append([]StorageAPI(nil), getDisks()...)
					for i := range disks {
						disks[i] = consistencyReadFaultDisk{StorageAPI: disks[i], bucket: bucket, object: encoded}
					}
					set.getDisks = func() []StorageAPI { return disks }
				}
				// No explicit versionId: delOpts permanently deletes the null version.
				rec := consistencyRequest(t, router, http.MethodDelete, bucket, object, "")
				if unreadable {
					if rec.Code != http.StatusServiceUnavailable {
						t.Fatalf("unreadable pool: %d %s", rec.Code, rec.Body.String())
					}
					if _, err := z.serverPools[holding].GetObjectInfo(ctx, bucket, encoded, ObjectOptions{VersionID: nullVersionID}); err != nil {
						t.Fatalf("readable directory marker lost: %v", err)
					}
					set.getDisks = getDisks
					rec = consistencyRequest(t, router, http.MethodDelete, bucket, object, "")
				}
				if rec.Code != http.StatusNoContent {
					t.Fatalf("DELETE: %d %s", rec.Code, rec.Body.String())
				}
				for i, pool := range z.serverPools {
					if _, err := pool.GetObjectInfo(ctx, bucket, encoded, ObjectOptions{VersionID: nullVersionID}); !isErrVersionNotFound(err) {
						t.Errorf("pool %d retained null version: %v", i, err)
					}
				}
				if rec := consistencyRequest(t, router, http.MethodHead, bucket, object, ""); rec.Code != http.StatusNotFound {
					t.Errorf("directory still visible: %d", rec.Code)
				}
			})
		}
	}
}

// An unconditional DELETE of an object without versions removes its copies in
// every pool. When the delete fails in one pool, the latest copy must stay in
// place: removing it anyway serves an older write of the object.
func TestPoolsDeleteUnversionedReportsOtherPoolFailure(t *testing.T) {
	for _, offline := range []bool{false, true} {
		for latest := range 2 {
			t.Run(fmt.Sprintf("offline=%v/latest=%d", offline, latest), func(t *testing.T) {
				z, bucket := consistencyPools(t)
				const object = "unversioned-failure"
				older := 1 - latest
				putConsistencyObject(t, z, bucket, object, older, "older", ObjectOptions{MaxParity: true, MTime: time.Now().Add(-time.Hour)})
				oi := putConsistencyObject(t, z, bucket, object, latest, "latest", ObjectOptions{MaxParity: true})
				set := z.serverPools[older].getHashedSet(object)
				getDisks := set.getDisks
				disks := append([]StorageAPI(nil), getDisks()...)
				for i := range disks {
					switch {
					case !offline:
						disks[i] = consistencyDeleteFaultDisk{StorageAPI: disks[i], bucket: bucket, object: object}
					case i < len(disks)/2:
						// An EC 8+8 copy stays readable, but a delete needs 9 drives.
						disks[i] = nil
					}
				}
				set.getDisks = func() []StorageAPI { return disks }
				defer func() { set.getDisks = getDisks }()
				if _, err := z.DeleteObject(t.Context(), bucket, object, ObjectOptions{}); err == nil {
					t.Error("delete reported success despite the other pool's write failure")
				}
				set.getDisks = getDisks
				if got, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); err != nil || got.ETag != oi.ETag {
					t.Errorf("after the failed delete the object reads ETag %q, %v; want the latest write %q", got.ETag, err, oi.ETag)
				}
			})
		}
	}
}

// consistencyBulkDeleteFaultDisk fails the multi-object deletes of one object.
type consistencyBulkDeleteFaultDisk struct {
	StorageAPI
	bucket, object string
}

func (d consistencyBulkDeleteFaultDisk) DeleteVersions(ctx context.Context, volume string, versions []FileInfoVersions, opts DeleteOptions) []error {
	errs := make([]error, len(versions))
	var rest []FileInfoVersions
	var restIdx []int
	for i, v := range versions {
		if volume == d.bucket && v.Name == d.object {
			errs[i] = errDiskFull
			continue
		}
		rest = append(rest, v)
		restIdx = append(restIdx, i)
	}
	if len(rest) > 0 {
		for i, err := range d.StorageAPI.DeleteVersions(ctx, volume, rest, opts) {
			errs[restIdx[i]] = err
		}
	}
	return errs
}

// A multi-object delete must not report an object or version as deleted while
// a pool that failed to delete it still holds a copy.
func TestPoolsDeleteObjectsReportsOtherPoolFailure(t *testing.T) {
	for _, versioned := range []bool{false, true} {
		t.Run(fmt.Sprintf("versioned=%v", versioned), func(t *testing.T) {
			z, bucket := consistencyPools(t)
			const object = "bulk-delete-failure"
			opts := ObjectOptions{Versioned: versioned}
			oi := putConsistencyObject(t, z, bucket, object, 0, "latest", opts)
			if versioned {
				// The copy a data movement leaves until it removes the source.
				putConsistencyObject(t, z, bucket, object, 1, "latest", ObjectOptions{Versioned: true, VersionID: oi.VersionID, MTime: oi.ModTime})
			} else {
				putConsistencyObject(t, z, bucket, object, 1, "older", ObjectOptions{MTime: time.Now().Add(-time.Hour)})
			}
			set := z.serverPools[1].getHashedSet(object)
			getDisks := set.getDisks
			faulty := append([]StorageAPI(nil), getDisks()...)
			for i := range faulty {
				faulty[i] = consistencyBulkDeleteFaultDisk{StorageAPI: faulty[i], bucket: bucket, object: object}
			}
			set.getDisks = func() []StorageAPI { return faulty }
			defer func() { set.getDisks = getDisks }()
			_, errs := z.DeleteObjects(t.Context(), bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: object, VersionID: oi.VersionID}}}, opts)
			if errs[0] == nil {
				t.Error("multi-object delete reported success despite the other pool's write failure")
			}
		})
	}
}

// Pools delete a multi-object batch in parallel. With half the drives of the
// older copy's set offline, an EC 8+8 copy stays readable but cannot be
// deleted: the batch must fail the object and keep its latest copy, instead of
// deleting it and serving the older write once the drives are back.
func TestPoolsDeleteObjectsKeepsLatestWithoutDeleteQuorum(t *testing.T) {
	for latest := range 2 {
		t.Run(fmt.Sprintf("latest=%d", latest), func(t *testing.T) {
			z, bucket := consistencyPools(t)
			const object = "bulk-delete-quorum"
			older := 1 - latest
			putConsistencyObject(t, z, bucket, object, older, "older", ObjectOptions{MaxParity: true, MTime: time.Now().Add(-time.Hour)})
			oi := putConsistencyObject(t, z, bucket, object, latest, "latest", ObjectOptions{MaxParity: true})
			set := z.serverPools[older].getHashedSet(object)
			getDisks := set.getDisks
			disks := append([]StorageAPI(nil), getDisks()...)
			for i := range len(disks) / 2 {
				disks[i] = nil
			}
			set.getDisks = func() []StorageAPI { return disks }
			defer func() { set.getDisks = getDisks }()
			_, errs := z.DeleteObjects(t.Context(), bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: object}}}, ObjectOptions{})
			if !errors.As(errs[0], &InsufficientWriteQuorum{}) {
				t.Errorf("multi-object delete: got %v, want InsufficientWriteQuorum", errs[0])
			}
			set.getDisks = getDisks
			if got, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); err != nil || got.ETag != oi.ETag {
				t.Errorf("after the failed delete the object reads ETag %q, %v; want the latest write %q", got.ETag, err, oi.ETag)
			}
			// Nothing was deleted, so the retry removes every copy.
			if _, errs = z.DeleteObjects(t.Context(), bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: object}}}, ObjectOptions{}); errs[0] != nil {
				t.Fatal(errs[0])
			}
			for i, pool := range z.serverPools {
				if _, err := pool.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); !isErrObjectNotFound(err) {
					t.Errorf("pool %d retained the object after the retry: %v", i, err)
				}
			}
		})
	}
}

// A delete marker hides the object in every pool. When the versions of an
// object are in two pools and the set of one of them cannot take a write, the
// marker goes to the other pool instead of failing the delete. The versions
// stay below the marker.
func TestPoolsDeleteMarkerSkipsSetWithoutQuorum(t *testing.T) {
	for _, tc := range []struct {
		name     string
		degraded int // pool whose set loses drives
		offline  int
	}{
		{"older version readable", 0, 8},
		{"older version unreadable", 0, 9},
		{"latest version readable", 1, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z, bucket := consistencyPools(t)
			const object = "marker-quorum"
			v1 := putConsistencyObject(t, z, bucket, object, 0, "v1", ObjectOptions{Versioned: true, MaxParity: true, MTime: time.Now().Add(-time.Hour)})
			v2 := putConsistencyObject(t, z, bucket, object, 1, "v2", ObjectOptions{Versioned: true, MaxParity: true})
			set := z.serverPools[tc.degraded].getHashedSet(object)
			getDisks := set.getDisks
			disks := append([]StorageAPI(nil), getDisks()...)
			for i := range tc.offline {
				disks[i] = nil
			}
			set.getDisks = func() []StorageAPI { return disks }
			defer func() { set.getDisks = getDisks }()
			if _, err := z.DeleteObject(t.Context(), bucket, object, ObjectOptions{Versioned: true}); err != nil {
				t.Fatalf("delete with the set of pool %d without quorum: %v", tc.degraded, err)
			}
			set.getDisks = getDisks
			if _, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); !isErrObjectNotFound(err) && !isErrMethodNotAllowed(err) {
				t.Errorf("object still readable after the delete: %v", err)
			}
			for pool, v := range []ObjectInfo{v1, v2} {
				if _, err := z.serverPools[pool].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: v.VersionID}); err != nil {
					t.Errorf("pool %d lost version %s: %v", pool, v.VersionID, err)
				}
			}
		})
	}
}
