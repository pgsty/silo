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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
	xhttp "github.com/minio/minio/internal/http"
)

// An explicit-version read uses ReadVersion. Only the added lifecycle scan
// uses ReadXL, so its errors/absence can be injected without failing the read.
type lifecycleReadDisk struct {
	StorageAPI
	bucket, object string
	scans          *atomic.Int64
	err            error
}

func (d lifecycleReadDisk) ReadXL(ctx context.Context, bucket, object string, data bool) (RawFileInfo, error) {
	if bucket == d.bucket && object == d.object {
		d.scans.Add(1)
		if d.err != nil {
			return RawFileInfo{}, d.err
		}
	}
	return d.StorageAPI.ReadXL(ctx, bucket, object, data)
}

func lifecycleReadDisks(t *testing.T, s *splitILM, object string, failedPool int, err error) *atomic.Int64 {
	t.Helper()
	var scans atomic.Int64
	for p, pool := range s.z.serverPools {
		pool.erasureDisksMu.Lock()
		previous := pool.erasureDisks
		wrapped := make([][]StorageAPI, len(previous))
		for i, disks := range previous {
			wrapped[i] = append([]StorageAPI(nil), disks...)
			for j, disk := range disks {
				var injected error
				if p == failedPool {
					injected = err
				}
				wrapped[i][j] = lifecycleReadDisk{StorageAPI: disk, bucket: s.bucket, object: object, scans: &scans, err: injected}
			}
		}
		pool.erasureDisks = wrapped
		pool.erasureDisksMu.Unlock()
		t.Cleanup(func() {
			pool.erasureDisksMu.Lock()
			pool.erasureDisks = previous
			pool.erasureDisksMu.Unlock()
		})
	}
	return &scans
}

// Real signed GET and HEAD requests use the author's two-pool storage fixture.
// Checking the queue as well as the response catches both false hiding and
// accidentally authorizing the latest version instead of the version read.
func TestPoolsLifecycleReadHTTP(t *testing.T) {
	const bothRules = `<Rule><ID>both</ID><Status>Enabled</Status><Filter><Prefix>both-</Prefix></Filter>` +
		`<Expiration><Days>1</Days></Expiration><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>`
	for _, state := range []versioning.State{versioning.Enabled, versioning.Suspended} {
		t.Run(string(state), func(t *testing.T) {
			s := newSplitILM(t, state, splitILMRules+bothRules)
			router := initTestAPIEndPoints(s.z, nil)
			for _, tc := range []struct {
				name, prefix string
				latestAge    float64
				readLatest   bool
				implicit     bool
				action       lifecycle.Action
				local        lifecycle.Action
				fault        error
				wantScan     bool
			}{
				{name: "old-version-new-latest", prefix: "exp-", latestAge: 0.01, local: lifecycle.DeleteAction, wantScan: true},
				{name: "old-version-expired-latest", prefix: "exp-", latestAge: 3, local: lifecycle.DeleteAction, wantScan: true},
				{name: "old-version-delete-all-latest", prefix: "eav-", latestAge: 3, local: lifecycle.DeleteAllVersionsAction, wantScan: true},
				{name: "expired-current", prefix: "exp-", latestAge: 3, readLatest: true, local: lifecycle.DeleteAction, action: lifecycle.DeleteAction, wantScan: true},
				{name: "expired-current-implicit", prefix: "exp-", latestAge: 3, readLatest: true, implicit: true, local: lifecycle.DeleteAction, action: lifecycle.DeleteAction, wantScan: true},
				{name: "expired-noncurrent", prefix: "both-", latestAge: 3, local: lifecycle.DeleteAction, action: lifecycle.DeleteVersionAction, wantScan: true},
				{name: "extra-read-quorum-error", prefix: "exp-", latestAge: 3, local: lifecycle.DeleteAction, fault: errDiskNotFound, wantScan: true},
				{name: "read-version-missing-from-recheck", prefix: "exp-", latestAge: 3, local: lifecycle.DeleteAction, fault: errFileNotFound, wantScan: true},
				{name: "local-none-global-expired", prefix: "ncv-", latestAge: 3, local: lifecycle.NoneAction},
			} {
				for _, null := range []bool{false, true} {
					for oldPool := range 2 {
						t.Run(fmt.Sprintf("%s/null=%t/old-pool=%d", tc.name, null, oldPool), func(t *testing.T) {
							key := fmt.Sprintf("%s%s-%t-%d", tc.prefix, tc.name, null, oldPool)
							old := splitAt("v1", 5, oldPool)
							old.null = null
							s.write(key, old)
							s.write(key, splitAt("v2", tc.latestAge, 1-oldPool))
							label := "v1"
							if tc.readLatest {
								label = "v2"
							}
							vid := s.ids[key+" "+label]
							if vid == "" {
								vid = nullVersionID
							}
							oi, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: vid, Versioned: state == versioning.Enabled, VersionSuspended: state == versioning.Suspended})
							if err != nil {
								t.Fatal(err)
							}
							lc, err := globalLifecycleSys.Get(s.bucket)
							if err != nil {
								t.Fatal(err)
							}
							if local := lc.Eval(oi.ToLifecycleOpts()); local.Action != tc.local {
								t.Fatalf("fixture local event=%v, want %v", local.Action, tc.local)
							}
							versions, events, err := s.z.lifecycleEventsAllPools(t.Context(), s.bucket, key)
							if err != nil {
								t.Fatal(err)
							}
							index := 1
							if tc.readLatest {
								index = 0
							}
							if tc.local == lifecycle.NoneAction && events[index].Action != lifecycle.DeleteVersionAction {
								t.Fatal("fixture must be globally expired but locally NoneAction")
							}
							scans := lifecycleReadDisks(t, s, key, oldPool, tc.fault)
							for _, method := range []string{http.MethodGet, http.MethodHead} {
								t.Run(method, func(t *testing.T) {
									scans.Store(0)
									requestID := vid
									if tc.implicit {
										requestID = ""
									}
									rec := consistencyRequest(t, router, method, s.bucket, key, requestID)
									want := http.StatusOK
									if tc.action.Delete() {
										want = http.StatusNotFound
									}
									if rec.Code != want {
										t.Errorf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
									}
									if want == http.StatusOK && method == http.MethodGet && rec.Body.String() != key+" "+label {
										t.Errorf("body=%q, want requested version %s", rec.Body.String(), label)
									}
									if !tc.implicit && (scans.Load() > 0) != tc.wantScan {
										t.Errorf("ReadXL calls=%d, want scan=%t", scans.Load(), tc.wantScan)
									}
									if tc.action.Delete() {
										select {
										case op := <-s.queue:
											task, ok := op.(expiryTask)
											src := lcEventSrc_s3GetObject
											if method == http.MethodHead {
												src = lcEventSrc_s3HeadObject
											}
											global := versions[index]
											if !ok || task.src != src || task.event != events[index] || task.event.Action != tc.action ||
												task.objInfo.VersionID != global.VersionID || task.objInfo.IsLatest != global.IsLatest ||
												task.objInfo.NumVersions != global.NumVersions || !task.objInfo.SuccessorModTime.Equal(global.SuccessorModTime) {
												t.Errorf("wrong queued expiry: %+v; want %s with global event %+v", task, vid, events[index])
											}
										default:
											t.Error("missing expiry task")
										}
									}
									if n := len(s.queue); n != 0 {
										t.Errorf("unexpected expiry tasks: %d", n)
										for len(s.queue) > 0 {
											<-s.queue
										}
									}
								})
							}
						})
					}
				}
			}
		})
	}
}

func TestPoolsLifecycleReadAuthorizationAndClose(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	initConfigSubsystem(t.Context(), s.z)
	globalIAMSys.Init(t.Context(), s.z, globalEtcdClient, 2*time.Second)
	denied := newObjectAttributesAuthzUser(t, "lifecycle-read", s.bucket, `"s3:PutObject"`)
	router := initTestAPIEndPoints(s.z, nil)
	for _, expire := range []bool{false, true} {
		key := fmt.Sprintf("exp-reader-%t", expire)
		v := splitAt("v1", 5, 0)
		v.size = 1 << 20 // a non-inline reader retains the object read lock
		s.write(key, v)
		if !expire {
			s.write(key, splitAt("v2", 0.01, 1))
		}
		vid := s.ids[key+" v1"]
		oi, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: vid, Versioned: true})
		if err != nil || oi.Inlined {
			t.Fatalf("fixture must retain a reader lock: inlined=%t err=%v", oi.Inlined, err)
		}
		scans := lifecycleReadDisks(t, s, key, -1, nil)
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			req, err := newTestSignedRequestV4(method, getGetObjectURL("", s.bucket, key)+"?versionId="+vid, 0, nil, denied.AccessKey, denied.SecretKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || scans.Load() != 0 || len(s.queue) != 0 {
				t.Fatalf("denied %s: status=%d scans=%d queued=%d", method, rec.Code, scans.Load(), len(s.queue))
			}
		}
		rec := consistencyRequest(t, router, http.MethodGet, s.bucket, key, vid)
		want := http.StatusOK
		if expire {
			want = http.StatusNotFound
		}
		if rec.Code != want {
			t.Errorf("authorized GET status=%d want=%d", rec.Code, want)
		}
		// The reader owns the multi-pool read lock until Close, including the
		// early 404 path. A writer must acquire it immediately after the handler.
		lk := s.z.NewNSLock(s.bucket, key)
		lkctx, err := lk.GetLock(t.Context(), newDynamicTimeout(time.Second, time.Second))
		if err != nil {
			t.Fatalf("GET leaked its reader/lock: %v", err)
		}
		lk.Unlock(lkctx)
		for len(s.queue) > 0 {
			<-s.queue
		}
	}
}

func TestPoolsLifecycleReadBoundaries(t *testing.T) {
	const transitionRules = `<Rule><ID>transition</ID><Status>Enabled</Status><Filter><Prefix>transition-</Prefix></Filter>` +
		`<Transition><Days>1</Days><StorageClass>WARM</StorageClass></Transition></Rule>`
	for _, tc := range []struct {
		name       string
		state      versioning.State
		null       bool
		singlePool bool
		restored   bool
		transition bool
		action     lifecycle.Action
		wantScan   bool
	}{
		{name: "single-pool", state: versioning.Enabled, singlePool: true, action: lifecycle.DeleteAction},
		{name: "single-pool-null", state: versioning.Enabled, singlePool: true, null: true, action: lifecycle.DeleteAction},
		{name: "unversioned", null: true, action: lifecycle.DeleteAction},
		{name: "current-null-enabled", state: versioning.Enabled, null: true, action: lifecycle.DeleteAction, wantScan: true},
		{name: "current-null-suspended", state: versioning.Suspended, null: true, action: lifecycle.DeleteAction, wantScan: true},
		{name: "transition", state: versioning.Enabled, transition: true, action: lifecycle.TransitionAction},
		{name: "restored", state: versioning.Enabled, restored: true, action: lifecycle.DeleteRestoredAction},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSplitILM(t, tc.state, splitILMRules+transitionRules)
			key := "exp-" + tc.name
			if tc.restored || tc.transition {
				key = "transition-" + tc.name
			}
			v := splitAt("v1", 5, 0)
			v.null, v.tiered = tc.null, tc.restored
			s.write(key, v)
			vid := s.ids[key+" v1"]
			if vid == "" {
				vid = nullVersionID
			}
			if tc.restored {
				globalTierConfigMgr.drivercache["WARM"] = &tierExpiryTestBackend{objects: map[string][]byte{"remote-v1": []byte(key + " v1")}}
				opts := ObjectOptions{VersionID: vid, Versioned: true}
				opts.EvalMetadataFn = func(oi *ObjectInfo, _ error) (ReplicateDecision, error) {
					oi.UserDefined[xhttp.AmzRestore] = completedRestoreObj(UTCNow().Add(-time.Hour)).String()
					return ReplicateDecision{}, nil
				}
				if _, err := s.z.PutObjectMetadata(t.Context(), s.bucket, key, opts); err != nil {
					t.Fatal(err)
				}
			}
			z := s.z
			if tc.singlePool {
				// Exercise the single-pool dispatch with the same storage fixture.
				z = &erasureServerPools{serverPools: s.z.serverPools[:1]}
			}
			router := initTestAPIEndPoints(z, []string{"GetObject", "HeadObject"})
			scans := lifecycleReadDisks(t, s, key, -1, nil)
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				scans.Store(0)
				rec := consistencyRequest(t, router, method, s.bucket, key, vid)
				want := http.StatusOK
				if tc.action.Delete() && !tc.action.DeleteRestored() {
					want = http.StatusNotFound
				}
				if rec.Code != want || (scans.Load() > 0) != tc.wantScan {
					t.Errorf("%s status=%d want=%d scans=%d wantScan=%t body=%s", method, rec.Code, want, scans.Load(), tc.wantScan, rec.Body.String())
				}
				if want == http.StatusOK && method == http.MethodGet && rec.Body.String() != key+" v1" {
					t.Errorf("%s lost object contents: %q", method, rec.Body.String())
				}
				if tc.action.Delete() {
					select {
					case op := <-s.queue:
						task, ok := op.(expiryTask)
						if !ok || task.event.Action != tc.action || s.key(key, task.objInfo.VersionID) != s.key(key, vid) {
							t.Errorf("%s wrong expiry: %+v", method, task)
						}
					default:
						t.Errorf("%s missing expiry", method)
					}
				}
				if n := len(s.queue); n != 0 {
					t.Fatalf("%s queued %d unexpected expiries", method, n)
				}
			}
		})
	}
}

func TestPoolsLifecycleReadProxy(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	const key, body = "exp-proxied", "remote object remains readable"
	vid := mustGetUUID()
	target := newILMTestTarget(t)
	var remoteRequests atomic.Int64
	registerILMTestTarget(t, s.z, s.bucket, target, func(w http.ResponseWriter, r *http.Request) {
		remoteRequests.Add(1)
		w.Header().Set(xhttp.ContentLength, fmt.Sprint(len(body)))
		w.Header().Set(xhttp.LastModified, UTCNow().Add(-5*24*time.Hour).Format(http.TimeFormat))
		w.Header().Set(xhttp.ETag, `"da39a3ee5e6b4b0d3255bfef95601890"`)
		w.Header().Set(xhttp.AmzVersionID, vid)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(body))
		}
	})
	setILMTestReplicationConfig(t, s.bucket, target.arn, target.bucket)
	// The delete-only target fixture omits credentials; proxy discovery clones
	// the target descriptor and requires its credentials field to be present.
	globalBucketTargetSys.Lock()
	globalBucketTargetSys.targetsMap[s.bucket][0].Credentials = &madmin.Credentials{AccessKey: "proxy-test"}
	globalBucketTargetSys.Unlock()
	stats := NewReplicationStats(t.Context(), nil)
	previous := globalReplicationStats.Swap(stats)
	t.Cleanup(func() { globalReplicationStats.Store(previous) })
	scans := lifecycleReadDisks(t, s, key, -1, nil)
	router := initTestAPIEndPoints(s.z, nil)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		before := remoteRequests.Load()
		rec := consistencyRequest(t, router, method, s.bucket, key, vid)
		if rec.Code != http.StatusOK || remoteRequests.Load() == before || scans.Load() != 0 || len(s.queue) != 0 {
			t.Errorf("proxy %s: status=%d remote=%d scans=%d queued=%d body=%s", method, rec.Code, remoteRequests.Load()-before, scans.Load(), len(s.queue), rec.Body.String())
		}
		if method == http.MethodGet && rec.Body.String() != body {
			t.Errorf("proxy body=%q", rec.Body.String())
		}
	}
}
