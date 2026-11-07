// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	polplugin "github.com/minio/minio/internal/config/policy/plugin"
	xnet "github.com/pgsty/silo-pkg/v3/net"
	"github.com/pgsty/silo-pkg/v3/policy"
	"github.com/tinylib/msgp/msgp"
)

func waitBatchState(t *testing.T, pool *BatchJobPool, id, state string) {
	t.Helper()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		pool.jmu.Lock()
		owner := pool.jobOwners[id]
		ready := owner == nil && state == ""
		if owner != nil {
			ready = owner.state == state
		}
		pool.jmu.Unlock()
		if ready {
			return
		}
		select {
		case <-timeout.C:
			t.Fatalf("job did not reach %q", state)
		case <-tick.C:
		}
	}
}

func TestBatchPluginPauseRecoversInProcess(t *testing.T) {
	for _, midrun := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-start", true: "during-delete"}[midrun], func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			older := f.putVersions(t, "data/key")
			var unavailable atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Input policy.Args `json:"input"`
				}
				_ = json.NewDecoder(r.Body).Decode(&request)
				if unavailable.Load() && (!midrun || request.Input.Action == policy.DeleteObjectVersionAction) {
					w.WriteHeader(503)
					io.WriteString(w, `{"result":true}`)
					return
				}
				io.WriteString(w, `{"result":true}`)
			}))
			defer server.Close()
			url, err := xnet.ParseHTTPURL(server.URL)
			mustIAM(t, err)
			previous := newGlobalAuthZPluginFn()
			setGlobalAuthZPlugin(polplugin.New(polplugin.Args{URL: url, CloseRespFn: func(r io.ReadCloser) { r.Close() }}))
			defer setGlobalAuthZPlugin(previous)
			rec, job := f.submit(t, globalActiveCred, f.expireYAML("data/"))
			if job == nil {
				t.Fatalf("submit %d: %s", rec.Code, rec.Body.String())
			}
			pool := globalBatchJobPool
			ctx, cancel := context.WithCancel(f.ctx)
			pool.ctx = ctx
			// Re-admit the fixture's consumed request with a context owned by this worker.
			pool.jmu.Lock()
			pool.jobOwners[job.ID].cancel()
			delete(pool.jobOwners, job.ID)
			pool.jmu.Unlock()
			mustIAM(t, pool.queueJob(job))
			unavailable.Store(true)
			done := make(chan struct{})
			go func() { defer close(done); pool.AddWorker() }()
			defer func() { cancel(); <-done }()
			waitBatchState(t, pool, job.ID, "paused")
			ri := f.jobInfo(t, job)
			if ri.Failed || ri.Complete || ri.FailureReason != "" || ri.PausedReason == "" || ri.Object != "" {
				t.Fatalf("paused report: %+v", ri)
			}
			if !f.versionExists(t, "data/key", older) {
				t.Fatal("outage authorized a deletion")
			}
			unavailable.Store(false)
			pool.retryDue(time.Now().Add(time.Hour))
			waitBatchState(t, pool, job.ID, "terminal")
			ri = f.jobInfo(t, job)
			if !ri.Complete || ri.Failed || ri.PausedReason != "" || ri.Objects != 1 || f.versionExists(t, "data/key", older) {
				t.Fatalf("resumed report: %+v", ri)
			}
		})
	}
}

func TestBatchSubmissionUnavailableIs503(t *testing.T) {
	f := newBatchAuthzFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503); io.WriteString(w, `{"result":true}`) }))
	defer server.Close()
	url, err := xnet.ParseHTTPURL(server.URL)
	mustIAM(t, err)
	previous := newGlobalAuthZPluginFn()
	setGlobalAuthZPlugin(polplugin.New(polplugin.Args{URL: url, CloseRespFn: func(r io.ReadCloser) { r.Close() }}))
	defer setGlobalAuthZPlugin(previous)
	rec, job := f.submit(t, globalActiveCred, f.expireYAML("data/"))
	if rec.Code != 503 || job != nil {
		t.Fatalf("outage submission: %d %s", rec.Code, rec.Body.String())
	}
}

func TestBatchPoolOwnershipAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pool := &BatchJobPool{ctx: ctx, jobCh: make(chan *BatchJobRequest, 1)}
	first, second := &BatchJobRequest{ID: "first"}, &BatchJobRequest{ID: "second"}
	mustIAM(t, pool.queueJob(first))
	mustIAM(t, pool.queueJob(second))
	if pool.jobOwners[second.ID].state != "paused" {
		t.Fatal("full queue lost pending owner")
	}
	original := second.ctx
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := pool.queueJob(&BatchJobRequest{ID: "second"}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if second.ctx != original || len(pool.jobCh) != 1 {
		t.Fatal("duplicate changed ownership")
	}
	if !pool.beginJob(<-pool.jobCh) {
		t.Fatal("first not owned")
	}
	pool.finishJob(first, nil)
	mustIAM(t, pool.queueJob(&BatchJobRequest{ID: first.ID}))
	if len(pool.jobCh) != 0 {
		t.Fatal("late discovery re-admitted a terminal job")
	}
	pool.retryDue(time.Now())
	next := <-pool.jobCh
	if next != second || !pool.beginJob(next) {
		t.Fatal("pending handoff lost ownership")
	}
	for range 2 {
		pool.finishJob(second, batchUnavailable("test", errors.New("outage")))
		pool.retryDue(time.Now().Add(time.Hour))
		if !pool.beginJob(<-pool.jobCh) {
			t.Fatal("retry lost owner")
		}
	}
	if pool.jobOwners[second.ID].retries != 2 {
		t.Fatal("retry count reset during handoff")
	}
	mustIAM(t, pool.canceler(second.ID, true))
	mustIAM(t, pool.canceler(second.ID, true))
	pool.finishJob(second, batchUnavailable("late", errors.New("outage")))
	pool.retryDue(time.Now().Add(time.Hour))
	if len(pool.jobCh) != 0 || second.ctx.Err() == nil {
		t.Fatal("cancel lost to retry")
	}
	if err := pool.queueJob(&BatchJobRequest{ID: second.ID}); !errors.Is(err, context.Canceled) {
		t.Fatalf("stale admission: %v", err)
	}
	// A cancellation before this node admitted a manifest is a tombstone too.
	mustIAM(t, pool.canceler("not-loaded", true))
	mustIAM(t, pool.canceler("not-loaded", true))
	if err := pool.queueJob(&BatchJobRequest{ID: "not-loaded"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("stale resume: %v", err)
	}
	cancel()
	if err := pool.queueJob(&BatchJobRequest{ID: "shutdown"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown admission: %v", err)
	}
	pool.retryDue(time.Now().Add(time.Hour)) // channel remains open; no send/close race.
}

// A cancellation of a job this node does not own leaves a record only while
// startup discovery may still admit its manifest. Once discovery has
// finished, canceling unknown IDs must not grow the ownership table.
func TestBatchCancelUnknownJobAfterDiscovery(t *testing.T) {
	pool := &BatchJobPool{ctx: t.Context(), jobCh: make(chan *BatchJobRequest, 1)}
	// Before discovery finished, the record fences the manifest it may admit.
	mustIAM(t, pool.canceler("expire-before-discovery", true))
	if err := pool.queueJob(&BatchJobRequest{ID: "expire-before-discovery"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("admission of a job canceled during discovery: %v", err)
	}
	pool.finishDiscovery()
	for i := range 1000 {
		mustIAM(t, pool.canceler(fmt.Sprintf("expire-unknown-%d", i), true))
	}
	pool.jmu.Lock()
	owners := len(pool.jobOwners)
	pool.jmu.Unlock()
	if owners != 1 {
		t.Fatalf("%d owner records after canceling unknown jobs, want only the record from discovery", owners)
	}
	// An owned job is still canceled and fenced.
	job := &BatchJobRequest{ID: "expire-owned"}
	mustIAM(t, pool.queueJob(job))
	mustIAM(t, pool.canceler(job.ID, true))
	if job.ctx.Err() == nil {
		t.Fatal("cancellation did not stop the owned job")
	}
	if err := pool.queueJob(&BatchJobRequest{ID: job.ID}); !errors.Is(err, context.Canceled) {
		t.Fatalf("stale admission of a canceled job: %v", err)
	}
}

type batchPolicyOutage struct {
	IAMStorageAPI
	failed string
	err    error
}

func (s *batchPolicyOutage) loadPolicyDoc(ctx context.Context, name string, out map[string]PolicyDoc) error {
	if name == s.failed {
		return s.err
	}
	return s.IAMStorageAPI.loadPolicyDoc(ctx, name, out)
}

func TestBatchPolicySnapshotKeepsUnavailableDeny(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "retry-allow", batchAuthzFullAccess)
	batchAuthzPolicy(f.ctx, t, f.sys, "retry-deny", `{"Effect":"Deny","Action":["s3:DeleteObjectVersion"],"Resource":["arn:aws:s3:::batch-authz/*"]}`)
	cred := iamAdminUser(f.ctx, t, f.sys, "retry-user", "retry-allow,retry-deny")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	store := f.sys.store
	original := store.IAMStorageAPI
	defer func() { store.IAMStorageAPI = original }()
	cache := store.lock()
	delete(cache.iamPolicyDocsMap, "retry-deny")
	store.unlock()
	store.IAMStorageAPI = &batchPolicyOutage{IAMStorageAPI: original, failed: "retry-deny", err: errErasureReadQuorum}
	request := batchAuthzRequest{action: policy.DeleteObjectVersionAction, bucket: f.bucket, object: "key", versionID: mustGetUUID()}
	if err := sub.authorize(f.ctx, request); !isBatchJobUnavailable(err) {
		t.Fatalf("missing Deny must pause, got %v", err)
	}
	store.IAMStorageAPI = original
	if err := sub.authorize(f.ctx, request); !isBatchJobAuthzError(err) {
		t.Fatalf("recovered Deny was not enforced: %v", err)
	}
	// Root also waits for IAM readiness; startup must not bypass the pause gate.
	root, err := newBatchJobSubmitter(globalActiveCred)
	mustIAM(t, err)
	f.sys.Lock()
	f.sys.store = nil
	f.sys.Unlock()
	_, err = root.principal(f.ctx)
	f.sys.Lock()
	f.sys.store = store
	f.sys.Unlock()
	if !isBatchJobUnavailable(err) {
		t.Fatalf("root before IAM readiness: %v", err)
	}
}

func TestBatchPausedReportCompatibility(t *testing.T) {
	before := &batchJobInfo{JobID: "paused", Object: "cursor", PausedReason: "IAM unavailable"}
	data, err := before.MarshalMsg(nil)
	mustIAM(t, err)
	var after batchJobInfo
	_, err = after.UnmarshalMsg(data)
	mustIAM(t, err)
	if after.PausedReason != before.PausedReason || after.clone().PausedReason != before.PausedReason || after.statusMetric().PausedReason != before.PausedReason {
		t.Fatal("paused reason lost")
	}
	old := msgp.AppendMapHeader(nil, 2)
	old = msgp.AppendString(old, "jid")
	old = msgp.AppendString(old, "legacy")
	old = msgp.AppendString(old, "cmp")
	old = msgp.AppendBool(old, true)
	var legacy batchJobInfo
	_, err = legacy.UnmarshalMsg(old)
	mustIAM(t, err)
	if legacy.PausedReason != "" || !legacy.Complete {
		t.Fatal("old report decode changed")
	}
	after.refuse(errBatchJobInvalid)
	if after.PausedReason != "" || !after.Failed {
		t.Fatal("terminal denial retained pause")
	}
}

func TestBatchPersistenceFencesOlderExecutors(t *testing.T) {
	f := newBatchAuthzFixture(t)
	rec, job := f.submit(t, globalActiveCred, f.expireYAML("data/"))
	if job == nil {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
	}
	raw, err := readConfig(f.ctx, f.obj, getJobPath(*job))
	mustIAM(t, err)
	if !bytes.HasPrefix(raw, []byte(batchJobEnvelope)) {
		t.Fatal("new manifest has no executor version fence")
	}
	var oldDecoder BatchJobRequest
	if _, err := oldDecoder.UnmarshalMsg(raw); err == nil {
		t.Fatal("old bare-msgpack executor could decode new manifest")
	}
	var loaded BatchJobRequest
	mustIAM(t, loaded.load(f.ctx, f.obj, getJobPath(*job)))
	if loaded.Submitter == nil {
		t.Fatal("new executor lost submitter")
	}
	ri := &batchJobInfo{JobID: job.ID, JobType: string(job.Type()), StartTime: job.Started}
	outage := batchUnavailable("test", errErasureReadQuorum)
	if err := ri.savePaused(f.ctx, f.obj, *job, outage); !errors.Is(err, outage) {
		t.Fatal(err)
	}
	reportPath, err := job.getJobReportPath()
	mustIAM(t, err)
	report, err := readConfig(f.ctx, f.obj, reportPath)
	mustIAM(t, err)
	if binary.LittleEndian.Uint16(report[2:4]) == batchExpireVersionV1 {
		t.Fatal("old executor would accept paused report")
	}
	mustIAM(t, ri.load(f.ctx, f.obj, *job))
	if ri.PausedReason == "" || ri.Failed {
		t.Fatal("restart lost pause")
	}
	// A stale resume loaded the manifest before cancellation.
	mustIAM(t, globalBatchJobPool.canceler(job.ID, true))
	mustIAM(t, job.delete(f.ctx, f.obj))
	if err := globalBatchJobPool.queueJob(&loaded); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled job re-admitted: %v", err)
	}
	if err := loaded.load(f.ctx, f.obj, getJobPath(*job)); !errors.Is(err, errNoSuchJob) {
		t.Fatalf("canceled manifest recreated: %v", err)
	}
}
