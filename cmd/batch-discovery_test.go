// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

type batchDiscoveryLayer struct {
	ObjectLayer
	walk func(context.Context, chan<- itemOrErr[ObjectInfo]) error
	read func(context.Context, string) ([]byte, error)
}

func (a batchDiscoveryLayer) Walk(ctx context.Context, _, _ string, results chan<- itemOrErr[ObjectInfo], _ WalkOptions) error {
	return a.walk(ctx, results)
}

func (a batchDiscoveryLayer) GetObjectNInfo(ctx context.Context, _, object string, _ *HTTPRangeSpec, _ http.Header, opts ObjectOptions) (*GetObjectReader, error) {
	data, err := a.read(ctx, object)
	if err != nil {
		return nil, err
	}
	return NewGetObjectReaderFromReader(bytes.NewReader(data), ObjectInfo{Name: object}, opts)
}

// A partially successful startup scan must retry the missing work without
// re-admitting work that finished while the scan was waiting to retry.
func TestBatchDiscoveryRecoversInProcess(t *testing.T) {
	for _, failure := range []string{"walk-start", "walk-stream", "manifest-read"} {
		t.Run(failure, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				pool := &BatchJobPool{ctx: ctx, jobCh: make(chan *BatchJobRequest, 10)}
				attempts := 0
				pool.objLayer = batchDiscoveryLayer{
					walk: func(_ context.Context, results chan<- itemOrErr[ObjectInfo]) error {
						attempts++
						if attempts == 1 && failure == "walk-start" {
							return errErasureReadQuorum
						}
						defer close(results)
						results <- itemOrErr[ObjectInfo]{Item: ObjectInfo{Name: "finished"}}
						if attempts == 1 && failure == "walk-stream" {
							results <- itemOrErr[ObjectInfo]{Err: errErasureReadQuorum}
						} else {
							results <- itemOrErr[ObjectInfo]{Item: ObjectInfo{Name: "pending"}}
						}
						return nil
					},
					read: func(_ context.Context, name string) ([]byte, error) {
						if attempts == 1 && failure == "manifest-read" && name == "pending" {
							return nil, errErasureReadQuorum
						}
						job := BatchJobRequest{ID: name}
						return job.MarshalMsg(nil)
					},
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					pool.resume(func() time.Duration { return 0 })
				}()
				synctest.Wait()
				if failure != "walk-start" {
					select {
					case job := <-pool.jobCh:
						if job.ID != "finished" || !pool.beginJob(job) {
							t.Fatal("first scan did not admit the healthy manifest")
						}
						pool.finishJob(job, nil)
					default:
						t.Fatal("first scan lost the healthy manifest")
					}
				}
				select {
				case <-done:
				case <-time.After(20 * time.Minute):
					t.Fatal("discovery failed to finish after storage recovered")
				}
				if attempts != 2 {
					t.Fatalf("discovery attempts = %d, want 2", attempts)
				}
				want := 1
				if failure == "walk-start" {
					want = 2
				}
				if len(pool.jobCh) != want {
					t.Fatalf("queued %d jobs, want %d; completed work was re-admitted or pending work was lost", len(pool.jobCh), want)
				}
				for len(pool.jobCh) > 0 {
					job := <-pool.jobCh
					if failure != "walk-start" && job.ID != "pending" {
						t.Fatalf("re-admitted %q", job.ID)
					}
					if !pool.beginJob(job) {
						t.Fatal("recovered job has no owner")
					}
					pool.finishJob(job, nil)
				}
			})
		})
	}
}

func TestBatchDiscoverySkipsUnusableManifests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := &BatchJobPool{ctx: t.Context(), jobCh: make(chan *BatchJobRequest, 1)}
		attempts := 0
		pool.objLayer = batchDiscoveryLayer{
			walk: func(_ context.Context, results chan<- itemOrErr[ObjectInfo]) error {
				attempts++
				defer close(results)
				for _, name := range []string{"canceled", "deleted", "malformed", "future", "empty-id"} {
					results <- itemOrErr[ObjectInfo]{Item: ObjectInfo{Name: name}}
				}
				return nil
			},
			read: func(_ context.Context, name string) ([]byte, error) {
				switch name {
				case "deleted":
					return nil, errConfigNotFound
				case "malformed":
					return []byte("bad manifest"), nil
				case "future":
					return []byte("SILO-BATCH-V999\n"), nil
				case "empty-id":
					return (&BatchJobRequest{}).MarshalMsg(nil)
				}
				// The administrator cancels after Walk, during manifest load.
				mustIAM(t, pool.canceler(name, true))
				job := BatchJobRequest{ID: name}
				return job.MarshalMsg(nil)
			},
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			pool.resume(func() time.Duration { return 0 })
		}()
		select {
		case <-done:
		case <-time.After(time.Hour):
			t.Fatal("unusable manifests kept discovery retrying")
		}
		if len(pool.jobCh) != 0 || attempts != 1 {
			t.Fatalf("canceled work was queued or retried: queue=%d scans=%d", len(pool.jobCh), attempts)
		}
	})
}

func TestBatchDiscoveryShutdownDuringBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		attempts := 0
		pool := &BatchJobPool{ctx: ctx, objLayer: batchDiscoveryLayer{
			walk: func(context.Context, chan<- itemOrErr[ObjectInfo]) error {
				attempts++
				return errErasureReadQuorum
			},
		}}
		done := make(chan struct{})
		go func() {
			defer close(done)
			pool.resume(func() time.Duration { return 0 })
		}()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("discovery abandoned a transient startup error")
		default:
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("discovery did not stop on shutdown")
		}
		if attempts != 1 {
			t.Fatalf("discovery scanned after shutdown: %d", attempts)
		}
	})
}

func TestBatchDiscoveryKeepsNewlyFinishedJobsTerminal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := &BatchJobPool{ctx: t.Context(), jobCh: make(chan *BatchJobRequest, 1)}
		attempts := 0
		pool.objLayer = batchDiscoveryLayer{
			walk: func(_ context.Context, results chan<- itemOrErr[ObjectInfo]) error {
				attempts++
				if attempts == 1 {
					// This job was submitted and failed while startup discovery
					// had not yet read any manifests. The retry must not rerun it.
					job := &BatchJobRequest{ID: "new-job"}
					mustIAM(t, pool.queueJob(job))
					if !pool.beginJob(<-pool.jobCh) {
						t.Fatal("submitted job has no owner")
					}
					pool.finishJob(job, errErasureWriteQuorum)
					return errErasureReadQuorum
				}
				defer close(results)
				results <- itemOrErr[ObjectInfo]{Item: ObjectInfo{Name: "new-job"}}
				return nil
			},
			read: func(_ context.Context, name string) ([]byte, error) {
				return (&BatchJobRequest{ID: name}).MarshalMsg(nil)
			},
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			pool.resume(func() time.Duration { return 0 })
		}()
		select {
		case <-done:
		case <-time.After(time.Hour):
			t.Fatal("discovery did not recover")
		}
		if attempts != 2 || len(pool.jobCh) != 0 {
			t.Fatalf("discovery re-admitted a failed job: scans=%d queue=%d", attempts, len(pool.jobCh))
		}
		if owner := pool.jobOwners["new-job"]; owner.state != "terminal" || owner.req != nil || owner.cancel != nil {
			t.Fatalf("terminal marker lost or retained the job payload: %+v", owner)
		}
	})
}
