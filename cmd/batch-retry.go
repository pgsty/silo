// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// An unavailable dependency is not an authorization decision. It stops the
// current attempt without turning an outage into either an allow or a denial.
type batchJobUnavailableError struct {
	reason string
	err    error
}

func (e batchJobUnavailableError) Error() string { return fmt.Sprintf("%s: %v", e.reason, e.err) }
func (e batchJobUnavailableError) Unwrap() error { return e.err }
func batchUnavailable(reason string, err error) error {
	if err == nil {
		return nil
	}
	if isBatchJobUnavailable(err) {
		return err
	}
	return batchJobUnavailableError{reason: reason, err: err}
}

func isBatchJobUnavailable(err error) bool { var e batchJobUnavailableError; return errors.As(err, &e) }

func isBatchJobStopped(err error) bool {
	return isBatchJobAuthzError(err) || isBatchJobUnavailable(err)
}

func batchListingError(err error) error {
	if isErrBucketNotFound(err) {
		return err
	}
	return batchUnavailable("object listing unavailable", err)
}

func (ri *batchJobInfo) pause(err error) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	// A concurrent explicit denial wins over a transient worker error.
	if ri.FailureReason != "" {
		return
	}
	ri.Complete, ri.Failed = false, false
	ri.PausedReason = err.Error()
}

func (ri *batchJobInfo) savePaused(ctx context.Context, api ObjectLayer, job BatchJobRequest, err error) error {
	ri.pause(err)
	globalBatchJobsMetrics.save(job.ID, ri)
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if saveErr := ri.updateAfter(saveCtx, api, 0, job); saveErr != nil {
		return batchUnavailable("saving paused job", errors.Join(err, saveErr))
	}
	return err
}

// Authenticate the HTTP request normally, but keep dependency errors through
// the authorization step so submission returns 503, not a permanent 403.
func validateBatchJobAdminReq(ctx context.Context, w http.ResponseWriter, r *http.Request) (ObjectLayer, auth.Credentials) {
	api := newObjectLayerFn()
	if api == nil || globalNotificationSys == nil || !batchIAMReady() {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return nil, auth.Credentials{}
	}
	cred, owner, code := validateAdminSignature(ctx, r, "")
	if code != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(code), r.URL)
		return nil, cred
	}
	submitter, err := newBatchJobSubmitter(cred)
	if err == nil {
		var principal batchJobPrincipal
		principal, err = submitter.principal(ctx)
		if err == nil {
			err = principal.authorizeArgs(policy.Args{
				AccountName: cred.AccessKey, Groups: cred.Groups,
				Action: policy.Action(policy.StartBatchJobAction), ConditionValues: getConditionValues(r, "", cred), IsOwner: owner, Claims: principal.claims,
			}, nil)
		}
	}
	if err != nil {
		apiErr := errorCodes.ToAPIErrWithErr(ErrAccessDenied, err)
		if isBatchJobUnavailable(err) {
			apiErr = batchServiceUnavailable(err)
		}
		writeErrorResponseJSON(ctx, w, apiErr, r.URL)
		return nil, cred
	}
	return api, cred
}

// One owner record spans queued, running and paused attempts. The request
// pointer is the generation token. Canceled and terminal records are small
// tombstones until process shutdown, so a delayed discovery cannot requeue a
// job after its owner finished, including a terminal partial failure.
type batchJobOwner struct {
	req     *BatchJobRequest
	cancel  context.CancelFunc
	state   string
	retries uint
	due     time.Time
}

func (j *BatchJobPool) beginJob(job *BatchJobRequest) bool {
	j.jmu.Lock()
	defer j.jmu.Unlock()
	o := j.jobOwners[job.ID]
	if o == nil || o.req != job || o.state != "queued" || job.ctx.Err() != nil || j.ctx.Err() != nil {
		return false
	}
	o.state = "running"
	return true
}

func (j *BatchJobPool) finishJob(job *BatchJobRequest, err error) {
	j.jmu.Lock()
	defer j.jmu.Unlock()
	o := j.jobOwners[job.ID]
	if o == nil || o.req != job || o.state != "running" {
		return
	}
	if isBatchJobUnavailable(err) && job.ctx.Err() == nil && j.ctx.Err() == nil {
		o.due = time.Now().Add(batchJobRetryDelay(o.retries))
		o.retries++
		o.state = "paused"
		return
	}
	o.cancel()
	j.jobOwners[job.ID] = &batchJobOwner{state: "terminal"}
}

func batchJobRetryDelay(retries uint) time.Duration {
	delay := 30 * time.Second * time.Duration(1<<min(retries, 4))
	return delay/2 + time.Duration(rand.Float64()*float64(delay))
}

// retryDue holds the ownership lock across the nonblocking handoff. A fast
// worker cannot replace a pause while the scheduler removes the old pause.
func (j *BatchJobPool) retryDue(now time.Time) {
	j.jmu.Lock()
	defer j.jmu.Unlock()
	if j.ctx.Err() != nil {
		return
	}
	for _, o := range j.jobOwners {
		if o.state != "paused" || now.Before(o.due) || o.req.ctx.Err() != nil {
			continue
		}
		select {
		case j.jobCh <- o.req:
			o.state = "queued"
		default:
		}
	}
}

func (j *BatchJobPool) retryLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-j.ctx.Done():
			return
		case now := <-ticker.C:
			j.retryDue(now)
		}
	}
}

func batchServiceUnavailable(err error) APIError {
	return APIError{Code: "ServiceUnavailable", Description: err.Error(), HTTPStatusCode: http.StatusServiceUnavailable}
}

// initStore precedes the first successful cache load. During that interval a
// missing identity or policy is not a revocation decision, including for root.
func batchIAMReady() bool {
	sys := globalIAMSys
	if sys == nil {
		return false
	}
	sys.Lock()
	defer sys.Unlock()
	if sys.store == nil {
		return false
	}
	select {
	case <-sys.configLoaded:
		return true
	default:
		return false
	}
}
