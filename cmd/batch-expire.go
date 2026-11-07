// Copyright (c) 2015-2023 MinIO, Inc.
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/minio/internal/bucket/versioning"
	xhttp "github.com/minio/minio/internal/http"
	xioutil "github.com/minio/minio/internal/ioutil"
	"github.com/pgsty/silo-pkg/v3/env"
	"github.com/pgsty/silo-pkg/v3/policy"
	"github.com/pgsty/silo-pkg/v3/wildcard"
	"github.com/pgsty/silo-pkg/v3/workers"
	"github.com/pgsty/silo-pkg/v3/xtime"
	"go.yaml.in/yaml/v3"
)

// expire: # Expire objects that match a condition
//   apiVersion: v1
//   bucket: mybucket # Bucket where this batch job will expire matching objects from
//   prefix: myprefix # (Optional) Prefix under which this job will expire objects matching the rules below.
//   rules:
//     - type: object  # regular objects with zero or more older versions
//       name: NAME # match object names that satisfy the wildcard expression.
//       olderThan: 70h # match objects older than this value
//       createdBefore: "2006-01-02T15:04:05.00Z" # match objects created before "date"
//       tags:
//         - key: name
//           value: pick* # match objects with tag 'name', all values starting with 'pick'
//       metadata:
//         - key: content-type
//           value: image/* # match objects with 'content-type', all values starting with 'image/'
//       size:
//         lessThan: "10MiB" # match objects with size less than this value (e.g. 10MiB)
//         greaterThan: 1MiB # match objects with size greater than this value (e.g. 1MiB)
//       purge:
//           # retainVersions: 0 # (default) delete all versions of the object. This option is the fastest.
//           # retainVersions: 5 # keep the latest 5 versions of the object.
//
//     - type: deleted # objects with delete marker as their latest version
//       name: NAME # match object names that satisfy the wildcard expression.
//       olderThan: 10h # match objects older than this value (e.g. 7d10h31s)
//       createdBefore: "2006-01-02T15:04:05.00Z" # match objects created before "date"
//       purge:
//           # retainVersions: 0 # (default) delete all versions of the object. This option is the fastest.
//           # retainVersions: 5 # keep the latest 5 versions of the object including delete markers.
//
//   notify:
//     endpoint: https://notify.endpoint # notification endpoint to receive job completion status
//     token: Bearer xxxxx # optional authentication token for the notification endpoint
//
//   retry:
//     attempts: 10 # number of retries for the job before giving up
//     delay: 500ms # least amount of delay between each retry

//go:generate msgp -file $GOFILE

// BatchJobExpirePurge type accepts non-negative versions to be retained
type BatchJobExpirePurge struct {
	line, col      int
	RetainVersions int `yaml:"retainVersions" json:"retainVersions"`
}

var _ yaml.Unmarshaler = &BatchJobExpirePurge{}

// UnmarshalYAML - BatchJobExpirePurge extends unmarshal to extract line, col
func (p *BatchJobExpirePurge) UnmarshalYAML(val *yaml.Node) error {
	type purge BatchJobExpirePurge
	var tmp purge
	err := val.Decode(&tmp)
	if err != nil {
		return err
	}

	*p = BatchJobExpirePurge(tmp)
	p.line, p.col = val.Line, val.Column
	return nil
}

// Validate returns nil if value is valid, ie > 0.
func (p BatchJobExpirePurge) Validate() error {
	if p.RetainVersions < 0 {
		return BatchJobYamlErr{
			line: p.line,
			col:  p.col,
			msg:  "retainVersions must be >= 0",
		}
	}
	return nil
}

// BatchJobExpireFilter holds all the filters currently supported for batch replication
type BatchJobExpireFilter struct {
	line, col     int
	OlderThan     xtime.Duration      `yaml:"olderThan,omitempty" json:"olderThan"`
	CreatedBefore *time.Time          `yaml:"createdBefore,omitempty" json:"createdBefore"`
	Tags          []BatchJobKV        `yaml:"tags,omitempty" json:"tags"`
	Metadata      []BatchJobKV        `yaml:"metadata,omitempty" json:"metadata"`
	Size          BatchJobSizeFilter  `yaml:"size" json:"size"`
	Type          string              `yaml:"type" json:"type"`
	Name          string              `yaml:"name" json:"name"`
	Purge         BatchJobExpirePurge `yaml:"purge" json:"purge"`
}

var _ yaml.Unmarshaler = &BatchJobExpireFilter{}

// UnmarshalYAML - BatchJobExpireFilter extends unmarshal to extract line, col
// information
func (ef *BatchJobExpireFilter) UnmarshalYAML(value *yaml.Node) error {
	type expFilter BatchJobExpireFilter
	var tmp expFilter
	err := value.Decode(&tmp)
	if err != nil {
		return err
	}
	*ef = BatchJobExpireFilter(tmp)
	ef.line, ef.col = value.Line, value.Column
	return err
}

// Matches returns true if obj matches the filter conditions specified in ef.
func (ef BatchJobExpireFilter) Matches(obj ObjectInfo, now time.Time) bool {
	switch ef.Type {
	case BatchJobExpireObject:
		if obj.DeleteMarker {
			return false
		}
	case BatchJobExpireDeleted:
		if !obj.DeleteMarker {
			return false
		}
	default:
		// we should never come here, Validate should have caught this.
		batchLogOnceIf(context.Background(), fmt.Errorf("invalid filter type: %s", ef.Type), ef.Type)
		return false
	}

	if len(ef.Name) > 0 && !wildcard.Match(ef.Name, obj.Name) {
		return false
	}
	if ef.OlderThan > 0 && now.Sub(obj.ModTime) <= ef.OlderThan.D() {
		return false
	}

	if ef.CreatedBefore != nil && !obj.ModTime.Before(*ef.CreatedBefore) {
		return false
	}

	if len(ef.Tags) > 0 && !obj.DeleteMarker {
		// Only parse object tags if tags filter is specified.
		var tagMap map[string]string
		if len(obj.UserTags) != 0 {
			t, err := tags.ParseObjectTags(obj.UserTags)
			if err != nil {
				return false
			}
			tagMap = t.ToMap()
		}

		for _, kv := range ef.Tags {
			// Object (version) must match all tags specified in
			// the filter
			var match bool
			for t, v := range tagMap {
				if kv.Match(BatchJobKV{Key: t, Value: v}) {
					match = true
				}
			}
			if !match {
				return false
			}
		}
	}

	if len(ef.Metadata) > 0 && !obj.DeleteMarker {
		for _, kv := range ef.Metadata {
			// Object (version) must match all x-amz-meta and
			// standard metadata headers
			// specified in the filter
			var match bool
			for k, v := range obj.UserDefined {
				if !stringsHasPrefixFold(k, "x-amz-meta-") && !isStandardHeader(k) {
					continue
				}
				// We only need to match x-amz-meta or standardHeaders
				if kv.Match(BatchJobKV{Key: k, Value: v}) {
					match = true
				}
			}
			if !match {
				return false
			}
		}
	}

	return ef.Size.InRange(obj.Size)
}

const (
	// BatchJobExpireObject - object type
	BatchJobExpireObject string = "object"
	// BatchJobExpireDeleted - delete marker type
	BatchJobExpireDeleted string = "deleted"
)

// Validate returns nil if ef has valid fields, validation error otherwise.
func (ef BatchJobExpireFilter) Validate() error {
	switch ef.Type {
	case BatchJobExpireObject:
	case BatchJobExpireDeleted:
		if len(ef.Tags) > 0 || len(ef.Metadata) > 0 {
			return BatchJobYamlErr{
				line: ef.line,
				col:  ef.col,
				msg:  "delete type filter can't have tags or metadata",
			}
		}
	default:
		return BatchJobYamlErr{
			line: ef.line,
			col:  ef.col,
			msg:  "invalid batch-expire type",
		}
	}

	for _, tag := range ef.Tags {
		if err := tag.Validate(); err != nil {
			return err
		}
	}

	for _, meta := range ef.Metadata {
		if err := meta.Validate(); err != nil {
			return err
		}
	}
	if err := ef.Purge.Validate(); err != nil {
		return err
	}
	if err := ef.Size.Validate(); err != nil {
		return err
	}
	if ef.CreatedBefore != nil && !ef.CreatedBefore.Before(time.Now()) {
		return BatchJobYamlErr{
			line: ef.line,
			col:  ef.col,
			msg:  "CreatedBefore is in the future",
		}
	}
	return nil
}

// BatchJobExpire represents configuration parameters for a batch expiration
// job typically supplied in yaml form
type BatchJobExpire struct {
	line, col       int
	APIVersion      string                 `yaml:"apiVersion" json:"apiVersion"`
	Bucket          string                 `yaml:"bucket" json:"bucket"`
	Prefix          BatchJobPrefix         `yaml:"prefix" json:"prefix"`
	NotificationCfg BatchJobNotification   `yaml:"notify" json:"notify"`
	Retry           BatchJobRetry          `yaml:"retry" json:"retry"`
	Rules           []BatchJobExpireFilter `yaml:"rules" json:"rules"`
}

var _ yaml.Unmarshaler = &BatchJobExpire{}

// UnmarshalYAML - BatchJobExpire extends default unmarshal to extract line, col information.
func (r *BatchJobExpire) UnmarshalYAML(val *yaml.Node) error {
	type expireJob BatchJobExpire
	var tmp expireJob
	err := val.Decode(&tmp)
	if err != nil {
		return err
	}

	*r = BatchJobExpire(tmp)
	r.line, r.col = val.Line, val.Column
	return nil
}

// Notify notifies notification endpoint if configured regarding job failure or success.
func (r BatchJobExpire) Notify(ctx context.Context, body io.Reader) error {
	if r.NotificationCfg.Endpoint == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.NotificationCfg.Endpoint, body)
	if err != nil {
		return err
	}

	if r.NotificationCfg.Token != "" {
		req.Header.Set("Authorization", r.NotificationCfg.Token)
	}

	clnt := http.Client{Transport: getRemoteInstanceTransport()}
	resp, err := clnt.Do(req)
	if err != nil {
		return err
	}

	xhttp.DrainBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	return nil
}

const (
	batchExpireName                 = "batch-expire.bin"
	batchExpireFormat               = 1
	batchExpireVersionV1            = 1
	batchExpireVersion              = batchExpireVersionV1
	batchExpireAPIVersion           = "v1"
	batchExpireJobDefaultRetries    = 3
	batchExpireJobDefaultRetryDelay = 250 * time.Millisecond
)

type expireObjInfo struct {
	ObjectInfo
	ExpireAll         bool
	DeleteMarkerCount int64
}

// isErrObjectLocked reports a version that Object Lock protects.
func isErrObjectLocked(err error) bool {
	var locked ObjectLocked
	return errors.As(err, &locked)
}

func (r *BatchJobExpire) tagsFiltered() bool {
	for _, rule := range r.Rules {
		if len(rule.Tags) > 0 {
			return true
		}
	}
	return false
}

// expireAuthzRequests are the actions the job takes on one version: it reads
// the version, and its tags when a rule filters by them, and deletes it.
func (r *BatchJobExpire) expireAuthzRequests(name, versionID, userTags string) []batchAuthzRequest {
	if versionID == "" {
		versionID = nullVersionID
	}
	reqs := []batchAuthzRequest{
		{action: policy.GetObjectAction, bucket: r.Bucket, object: name, versionID: versionID, tags: userTags},
		{action: policy.GetObjectVersionAction, bucket: r.Bucket, object: name, versionID: versionID, tags: userTags},
		{action: policy.DeleteObjectAction, bucket: r.Bucket, object: name, versionID: versionID, tags: userTags},
		{action: policy.DeleteObjectVersionAction, bucket: r.Bucket, object: name, versionID: versionID, tags: userTags},
	}
	if r.tagsFiltered() {
		reqs = append(reqs,
			batchAuthzRequest{action: policy.GetObjectTaggingAction, bucket: r.Bucket, object: name, versionID: versionID, tags: userTags},
			batchAuthzRequest{action: policy.GetObjectVersionTaggingAction, bucket: r.Bucket, object: name, versionID: versionID, tags: userTags},
		)
	}
	return reqs
}

// expireVersion deletes one version that is older than the versions the rule
// retains. Under the object's write lock, with the version as it is then, it
// leaves a version that Object Lock protects (ObjectLocked) and refuses one
// that the submitter may not delete (batchJobAuthzError). An unreadable
// version is not deleted.
func (r *BatchJobExpire) expireVersion(ctx context.Context, api ObjectLayer, vc *versioning.Versioning, job BatchJobRequest, exp expireObjInfo) error {
	p, err := job.Submitter.principal(ctx)
	if err != nil {
		return err
	}
	versionID := exp.VersionID
	if versionID == "" {
		// An empty version ID would add a delete marker instead.
		versionID = nullVersionID
	}
	opts := ObjectOptions{
		VersionID:        versionID,
		Versioned:        vc.PrefixEnabled(exp.Name),
		VersionSuspended: vc.Suspended(),
	}
	opts.SetEvalRetentionBypassFn(func(goi ObjectInfo, gerr error) error {
		// A delete marker reads as MethodNotAllowed; any other error,
		// including a missing version, stops the delete.
		marker := isErrMethodNotAllowed(gerr) && (goi.DeleteMarker || !goi.VersionPurgeStatus.Empty())
		if gerr != nil && !marker {
			return gerr
		}
		if enforceRetentionForDeletion(ctx, goi) {
			return ObjectLocked{Bucket: r.Bucket, Object: exp.Name, VersionID: versionID}
		}
		for _, req := range r.expireAuthzRequests(exp.Name, versionID, goi.UserTags) {
			if err := p.authorize(req); err != nil {
				return err
			}
		}
		return nil
	})
	_, err = api.DeleteObject(ctx, r.Bucket, exp.Name, opts)
	return err
}

// expireVersions deletes the versions of one batch entry and records the
// outcome in res. It returns an error that ends the job.
func (r *BatchJobExpire) expireVersions(ctx context.Context, api ObjectLayer, vc *versioning.Versioning, job BatchJobRequest, ri *batchJobInfo, exp expireObjInfo, retryAttempts int, delay time.Duration, res *batchCounts) error {
	for attempts := 1; attempts <= retryAttempts; attempts++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		stopFn := globalBatchJobsMetrics.trace(batchJobMetricExpire, ri.JobID, attempts)
		err := r.expireVersion(ctx, api, vc, job, exp)
		stopFn(exp, err)
		switch {
		case err == nil:
			if exp.DeleteMarker {
				ri.countRemoved(r.Bucket, 0, 1)
			} else {
				ri.countRemoved(r.Bucket, 1, 0)
			}
			return nil
		case isBatchJobStopped(err):
			return err
		case isErrObjectLocked(err):
			// Left in place, not retried and not a failure.
			res.versionsSkipped++
			return nil
		case isErrVersionNotFound(err) || isErrObjectNotFound(err):
			// Removed concurrently.
			return nil
		}
		batchLogIf(ctx, fmt.Errorf("Failed to expire %s/%s versionID=%s due to %v (attempts=%d)", r.Bucket, exp.Name, exp.VersionID, err, attempts))
		if attempts < retryAttempts {
			time.Sleep(delay)
		}
	}
	if exp.DeleteMarker {
		res.deleteMarkersFailed++
	} else {
		res.objectsFailed++
	}
	return nil
}

// expireAllVersions purges every version of a key whose rule retains none,
// with the purge of exactly that key (erasureServerPools.deleteAllVersions),
// while the version the walk matched is still its latest. Under its lock,
// before it deletes anything, the purge refuses the key when a version is
// transitioned or Object Lock protects one, and has every write it would
// delete, each copy and each revision a drive holds, authorized for the
// submitter, with the version ID and tags it has then.
//
// What the purge removed is counted at once; a refused key is counted in res
// as refused, and the versions a failed purge left in res as failures. A
// failed purge is retried up to retryAttempts times, each time with the
// version the walk matched; a purge that stopped at its budget after
// removing versions continues without spending an attempt. A key whose
// latest version changed since the walk is not expired. It returns an error
// that ends the job: an authorization failure or the end of ctx.
func (r *BatchJobExpire) expireAllVersions(ctx context.Context, api ObjectLayer, job BatchJobRequest, ri *batchJobInfo, exp expireObjInfo, retryAttempts int, res *batchCounts) error {
	var objects, markers int64
	matched := deleteAllMatch{VersionID: exp.VersionID, ModTime: exp.ModTime}
	for attempts := 1; attempts <= retryAttempts; attempts++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		stopFn := globalBatchJobsMetrics.trace(batchJobMetricExpire, ri.JobID, attempts)
		latest := matched
		var purge deleteAllResult
		p, err := job.Submitter.principal(ctx)
		if err == nil {
			_, err = api.DeleteObject(ctx, exp.Bucket, encodeDirObject(exp.Name), ObjectOptions{
				DeleteAllVersions:  true,
				DeleteAllLatest:    &latest,
				DeleteAllResult:    &purge,
				deleteAllAuthorize: r.expireAllAuthorize(p, exp.Name),
			})
		}
		// Removed versions are gone for any later run: count them now.
		if purge.Removed > 0 {
			ri.countRemoved(r.Bucket, int64(purge.Removed-purge.Markers), int64(purge.Markers))
			objects += int64(purge.Removed - purge.Markers)
			markers += int64(purge.Markers)
		}
		stopFn(exp, err)
		switch {
		case err == nil:
			return nil
		case isBatchJobStopped(err):
			return err
		case errors.Is(err, errDeleteAllChanged):
			// Changed since the walk matched it: not expired.
			return nil
		case isErrObjectLocked(err), errors.Is(err, errDeleteAllTiered):
			// Refused as a whole: nothing removed, not retried and not a
			// failure. A later run of the job checks the key again.
			res.keysRefused++
			return nil
		case errors.Is(err, errDeleteAllBudget) && purge.Removed > 0:
			attempts-- // progress
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		batchLogIf(ctx, fmt.Errorf("Failed to expire %s/%s due to %v (attempts=%d)", exp.Bucket, exp.Name, err, attempts))
	}
	res.expireAllFailed(exp, objects, markers)
	return nil
}

// expireAllAuthorize returns the authorization of a purge of all versions of
// name for p: each version the purge would delete, as it holds it, needs the
// actions of expiring it (expireAuthzRequests).
func (r *BatchJobExpire) expireAllAuthorize(p batchJobPrincipal, name string) func([]ObjectInfo) error {
	return func(versions []ObjectInfo) error {
		for _, v := range versions {
			for _, req := range r.expireAuthzRequests(name, v.VersionID, v.UserTags) {
				if err := p.authorize(req); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

// expireAllFailed counts the versions of info, as the walk saw them, that a
// failed purge of all its versions did not remove: those beyond the objects
// and markers it removed, at least one.
func (c *batchCounts) expireAllFailed(info expireObjInfo, objects, markers int64) {
	failedObjects := max(int64(info.NumVersions)-info.DeleteMarkerCount-objects, 0)
	failedMarkers := max(info.DeleteMarkerCount-markers, 0)
	if failedObjects+failedMarkers == 0 {
		failedObjects = 1
	}
	c.objectsFailed += failedObjects
	c.deleteMarkersFailed += failedMarkers
}

// batchObjsForDelete expires the batches of expireCh. walkDone reports, once
// expireCh is closed, whether the walk reached its end: only then is its last
// key known to be complete.
func batchObjsForDelete(ctx context.Context, refuse func(error), walkDone func() bool, r *BatchJobExpire, ri *batchJobInfo, job BatchJobRequest, api ObjectLayer, wk *workers.Workers, expireCh <-chan []expireObjInfo) {
	vc, _ := globalBucketVersioningSys.Get(r.Bucket)
	retryAttempts := job.Expire.Retry.Attempts
	if retryAttempts <= 0 {
		retryAttempts = batchExpireJobDefaultRetries
	}
	delay := job.Expire.Retry.Delay
	if delay <= 0 {
		delay = batchExpireJobDefaultRetryDelay
	}

	progress := newBatchProgress(ri, r.Bucket)
	defer func() {
		wk.Wait()
		if walkDone() {
			progress.finish()
		}
	}()
	for toExpire := range expireCh {
		select {
		case <-ctx.Done():
			return
		default:
		}
		seq := progress.begin()
		if seq > 0 {
			if wait := globalBatchConfig.ExpirationWait(); wait > 0 {
				time.Sleep(wait)
			}
		}
		wk.Take()
		go func(seq uint64, toExpire []expireObjInfo) {
			defer wk.Give()
			var res batchCounts
			for _, exp := range toExpire {
				var err error
				if exp.ExpireAll {
					err = r.expireAllVersions(ctx, api, job, ri, exp, retryAttempts, &res)
				} else {
					err = r.expireVersions(ctx, api, vc, job, ri, exp, retryAttempts, delay, &res)
				}
				if err != nil {
					// The batch is not done; a later run does it again.
					if isBatchJobStopped(err) {
						refuse(err)
					}
					globalBatchJobsMetrics.save(ri.JobID, ri)
					return
				}
			}
			if n := len(toExpire); n > 0 {
				progress.done(seq, toExpire[n-1].Name, res)
			}
			globalBatchJobsMetrics.save(ri.JobID, ri)
		}(seq, toExpire)
	}
}

// Start the batch expiration job, resumes if there was a pending job via "job.ID"
func (r *BatchJobExpire) Start(ctx context.Context, api ObjectLayer, job BatchJobRequest) error {
	ri := &batchJobInfo{
		JobID:     job.ID,
		JobType:   string(job.Type()),
		StartTime: job.Started,
	}
	if err := ri.loadOrInit(ctx, api, job); err != nil {
		return batchUnavailable("loading job progress", err)
	}
	// A completed job is not run again, as replication and key rotation
	// jobs are not: its submitter is not checked again either, so a
	// credential that expired since cannot turn it into a failed job.
	if ri.Complete {
		return nil
	}
	if done, err := ri.startAuthorized(ctx, api, job); done || err != nil {
		return err
	}

	globalBatchJobsMetrics.save(job.ID, ri)
	lastObject := ri.Object

	now := time.Now().UTC()

	workerSize, err := strconv.Atoi(env.Get("_MINIO_BATCH_EXPIRATION_WORKERS", strconv.Itoa(runtime.GOMAXPROCS(0)/2)))
	if err != nil {
		return err
	}

	wk, err := workers.New(workerSize)
	if err != nil {
		// invalid worker size.
		return err
	}

	ctx, cancelCause := context.WithCancelCause(ctx)
	defer cancelCause(nil)
	// refuse ends the job for its submitter: record why before stopping.
	refuse := func(err error) {
		if isBatchJobUnavailable(err) {
			ri.pause(err)
		} else {
			ri.refuse(err)
		}
		cancelCause(err)
	}

	// The walk stops at a listing failure: work after it is left to a later
	// run, so the cursor cannot move past what was not listed.
	walkCtx, stopWalk := context.WithCancel(ctx)
	defer stopWalk()
	results := make(chan itemOrErr[ObjectInfo], workerSize)
	go func() {
		// One ascending walk over disjoint prefixes, which the cursor
		// describes.
		for _, prefix := range batchCanonicalPrefixes(r.Prefix.F()) {
			if walkCtx.Err() != nil {
				break
			}
			prefixResultCh := make(chan itemOrErr[ObjectInfo], workerSize)
			err := api.Walk(walkCtx, r.Bucket, prefix, prefixResultCh, WalkOptions{
				Marker:       lastObject,
				LatestOnly:   false, // we need to visit all versions of the object to implement purge: retainVersions
				VersionsSort: WalkVersionsSortDesc,
			})
			if err != nil {
				if walkCtx.Err() == nil {
					cancelCause(batchListingError(err))
				}
				xioutil.SafeClose(results)
				return
			}
			for result := range prefixResultCh {
				select {
				case results <- result:
				case <-walkCtx.Done():
					// Stopped: let the walk end without a reader.
				}
			}
		}
		xioutil.SafeClose(results)
	}()

	// Goroutine to periodically save batch-expire job's in-memory state
	saverQuitCh := make(chan struct{})
	saverDoneCh := make(chan struct{})
	go func() {
		defer close(saverDoneCh)
		saveTicker := time.NewTicker(10 * time.Second)
		defer saveTicker.Stop()
		quit := false
		after := time.Minute
		for !quit {
			select {
			case <-saveTicker.C:
			case <-ctx.Done():
				quit = true
			case <-saverQuitCh:
				quit = true
			}

			if quit {
				// save immediately if we are quitting
				after = 0
			}

			ctx, cancel := context.WithTimeout(GlobalContext, 30*time.Second) // independent context
			batchLogIf(ctx, ri.updateAfter(ctx, api, after, job))
			cancel()
		}
	}()

	expireCh := make(chan []expireObjInfo, workerSize)
	expireDoneCh := make(chan struct{})
	var walkDone atomic.Bool
	go func() {
		defer close(expireDoneCh)
		batchObjsForDelete(ctx, refuse, walkDone.Load, r, ri, job, api, wk, expireCh)
	}()

	var (
		prevObj       ObjectInfo
		matchedFilter BatchJobExpireFilter
		versionsCount int
		toDel         []expireObjInfo
		failed        bool
		done          bool
	)
	deleteMarkerCountMap := map[string]int64{}
	// pushToExpire is called between keys only, so that a batch holds all
	// the versions of its keys and its last key is done with it.
	pushToExpire := func() {
		// set preObject deleteMarkerCount
		if len(toDel) > 0 {
			lastDelIndex := len(toDel) - 1
			lastDel := toDel[lastDelIndex]
			if lastDel.ExpireAll {
				toDel[lastDelIndex].DeleteMarkerCount = deleteMarkerCountMap[lastDel.Name]
				// delete the key
				delete(deleteMarkerCountMap, lastDel.Name)
			}
		}
		// send down filtered entries to be deleted using
		// DeleteObjects method
		if len(toDel) > 10 { // batch up to 10 objects/versions to be expired simultaneously.
			xfer := make([]expireObjInfo, len(toDel))
			copy(xfer, toDel)
			select {
			case expireCh <- xfer:
				toDel = toDel[:0] // resetting toDel
			case <-ctx.Done():
				done = true
			}
		}
	}
	var listingErr error
	for {
		select {
		case result, ok := <-results:
			if !ok {
				done = true
				break
			}
			if result.Err != nil {
				failed = true
				listingErr = batchListingError(result.Err)
				batchLogIf(ctx, result.Err)
				stopWalk()
				done = true
				break
			}
			if !batchResumeAfter(lastObject, result.Item.Name) {
				// Completed by the run that set the cursor.
				continue
			}
			if result.Item.DeleteMarker {
				deleteMarkerCountMap[result.Item.Name]++
			}
			// Apply filter to find the matching rule to apply expiry
			// actions accordingly.
			// nolint:gocritic
			if result.Item.IsLatest {
				var match BatchJobExpireFilter
				var found bool
				for _, rule := range r.Rules {
					if rule.Matches(result.Item, now) {
						match = rule
						found = true
						break
					}
				}
				if !found {
					continue
				}

				if prevObj.Name != result.Item.Name {
					// switch the object
					pushToExpire()
				}

				prevObj = result.Item
				matchedFilter = match
				versionsCount = 1
				// Include the latest version
				if matchedFilter.Purge.RetainVersions == 0 {
					toDel = append(toDel, expireObjInfo{
						ObjectInfo: result.Item,
						ExpireAll:  true,
					})
					continue
				}
			} else if prevObj.Name == result.Item.Name {
				if matchedFilter.Purge.RetainVersions == 0 {
					continue // including latest version in toDel suffices, skipping other versions
				}
				versionsCount++
			} else {
				// switch the object
				pushToExpire()
				// a file switched with no LatestVersion, logging it
				batchLogIf(ctx, fmt.Errorf("skipping object %s, no latest version found", result.Item.Name))
				continue
			}

			if versionsCount <= matchedFilter.Purge.RetainVersions {
				continue // retain versions
			}
			toDel = append(toDel, expireObjInfo{
				ObjectInfo: result.Item,
			})
		case <-ctx.Done():
			done = true
		}
		if done {
			break
		}
	}

	if context.Cause(ctx) == nil {
		walkDone.Store(!failed)
		pushToExpire()
		// Send any remaining objects downstream
		if len(toDel) > 0 {
			select {
			case <-ctx.Done():
			case expireCh <- toDel:
			}
		}
	}
	xioutil.SafeClose(expireCh)

	<-expireDoneCh // waits for the expire goroutine to complete
	wk.Wait()      // waits for all expire workers to retire

	// Persist the final state once the saver has stopped, so that its last
	// save cannot overwrite it.
	xioutil.SafeClose(saverQuitCh)
	<-saverDoneCh
	refused := ri.refused()
	cause := context.Cause(ctx)
	if cause == nil {
		cause = listingErr
	}
	if cause != nil && !refused {
		if isBatchJobUnavailable(cause) {
			return ri.savePaused(ctx, api, job, cause)
		}
		if isErrBucketNotFound(cause) {
			ri.mu.Lock()
			ri.Failed = true
			ri.mu.Unlock()
		}
		saveCtx, cancel := context.WithTimeout(GlobalContext, 30*time.Second)
		batchLogIf(saveCtx, ri.updateAfter(saveCtx, api, 0, job))
		cancel()
		globalBatchJobsMetrics.save(job.ID, ri)
		return cause
	}

	ri.mu.Lock()
	itemsFailed := ri.expireFailures()
	ri.Complete = !refused && !failed && !itemsFailed
	ri.Failed = refused || failed || itemsFailed
	ri.mu.Unlock()
	globalBatchJobsMetrics.save(job.ID, ri)
	saveCtx, cancel := context.WithTimeout(GlobalContext, 30*time.Second)
	batchLogIf(saveCtx, ri.updateAfter(saveCtx, api, 0, job))
	cancel()

	// Notify expire jobs final status to the configured endpoint
	buf, _ := json.Marshal(ri)
	if err := r.Notify(context.Background(), bytes.NewReader(buf)); err != nil {
		batchLogIf(context.Background(), fmt.Errorf("unable to notify %v", err))
	}

	return nil
}

//msgp:ignore batchExpireJobError
type batchExpireJobError struct {
	Code           string
	Description    string
	HTTPStatusCode int
}

func (e batchExpireJobError) Error() string {
	return e.Description
}

// maxBatchRules maximum number of rules a batch-expiry job supports
const maxBatchRules = 50

// Validate validates the job definition input
func (r *BatchJobExpire) Validate(ctx context.Context, job BatchJobRequest, o ObjectLayer) error {
	if r == nil {
		return nil
	}

	if r.APIVersion != batchExpireAPIVersion {
		return batchExpireJobError{
			Code:           "InvalidArgument",
			Description:    "Unsupported batch expire API version",
			HTTPStatusCode: http.StatusBadRequest,
		}
	}

	if r.Bucket == "" {
		return batchExpireJobError{
			Code:           "InvalidArgument",
			Description:    "Bucket argument missing",
			HTTPStatusCode: http.StatusBadRequest,
		}
	}

	if _, err := o.GetBucketInfo(ctx, r.Bucket, BucketOptions{}); err != nil {
		if isErrBucketNotFound(err) {
			return batchExpireJobError{
				Code:           "NoSuchSourceBucket",
				Description:    "The specified source bucket does not exist",
				HTTPStatusCode: http.StatusNotFound,
			}
		}
		return err
	}

	if len(r.Rules) > maxBatchRules {
		return batchExpireJobError{
			Code:           "InvalidArgument",
			Description:    "Too many rules. Batch expire job can't have more than 100 rules",
			HTTPStatusCode: http.StatusBadRequest,
		}
	}

	for _, rule := range r.Rules {
		if err := rule.Validate(); err != nil {
			return batchExpireJobError{
				Code:           "InvalidArgument",
				Description:    fmt.Sprintf("Invalid batch expire rule: %s", err),
				HTTPStatusCode: http.StatusBadRequest,
			}
		}
	}

	if err := r.Retry.Validate(); err != nil {
		return batchExpireJobError{
			Code:           "InvalidArgument",
			Description:    fmt.Sprintf("Invalid batch expire retry configuration: %s", err),
			HTTPStatusCode: http.StatusBadRequest,
		}
	}
	return nil
}
