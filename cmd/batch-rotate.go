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
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"math/rand"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
	"github.com/pgsty/silo-pkg/v3/env"
	"github.com/pgsty/silo-pkg/v3/policy"
	"github.com/pgsty/silo-pkg/v3/workers"
)

// keyrotate:
//   apiVersion: v1
//   bucket: BUCKET
//   prefix: PREFIX
//   encryption:
//     type: sse-s3 # valid values are sse-s3 and sse-kms
//     key: <new-kms-key> # valid only for sse-kms
//     context: <new-kms-key-context> # valid only for sse-kms
// # optional flags based filtering criteria
// # for all objects
// flags:
//   filter:
//     newerThan: "7d" # match objects newer than this value (e.g. 7d10h31s)
//     olderThan: "7d" # match objects older than this value (e.g. 7d10h31s)
//     createdAfter: "date" # match objects created after "date"
//     createdBefore: "date" # match objects created before "date"
//     tags:
//       - key: "name"
//         value: "pick*" # match objects with tag 'name', with all values starting with 'pick'
//     metadata:
//       - key: "content-type"
//         value: "image/*" # match objects with 'content-type', with all values starting with 'image/'
//     kmskey: "key-id" # match objects with KMS key-id (applicable only for sse-kms)
//   notify:
//     endpoint: "https://notify.endpoint" # notification endpoint to receive job status events
//     token: "Bearer xxxxx" # optional authentication token for the notification endpoint

//   retry:
//     attempts: 10 # number of retries for the job before giving up
//     delay: "500ms" # least amount of delay between each retry

//go:generate msgp -file $GOFILE -unexported

// BatchKeyRotationType defines key rotation type
type BatchKeyRotationType string

const (
	sses3  BatchKeyRotationType = "sse-s3"
	ssekms BatchKeyRotationType = "sse-kms"
)

// BatchJobKeyRotateEncryption defines key rotation encryption options passed
type BatchJobKeyRotateEncryption struct {
	Type       BatchKeyRotationType `yaml:"type" json:"type"`
	Key        string               `yaml:"key" json:"key"`
	Context    string               `yaml:"context" json:"context"`
	kmsContext kms.Context          `msg:"-"`
}

// Validate validates input key rotation encryption options.
func (e BatchJobKeyRotateEncryption) Validate() error {
	if e.Type != sses3 && e.Type != ssekms {
		return errInvalidArgument
	}
	spaces := strings.HasPrefix(e.Key, " ") || strings.HasSuffix(e.Key, " ")
	if e.Type == ssekms && spaces {
		return crypto.ErrInvalidEncryptionKeyID
	}

	if e.Type == ssekms && GlobalKMS != nil {
		ctx := kms.Context{}
		if e.Context != "" {
			b, err := base64.StdEncoding.DecodeString(e.Context)
			if err != nil {
				return err
			}

			json := jsoniter.ConfigCompatibleWithStandardLibrary
			if err := json.Unmarshal(b, &ctx); err != nil {
				return err
			}
		}
		e.kmsContext = kms.Context{}
		maps.Copy(e.kmsContext, ctx)
		ctx["MinIO batch API"] = "batchrotate" // Context for a test key operation
		if _, err := GlobalKMS.GenerateKey(GlobalContext, &kms.GenerateKeyRequest{Name: e.Key, AssociatedData: ctx}); err != nil {
			return err
		}
	}
	return nil
}

// BatchKeyRotateFilter holds all the filters currently supported for batch replication
type BatchKeyRotateFilter struct {
	NewerThan     time.Duration `yaml:"newerThan,omitempty" json:"newerThan"`
	OlderThan     time.Duration `yaml:"olderThan,omitempty" json:"olderThan"`
	CreatedAfter  time.Time     `yaml:"createdAfter,omitempty" json:"createdAfter"`
	CreatedBefore time.Time     `yaml:"createdBefore,omitempty" json:"createdBefore"`
	Tags          []BatchJobKV  `yaml:"tags,omitempty" json:"tags"`
	Metadata      []BatchJobKV  `yaml:"metadata,omitempty" json:"metadata"`
	KMSKeyID      string        `yaml:"kmskeyid" json:"kmskey"`
}

// BatchKeyRotateNotification success or failure notification endpoint for each job attempts
type BatchKeyRotateNotification struct {
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	Token    string `yaml:"token" json:"token"`
}

// BatchJobKeyRotateFlags various configurations for replication job definition currently includes
// - filter
// - notify
// - retry
type BatchJobKeyRotateFlags struct {
	Filter BatchKeyRotateFilter `yaml:"filter" json:"filter"`
	Notify BatchJobNotification `yaml:"notify" json:"notify"`
	Retry  BatchJobRetry        `yaml:"retry" json:"retry"`
}

// BatchJobKeyRotateV1 v1 of batch key rotation job
type BatchJobKeyRotateV1 struct {
	APIVersion string                      `yaml:"apiVersion" json:"apiVersion"`
	Flags      BatchJobKeyRotateFlags      `yaml:"flags" json:"flags"`
	Bucket     string                      `yaml:"bucket" json:"bucket"`
	Prefix     string                      `yaml:"prefix" json:"prefix"`
	Encryption BatchJobKeyRotateEncryption `yaml:"encryption" json:"encryption"`
}

// Notify notifies notification endpoint if configured regarding job failure or success.
func (r BatchJobKeyRotateV1) Notify(ctx context.Context, ri *batchJobInfo) error {
	return notifyEndpoint(ctx, ri, r.Flags.Notify.Endpoint, r.Flags.Notify.Token)
}

// batchAuthoritativeVersion returns the version obj as all its copies
// describe it. With several pools a version can have copies in more than one
// pool, and a read returns one of them; the merged copy carries the newest
// Object Lock and tag state. The caller holds the object's write lock.
func batchAuthoritativeVersion(ctx context.Context, api ObjectLayer, bucket, object string, obj ObjectInfo) (ObjectInfo, error) {
	z, ok := api.(*erasureServerPools)
	if !ok || z.SinglePool() {
		return obj, nil
	}
	versionID := obj.VersionID
	if versionID == "" {
		versionID = nullVersionID
	}
	return z.replicaObjectInfo(ctx, bucket, encodeDirObject(object), ObjectOptions{VersionID: versionID, NoLock: true, NoAuditLog: true})
}

// batchAuthoritativeRead is batchAuthoritativeVersion for a version that has
// been opened for reading. It takes the object's read lock itself, since an
// opened reader may hold none.
func batchAuthoritativeRead(ctx context.Context, api ObjectLayer, bucket, object string, obj ObjectInfo) (ObjectInfo, error) {
	z, ok := api.(*erasureServerPools)
	if !ok || z.SinglePool() {
		return obj, nil
	}
	lk := z.NewNSLock(bucket, encodeDirObject(object))
	lkctx, err := lk.GetRLock(ctx, globalOperationTimeout)
	if err != nil {
		return ObjectInfo{}, err
	}
	defer lk.RUnlock(lkctx)
	return batchAuthoritativeVersion(lkctx.Context(), api, bucket, object, obj)
}

// rotateAuthzRequests are the actions of rotating one version: it is read and
// written again in place with the new key.
func (r *BatchJobKeyRotateV1) rotateAuthzRequests(oi ObjectInfo) []batchAuthzRequest {
	versionID := oi.VersionID
	if versionID == "" {
		versionID = nullVersionID
	}
	// The encryption the rewrite leaves: rotation keeps the kind of the
	// version (rotateKey), and SSE-KMS takes the requested key.
	values := map[string][]string{}
	switch {
	case crypto.S3KMS.IsEncrypted(oi.UserDefined):
		values[strings.ToLower(xhttp.AmzServerSideEncryption)] = []string{xhttp.AmzEncryptionKMS}
		if r.Encryption.Type == ssekms && r.Encryption.Key != "" {
			values[strings.ToLower(xhttp.AmzServerSideEncryptionKmsID)] = []string{r.Encryption.Key}
		}
	case crypto.S3.IsEncrypted(oi.UserDefined):
		values[strings.ToLower(xhttp.AmzServerSideEncryption)] = []string{xhttp.AmzEncryptionAES}
	}
	return []batchAuthzRequest{
		{action: policy.GetObjectAction, bucket: r.Bucket, object: oi.Name, versionID: versionID, tags: oi.UserTags},
		{action: policy.GetObjectVersionAction, bucket: r.Bucket, object: oi.Name, versionID: versionID, tags: oi.UserTags},
		{action: policy.PutObjectAction, bucket: r.Bucket, object: oi.Name, versionID: versionID, tags: oi.UserTags, values: values},
	}
}

// KeyRotate rotates encryption key of an object. A version that Object Lock
// protects is not rewritten: it returns ObjectLocked.
func (r *BatchJobKeyRotateV1) KeyRotate(ctx context.Context, api ObjectLayer, objInfo ObjectInfo, sub *batchJobSubmitter) error {
	srcBucket := r.Bucket
	srcObject := objInfo.Name

	if objInfo.DeleteMarker || !objInfo.VersionPurgeStatus.Empty() {
		return nil
	}
	sseKMS := crypto.S3KMS.IsEncrypted(objInfo.UserDefined)
	sseS3 := crypto.S3.IsEncrypted(objInfo.UserDefined)
	if !sseKMS && !sseS3 { // neither sse-s3 nor sse-kms disallowed
		return errInvalidEncryptionParameters
	}
	if sseKMS && r.Encryption.Type == sses3 { // previously encrypted with sse-kms, now sse-s3 disallowed
		return errInvalidEncryptionParameters
	}
	versioned := globalBucketVersioningSys.PrefixEnabled(srcBucket, srcObject)
	versionSuspended := globalBucketVersioningSys.PrefixSuspended(srcBucket, srcObject)

	// Lock the name writers lock: the stored name of a directory object.
	lock := api.NewObjectNSLock(r.Bucket, encodeDirObject(objInfo.Name))
	lkctx, err := lock.GetLock(ctx, globalOperationTimeout)
	if err != nil {
		return err
	}
	ctx = lkctx.Context()
	defer lock.Unlock(lkctx)

	opts := ObjectOptions{
		VersionID:        objInfo.VersionID,
		Versioned:        versioned,
		VersionSuspended: versionSuspended,
		NoLock:           true,
	}
	obj, err := api.GetObjectInfo(ctx, r.Bucket, objInfo.Name, opts)
	if err != nil {
		return err
	}
	// Decide on the version as it is under the lock that the rewrite holds,
	// before any key is requested, with the metadata of all its copies.
	logical, err := batchAuthoritativeVersion(ctx, api, r.Bucket, objInfo.Name, obj)
	if err != nil {
		return err
	}
	if enforceRetentionForDeletion(ctx, logical) {
		return ObjectLocked{Bucket: r.Bucket, Object: obj.Name, VersionID: obj.VersionID}
	}
	p, err := sub.principal(ctx)
	if err != nil {
		return err
	}
	for _, req := range r.rotateAuthzRequests(logical) {
		if err := p.authorize(req); err != nil {
			return err
		}
	}
	oi := obj.Clone()
	var (
		newKeyID      string
		newKeyContext kms.Context
	)
	encMetadata := make(map[string]string)
	for k, v := range oi.UserDefined {
		if stringsHasPrefixFold(k, ReservedMetadataPrefixLower) {
			encMetadata[k] = v
		}
	}

	if (sseKMS || sseS3) && r.Encryption.Type == ssekms {
		if err = r.Encryption.Validate(); err != nil {
			return err
		}
		newKeyID = strings.TrimPrefix(r.Encryption.Key, crypto.ARNPrefix)
		newKeyContext = r.Encryption.kmsContext
	}
	if err = rotateKey(ctx, []byte{}, newKeyID, []byte{}, r.Bucket, oi.Name, encMetadata, newKeyContext); err != nil {
		return err
	}

	// Since we are rotating the keys, make sure to update the metadata.
	oi.metadataOnly = true
	oi.keyRotation = true
	maps.Copy(oi.UserDefined, encMetadata)
	if _, err := api.CopyObject(ctx, r.Bucket, oi.Name, r.Bucket, oi.Name, oi, ObjectOptions{
		VersionID: oi.VersionID,
	}, ObjectOptions{
		VersionID: oi.VersionID,
		NoLock:    true,
	}); err != nil {
		return err
	}

	return nil
}

const (
	batchKeyRotationName               = "batch-rotate.bin"
	batchKeyRotationFormat             = 1
	batchKeyRotateVersionV1            = 1
	batchKeyRotateVersion              = batchKeyRotateVersionV1
	batchKeyRotateAPIVersion           = "v1"
	batchKeyRotateJobDefaultRetries    = 3
	batchKeyRotateJobDefaultRetryDelay = 25 * time.Millisecond
)

// Start the batch key rottion job, resumes if there was a pending job via "job.ID"
func (r *BatchJobKeyRotateV1) Start(ctx context.Context, api ObjectLayer, job BatchJobRequest) error {
	ri := &batchJobInfo{
		JobID:     job.ID,
		JobType:   string(job.Type()),
		StartTime: job.Started,
	}
	if err := ri.loadOrInit(ctx, api, job); err != nil {
		return err
	}
	if ri.Complete {
		return nil
	}
	if done, err := ri.startAuthorized(ctx, api, job); done || err != nil {
		return err
	}

	globalBatchJobsMetrics.save(job.ID, ri)
	lastObject := ri.Object

	retryAttempts := job.KeyRotate.Flags.Retry.Attempts
	if retryAttempts <= 0 {
		retryAttempts = batchKeyRotateJobDefaultRetries
	}
	delay := job.KeyRotate.Flags.Retry.Delay
	if delay <= 0 {
		delay = batchKeyRotateJobDefaultRetryDelay
	}

	selectObj := func(info FileInfo) (ok bool) {
		if r.Flags.Filter.OlderThan > 0 && time.Since(info.ModTime) < r.Flags.Filter.OlderThan {
			// skip all objects that are newer than specified older duration
			return false
		}

		if r.Flags.Filter.NewerThan > 0 && time.Since(info.ModTime) >= r.Flags.Filter.NewerThan {
			// skip all objects that are older than specified newer duration
			return false
		}

		if !r.Flags.Filter.CreatedAfter.IsZero() && r.Flags.Filter.CreatedAfter.Before(info.ModTime) {
			// skip all objects that are created before the specified time.
			return false
		}

		if !r.Flags.Filter.CreatedBefore.IsZero() && r.Flags.Filter.CreatedBefore.After(info.ModTime) {
			// skip all objects that are created after the specified time.
			return false
		}

		if len(r.Flags.Filter.Tags) > 0 {
			// Only parse object tags if tags filter is specified.
			tagMap := map[string]string{}
			tagStr := info.Metadata[xhttp.AmzObjectTagging]
			if len(tagStr) != 0 {
				t, err := tags.ParseObjectTags(tagStr)
				if err != nil {
					return false
				}
				tagMap = t.ToMap()
			}

			for _, kv := range r.Flags.Filter.Tags {
				for t, v := range tagMap {
					if kv.Match(BatchJobKV{Key: t, Value: v}) {
						return true
					}
				}
			}

			// None of the provided tags filter match skip the object
			return false
		}

		if len(r.Flags.Filter.Metadata) > 0 {
			for _, kv := range r.Flags.Filter.Metadata {
				for k, v := range info.Metadata {
					if !stringsHasPrefixFold(k, "x-amz-meta-") && !isStandardHeader(k) {
						continue
					}
					// We only need to match x-amz-meta or standardHeaders
					if kv.Match(BatchJobKV{Key: k, Value: v}) {
						return true
					}
				}
			}

			// None of the provided metadata filters match skip the object.
			return false
		}
		if r.Flags.Filter.KMSKeyID != "" {
			if v, ok := info.Metadata[xhttp.AmzServerSideEncryptionKmsID]; ok && strings.TrimPrefix(v, crypto.ARNPrefix) != r.Flags.Filter.KMSKeyID {
				return false
			}
		}
		return true
	}

	workerSize, err := strconv.Atoi(env.Get("_MINIO_BATCH_KEYROTATION_WORKERS", strconv.Itoa(runtime.GOMAXPROCS(0)/2)))
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
		ri.refuse(err)
		cancelCause(err)
	}
	progress := newBatchProgress(ri, r.Bucket)

	results := make(chan itemOrErr[ObjectInfo], 100)
	if err := api.Walk(ctx, r.Bucket, r.Prefix, results, WalkOptions{
		Marker: lastObject,
		Filter: selectObj,
	}); err != nil {
		// Do not need to retry if we can't list objects on source.
		return err
	}
	failed := false
	for res := range results {
		if context.Cause(ctx) != nil {
			// Refused or canceled: schedule nothing more.
			continue
		}
		if res.Err != nil {
			failed = true
			batchLogIf(ctx, res.Err)
			break
		}
		result := res.Item
		if !batchResumeAfter(lastObject, result.Name) {
			// Completed by the run that set the cursor.
			continue
		}
		sseKMS := crypto.S3KMS.IsEncrypted(result.UserDefined)
		sseS3 := crypto.S3.IsEncrypted(result.UserDefined)
		if !sseKMS && !sseS3 { // neither sse-s3 nor sse-kms disallowed
			continue
		}
		seq := progress.begin()
		wk.Take()
		go func() {
			defer wk.Give()
			var counts batchCounts
			for attempts := 1; attempts <= retryAttempts; attempts++ {
				stopFn := globalBatchJobsMetrics.trace(batchJobMetricKeyRotation, job.ID, attempts)
				err := r.KeyRotate(ctx, api, result, job.Submitter)
				stopFn(result, err)
				if err == nil {
					counts.objects = 1
					break
				}
				if isBatchJobAuthzError(err) {
					refuse(err)
					return
				}
				if isErrObjectLocked(err) {
					// Left as it is, not retried and not a failure.
					counts.versionsSkipped = 1
					break
				}
				if ctx.Err() != nil {
					// Not done; a later run rotates it.
					return
				}
				batchLogIf(ctx, err)
				if attempts >= retryAttempts {
					auditOptions := AuditLogOptions{
						Event:     "KeyRotate",
						APIName:   "StartBatchJob",
						Bucket:    result.Bucket,
						Object:    result.Name,
						VersionID: result.VersionID,
						Error:     err.Error(),
					}
					auditLogInternal(ctx, auditOptions)
					counts.objectsFailed = 1
					break
				}
				if delay > 0 {
					time.Sleep(delay + time.Duration(rand.Float64()*float64(delay)))
				}
			}
			progress.done(seq, result.Name, counts)
			globalBatchJobsMetrics.save(job.ID, ri)
			// persist in-memory state to disk after every 10secs.
			batchLogIf(ctx, ri.updateAfter(ctx, api, 10*time.Second, job))

			if wait := globalBatchConfig.KeyRotationWait(); wait > 0 {
				time.Sleep(wait)
			}
		}()
	}
	wk.Wait()
	cause := context.Cause(ctx)
	if !failed && cause == nil {
		// The walk ended: its last key is done.
		progress.finish()
	}
	if cause != nil && !ri.refused() {
		// Stopped before the end: keep the work after the cursor pending.
		globalBatchJobsMetrics.save(job.ID, ri)
		batchLogIf(ctx, ri.updateAfter(GlobalContext, api, 0, job))
		return cause
	}

	if !ri.refused() {
		ri.mu.Lock()
		ri.Complete = !failed && ri.ObjectsFailed == 0
		ri.Failed = failed || ri.ObjectsFailed > 0
		ri.mu.Unlock()
	}
	globalBatchJobsMetrics.save(job.ID, ri)
	// persist in-memory state to disk.
	batchLogIf(ctx, ri.updateAfter(GlobalContext, api, 0, job))

	if err := r.Notify(GlobalContext, ri); err != nil {
		batchLogIf(ctx, fmt.Errorf("unable to notify %v", err))
	}
	return nil
}

//msgp:ignore batchKeyRotationJobError
type batchKeyRotationJobError struct {
	Code           string
	Description    string
	HTTPStatusCode int
}

func (e batchKeyRotationJobError) Error() string {
	return e.Description
}

// Validate validates the job definition input
func (r *BatchJobKeyRotateV1) Validate(ctx context.Context, job BatchJobRequest, o ObjectLayer) error {
	if r == nil {
		return nil
	}

	if r.APIVersion != batchKeyRotateAPIVersion {
		return errInvalidArgument
	}

	if r.Bucket == "" {
		return errInvalidArgument
	}

	if _, err := o.GetBucketInfo(ctx, r.Bucket, BucketOptions{}); err != nil {
		if isErrBucketNotFound(err) {
			return batchKeyRotationJobError{
				Code:           "NoSuchSourceBucket",
				Description:    "The specified source bucket does not exist",
				HTTPStatusCode: http.StatusNotFound,
			}
		}
		return err
	}
	if GlobalKMS == nil {
		return errKMSNotConfigured
	}
	if err := r.Encryption.Validate(); err != nil {
		return err
	}

	for _, tag := range r.Flags.Filter.Tags {
		if err := tag.Validate(); err != nil {
			return err
		}
	}

	for _, meta := range r.Flags.Filter.Metadata {
		if err := meta.Validate(); err != nil {
			return err
		}
	}

	return r.Flags.Retry.Validate()
}
