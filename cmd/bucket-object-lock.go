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
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio/internal/amztime"
	"github.com/minio/minio/internal/auth"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// BucketObjectLockSys - map of bucket and retention configuration.
type BucketObjectLockSys struct{}

// Get - Get retention configuration.
func (sys *BucketObjectLockSys) Get(bucketName string) (r objectlock.Retention, err error) {
	config, _, err := globalBucketMetadataSys.GetObjectLockConfig(bucketName)
	if err != nil {
		if errors.Is(err, BucketObjectLockConfigNotFound{Bucket: bucketName}) {
			return r, nil
		}
		if errors.Is(err, errInvalidArgument) {
			return r, err
		}
		return r, err
	}
	return config.ToRetention(), nil
}

// enforceRetentionForDeletion checks if it is appropriate to remove an
// object according to locking configuration when this is lifecycle/ bucket quota asking.
func enforceRetentionForDeletion(ctx context.Context, objInfo ObjectInfo) (locked bool) {
	if objInfo.DeleteMarker {
		return false
	}

	lhold := objectlock.GetObjectLegalHoldMeta(objInfo.UserDefined)
	if lhold.Status.Valid() && lhold.Status == objectlock.LegalHoldOn {
		return true
	}

	ret := objectlock.GetObjectRetentionMeta(objInfo.UserDefined)
	if ret.Mode.Valid() && (ret.Mode == objectlock.RetCompliance || ret.Mode == objectlock.RetGovernance) {
		t, err := objectlock.UTCNowNTP()
		if err != nil {
			internalLogIf(ctx, err, logger.WarningKind)
			return true
		}
		if ret.RetainUntilDate.After(t) {
			return true
		}
	}
	return false
}

// enforceRetentionBypassForDelete enforces whether an existing object under governance can be deleted
// with governance bypass headers set in the request.
// Objects under site wide WORM can never be overwritten.
// For objects in "Governance" mode, overwrite is allowed if a) object retention date is past OR
// governance bypass headers are set and user has governance bypass permissions.
// Objects in "Compliance" mode can be overwritten only if retention date is past.
func enforceRetentionBypassForDelete(ctx context.Context, r *http.Request, bucket string, object ObjectToDelete, oi ObjectInfo, gerr error) error {
	if gerr != nil { // error from GetObjectInfo
		if _, ok := gerr.(MethodNotAllowed); ok {
			// This happens usually for a delete marker
			if oi.DeleteMarker || !oi.VersionPurgeStatus.Empty() {
				// Delete marker should be present and valid.
				return nil
			}
		}
		if isErrObjectNotFound(gerr) || isErrVersionNotFound(gerr) {
			return nil
		}
		return gerr
	}

	lhold := objectlock.GetObjectLegalHoldMeta(oi.UserDefined)
	if lhold.Status.Valid() && lhold.Status == objectlock.LegalHoldOn {
		return ObjectLocked{}
	}

	ret := objectlock.GetObjectRetentionMeta(oi.UserDefined)
	if ret.Mode.Valid() {
		switch ret.Mode {
		case objectlock.RetCompliance:
			// In compliance mode, a protected object version can't be overwritten
			// or deleted by any user, including the root user in your AWS account.
			// When an object is locked in compliance mode, its retention mode can't
			// be changed, and its retention period can't be shortened. Compliance mode
			// ensures that an object version can't be overwritten or deleted for the
			// duration of the retention period.
			t, err := objectlock.UTCNowNTP()
			if err != nil {
				internalLogIf(ctx, err, logger.WarningKind)
				return ObjectLocked{}
			}

			if !ret.RetainUntilDate.Before(t) {
				return ObjectLocked{}
			}
			return nil
		case objectlock.RetGovernance:
			// In governance mode, users can't overwrite or delete an object
			// version or alter its lock settings unless they have special
			// permissions. With governance mode, you protect objects against
			// being deleted by most users, but you can still grant some users
			// permission to alter the retention settings or delete the object
			// if necessary. You can also use governance mode to test retention-period
			// settings before creating a compliance-mode retention period.
			// To override or remove governance-mode retention settings, a
			// user must have the s3:BypassGovernanceRetention permission
			// and must explicitly include x-amz-bypass-governance-retention:true
			// as a request header with any request that requires overriding
			// governance mode.
			//
			byPassSet := objectlock.IsObjectLockGovernanceBypassSet(r.Header)
			if !byPassSet {
				t, err := objectlock.UTCNowNTP()
				if err != nil {
					internalLogIf(ctx, err, logger.WarningKind)
					return ObjectLocked{}
				}

				if !ret.RetainUntilDate.Before(t) {
					return ObjectLocked{}
				}
				return nil
			}
			// https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock-overview.html#object-lock-retention-modes
			// If you try to delete objects protected by governance mode and have s3:BypassGovernanceRetention, the operation will succeed.
			if reqInfo := logger.GetReqInfo(ctx); reqInfo != nil {
				reqInfo.BucketName = bucket
				reqInfo.ObjectName = object.ObjectName
			}
			if authorizeRequest(ctx, r, policy.BypassGovernanceRetentionAction) != ErrNone {
				return errAuthentication
			}
		}
	}
	return nil
}

// isRetentionActionAllowed evaluates action for a PutObjectRetention request
// with the object-lock condition keys derived from the requested retention.
// The keys come from the request, not from the stored version, so the
// handler can decide s3:PutObjectRetention before reading any object state.
func isRetentionActionAllowed(action policy.Action, bucket, object string, objRetention *objectlock.ObjectRetention, r *http.Request, cred auth.Credentials, owner bool) bool {
	if cred.AccessKey == "" {
		return false
	}
	t, err := objectlock.UTCNowNTP()
	if err != nil {
		return false
	}
	conditions := getConditionValues(r, "", cred)
	conditions["object-lock-mode"] = []string{string(objRetention.Mode)}
	conditions["object-lock-retain-until-date"] = []string{objRetention.RetainUntilDate.UTC().Format(time.RFC3339)}
	// Relative days from now, for "object-lock-remaining-retention-days".
	// Clearing retention (<Retention/>) has a zero RetainUntilDate, which must
	// evaluate as 0 remaining days rather than a large positive math.Abs delta
	// from year 0001.
	days := 0
	if !objRetention.RetainUntilDate.IsZero() && objRetention.RetainUntilDate.After(t) {
		// Time.Sub saturates after about 292 years. Count seconds instead so
		// maximum-retention policies also apply to distant RFC3339 dates.
		seconds := objRetention.RetainUntilDate.Unix() - t.Unix()
		days = int(seconds / 86400)
		if seconds%86400 != 0 || objRetention.RetainUntilDate.Nanosecond() > t.Nanosecond() {
			days++
		}
	}
	conditions["object-lock-remaining-retention-days"] = []string{strconv.Itoa(days)}
	return globalIAMSys.IsAllowed(policy.Args{
		AccountName:     cred.AccessKey,
		Groups:          cred.Groups,
		Action:          action,
		BucketName:      bucket,
		ConditionValues: conditions,
		ObjectName:      object,
		IsOwner:         owner,
		Claims:          cred.Claims,
	})
}

// enforceRetentionBypassForPut enforces the stored retention of oi against a
// PutObjectRetention request. The caller must already hold
// s3:PutObjectRetention; this only decides changes that depend on the stored
// state. Expired or absent retention may be changed freely. Unexpired
// GOVERNANCE retention may be shortened, removed or have its mode changed only
// with the bypass header and s3:BypassGovernanceRetention. Unexpired
// COMPLIANCE retention may only be extended.
func enforceRetentionBypassForPut(ctx context.Context, r *http.Request, oi ObjectInfo, objRetention *objectlock.ObjectRetention, cred auth.Credentials, owner bool) error {
	ret := objectlock.GetObjectRetentionMeta(oi.UserDefined)
	if !ret.Mode.Valid() {
		return nil
	}

	t, err := objectlock.UTCNowNTP()
	if err != nil {
		internalLogIf(ctx, err, logger.WarningKind)
		return ObjectLocked{Bucket: oi.Bucket, Object: oi.Name, VersionID: oi.VersionID}
	}
	if ret.RetainUntilDate.Before(t) {
		return nil
	}

	weakens := objRetention.Mode != ret.Mode || objRetention.RetainUntilDate.Before(ret.RetainUntilDate.Time)
	if !weakens {
		return nil
	}
	switch ret.Mode {
	case objectlock.RetGovernance:
		// https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html#object-lock-bypass-governance
		if !objectlock.IsObjectLockGovernanceBypassSet(r.Header) {
			return ObjectLocked{Bucket: oi.Bucket, Object: oi.Name, VersionID: oi.VersionID}
		}
		if !isRetentionActionAllowed(policy.BypassGovernanceRetentionAction, oi.Bucket, oi.Name, objRetention, r, cred, owner) {
			return errAuthentication
		}
		return nil
	default:
		// Compliance retention mode cannot be changed or shortened.
		// https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock-overview.html#object-lock-retention-modes
		return ObjectLocked{Bucket: oi.Bucket, Object: oi.Name, VersionID: oi.VersionID}
	}
}

// checkObjectLockedForOverwrite re-checks under the object write lock whether an
// in-place write to the null version (such as a directory object) would
// overwrite a locked version in an Object Lock bucket.
func checkObjectLockedForOverwrite(ctx context.Context, bucket, object string, getObjectInfoFn GetObjectInfoFn) error {
	if isMinioMetaBucketName(bucket) {
		return nil
	}
	retentionCfg, err := globalBucketObjectLockSys.Get(bucket)
	if err != nil {
		return err
	}
	if !retentionCfg.LockEnabled {
		return nil
	}
	objInfo, err := getObjectInfoFn(ctx, bucket, object, ObjectOptions{
		VersionID:  nullVersionID,
		NoLock:     true,
		NoAuditLog: true,
	})
	if err != nil {
		if isErrObjectNotFound(err) || isErrVersionNotFound(err) || errors.As(err, &MethodNotAllowed{}) {
			return nil
		}
		return err
	}
	if objectlock.GetObjectLegalHoldMeta(objInfo.UserDefined).Status == objectlock.LegalHoldOn {
		return ObjectLocked{Bucket: bucket, Object: decodeDirObject(object), VersionID: nullVersionID}
	}
	r := objectlock.GetObjectRetentionMeta(objInfo.UserDefined)
	if r.Mode == objectlock.RetCompliance || r.Mode == objectlock.RetGovernance {
		t, err := objectlock.UTCNowNTP()
		if err != nil {
			internalLogIf(ctx, err, logger.WarningKind)
			return ObjectLocked{Bucket: bucket, Object: decodeDirObject(object), VersionID: nullVersionID}
		}
		if r.RetainUntilDate.After(t) {
			return ObjectLocked{Bucket: bucket, Object: decodeDirObject(object), VersionID: nullVersionID}
		}
	}
	return nil
}

// checkPutObjectLockAllowed enforces object retention policy and legal hold policy
// for requests with WORM headers
// See https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock-managing.html for the spec.
// For non-existing objects with object retention headers set, this method returns ErrNone if bucket has
// locking enabled and user has requisite permissions (s3:PutObjectRetention)
// If object exists on object store and site wide WORM enabled - this method
// returns an error. For objects in "Governance" mode, overwrite is allowed if the retention date has expired.
// For objects in "Compliance" mode, retention date cannot be shortened, and mode cannot be altered.
// For objects with legal hold header set, the s3:PutObjectLegalHold permission is expected to be set
// Both legal hold and retention can be applied independently on an object
func checkPutObjectLockAllowed(ctx context.Context, rq *http.Request, bucket, object string, getObjectInfoFn GetObjectInfoFn, retentionPermErr, legalHoldPermErr APIErrorCode, replicaTrusted bool) (objectlock.RetMode, objectlock.RetentionDate, objectlock.ObjectLegalHold, APIErrorCode) {
	var mode objectlock.RetMode
	var retainDate objectlock.RetentionDate
	var legalHold objectlock.ObjectLegalHold

	retentionRequested := objectlock.IsObjectLockRetentionRequested(rq.Header)
	legalHoldRequested := objectlock.IsObjectLockLegalHoldRequested(rq.Header)

	retentionCfg, err := globalBucketObjectLockSys.Get(bucket)
	if err != nil {
		return mode, retainDate, legalHold, ErrInvalidBucketObjectLockConfiguration
	}

	if !retentionCfg.LockEnabled {
		if legalHoldRequested || retentionRequested {
			return mode, retainDate, legalHold, ErrInvalidBucketObjectLockConfiguration
		}

		// If this not a WORM enabled bucket, we should return right here.
		return mode, retainDate, legalHold, ErrNone
	}

	opts, err := getOpts(ctx, rq, bucket, object)
	if err != nil {
		return mode, retainDate, legalHold, toAPIErrorCode(ctx, err)
	}
	if isDirObject(object) && opts.VersionID == "" {
		opts.VersionID = nullVersionID
	}

	if opts.VersionID != "" && !replicaTrusted {
		objInfo, err := getObjectInfoFn(ctx, bucket, object, opts)
		if err != nil {
			if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) && !errors.As(err, &MethodNotAllowed{}) {
				return mode, retainDate, legalHold, toAPIErrorCode(ctx, err)
			}
		} else {
			r := objectlock.GetObjectRetentionMeta(objInfo.UserDefined)
			t, err := objectlock.UTCNowNTP()
			if err != nil {
				internalLogIf(ctx, err, logger.WarningKind)
				return mode, retainDate, legalHold, ErrObjectLocked
			}
			if (r.Mode == objectlock.RetCompliance || r.Mode == objectlock.RetGovernance) && r.RetainUntilDate.After(t) {
				return mode, retainDate, legalHold, ErrObjectLocked
			}
			mode = r.Mode
			retainDate = r.RetainUntilDate
			legalHold = objectlock.GetObjectLegalHoldMeta(objInfo.UserDefined)
			// Disallow overwriting an object on legal hold
			if legalHold.Status == objectlock.LegalHoldOn {
				return mode, retainDate, legalHold, ErrObjectLocked
			}
		}
	}

	if legalHoldRequested {
		var lerr error
		if legalHold, lerr = objectlock.ParseObjectLockLegalHoldHeaders(rq.Header); lerr != nil {
			return mode, retainDate, legalHold, toAPIErrorCode(ctx, lerr)
		}
		if legalHoldPermErr != ErrNone {
			return mode, retainDate, legalHold, legalHoldPermErr
		}
	}

	if retentionRequested {
		legalHold, err := objectlock.ParseObjectLockLegalHoldHeaders(rq.Header)
		if err != nil {
			return mode, retainDate, legalHold, toAPIErrorCode(ctx, err)
		}
		rMode, rDate, err := objectlock.ParseObjectLockRetentionHeaders(rq.Header, replicaTrusted)
		if err != nil && (!replicaTrusted || rMode != "" || !rDate.IsZero()) {
			return mode, retainDate, legalHold, toAPIErrorCode(ctx, err)
		}
		if retentionPermErr != ErrNone {
			return mode, retainDate, legalHold, retentionPermErr
		}
		return rMode, rDate, legalHold, ErrNone
	}
	if replicaTrusted { // replica inherits retention metadata only from source
		return "", objectlock.RetentionDate{}, legalHold, ErrNone
	}
	if !retentionRequested && retentionCfg.Validity > 0 {
		if retentionPermErr != ErrNone {
			return mode, retainDate, legalHold, retentionPermErr
		}

		t, err := objectlock.UTCNowNTP()
		if err != nil {
			internalLogIf(ctx, err, logger.WarningKind)
			return mode, retainDate, legalHold, ErrObjectLocked
		}

		// Inherit retention from the bucket configuration. A legal-hold header
		// on the same request, ON or OFF, is independent of retention and must
		// not suppress the default (#165).
		return retentionCfg.Mode, objectlock.RetentionDate{Time: t.Add(retentionCfg.Validity)}, legalHold, ErrNone
	}
	return mode, retainDate, legalHold, ErrNone
}

// NewBucketObjectLockSys returns initialized BucketObjectLockSys
func NewBucketObjectLockSys() *BucketObjectLockSys {
	return &BucketObjectLockSys{}
}

// objectLockState is the Object Lock metadata of a stored object version
// together with the replication timestamps that order updates to it.
type objectLockState struct {
	mode, retainUntil, retentionTimestamp string
	legalHold, legalHoldTimestamp         string
}

func storedObjectLockState(metadata map[string]string) objectLockState {
	return objectLockState{
		mode:               metadata[strings.ToLower(xhttp.AmzObjectLockMode)],
		retainUntil:        metadata[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)],
		retentionTimestamp: metadata[ReservedMetadataPrefixLower+ObjectLockRetentionTimestamp],
		legalHold:          metadata[strings.ToLower(xhttp.AmzObjectLockLegalHold)],
		legalHoldTimestamp: metadata[ReservedMetadataPrefixLower+ObjectLockLegalHoldTimestamp],
	}
}

// olderThan reports whether a stored replication timestamp is missing,
// unreadable, or earlier than the source timestamp, in which case the
// replica update wins. A zero source timestamp never wins.
func olderThan(stored string, src time.Time) bool {
	if src.IsZero() {
		return false
	}
	ondisk, err := time.Parse(time.RFC3339Nano, stored)
	return err != nil || ondisk.Before(src)
}

func (s objectLockState) retentionIsOlderThan(src time.Time) bool {
	return olderThan(s.retentionTimestamp, src)
}

func (s objectLockState) legalHoldIsOlderThan(src time.Time) bool {
	return olderThan(s.legalHoldTimestamp, src)
}

// restoreRetention and restoreLegalHold put the stored state back into
// metadata that was rebuilt from a request whose update was not applied.
func (s objectLockState) restoreRetention(metadata map[string]string) {
	// The stored timestamp orders the next update and must survive even when
	// the stored value is empty, which is how a removal is recorded.
	if s.retentionTimestamp != "" {
		metadata[ReservedMetadataPrefixLower+ObjectLockRetentionTimestamp] = s.retentionTimestamp
	}
	if s.mode == "" {
		return
	}
	metadata[strings.ToLower(xhttp.AmzObjectLockMode)] = s.mode
	metadata[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = s.retainUntil
}

func (s objectLockState) restoreLegalHold(metadata map[string]string) {
	if s.legalHoldTimestamp != "" {
		metadata[ReservedMetadataPrefixLower+ObjectLockLegalHoldTimestamp] = s.legalHoldTimestamp
	}
	if s.legalHold == "" {
		return
	}
	metadata[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = s.legalHold
}

// replicaStoredLock reads the Object Lock state stored on the addressed version
// so a trusted replica write can order its update against it. A missing object
// or version yields an empty state, which is correct for the first write of a
// version; any other read error is returned so the caller fails the write rather
// than ordering an incoming update against lock state it merely failed to read
// (an older incoming value must not win over a newer stored one just because the
// read timed out).
func replicaStoredLock(ctx context.Context, getObjectInfo GetObjectInfoFn, bucket, object, versionID string) (objectLockState, error) {
	oi, err := getObjectInfo(ctx, bucket, object, ObjectOptions{VersionID: versionID})
	switch {
	case err == nil:
		return storedObjectLockState(oi.UserDefined), nil
	case isErrObjectNotFound(err) || isErrVersionNotFound(err):
		return objectLockState{}, nil
	default:
		return objectLockState{}, err
	}
}

// applyReplicatedObjectLock writes the retention and legal-hold decision into
// metadata for a PUT, CopyObject, or multipart-initiation request. A request
// that is not an actual trusted replica -- a normal user write, or a trusted
// peer that carried the replication marker without REPLICA status -- takes
// ordinary write semantics: a validated value is applied and stamped now, and a
// missing value is left as is. Only an actual replica update is ordered against
// the state already stored on the addressed version, so a stale value cannot
// overwrite a newer one and a full retransmit cannot roll a destination back.
// The stored argument is meaningful only for a replica; callers pass an empty
// state otherwise. Only the two Object Lock keys and their reserved ordering
// timestamps are touched; any encryption-metadata reconciliation stays with the
// caller.
func applyReplicatedObjectLock(metadata map[string]string, stored objectLockState,
	replicaTrusted bool,
	retentionMode objectlock.RetMode, retentionDate objectlock.RetentionDate,
	legalHold objectlock.ObjectLegalHold, srcRetentionTimestamp, srcLegalholdTimestamp time.Time,
) {
	switch {
	case !replicaTrusted:
		// Ordinary write semantics: apply a validated retention and stamp it now;
		// a missing value carries no instruction, so leave the metadata as it is.
		if retentionMode.Valid() {
			metadata[strings.ToLower(xhttp.AmzObjectLockMode)] = string(retentionMode)
			metadata[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = amztime.ISO8601Format(retentionDate.UTC())
			metadata[ReservedMetadataPrefixLower+ObjectLockRetentionTimestamp] = UTCNow().Format(time.RFC3339Nano)
		}
	case !stored.retentionIsOlderThan(srcRetentionTimestamp):
		// The stored update is at least as new as this replica's, or the replica
		// carries no ordering timestamp: keep what is stored. This is also how a
		// stale retransmit is rejected.
		stored.restoreRetention(metadata)
	default:
		// The replica update wins. A removal carries no value but still records
		// the source timestamp that orders it.
		if retentionMode.Valid() {
			metadata[strings.ToLower(xhttp.AmzObjectLockMode)] = string(retentionMode)
			metadata[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = amztime.ISO8601Format(retentionDate.UTC())
		}
		metadata[ReservedMetadataPrefixLower+ObjectLockRetentionTimestamp] = srcRetentionTimestamp.UTC().Format(time.RFC3339Nano)
	}

	// Legal hold has no removal in S3: an explicitly empty header is already
	// rejected as an invalid status, so the only value-less shape that gets here
	// is an absent one, which conveys no legal-hold change. Only a valid status
	// can win.
	switch {
	case !replicaTrusted:
		if legalHold.Status.Valid() {
			metadata[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = string(legalHold.Status)
			metadata[ReservedMetadataPrefixLower+ObjectLockLegalHoldTimestamp] = UTCNow().Format(time.RFC3339Nano)
		}
	case legalHold.Status.Valid() && stored.legalHoldIsOlderThan(srcLegalholdTimestamp):
		metadata[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = string(legalHold.Status)
		metadata[ReservedMetadataPrefixLower+ObjectLockLegalHoldTimestamp] = srcLegalholdTimestamp.UTC().Format(time.RFC3339Nano)
	default:
		stored.restoreLegalHold(metadata)
	}
}

// reconcileStoredObjectLock re-orders the Object Lock already written into
// metadata against the state currently stored on the destination version, both
// compared by their reserved ordering timestamps. It runs inside the object
// layer under the namespace write lock that guards the version replacement,
// after the destination version is read and before the new one is committed, so
// a replica update whose ordering was decided at handler time (or, for multipart,
// at initiation) cannot overwrite a newer lock update that reached the version in
// between. metadata already carries the incoming update with its source
// timestamps; a stored value that is not older than the incoming one is put back,
// which for a stored removal means clearing the incoming value and keeping only
// the removal's timestamp. Only the two lock keys and their reserved timestamps
// move; a non-replica write never sets the flag that invokes this.
func reconcileStoredObjectLock(metadata map[string]string, stored objectLockState) {
	incoming := storedObjectLockState(metadata)

	incomingRetentionTS, _ := time.Parse(time.RFC3339Nano, incoming.retentionTimestamp)
	if !stored.retentionIsOlderThan(incomingRetentionTS) {
		// The stored retention is at least as new as the incoming one (or the
		// incoming update is unordered): drop the incoming value and put the stored
		// state back, which may itself be a removal (value keys absent, timestamp
		// present).
		delete(metadata, strings.ToLower(xhttp.AmzObjectLockMode))
		delete(metadata, strings.ToLower(xhttp.AmzObjectLockRetainUntilDate))
		delete(metadata, ReservedMetadataPrefixLower+ObjectLockRetentionTimestamp)
		stored.restoreRetention(metadata)
	}

	incomingLegalHoldTS, _ := time.Parse(time.RFC3339Nano, incoming.legalHoldTimestamp)
	if incoming.legalHold == "" || !stored.legalHoldIsOlderThan(incomingLegalHoldTS) {
		delete(metadata, strings.ToLower(xhttp.AmzObjectLockLegalHold))
		delete(metadata, ReservedMetadataPrefixLower+ObjectLockLegalHoldTimestamp)
		stored.restoreLegalHold(metadata)
	}
}
