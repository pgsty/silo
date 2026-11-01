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
	"maps"
	"sort"
	"strings"
	"time"

	madmin "github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/bucket/lifecycle"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/sync/errgroup"
)

// objectPoolInfos reads the addressed version in every pool, including pools
// draining their contents. The caller must hold the pools-layer object lock.
// An unreadable pool may contain a newer version or metadata; it is not absence.
func (z *erasureServerPools) objectPoolInfos(ctx context.Context, bucket, object string, opts ObjectOptions) ([]PoolObjInfo, error) {
	opts.NoLock = true
	opts.CheckPrecondFn = nil
	var copies []PoolObjInfo
	for i, pool := range z.serverPools {
		oi, err := pool.GetObjectInfo(ctx, bucket, object, opts)
		if err == nil || (oi.DeleteMarker && (isErrObjectNotFound(err) || isErrMethodNotAllowed(err))) {
			copies = append(copies, PoolObjInfo{Index: i, ObjInfo: oi})
			continue
		}
		if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
			return nil, err
		}
	}
	sort.Slice(copies, func(i, j int) bool {
		a, b := copies[i], copies[j]
		if a.ObjInfo.ModTime.Equal(b.ObjInfo.ModTime) {
			return a.Index < b.Index
		}
		return a.ObjInfo.ModTime.After(b.ObjInfo.ModTime)
	})
	if len(copies) == 0 {
		if opts.VersionID != "" {
			return nil, VersionNotFound{Bucket: bucket, Object: decodeDirObject(object), VersionID: opts.VersionID}
		}
		return nil, ObjectNotFound{Bucket: bucket, Object: decodeDirObject(object)}
	}
	return copies, nil
}

// checkDataMovementCopies rejects moving a version when another pool holds a
// newer copy of it, which reads return instead. A cross-pool overwrite can
// leave such a copy, and a client write can add one while the move copies.
// Equal timestamps normally identify an interrupted move. Conflicting ties
// retain the same pool-order winner as reads. While the caller holds the
// pools-layer object lock, the returned resolver serves the set layer's
// reconciliation of this version from the same reads. Without opts.NoLock
// it takes the read lock itself.
func (z *erasureServerPools) checkDataMovementCopies(ctx context.Context, bucket, object string, opts ObjectOptions) (GetObjectInfoFn, error) {
	if opts.MTime.IsZero() {
		// The set layer would stamp the moved copy as the newest one.
		return nil, errInvalidArgument
	}
	if !opts.NoLock {
		lk := z.NewNSLock(bucket, object)
		lkctx, err := lk.GetRLock(ctx, globalOperationTimeout)
		if err != nil {
			return nil, err
		}
		ctx = lkctx.Context()
		defer lk.RUnlock(lkctx)
	}
	versionID := opts.VersionID
	if versionID == "" {
		versionID = nullVersionID
	}
	copies, err := z.objectPoolInfos(ctx, bucket, object, ObjectOptions{VersionID: versionID, NoAuditLog: true})
	if err != nil && !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
		return nil, err
	}
	// The snapshot may have been purged or replaced after the reader opened.
	// In that case the walker must leave the current source state alone.
	sourcePresent := false
	for _, copy := range copies {
		if copy.Index == opts.SrcPoolIdx && copy.ObjInfo.ModTime.Equal(opts.MTime) && copy.ObjInfo.DeleteMarker == opts.DeleteMarker {
			sourcePresent = true
		}
	}
	if !sourcePresent {
		return nil, VersionNotFound{Bucket: bucket, Object: decodeDirObject(object), VersionID: versionID}
	}
	for _, copy := range copies {
		if copy.Index != opts.SrcPoolIdx && copy.ObjInfo.ModTime.After(opts.MTime) {
			return nil, DataMovementOverwriteErr{Bucket: bucket, Object: object, VersionID: opts.VersionID, Err: errDataMovementSuperseded}
		}
	}
	if winner := copies[0]; winner.Index != opts.SrcPoolIdx && winner.ObjInfo.ModTime.Equal(opts.MTime) {
		for _, copy := range copies {
			if copy.Index == opts.SrcPoolIdx && (copy.ObjInfo.ETag != winner.ObjInfo.ETag || copy.ObjInfo.DeleteMarker != winner.ObjInfo.DeleteMarker || copy.ObjInfo.Size != winner.ObjInfo.Size) {
				return nil, DataMovementOverwriteErr{Bucket: bucket, Object: object, VersionID: opts.VersionID, Err: errDataMovementSuperseded}
			}
		}
	}
	return func(ctx context.Context, b, o string, ropts ObjectOptions) (ObjectInfo, error) {
		if ropts.VersionID == "" {
			ropts.VersionID = nullVersionID
		}
		if b != bucket || o != object || ropts.VersionID != versionID {
			return z.replicaObjectInfo(ctx, b, o, ropts)
		}
		return replicaCopiesInfo(copies, err, bucket, object, versionID)
	}, nil
}

// removeMovedVersions retires only the source versions in the walker's
// snapshot. A concurrent delete can create a new marker in the source pool;
// deleting the whole prefix would remove that marker and expose moved data.
func (z *erasureServerPools) removeMovedVersions(ctx context.Context, bucket, object string, source int, versions []FileInfo) error {
	object = encodeDirObject(object)
	lk := z.NewNSLock(bucket, object)
	lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
	if err != nil {
		return err
	}
	ctx = lkctx.Context()
	defer lk.Unlock(lkctx)
	for _, version := range versions {
		vid := version.VersionID
		if vid == "" {
			vid = nullVersionID
		}
		copies, err := z.objectPoolInfos(ctx, bucket, object, ObjectOptions{VersionID: vid, NoAuditLog: true})
		if isErrObjectNotFound(err) || isErrVersionNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		var src *ObjectInfo
		var retained []PoolObjInfo
		for _, copy := range copies {
			if copy.Index == source {
				src = &copy.ObjInfo
			} else {
				retained = append(retained, copy)
			}
		}
		if src == nil {
			continue
		}
		if !src.ModTime.Equal(version.ModTime) || src.DeleteMarker != version.Deleted {
			return PreConditionFailed{}
		}
		// Successful movement is not enough if the destination changed again.
		// Keep the source unless another copy still preserves its read result.
		if len(retained) == 0 || retained[0].ObjInfo.ModTime.Before(src.ModTime) {
			return PreConditionFailed{}
		}
		_, err = z.serverPools[source].DeleteObject(ctx, bucket, object, ObjectOptions{
			VersionID: vid, NoLock: true, NoAuditLog: true,
			SkipFreeVersion: true, // preserve the old prefix cleanup's tier-GC behavior
		})
		if err != nil && !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
			return err
		}
	}
	return nil
}

// Healing also commits object metadata. Both queued healing and drive healing
// must use the same namespace as pooled writes, rather than racing them under
// a destination set's independent namespace.
func (z *erasureServerPools) healObjectInPool(ctx context.Context, er *erasureObjects, bucket, object, versionID string, opts madmin.HealOpts) (madmin.HealResultItem, error) {
	if !z.SinglePool() && !opts.NoLock {
		lk := z.NewNSLock(bucket, object)
		lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
		if err != nil {
			return madmin.HealResultItem{}, err
		}
		ctx = lkctx.Context()
		defer lk.Unlock(lkctx)
		opts.NoLock = true
	}
	return er.HealObject(ctx, bucket, object, versionID, opts)
}

// mergePoolLockState resolves each independently ordered field. An ordered
// removal is a value in its own right; an absent unordered field is not one.
func mergePoolLockState(copies []PoolObjInfo) objectLockState {
	state := storedObjectLockState(copies[0].ObjInfo.UserDefined)
	for _, copy := range copies[1:] {
		next := storedObjectLockState(copy.ObjInfo.UserDefined)
		retentionTime, _ := time.Parse(time.RFC3339Nano, next.retentionTimestamp)
		if state.retentionIsOlderThan(retentionTime) || (state.retentionTimestamp == "" && state.mode == "" && next.mode != "") {
			state.mode, state.retainUntil, state.retentionTimestamp = next.mode, next.retainUntil, next.retentionTimestamp
		}
		holdTime, _ := time.Parse(time.RFC3339Nano, next.legalHoldTimestamp)
		if state.legalHoldIsOlderThan(holdTime) || (state.legalHoldTimestamp == "" && state.legalHold == "" && next.legalHold != "") {
			state.legalHold, state.legalHoldTimestamp = next.legalHold, next.legalHoldTimestamp
		}
	}
	return state
}

func replaceObjectLockMetadata(metadata map[string]string, state objectLockState) {
	for _, key := range []string{
		strings.ToLower(xhttp.AmzObjectLockMode), strings.ToLower(xhttp.AmzObjectLockRetainUntilDate),
		strings.ToLower(xhttp.AmzObjectLockLegalHold),
		ReservedMetadataPrefixLower + ObjectLockRetentionTimestamp,
		ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp,
	} {
		// Metadata updates use maps.Copy at the set layer. Empty values also
		// clear a previous value there, including timestamp-only removals.
		if _, exists := metadata[key]; exists {
			metadata[key] = ""
		}
	}
	state.restoreRetention(metadata)
	state.restoreLegalHold(metadata)
}

func mergedPoolObjectInfo(copies []PoolObjInfo) ObjectInfo {
	oi := copies[0].ObjInfo
	oi.UserDefined = maps.Clone(oi.UserDefined)
	if oi.UserDefined == nil {
		oi.UserDefined = make(map[string]string)
	}
	replaceObjectLockMetadata(oi.UserDefined, mergePoolLockState(copies))
	for _, copy := range copies[1:] {
		ts := copy.ObjInfo.UserDefined[ReservedMetadataPrefixLower+TaggingTimestamp]
		stamp, _ := time.Parse(time.RFC3339Nano, ts)
		if olderThan(oi.UserDefined[ReservedMetadataPrefixLower+TaggingTimestamp], stamp) {
			oi.UserDefined[ReservedMetadataPrefixLower+TaggingTimestamp] = ts
			oi.UserTags = copy.ObjInfo.UserTags
		}
	}
	return oi
}

func (z *erasureServerPools) replicaObjectInfo(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	if opts.VersionID == "" {
		opts.VersionID = nullVersionID
	}
	copies, err := z.objectPoolInfos(ctx, bucket, object, opts)
	return replicaCopiesInfo(copies, err, bucket, object, opts.VersionID)
}

func replicaCopiesInfo(copies []PoolObjInfo, err error, bucket, object, versionID string) (ObjectInfo, error) {
	if err != nil {
		return ObjectInfo{}, err
	}
	if copies[0].ObjInfo.DeleteMarker {
		return copies[0].ObjInfo, MethodNotAllowed{Bucket: bucket, Object: decodeDirObject(object), VersionID: versionID}
	}
	return mergedPoolObjectInfo(copies), nil
}

// metadataPoolInfos resolves an unqualified metadata request to one logical
// version before collecting its copies, rather than mixing different versions.
func (z *erasureServerPools) metadataPoolInfos(ctx context.Context, bucket, object string, opts ObjectOptions) ([]PoolObjInfo, error) {
	copies, err := z.objectPoolInfos(ctx, bucket, object, opts)
	if err != nil {
		return nil, err
	}
	if copies[0].ObjInfo.DeleteMarker {
		return nil, MethodNotAllowed{Bucket: bucket, Object: decodeDirObject(object), VersionID: opts.VersionID}
	}
	if opts.VersionID == "" {
		opts.VersionID = copies[0].ObjInfo.VersionID
		if opts.VersionID == "" {
			opts.VersionID = nullVersionID
		}
		return z.objectPoolInfos(ctx, bucket, object, opts)
	}
	return copies, nil
}

func (z *erasureServerPools) updatePoolMetadata(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	copies, err := z.metadataPoolInfos(ctx, bucket, object, opts)
	if err != nil {
		return ObjectInfo{}, err
	}
	updated := mergedPoolObjectInfo(copies)
	before := maps.Clone(updated.UserDefined)
	if opts.EvalMetadataFn != nil {
		if _, err := opts.EvalMetadataFn(&updated, nil); err != nil {
			return ObjectInfo{}, err
		}
	}
	changes := make(map[string]string)
	for key, value := range updated.UserDefined {
		if prior, ok := before[key]; !ok || prior != value {
			changes[key] = value
		}
	}
	for key := range before {
		if _, ok := updated.UserDefined[key]; !ok {
			changes[key] = ""
		}
	}
	// Metadata callbacks may explicitly replace tags in the raw write map.
	// Otherwise retain the merged value from the ObjectInfo read model.
	tags, ok := updated.UserDefined[xhttp.AmzObjectTagging]
	if !ok {
		tags = updated.UserTags
	}
	state := storedObjectLockState(updated.UserDefined)
	opts.VersionID = updated.VersionID
	if opts.VersionID == "" {
		opts.VersionID = nullVersionID
	}
	opts.NoLock = true
	opts.EvalMetadataFn = func(oi *ObjectInfo, _ error) (ReplicateDecision, error) {
		maps.Copy(oi.UserDefined, changes)
		replaceObjectLockMetadata(oi.UserDefined, state)
		// Reassemble the tag value and its ordering timestamp for storage.
		if tags != "" || oi.UserTags != "" {
			oi.UserDefined[xhttp.AmzObjectTagging] = tags
		}
		key := ReservedMetadataPrefixLower + TaggingTimestamp
		if value, exists := updated.UserDefined[key]; exists || oi.UserDefined[key] != "" {
			oi.UserDefined[key] = value
		}
		return ReplicateDecision{}, nil
	}
	var primary ObjectInfo
	for _, copy := range copies {
		oi, err := z.serverPools[copy.Index].PutObjectMetadata(ctx, bucket, object, opts)
		if err != nil {
			return ObjectInfo{}, err
		}
		if copy.Index == copies[0].Index {
			primary = oi
		}
	}
	return primary, nil
}

// Pass the stored tag value explicitly: ObjectInfo.UserDefined excludes it,
// whereas FileInfo.Metadata retains the raw storage key.
func reconcileStoredObjectTags(metadata map[string]string, storedTags, storedTimestamp string) {
	key := ReservedMetadataPrefixLower + TaggingTimestamp
	stamp, err := time.Parse(time.RFC3339Nano, storedTimestamp)
	if err != nil {
		return
	}
	incoming, err := time.Parse(time.RFC3339Nano, metadata[key])
	if err != nil || !stamp.Before(incoming) {
		metadata[key] = storedTimestamp
		metadata[xhttp.AmzObjectTagging] = storedTags
	}
}

// Local tagging mutations must advance the revision they overwrite, even when
// a request's clock or lock acquisition order is behind the stored revision.
// Replica writes use reconcileStoredObjectTags instead of minting a revision.
func monotonicTaggingTimestamp(incoming, stored string) string {
	requested, err := time.Parse(time.RFC3339Nano, incoming)
	if err != nil {
		return incoming
	}
	current, err := time.Parse(time.RFC3339Nano, stored)
	if err != nil || requested.After(current) {
		return incoming
	}
	return current.Add(time.Nanosecond).UTC().Format(time.RFC3339Nano)
}

// A restored version still owns its tier reference even while IsRemote is
// false. Only the last copy of a reference may schedule its contents for GC.
func sharesTierObject(oi ObjectInfo, copies []PoolObjInfo) bool {
	ref := oi.TransitionedObject
	if ref.Status != lifecycle.TransitionComplete {
		return false
	}
	for _, copy := range copies {
		other := copy.ObjInfo.TransitionedObject
		if other.Status == lifecycle.TransitionComplete && ref.Tier == other.Tier && ref.Name == other.Name && ref.VersionID == other.VersionID {
			return true
		}
	}
	return false
}

// retireReplicaCopies runs only after committing a replacement. Failures are
// returned to the caller, so a stale copy cannot be hidden behind a successful
// response. Data movement owns its source cleanup and does not use this helper.
func (z *erasureServerPools) retireReplicaCopies(ctx context.Context, bucket, object string, keep int, oi ObjectInfo) error {
	versionID := oi.VersionID
	if versionID == "" {
		versionID = nullVersionID
	}
	copies, err := z.objectPoolInfos(ctx, bucket, object, ObjectOptions{VersionID: versionID})
	if err != nil {
		return err
	}
	var retained []PoolObjInfo
	for _, copy := range copies {
		if copy.Index == keep {
			retained = []PoolObjInfo{copy}
			break
		}
	}
	if len(retained) == 0 {
		return VersionNotFound{Bucket: bucket, Object: decodeDirObject(object), VersionID: versionID}
	}
	for i, copy := range copies {
		if copy.Index == keep {
			continue
		}
		_, err := z.serverPools[copy.Index].DeleteObject(ctx, bucket, object,
			ObjectOptions{
				VersionID: versionID, NoLock: true, NoAuditLog: true,
				SkipFreeVersion: sharesTierObject(copy.ObjInfo, retained) || sharesTierObject(copy.ObjInfo, copies[i+1:]),
			})
		if err != nil && !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
			return err
		}
	}
	return nil
}

// deleteObjectReconciled evaluates any condition once against the logical
// version, then removes all its copies under the same lock as pooled writers.
func (z *erasureServerPools) deleteObjectReconciled(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	copies, err := z.objectPoolInfos(ctx, bucket, object, opts)
	if err != nil {
		if opts.isVersionPurge() && (isErrObjectNotFound(err) || isErrVersionNotFound(err)) {
			if quorumErr := z.checkPurgeAbsent(ctx, bucket, object, opts.VersionID); quorumErr != nil {
				return ObjectInfo{}, quorumErr
			}
		}
		return ObjectInfo{}, err
	}
	primary := copies[0]
	if opts.CheckPrecondFn != nil && opts.CheckPrecondFn(primary.ObjInfo) {
		return ObjectInfo{}, PreConditionFailed{}
	}
	opts.CheckPrecondFn = nil
	opts.NoLock = true
	if opts.EvalRetentionBypassFn != nil || opts.EvalMetadataFn != nil {
		logical := primary.ObjInfo
		var gerr error
		switch {
		case logical.DeleteMarker:
			// Markers can be deleted by version ID. Match the set layer's
			// callback inputs instead of rejecting them as metadata updates.
			gerr = toObjectErr(errMethodNotAllowed, bucket, object)
			if opts.VersionID == "" || opts.DeleteMarker {
				gerr = toObjectErr(errFileNotFound, bucket, object)
			}
		case opts.VersionID != "":
			// An addressed version already resolved every copy above.
			logical = mergedPoolObjectInfo(copies)
		default:
			versions, err := z.metadataPoolInfos(ctx, bucket, object, opts)
			if err != nil {
				return ObjectInfo{}, err
			}
			logical = mergedPoolObjectInfo(versions)
		}
		// Keep the retention gate first. These callbacks independently evaluate
		// the logical version and run once before any deletion; the handler only
		// sweeps metadata's transition state after a successful delete.
		if opts.EvalRetentionBypassFn != nil {
			if err := opts.EvalRetentionBypassFn(logical, gerr); err != nil {
				return ObjectInfo{}, err
			}
			opts.EvalRetentionBypassFn = nil
		}
		if opts.EvalMetadataFn != nil {
			decision, err := opts.EvalMetadataFn(&logical, gerr)
			if err != nil {
				return ObjectInfo{}, err
			}
			if decision.ReplicateAny() {
				opts.SetDeleteReplicationState(decision, opts.VersionID)
			}
			opts.EvalMetadataFn = nil
		}
	}
	if opts.isVersionPurge() {
		// A missing pool may have only read-quorum absence. Verify every pool
		// omitted by lookup before mutating the known copies.
		for i, pool := range z.serverPools {
			found := false
			for _, copy := range copies {
				found = found || copy.Index == i
			}
			if !found {
				if err := pool.getHashedSet(object).checkPurgeAbsent(ctx, bucket, object, opts.VersionID); err != nil {
					return ObjectInfo{}, err
				}
			}
		}
	}
	if opts.VersionID == "" && (opts.Versioned || opts.VersionSuspended) {
		// A single new delete marker hides the current version. Older versions
		// remain history and must not be removed by an unqualified DELETE.
		oi, err := z.serverPools[primary.Index].DeleteObject(ctx, bucket, object, opts)
		oi.Name = decodeDirObject(object)
		oi.replicationDecision = opts.DeleteReplication.ReplicateDecisionStr
		return oi, err
	}
	// Retire non-authoritative copies first. If cleanup fails, retain the
	// authoritative version and report the error instead of acknowledging a
	// deletion that would expose an older copy.
	for i := 1; i < len(copies); i++ {
		candidate := copies[i]
		deleteOpts := opts
		deleteOpts.SkipFreeVersion = opts.SkipFreeVersion || sharesTierObject(candidate.ObjInfo, copies[:1]) || sharesTierObject(candidate.ObjInfo, copies[i+1:])
		_, err := z.serverPools[candidate.Index].DeleteObject(ctx, bucket, object, deleteOpts)
		if err != nil && !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
			return ObjectInfo{}, err
		}
	}
	oi, err := z.serverPools[primary.Index].DeleteObject(ctx, bucket, object, opts)
	oi.Name = decodeDirObject(object)
	oi.replicationDecision = opts.DeleteReplication.ReplicateDecisionStr
	return oi, err
}

// deleteObjectsReconciled removes data while retaining each item's authoritative
// copy until every other pool has completed its cleanup. The caller holds the
// pools-layer write locks and separates marker creation from this batch.
func (z *erasureServerPools) deleteObjectsReconciled(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions) ([]DeletedObject, []error) {
	deleted := make([]DeletedObject, len(objects))
	errs := make([]error, len(objects))
	primary := make([]int, len(objects))
	tiered := make([]bool, len(objects))
	lookup := errgroup.WithNErrs(len(objects)).WithConcurrency(32)
	for i, obj := range objects {
		// Preserve the full request identity even if lookup or cleanup fails.
		// The HTTP handler includes replication state in its response-index key.
		deleted[i] = DeletedObject{
			ObjectName:       obj.ObjectName,
			VersionID:        obj.VersionID,
			ReplicationState: obj.ReplicationState(),
		}
		primary[i] = -1
		lookup.Go(func() error {
			copies, err := z.objectPoolInfos(ctx, bucket, obj.ObjectName, ObjectOptions{VersionID: obj.VersionID, NoAuditLog: true})
			if err == nil {
				primary[i] = copies[0].Index
				for _, copy := range copies {
					tiered[i] = tiered[i] || copy.ObjInfo.TransitionedObject.Status == lifecycle.TransitionComplete
				}
			} else if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
				if isErrReadQuorum(err) {
					err = InsufficientWriteQuorum{Bucket: bucket, Object: decodeDirObject(obj.ObjectName)}
				}
				errs[i] = err
			}
			return nil
		}, i)
	}
	lookup.Wait()

	type poolBatch struct {
		objects []ObjectToDelete
		indices []int
		deleted []DeletedObject
		errs    []error
	}
	for phase := 0; phase < 2; phase++ {
		batches := make([]poolBatch, len(z.serverPools))
		for i, obj := range objects {
			if errs[i] != nil || tiered[i] {
				continue
			}
			for p := range z.serverPools {
				if (p == primary[i]) != (phase == 1) {
					continue
				}
				batches[p].objects = append(batches[p].objects, obj)
				batches[p].indices = append(batches[p].indices, i)
			}
		}
		// Each phase still uses the set layer's bulk disk I/O and runs pools
		// concurrently. Include apparently absent pools in cleanup: read-quorum
		// absence is not proof that an offline drive holds no remaining copy.
		group := errgroup.WithNErrs(len(z.serverPools))
		for p, pool := range z.serverPools {
			if len(batches[p].objects) == 0 {
				continue
			}
			group.Go(func() error {
				batches[p].deleted, batches[p].errs = pool.DeleteObjects(ctx, bucket, batches[p].objects, opts)
				return nil
			}, p)
		}
		group.Wait()
		for _, batch := range batches {
			for j, i := range batch.indices {
				if errs[i] != nil {
					continue
				}
				if batch.errs[j] != nil {
					errs[i] = batch.errs[j]
				} else if phase == 1 || primary[i] == -1 {
					deleted[i] = batch.deleted[j]
				}
			}
		}
	}
	// Tiered copies can share one remote object, including restored copies.
	// Reuse the existing reconciliation which suppresses premature tier GC.
	// Serializing this uncommon path also keeps duplicate key/version entries
	// in one request from racing their metadata updates under the shared lock.
	for i, obj := range objects {
		if !tiered[i] || errs[i] != nil {
			continue
		}
		deleteOpts := opts
		deleteOpts.VersionID, deleteOpts.NoLock = obj.VersionID, true
		deleteOpts.DeleteReplication = obj.ReplicationState()
		if opts.PrefixEnabledFn != nil {
			deleteOpts.Versioned = opts.PrefixEnabledFn(obj.ObjectName)
		}
		_, err := z.deleteObjectReconciled(ctx, bucket, obj.ObjectName, deleteOpts)
		if err != nil && !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
			errs[i] = err
		} else {
			deleted[i].found = true
		}
	}
	return deleted, errs
}
