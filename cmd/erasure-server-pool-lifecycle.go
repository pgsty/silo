// Copyright (c) 2026 Denis Babchuk
//
// This file is part of Silo Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
)

// An ordinary ILM rejection is not evidence that the version is absent. In
// particular it must not acknowledge a pending replication purge.
var errLifecycleNotApplicable = errors.New("lifecycle expiry no longer applies")

// ILM decides on the versions of an object that one pool holds: the scanner
// and the drive heal read the drives of one set, decommission and rebalance
// walk one pool, and a GET or HEAD of a version reads the pool that holds it.
// IsLatest, NumVersions and SuccessorModTime count only these. An object can
// have versions in several pools: from two concurrent first writes, from
// overwrites that went to another pool, from data movement. The expiries
// these decisions run delete in every pool, so a version that is the latest
// in its own pool but not of the object had a newer version hidden under a
// delete marker or deleted with all versions, and a delete marker without
// noncurrent versions in its pool was removed over the versions of another
// pool. Deciding on fewer versions only delays the expiry of a noncurrent
// version: its successor in the pool is not older than the one of the object,
// and fewer newer versions count against NewerNoncurrentVersions.
//
// Before an expiry deletes in any pool, it is evaluated again with the
// versions of the object in all pools, as the scanner would evaluate it if
// one pool held them all. An expiry that no longer applies is not run, as the
// recheck of a set does it: the scanner queues it again once the rule
// applies to the object.

// objectVersions returns the versions of object that a read quorum of the
// drives of the set agree on, newest first, without free versions. It returns
// no versions when the set does not hold the object, and an error when too
// few drives answer to tell.
func (er erasureObjects) objectVersions(ctx context.Context, bucket, object string) ([]FileInfo, error) {
	disks := er.getDisks()
	rawFileInfos, errs := readAllRawFileInfo(ctx, disks, bucket, object, false)
	readQuorum := (len(disks) + 1) / 2

	var (
		metas   [][]xlMetaV2ShallowVersion
		metaV   uint8
		unknown int
	)
	for i, rf := range rawFileInfos {
		if errs[i] != nil {
			if !errors.Is(errs[i], errFileNotFound) && !errors.Is(errs[i], errVolumeNotFound) {
				unknown++
			}
			continue
		}
		var xl xlMetaV2
		if err := xl.LoadOrConvert(rf.Buf); err != nil {
			unknown++
			continue
		}
		metas = append(metas, xl.versions)
		metaV = xl.metaV
	}
	if len(metas) < readQuorum {
		if len(metas)+unknown < readQuorum {
			return nil, nil // not in this set
		}
		return nil, toObjectErr(errErasureReadQuorum, bucket, object)
	}

	merged := mergeXLV2Versions(readQuorum, false, 0, metas...)
	if len(merged) == 0 {
		for _, versions := range metas {
			if len(versions) > 0 {
				return nil, toObjectErr(errErasureReadQuorum, bucket, object)
			}
		}
		return nil, nil
	}
	all, err := xlMetaV2{versions: merged, metaV: metaV}.ListVersions(bucket, object, false)
	if err != nil {
		return nil, toObjectErr(err, bucket, object)
	}
	versions := all[:0]
	for _, fi := range all {
		if !fi.TierFreeVersion() {
			versions = append(versions, fi)
		}
	}
	return versions, nil
}

// lifecycleEventsAllPools returns the versions of object in all pools,
// newest first, and the lifecycle event of each as the scanner evaluates it
// on them. A version with copies in several pools, as an interrupted move
// leaves it, counts once.
func (z *erasureServerPools) lifecycleEventsAllPools(ctx context.Context, bucket, object string) ([]ObjectInfo, []lifecycle.Event, error) {
	lc, err := globalLifecycleSys.Get(bucket)
	if err != nil {
		if errors.Is(err, BucketLifecycleNotFound{Bucket: bucket}) {
			return nil, nil, errLifecycleNotApplicable
		}
		return nil, nil, err
	}
	lr, err := globalBucketObjectLockSys.Get(bucket)
	if err != nil {
		return nil, nil, err
	}
	rcfg, err := getReplicationConfig(ctx, bucket)
	if err != nil {
		return nil, nil, err
	}

	poolVersions := make([][]FileInfo, len(z.serverPools))
	errs := make([]error, len(z.serverPools))
	var wg sync.WaitGroup
	for i, pool := range z.serverPools {
		wg.Add(1)
		go func(i int, set *erasureObjects) {
			defer wg.Done()
			poolVersions[i], errs[i] = set.objectVersions(ctx, bucket, object)
		}(i, pool.getHashedSet(object))
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, nil, err
		}
	}

	vc, _ := globalBucketVersioningSys.Get(bucket)
	versioned := vc != nil && vc.Versioned(decodeDirObject(object))
	var all []PoolObjInfo
	for pool, versions := range poolVersions {
		for _, fi := range versions {
			all = append(all, PoolObjInfo{Index: pool, ObjInfo: fi.ToObjectInfo(bucket, object, versioned)})
		}
	}
	// Each pool lists its versions newest first. On equal times the lower
	// pool comes first, as reads choose it.
	sort.SliceStable(all, func(i, j int) bool { return all[i].ObjInfo.ModTime.After(all[j].ObjInfo.ModTime) })
	seen := make(map[string]int, len(all))
	var versions [][]PoolObjInfo
	for _, copy := range all {
		if i, ok := seen[copy.ObjInfo.VersionID]; ok {
			versions[i] = append(versions[i], copy)
			continue
		}
		seen[copy.ObjInfo.VersionID] = len(versions)
		versions = append(versions, []PoolObjInfo{copy})
	}

	objInfos := make([]ObjectInfo, len(versions))
	objOpts := make([]lifecycle.ObjectOpts, len(versions))
	for i, copies := range versions {
		oi := copies[0].ObjInfo
		if len(copies) > 1 {
			// Count the version once, but retain independently ordered lock
			// and tag revisions, including explicit removals, from every copy.
			oi = mergedPoolObjectInfo(copies)
		}
		oi.IsLatest = i == 0
		oi.NumVersions = len(versions)
		oi.SuccessorModTime = time.Time{}
		if i > 0 {
			oi.SuccessorModTime = objInfos[i-1].ModTime
		}
		objInfos[i] = oi
		objOpts[i] = oi.ToLifecycleOpts()
	}
	events, err := lifecycle.NewEvaluator(*lc).WithLockRetention(&lr).WithReplicationConfig(rcfg).Eval(objOpts)
	if err != nil {
		return nil, nil, err
	}
	return objInfos, events, nil
}

// lifecycleAllPools holds the versions of an object in all pools and their
// lifecycle events, see lifecycleEventsAllPools.
type lifecycleAllPools struct {
	versions []ObjectInfo
	events   []lifecycle.Event
	err      error
}

// checkExpiryAllPools returns nil when the ILM expiry that opts describe
// still applies to object with the versions it has in all pools, see
// lifecycleAllPools.expiryApplies.
func (z *erasureServerPools) checkExpiryAllPools(ctx context.Context, bucket, object string, opts ObjectOptions) error {
	var all lifecycleAllPools
	all.versions, all.events, all.err = z.lifecycleEventsAllPools(ctx, bucket, object)
	return all.expiryApplies(bucket, object, opts)
}

// expiryApplies returns nil when the ILM expiry that opts describe applies
// to the versions. A missing version and a rejected expiry remain distinct:
//   - an expiry of all versions (DeletePrefix) needs the latest version to
//     expire with all versions;
//   - a delete marker (no VersionID) hides the latest version, which has to
//     expire;
//   - a version (VersionID) has to expire by itself: a noncurrent version,
//     or a delete marker without noncurrent versions.
func (all lifecycleAllPools) expiryApplies(bucket, object string, opts ObjectOptions) error {
	if all.err != nil {
		if _, ok := all.err.(InsufficientReadQuorum); ok {
			return InsufficientWriteQuorum{}
		}
		return all.err
	}
	name := decodeDirObject(object)
	switch {
	case opts.DeletePrefix:
		if len(all.events) > 0 && all.events[0].Action.DeleteAll() {
			return nil
		}
	case opts.VersionID == "":
		if len(all.events) > 0 && (all.events[0].Action == lifecycle.DeleteAction || all.events[0].Action == lifecycle.DeleteAllVersionsAction) {
			return nil
		}
	default:
		for i, oi := range all.versions {
			if oi.VersionID == opts.VersionID || oi.VersionID == "" && opts.VersionID == nullVersionID {
				if all.events[i].Action == lifecycle.DeleteVersionAction {
					return nil
				}
				return errLifecycleNotApplicable
			}
		}
		return VersionNotFound{Bucket: bucket, Object: name, VersionID: opts.VersionID}
	}
	if len(all.versions) > 0 {
		return errLifecycleNotApplicable
	}
	return ObjectNotFound{Bucket: bucket, Object: name}
}

// expiryNeedsAllPools reports whether an ILM expiry in opts deletes or hides
// versions by a rule that depends on the other versions of the object. A
// restored copy expires by its own restore date. Without versions each copy
// of an object is a write of its own, and a set rechecks the rule on its
// copy (deleteObjectFromAllPools).
func (z *erasureServerPools) expiryNeedsAllPools(opts ObjectOptions) bool {
	if !opts.Expiration.Expire || z.SinglePool() || opts.Transition.ExpireRestored {
		return false
	}
	return opts.DeletePrefix || opts.VersionID != "" || opts.Versioned || opts.VersionSuspended
}

// migrationExpiryApplies reports whether the ILM expiry evt, which a
// decommission or rebalance decided for oi on the versions of the pool it
// walks, applies with the versions of the object in all pools too. Only then
// may the walk leave the version to the expiry instead of moving it. A
// version that is the latest in the walked pool can be a noncurrent version
// of the object, and a delete marker alone in that pool can hide versions in
// another one. Such a version is moved like any other, and the scanner
// applies the rule in the pool that holds the object then.
func (z *erasureServerPools) migrationExpiryApplies(ctx context.Context, oi ObjectInfo, evt lifecycle.Event) bool {
	// The options the expiry deletes with, see
	// applyExpiryOnNonTransitionedObjects and expireTransitionedObject.
	opts := ObjectOptions{
		Expiration:       ExpirationOptions{Expire: true},
		Versioned:        globalBucketVersioningSys.PrefixEnabled(oi.Bucket, oi.Name),
		VersionSuspended: globalBucketVersioningSys.PrefixSuspended(oi.Bucket, oi.Name),
	}
	if evt.Action.DeleteVersioned() {
		opts.VersionID = oi.VersionID
	}
	if evt.Action.DeleteAll() {
		opts.DeletePrefix = true
	}
	opts.Transition.ExpireRestored = evt.Action.DeleteRestored()
	if !z.expiryNeedsAllPools(opts) {
		return true
	}
	return z.checkExpiryAllPools(ctx, oi.Bucket, encodeDirObject(oi.Name), opts) == nil
}
