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
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/sync/errgroup"
)

// An expiry of all versions of a key (ExpiredObjectAllVersions,
// DelMarkerExpiration, a batch expiry that keeps no versions) removes the
// versions of that key and nothing else. On the drives, object a/b lives
// inside the directory of object a, next to the metadata and data of a. The
// purge therefore never deletes that directory: it deletes the versions of
// the key one by one, by version ID, with the version delete of the drives,
// which removes the directory only once it is empty.
//
// It decides and deletes under the object lock that DeleteObject holds, on
// the authoritative history of the key in all pools (objectVersions):
//   - an ILM expiry needs the latest version to expire with all versions as
//     the scanner evaluates it on all of them (lifecycleEventsAllPools); a
//     batch expiry needs the version it matched to be the latest still;
//   - it deletes exactly the versions it approved, with every copy of them
//     in every pool and the older writes of their IDs, and nothing else;
//   - before it deletes anything it reads every drive of every set that
//     holds a copy, and refuses the whole key when a drive cannot be read or
//     when any revision of an approved version there is transitioned or,
//     when the bucket has Object Lock, protected by retention or a legal
//     hold. It deletes on exactly the drives it read;
//   - a batch expiry then authorizes every copy of every approved version,
//     and every revision of one that a drive holds, for the submitter of the
//     job, and the purge deletes nothing unless all of them are allowed;
//   - it deletes the oldest version first and the latest version last and
//     alone, once every older version is gone from every pool. A purge that
//     stops early keeps the latest version, so it never exposes an older
//     one, and the next expiry continues on a fresh history.

var (
	// errDeleteAllChanged: the version a batch expiry matched is no longer
	// the latest version of the key.
	errDeleteAllChanged = fmt.Errorf("%w: the latest version changed", errLifecycleNotApplicable)
	// errDeleteAllTiered: a version of the key is in a remote tier. Removing
	// all versions is left to a later release, which hands the remote
	// objects to the tier cleanup.
	errDeleteAllTiered = fmt.Errorf("%w: a version is transitioned", errLifecycleNotApplicable)
	// errDeleteAllBudget: the purge stopped at its budget, before the
	// latest version.
	errDeleteAllBudget = errors.New("purge of all versions stopped at its budget")
	// errDeleteAllHistoryUnavailable: a drive that may hold a revision of
	// an approved version could not be read or decoded. Callers see a
	// write quorum error.
	errDeleteAllHistoryUnavailable = fmt.Errorf("a drive that may hold a version of the key cannot be read or decoded: %w", InsufficientWriteQuorum{})
	// errDeleteAllUnsupported: only a single-object delete of the pools
	// purges all versions. Any other layer would turn the request into
	// another delete.
	errDeleteAllUnsupported = NotImplemented{Message: "purge of all versions is a single-object delete of the pools"}
)

// deleteAllBudget bounds one purge, which holds the object lock while it
// runs. It stops before the next version once it removed versions versions
// or ran for duration, its reads and checks included.
var deleteAllBudget = struct {
	versions int
	duration time.Duration
}{versions: 1000, duration: time.Minute}

// deleteAllRetries bounds how often a version delete that reached its write
// quorum is repeated on the drives that failed it.
const deleteAllRetries = 2

// deleteAllMatch identifies the latest version that a batch expiry matched.
type deleteAllMatch struct {
	VersionID string
	ModTime   time.Time
}

// matches reports whether fi is the version m identifies.
func (m deleteAllMatch) matches(fi FileInfo) bool {
	return deleteAllVersionID(m.VersionID) == deleteAllVersionID(fi.VersionID) && m.ModTime.Equal(fi.ModTime)
}

// deleteAllResult is what a purge of all versions confirmed.
type deleteAllResult struct {
	// Latest is the latest version the purge approved.
	Latest ObjectInfo
	// Removed counts the versions, delete markers included, that are gone
	// from every pool, Markers the delete markers among them. Free versions
	// and further copies of a version do not count.
	Removed, Markers int
	// Started: the purge began to delete. A failure after that can have
	// removed copies that Removed does not count.
	Started bool
	// Complete: every approved version is gone, the latest included.
	Complete bool
}

// deleteAllVersionID returns versionID, "null" for the null version.
func deleteAllVersionID(versionID string) string {
	if versionID == "" {
		return nullVersionID
	}
	return versionID
}

// deleteAllInvalid returns why opts cannot ask for a purge of all versions.
// The purge is approved either as an ILM expiry or by a batch match, which
// also authorizes the versions it deletes, and it only deletes: it never
// creates a marker, addresses a single version, moves data or deletes a
// prefix.
func (opts ObjectOptions) deleteAllInvalid() error {
	switch {
	case !opts.DeleteAllVersions:
		return errors.New("only a purge of all versions authorizes the versions it deletes")
	case opts.DeletePrefix || opts.DeletePrefixObject:
		return errors.New("a purge of all versions is not a prefix delete")
	case opts.VersionID != "":
		return errors.New("a purge of all versions addresses no single version")
	case opts.DataMovement:
		return errors.New("a purge of all versions moves no data")
	case opts.DeleteMarker || opts.Versioned || opts.VersionSuspended:
		return errors.New("a purge of all versions creates no delete marker")
	case opts.ReplicationRequest || opts.InclFreeVersions || opts.Transition != (TransitionOptions{}) ||
		opts.CheckPrecondFn != nil || opts.EvalMetadataFn != nil || opts.EvalRetentionBypassFn != nil ||
		opts.Expiration.CheckedAllPools:
		return errors.New("a purge of all versions takes no options of other deletes")
	case opts.Expiration.Expire == (opts.DeleteAllLatest != nil):
		return errors.New("a purge of all versions needs exactly one approval")
	case (opts.DeleteAllLatest != nil) != (opts.deleteAllAuthorize != nil):
		return errors.New("a batch purge of all versions, and only it, authorizes the versions it deletes")
	}
	return nil
}

// deleteAllCopy is the copy of a version in a pool: the revision of it that
// the authoritative history of the set of the key in that pool accepted.
// Copies of one write share its ModTime, since data movement keeps it and
// writes a new data dir. Other writes of a version ID, such as null versions
// written in several pools, have another ModTime.
type deleteAllCopy struct {
	pool int
	fi   FileInfo
}

// deleteAllVersion is a version of the key, "null" for the null version, and
// its copies in all pools, the newest write first and, on equal times, the
// lower pool first. The first copy is the one reads choose.
type deleteAllVersion struct {
	id     string
	copies []deleteAllCopy
}

// deleteAllHistory returns the versions of object in all pools, newest first,
// with the copies of each, from the authoritative history of each pool. It
// fails when a pool cannot tell the history.
func (z *erasureServerPools) deleteAllHistory(ctx context.Context, bucket, object string) ([]deleteAllVersion, error) {
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
			return nil, err
		}
	}

	var all []deleteAllCopy
	for pool, versions := range poolVersions {
		for _, fi := range versions {
			if fi.ModTime.IsZero() {
				// A write that cannot be ordered cannot be deleted in order.
				return nil, toObjectErr(errErasureReadQuorum, bucket, object)
			}
			all = append(all, deleteAllCopy{pool: pool, fi: fi})
		}
	}
	// The order of lifecycleEventsAllPools and of reads.
	sort.SliceStable(all, func(i, j int) bool { return all[i].fi.ModTime.After(all[j].fi.ModTime) })
	index := make(map[string]int, len(all))
	var history []deleteAllVersion
	for _, c := range all {
		id := deleteAllVersionID(c.fi.VersionID)
		if i, ok := index[id]; ok {
			history[i].copies = append(history[i].copies, c)
			continue
		}
		index[id] = len(history)
		history = append(history, deleteAllVersion{id: id, copies: []deleteAllCopy{c}})
	}
	return history, nil
}

// deleteAllApproved reports whether history holds exactly the versions that
// the ILM evaluation approved, in the same order, the same writes chosen.
func deleteAllApproved(history []deleteAllVersion, approved []ObjectInfo) bool {
	if len(history) != len(approved) {
		return false
	}
	for i, v := range history {
		got := v.copies[0].fi.ToObjectInfo("", "", false)
		want := approved[i]
		if v.id != deleteAllVersionID(want.VersionID) || !got.ModTime.Equal(want.ModTime) ||
			got.DeleteMarker != want.DeleteMarker || got.ETag != want.ETag || got.Size != want.Size {
			return false
		}
	}
	return true
}

// deleteAllVersions deletes every version of object, whose expiry of all
// versions opts describe, and nothing else, see the comment above. The
// caller holds the object lock. It returns the approved latest version, and
// what it confirmed in opts.DeleteAllResult, also on an error. A key without
// versions is a success that removes nothing.
func (z *erasureServerPools) deleteAllVersions(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	res := opts.DeleteAllResult
	if res == nil {
		res = &deleteAllResult{}
	}
	*res = deleteAllResult{}
	start := time.Now()
	name := decodeDirObject(object)
	fail := func(err error) (ObjectInfo, error) {
		// A history refused for metadata that did not decode: queue a heal
		// of each version the drives show, as deleteAllDrives does for a
		// drive it checks, so that a later attempt finds the key whole. The
		// purge remains refused.
		var undecodable undecodableHistory
		if errors.As(err, &undecodable) {
			for _, id := range undecodable.ids {
				globalMRFState.addPartialOp(PartialOperation{
					Bucket:    bucket,
					Object:    object,
					VersionID: id,
					Queued:    time.Now(),
				})
			}
		}
		if isErrReadQuorum(err) {
			err = InsufficientWriteQuorum{}
		}
		return ObjectInfo{Bucket: bucket, Name: name}, err
	}

	lr, err := globalBucketObjectLockSys.Get(bucket)
	if err != nil {
		return fail(err)
	}

	// Decide.
	var approved []ObjectInfo
	if opts.Expiration.Expire {
		var all lifecycleAllPools
		all.versions, all.events, all.err = z.lifecycleEventsAllPools(ctx, bucket, object)
		if all.err != nil || len(all.versions) > 0 {
			if err := all.expiryApplies(bucket, object, ObjectOptions{DeletePrefix: true}); err != nil {
				if all.err != nil {
					// The history refused, not the rule: fail with it, which
					// callers see as the same write quorum error.
					err = all.err
				}
				return fail(err)
			}
		}
		approved = all.versions
	}
	// The placement of the approved versions. This read may only confirm
	// them: whatever differs from the approval refuses the key.
	history, err := z.deleteAllHistory(ctx, bucket, object)
	if err != nil {
		return fail(err)
	}
	if opts.Expiration.Expire && !deleteAllApproved(history, approved) {
		return fail(InsufficientWriteQuorum{})
	}
	if len(history) == 0 {
		res.Complete = true
		return ObjectInfo{Bucket: bucket, Name: name}, nil
	}
	if opts.DeleteAllLatest != nil && !opts.DeleteAllLatest.matches(history[0].copies[0].fi) {
		return fail(errDeleteAllChanged)
	}
	if opts.Expiration.Expire {
		res.Latest = approved[0]
	} else {
		vc, _ := globalBucketVersioningSys.Get(bucket)
		res.Latest = history[0].copies[0].fi.ToObjectInfo(bucket, object, vc != nil && vc.Versioned(name))
	}
	res.Latest.Bucket, res.Latest.Name = bucket, name

	// Check every write before deleting any: the accepted revisions, then
	// every revision on every drive that the purge will delete on.
	ids := make(map[string]bool, len(history))
	for _, v := range history {
		ids[v.id] = true
		for _, c := range v.copies {
			if err := deleteAllRefuses(ctx, bucket, object, c.fi, lr.LockEnabled); err != nil {
				return fail(err)
			}
		}
	}
	// A batch expiry deletes as its submitter: every write it is about to
	// delete, the accepted copies and every revision a drive holds, must be
	// allowed with the version ID and tags it has now.
	var writes *deleteAllWrites
	if opts.deleteAllAuthorize != nil {
		writes = &deleteAllWrites{bucket: bucket, name: name, seen: make(map[[2]string]bool, len(history))}
		for _, v := range history {
			for _, c := range v.copies {
				writes.add(c.fi)
			}
		}
	}
	drives := make([][]StorageAPI, len(z.serverPools))
	for pool := range z.serverPools {
		if drives[pool], err = z.serverPools[pool].getHashedSet(object).deleteAllDrives(ctx, bucket, object, ids, lr.LockEnabled, writes); err != nil {
			return fail(err)
		}
	}
	if opts.deleteAllAuthorize != nil {
		if err := opts.deleteAllAuthorize(writes.versions); err != nil {
			return fail(err)
		}
	}

	// Delete the oldest version first. The latest one is the last and is
	// only reached once every older one is gone from every pool.
	for i := len(history) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if res.Removed >= deleteAllBudget.versions || time.Since(start) >= deleteAllBudget.duration {
			return fail(errDeleteAllBudget)
		}
		res.Started = true
		if err := z.deleteAllCopies(ctx, bucket, object, history[i], drives); err != nil {
			return fail(err)
		}
		res.Removed++
		if history[i].copies[0].fi.Deleted {
			res.Markers++
		}
	}
	res.Complete = true
	return res.Latest, nil
}

// deleteAllWrites collects, for the authorization of a batch purge, the
// writes it deletes: one of each distinct version ID and tags.
type deleteAllWrites struct {
	bucket, name string
	seen         map[[2]string]bool
	versions     []ObjectInfo
}

// add adds the write fi unless w is nil or holds one with its version ID and
// tags.
func (w *deleteAllWrites) add(fi FileInfo) {
	if w == nil {
		return
	}
	key := [2]string{deleteAllVersionID(fi.VersionID), fi.Metadata[xhttp.AmzObjectTagging]}
	if w.seen[key] {
		return
	}
	w.seen[key] = true
	w.versions = append(w.versions, fi.ToObjectInfo(w.bucket, w.name, true))
}

// tierRefusesDeleteAll reports whether a version with these transition
// fields makes the purge refuse its key: any version that is not a free
// version and is transitioned, being transitioned, or restored. A free
// version only records a remote object for the tier cleanup.
func tierRefusesDeleteAll(freeVersion bool, status, tier, remote string) bool {
	return !freeVersion && (status != "" || tier != "" || remote != "")
}

// deleteAllTierRefuses: see tierRefusesDeleteAll.
func (fi FileInfo) deleteAllTierRefuses() bool {
	return tierRefusesDeleteAll(fi.TierFreeVersion(), fi.TransitionStatus, fi.TransitionTier, fi.TransitionedObjName)
}

// deleteAllTierRefuses: see tierRefusesDeleteAll.
func (oi ObjectInfo) deleteAllTierRefuses() bool {
	t := oi.TransitionedObject
	return tierRefusesDeleteAll(t.FreeVersion, t.Status, t.Tier, t.Name)
}

// deleteAllRefuses returns why the purge must keep the key that holds the
// revision fi of an approved version: it is transitioned, whose remote
// object a later release hands to the tier cleanup, or, with Object Lock,
// protected by retention or a legal hold.
func deleteAllRefuses(ctx context.Context, bucket, object string, fi FileInfo, lockEnabled bool) error {
	if fi.deleteAllTierRefuses() {
		return errDeleteAllTiered
	}
	if lockEnabled && enforceRetentionForDeletion(ctx, fi.ToObjectInfo(bucket, object, true)) {
		return ObjectLocked{Bucket: bucket, Object: decodeDirObject(object), VersionID: deleteAllVersionID(fi.VersionID)}
	}
	return nil
}

// deleteAllDrives reads object on every drive of the set and checks each
// revision of the versions ids that a drive holds with deleteAllRefuses, and
// adds it to writes.
// A minority of drives can hold a revision other than the accepted one, and
// heal would later remove what the purge leaves on a drive, so a drive that
// cannot be read or decoded refuses the key. A drive without the object
// holds nothing to check. It returns the drive handles it read, which the
// purge deletes on; a handle that a reconnect installs later is not used. A
// handle names a drive, not a backend: a backend that replaces the drive
// behind it starts empty and receives this object only from a write or a
// heal of it, which take the object lock the purge holds.
func (er erasureObjects) deleteAllDrives(ctx context.Context, bucket, object string, ids map[string]bool, lockEnabled bool, writes *deleteAllWrites) ([]StorageAPI, error) {
	disks := slices.Clone(er.getDisks())
	raws, errs := readAllRawFileInfo(ctx, disks, bucket, object, false)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for i := range disks {
		if errors.Is(errs[i], errFileNotFound) || errors.Is(errs[i], errVolumeNotFound) {
			continue
		}
		if errs[i] != nil {
			return nil, errDeleteAllHistoryUnavailable
		}
		var xl xlMetaV2
		if err := xl.LoadOrConvert(raws[i].Buf); err != nil {
			if errors.Is(err, errFileCorrupt) {
				// The purge remains refused. Heal each approved version explicitly,
				// including a noncurrent null version, before a later attempt retries.
				for id := range ids {
					er.addPartial(bucket, object, id)
				}
			}
			return nil, errDeleteAllHistoryUnavailable
		}
		versions, err := xl.ListVersions(bucket, object, false)
		if err != nil {
			return nil, errDeleteAllHistoryUnavailable
		}
		for _, fi := range versions {
			// A minority-drive or other-pool revision can be hidden by the
			// logical history merge. It still owns its remote object.
			if tierRefusesDeleteAll(fi.TierFreeVersion(), fi.TransitionStatus, fi.TransitionTier, fi.TransitionedObjName) {
				return nil, errDeleteAllTiered
			}
			if fi.TierFreeVersion() || !ids[deleteAllVersionID(fi.VersionID)] {
				continue
			}
			if err := deleteAllRefuses(ctx, bucket, object, fi, lockEnabled); err != nil {
				return nil, err
			}
			writes.add(fi)
		}
	}
	return disks, nil
}

// deleteAllCopies deletes every copy of the version v: the older writes of
// its ID first, the copy that reads choose last, so that a failure leaves
// what a read returned before. It deletes on the drives that drives holds
// for the pool of a copy.
func (z *erasureServerPools) deleteAllCopies(ctx context.Context, bucket, object string, v deleteAllVersion, drives [][]StorageAPI) error {
	for i := len(v.copies) - 1; i >= 0; i-- {
		pool := v.copies[i].pool
		set := z.serverPools[pool].getHashedSet(object)
		if err := set.purgeVersion(ctx, bucket, object, v.id, drives[pool]); err != nil {
			return toObjectErr(err, bucket, decodeDirObject(object), v.id)
		}
	}
	return nil
}

// purgeVersion physically removes the version versionID of object from
// disks, the drives of the set that deleteAllDrives checked: no delete
// marker, no replication state, no free version. A drive that does not hold
// the version counts as done, so that a retry is idempotent. When the delete
// reaches its write quorum but fails on some drives, it is repeated on those
// while the caller still holds the object lock; what remains is left to
// heal. The caller holds the object lock.
func (er erasureObjects) purgeVersion(ctx context.Context, bucket, object, versionID string, disks []StorageAPI) error {
	writeQuorum := len(disks)/2 + 1
	fi := FileInfo{Name: object, VersionID: versionID}
	// The purge checked that no drive it deletes on holds a transitioned
	// revision. A free version would hand a remote object to the tier
	// cleanup, so none is made.
	fi.SetSkipTierFreeVersion()

	errs := make([]error, len(disks))
	for attempt := 0; attempt <= deleteAllRetries; attempt++ {
		g := errgroup.WithNErrs(len(disks))
		for index := range disks {
			if attempt > 0 && (errs[index] == nil || disks[index] == nil) {
				continue
			}
			g.Go(func() error {
				if disks[index] == nil {
					return errDiskNotFound
				}
				err := disks[index].DeleteVersion(ctx, bucket, object, fi, false, DeleteOptions{})
				if errors.Is(err, errFileNotFound) || errors.Is(err, errFileVersionNotFound) {
					return nil
				}
				return err
			}, index)
		}
		for index, err := range g.Wait() {
			if attempt == 0 || (errs[index] != nil && disks[index] != nil) {
				errs[index] = err
			}
		}
		if err := reduceWriteQuorumErrs(ctx, errs, objectOpIgnoredErrs, writeQuorum); err != nil {
			er.addPartial(bucket, object, versionID)
			return err
		}
		if !slices.ContainsFunc(errs, func(err error) bool { return err != nil }) {
			return nil
		}
		retry := false
		for index, err := range errs {
			retry = retry || err != nil && disks[index] != nil
		}
		if !retry {
			break
		}
	}
	er.addPartial(bucket, object, versionID)
	return nil
}
