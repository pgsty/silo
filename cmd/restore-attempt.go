// Copyright (c) 2026 Feng Ruohang
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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio/internal/bucket/lifecycle"
	xhttp "github.com/minio/minio/internal/http"
)

// The version that POST marks ongoing names the native restore attempt that
// owns the marker. Clients cannot set it: requests with reserved metadata are
// refused, and it is never extracted from headers.
const restoreAttemptKey = ReservedMetadataPrefixLower + "restore-attempt"

const (
	// restoreTakeoverWait bounds how long a POST waits for the restore lock
	// of its version. A running restore holds it for its whole run.
	restoreTakeoverWait = 2 * time.Second
	// restoreResetAttemptTimeout bounds the synchronous cleanup attempt made
	// after a restore fails. A caller whose context has ended must not wait for
	// another object operation to release the restore lock; the recovery loop
	// below retries the cleanup after this attempt gives up.
	restoreResetAttemptTimeout = 100 * time.Millisecond
	// restoreCleanupTimeout bounds each status reset and convergence pass.
	restoreCleanupTimeout = time.Minute
)

// restoreRecoveryDelays are the in-memory retries that clear the ongoing
// marker of a restore that failed before it could clear the marker itself.
// A restart loses them; a later POST then takes the marker over.
var restoreRecoveryDelays = []time.Duration{0, 100 * time.Millisecond, time.Second, 5 * time.Second, 30 * time.Second, 2 * time.Minute}

var (
	// errRestoreSuperseded: the version no longer belongs to this attempt.
	// The attempt must not rehydrate, complete or reset anything.
	errRestoreSuperseded = errors.New("restore attempt superseded")
	// errRestoreInProgress: a restore holds the restore lock of the version.
	errRestoreInProgress = errors.New("restore already in progress")
	// errRestoreUnchanged: a restore status update found nothing to write.
	errRestoreUnchanged = errors.New("restore status unchanged")
)

// restoreResetError marks a failed restore that may have left its ongoing
// marker behind. The pools layer hands it to recoverRestoreStatus.
type restoreResetError struct{ error }

func (e restoreResetError) Unwrap() error { return e.error }

// restoreVersionID is the explicit version ID of a resolved restore target.
func restoreVersionID(versionID string) string {
	if versionID == "" {
		return nullVersionID
	}
	return versionID
}

// restoreAttempt identifies one native restore of one stored version.
type restoreAttempt struct {
	ID        string    `json:"id"`
	VersionID string    `json:"v"` // "null" for the null version
	ETag      string    `json:"e"`
	Size      int64     `json:"s"`
	ModTime   time.Time `json:"m"`
}

func newRestoreAttempt(oi ObjectInfo) *restoreAttempt {
	return &restoreAttempt{
		ID:        mustGetUUID(),
		VersionID: restoreVersionID(oi.VersionID),
		ETag:      oi.ETag,
		Size:      oi.Size,
		ModTime:   oi.ModTime.UTC(),
	}
}

func (a *restoreAttempt) String() string {
	b, _ := json.Marshal(a)
	return string(b)
}

// targets reports whether oi is still the version the attempt was made for.
// A replacement under the same version ID differs in ETag, size or ModTime.
func (a *restoreAttempt) targets(oi ObjectInfo) bool {
	return a != nil && !oi.DeleteMarker && restoreVersionID(oi.VersionID) == a.VersionID &&
		oi.ETag == a.ETag && oi.Size == a.Size && oi.ModTime.Equal(a.ModTime) &&
		oi.TransitionedObject.Status == lifecycle.TransitionComplete
}

// owns reports whether the version is ongoing under this attempt.
func (a *restoreAttempt) owns(oi ObjectInfo) bool {
	return a.targets(oi) && oi.RestoreOngoing && oi.UserDefined[restoreAttemptKey] == a.ID
}

// ownsGeneration reports whether the attempt owns the authoritative
// generation of the version. Where the drives disagree only in their restore
// fields, see restoreGeneration, it owns the version only when its marker is
// the only ongoing marker there: holding one of several is not enough.
func (a *restoreAttempt) ownsGeneration(gen restoreGeneration, bucket, object string) bool {
	oi := gen.fi.ToObjectInfo(bucket, object, false)
	if !gen.split {
		return a.owns(oi)
	}
	return a.targets(oi) && len(gen.ongoing) == 1 && gen.ongoing[a.ID]
}

// restoreGeneration is the metadata generation of one version that the drives
// of a set hold authoritatively: the revision (header and normalized metadata
// digest, versionRevision) that at least max(n/2+1, its read quorum) drives
// hold. drives has each drive's own copy of it, with that drive's erasure
// index and inline data, and an invalid entry where a drive holds another or
// no revision; disks has nil there.
//
// A failed restore status write can leave drives that differ only in their
// restore fields, with no revision on a quorum. Then the generation is the
// restore-neutral revision that a quorum holds once those fields are left
// out: fi has no restore fields, and ongoing names the attempts whose
// ongoing marker some of its drives hold ("" for one without an attempt).
// Every other field, protection included, still needs the quorum.
//
// revs has, for every drive that holds the version, the full revision of the
// entry it holds, whether or not that revision is the generation; nil where a
// drive does not hold the version or cannot be read. A native restore's
// commit compares the drives against it later, see restorePublication.
type restoreGeneration struct {
	fi      FileInfo
	drives  []FileInfo
	disks   []StorageAPI
	split   bool
	ongoing map[string]bool
	revs    []*revisionKey
}

// restoreFieldKeys are the metadata keys a restore status write sets.
var restoreFieldKeys = []string{xhttp.AmzRestore, xhttp.AmzRestoreExpiryDays, xhttp.AmzRestoreRequestDate, restoreAttemptKey}

// restoreHealMeta returns latest, the metadata heal copies to drives that
// lack the version, with the restore fields that at least quorum drives of
// that version hold. When some drive holds restore fields and no set of
// them has the quorum, healing the version waits.
func restoreHealMeta(metas []FileInfo, latest FileInfo, quorum int) (FileInfo, error) {
	counts := make(map[string]int)
	fields := make(map[string]map[string]string)
	restoring := false
	for _, m := range metas {
		if !m.IsValid() || m.Deleted || !m.ModTime.Equal(latest.ModTime) {
			continue
		}
		f := make(map[string]string)
		var key strings.Builder
		for _, k := range restoreFieldKeys {
			if v, ok := m.Metadata[k]; ok {
				f[k] = v
				fmt.Fprintf(&key, "%d:%s=%d:%s;", len(k), k, len(v), v)
				restoring = true
			}
		}
		counts[key.String()]++
		fields[key.String()] = f
	}
	if !restoring {
		return latest, nil
	}
	best, bestCount := "", 0
	for key, c := range counts {
		if c > bestCount {
			best, bestCount = key, c
		}
	}
	if bestCount < quorum {
		return latest, errErasureReadQuorum
	}
	latest.Metadata = maps.Clone(latest.Metadata)
	for _, k := range restoreFieldKeys {
		delete(latest.Metadata, k)
	}
	maps.Copy(latest.Metadata, fields[best])
	return latest, nil
}

// restoreNeutralRevision is the revision of ver without its restore fields.
func restoreNeutralRevision(ver xlMetaV2ShallowVersion, metaV uint8) (revisionKey, bool) {
	var v xlMetaV2Version
	if _, err := v.unmarshalV(metaV, ver.meta); err != nil || v.Type != ObjectType || v.ObjectV2 == nil {
		return revisionKey{}, false
	}
	o := *v.ObjectV2
	o.MetaUser, o.MetaSys = maps.Clone(o.MetaUser), maps.Clone(o.MetaSys)
	for _, k := range restoreFieldKeys {
		delete(o.MetaUser, k)
		delete(o.MetaSys, k)
	}
	v.ObjectV2 = &o
	meta, err := v.MarshalMsg(nil)
	if err != nil {
		return revisionKey{}, false
	}
	return versionRevision(xlMetaV2ShallowVersion{header: v.header(), meta: meta}, xlMetaVersion), true
}

// readRestoreGeneration selects the authoritative generation of a version,
// or fails closed: a revision that only some drives hold, such as one a
// failed metadata update left behind, is never selected. An empty version ID
// addresses the latest version, as a direct restore may.
func (er erasureObjects) readRestoreGeneration(ctx context.Context, bucket, object, versionID string) (restoreGeneration, error) {
	if versionID == "" {
		fi, _, _, err := er.getObjectFileInfo(ctx, bucket, object, ObjectOptions{
			NoLock:     true,
			Transition: TransitionOptions{RestoreRequest: &RestoreObjectRequest{}},
		}, false)
		if err != nil {
			return restoreGeneration{}, err
		}
		versionID = restoreVersionID(fi.VersionID)
	}
	var uv [16]byte
	if versionID != nullVersionID {
		id, err := uuid.Parse(versionID)
		if err != nil {
			return restoreGeneration{}, errFileVersionNotFound
		}
		uv = id
	}
	disks := er.getDisks()
	n := len(disks)
	majority := n/2 + 1
	raws, errs := readAllRawFileInfo(ctx, disks, bucket, object, true)
	type revision struct {
		ver   xlMetaV2ShallowVersion
		metaV uint8
		count int
	}
	keys := make([]*revisionKey, n)
	neutral := make([]*revisionKey, n)
	revisions := make(map[revisionKey]*revision)
	neutrals := make(map[revisionKey]*revision)
	absent := 0
	for i := range disks {
		if errs[i] != nil {
			if errors.Is(errs[i], errFileNotFound) || errors.Is(errs[i], errVolumeNotFound) {
				absent++
			}
			continue
		}
		var xl xlMetaV2
		if xl.LoadOrConvert(raws[i].Buf) != nil {
			continue
		}
		found := false
		for _, ver := range xl.versions {
			if ver.header.VersionID != uv || ver.header.FreeVersion() {
				continue
			}
			key := versionRevision(ver, xl.metaV)
			keys[i], found = &key, true
			r := revisions[key]
			if r == nil {
				r = &revision{ver: ver, metaV: xl.metaV}
				revisions[key] = r
			}
			r.count++
			if nkey, ok := restoreNeutralRevision(ver, xl.metaV); ok {
				neutral[i] = &nkey
				if neutrals[nkey] == nil {
					neutrals[nkey] = &revision{ver: ver, metaV: xl.metaV}
				}
				neutrals[nkey].count++
			}
			break
		}
		if !found {
			absent++
		}
	}
	accepted := func(revs map[revisionKey]*revision) (revisionKey, bool) {
		var best *revision
		var bestKey revisionKey
		for key, r := range revs {
			if best == nil || r.count > best.count {
				best, bestKey = r, key
			}
		}
		return bestKey, best != nil && best.count >= majority &&
			best.count >= er.versionReadQuorum(ctx, bucket, object, best.ver, best.metaV, make([]FileInfo, n), make([]error, n))
	}
	gen := restoreGeneration{drives: make([]FileInfo, n), disks: make([]StorageAPI, n), revs: slices.Clone(keys)}
	bestKey, ok := accepted(revisions)
	if !ok {
		if bestKey, ok = accepted(neutrals); !ok {
			if absent >= majority {
				return restoreGeneration{}, errFileVersionNotFound
			}
			return restoreGeneration{}, errErasureReadQuorum
		}
		keys, gen.split, gen.ongoing = neutral, true, make(map[string]bool)
	}
	for i := range disks {
		if keys[i] == nil || *keys[i] != bestKey {
			continue
		}
		fi, err := getFileInfo(raws[i].Buf, bucket, object, versionID, fileInfoOpts{Data: true})
		if err != nil {
			continue
		}
		gen.drives[i], gen.disks[i] = fi, disks[i]
		if gen.split {
			if st, err := parseRestoreObjStatus(fi.Metadata[xhttp.AmzRestore]); err == nil && st.Ongoing() {
				gen.ongoing[fi.Metadata[restoreAttemptKey]] = true
			}
		}
		if !gen.fi.IsValid() {
			gen.fi = fi
		}
	}
	if !gen.fi.IsValid() && !gen.fi.Deleted {
		return restoreGeneration{}, errErasureReadQuorum
	}
	if gen.split {
		gen.fi.Metadata = maps.Clone(gen.fi.Metadata)
		for _, k := range restoreFieldKeys {
			delete(gen.fi.Metadata, k)
		}
	}
	return gen, nil
}

// updateRestoreStatus rewrites the restore fields of one stored version. It
// selects the authoritative generation of the version, see
// readRestoreGeneration, patches only the restore fields onto exactly that
// generation, keeping every other field and its ModTime, and writes it back
// only to the drives that hold it. The caller holds the object lock. update
// edits the metadata in place, or returns an error, errRestoreUnchanged to
// write nothing; ongoing names the attempts whose ongoing marker the
// generation holds. A failed read never removes the version, and a failed
// write puts the generation it read back.
func (er erasureObjects) updateRestoreStatus(ctx context.Context, bucket, object, versionID string, update func(oi ObjectInfo, meta map[string]string, ongoing map[string]bool) error) (ObjectInfo, error) {
	gen, err := er.readRestoreGeneration(ctx, bucket, object, versionID)
	if err != nil {
		return ObjectInfo{}, toObjectErr(err, bucket, object, versionID)
	}
	fi := gen.fi
	oi := fi.ToObjectInfo(bucket, object, false)
	if fi.Deleted {
		return oi, toObjectErr(errMethodNotAllowed, bucket, object)
	}
	ongoing := gen.ongoing
	if !gen.split && oi.RestoreOngoing {
		ongoing = map[string]bool{oi.UserDefined[restoreAttemptKey]: true}
	}
	meta := maps.Clone(fi.Metadata)
	if err := update(oi, meta, ongoing); err != nil {
		return oi, err
	}
	write := func(meta func(FileInfo) map[string]string) error {
		metaArr := make([]FileInfo, len(gen.drives))
		for i, d := range gen.drives {
			if gen.disks[i] == nil {
				continue
			}
			if !d.InlineData() {
				d.Data = nil
			}
			d.Metadata = meta(d)
			metaArr[i] = d
		}
		// The write assigns each drive its slot as erasure index: order the
		// drives by the version's distribution first.
		disks, metaArr := shuffleDisksAndPartsMetadata(gen.disks, metaArr, fi)
		_, err := writeUniqueFileInfo(ctx, disks, "", bucket, object, metaArr, fi.WriteQuorum(er.defaultWQuorum()))
		return err
	}
	if err := write(func(FileInfo) map[string]string { return meta }); err != nil {
		// Without the read generation back, its drives could hold two
		// revisions and no quorum for either. A split that stays differs
		// only in restore fields, which the next write or reset resolves.
		if rerr := write(func(d FileInfo) map[string]string { return d.Metadata }); rerr != nil {
			storageLogIf(ctx, fmt.Errorf("Unable to put back the restore status of %s/%s(%s): %w", bucket, object, versionID, rerr))
		}
		return oi, toObjectErr(err, bucket, object)
	}
	fi.Metadata = meta
	return fi.ToObjectInfo(bucket, object, false), nil
}

// clearRestoreStatus makes a version retryable again while attempt a still
// owns its ongoing marker. It never brings back an earlier completed status:
// POST only starts a restore when that restored copy is gone.
func (er erasureObjects) clearRestoreStatus(ctx context.Context, bucket, object, versionID string, a *restoreAttempt) error {
	_, err := er.updateRestoreStatus(ctx, bucket, object, versionID, func(oi ObjectInfo, meta map[string]string, ongoing map[string]bool) error {
		id := ""
		if a != nil {
			id = a.ID
			if !a.targets(oi) {
				return errRestoreUnchanged
			}
		}
		// Clear only this attempt's marker. Where drives disagree, another
		// attempt's marker may be the acknowledged one: leave that to it,
		// or to a later POST, which takes it over under the lock.
		if !ongoing[id] || len(ongoing) != 1 {
			return errRestoreUnchanged
		}
		delete(meta, xhttp.AmzRestore)
		delete(meta, xhttp.AmzRestoreExpiryDays)
		delete(meta, xhttp.AmzRestoreRequestDate)
		delete(meta, restoreAttemptKey)
		return nil
	})
	if errors.Is(err, errRestoreUnchanged) {
		return nil
	}
	return err
}

// restoreLock is the object lock that restores and their status updates
// share: the lock every write of the object takes.
func (z *erasureServerPools) restoreLock(bucket, object string) RWLocker {
	return z.NewObjectNSLock(bucket, object)
}

// restoreRequestStatus is what a POST restore recorded on its version.
type restoreRequestStatus struct {
	objInfo ObjectInfo
	// attempt is the restore that must rehydrate the version; nil when a
	// restored copy was still there and its expiry was renewed.
	attempt *restoreAttempt
	// owner is the restore lock of the version, held for attempt. The
	// caller hands it to the worker that runs attempt, or releases it.
	owner *restoreOwner
	// date is the request date recorded with attempt.
	date string
}

// restoreRequest records a POST restore on target, the version that POST
// resolved, on a fresh read under the object lock. The version must still
// be target: a replacement under the same version ID is refused. A copy that
// still holds its restored data is renewed. Otherwise the version is marked
// ongoing for a new attempt, which also takes over a marker that no running
// restore holds. Only the copy that is to be restored is written, so no copy
// claims a restored copy it does not hold.
//
// It takes the restore lock R of the version before the object lock O. A
// running restore holds R for its whole run, so a POST that cannot take R
// within the takeover wait answers from the drives: in progress when they
// show the version ongoing, and a retryable timeout otherwise, such as while
// another POST of the version registers. ctx must outlive the request: a new
// attempt keeps R in the returned status.
func (z *erasureServerPools) restoreRequest(ctx context.Context, bucket, object string, opts ObjectOptions, target ObjectInfo) (status restoreRequestStatus, err error) {
	object = encodeDirObject(object)
	versionID := restoreVersionID(target.VersionID)
	owner, err := z.takeRestoreOwner(ctx, bucket, object, versionID, newDynamicTimeout(restoreTakeoverWait, restoreTakeoverWait))
	if err != nil {
		if errors.As(err, &OperationTimedOut{}) && ctx.Err() == nil {
			running, rerr := z.restoreRunning(ctx, bucket, object, versionID)
			switch {
			case rerr != nil:
				return restoreRequestStatus{}, rerr
			case running:
				return restoreRequestStatus{}, errRestoreInProgress
			}
		}
		return restoreRequestStatus{}, err
	}
	defer func() {
		if status.attempt == nil {
			owner.release()
		}
	}()
	lk := z.restoreLock(bucket, object)
	lkctx, err := lk.GetLock(owner.ctx, globalOperationTimeout)
	if err != nil {
		return restoreRequestStatus{}, err
	}
	ctx = lkctx.Context()
	defer lk.Unlock(lkctx)

	expected := newRestoreAttempt(target)
	copies, err := z.objectPoolInfos(ctx, bucket, object, ObjectOptions{
		VersionID:        versionID,
		Versioned:        opts.Versioned,
		VersionSuspended: opts.VersionSuspended,
		Transition:       opts.Transition,
	})
	if err != nil {
		return restoreRequestStatus{}, err
	}
	// Restore the copy reads serve first, outside pools being decommissioned,
	// as RestoreTransitionedObject does.
	pool := -1
	for _, c := range copies {
		if !z.IsSuspended(c.Index) {
			pool = c.Index
			break
		}
	}
	if pool < 0 {
		return restoreRequestStatus{}, VersionNotFound{Bucket: bucket, Object: decodeDirObject(object), VersionID: versionID}
	}

	rreq := opts.Transition.RestoreRequest
	date := UTCNow().Format(http.TimeFormat)
	var attempt *restoreAttempt
	oi, err := z.serverPools[pool].getHashedSet(object).updateRestoreStatus(ctx, bucket, object, versionID, func(oi ObjectInfo, meta map[string]string, _ map[string]bool) error {
		if !expected.targets(oi) {
			// Not the version POST resolved, or no longer transitioned.
			return InvalidObjectState{Bucket: bucket, Object: decodeDirObject(object)}
		}
		attempt = nil
		meta[xhttp.AmzRestoreExpiryDays] = strconv.Itoa(rreq.Days)
		meta[xhttp.AmzRestoreRequestDate] = date
		if !oi.RestoreOngoing && !oi.RestoreExpires.IsZero() {
			// Cleanup removes a restored copy together with its header.
			meta[xhttp.AmzRestore] = completedRestoreObj(opts.Transition.RestoreExpiry).String()
			delete(meta, restoreAttemptKey)
			return nil
		}
		attempt = newRestoreAttempt(oi)
		meta[xhttp.AmzRestore] = ongoingRestoreObj().String()
		meta[restoreAttemptKey] = attempt.ID
		return nil
	})
	if err != nil {
		if attempt != nil {
			// The marker may have reached some drives, or all of them.
			z.recoverRestoreStatus(bucket, object, ObjectOptions{
				VersionID:  attempt.VersionID,
				Transition: TransitionOptions{attempt: attempt},
			})
		}
		return restoreRequestStatus{}, err
	}
	if attempt == nil {
		return restoreRequestStatus{objInfo: oi}, nil
	}
	return restoreRequestStatus{objInfo: oi, attempt: attempt, owner: owner, date: date}, nil
}

// restoreRunning reports, without the object lock and within the takeover
// wait, whether the drives show a restore of the version ongoing in a pool.
// An error means that this cannot be told.
func (z *erasureServerPools) restoreRunning(ctx context.Context, bucket, object, versionID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, restoreTakeoverWait)
	defer cancel()
	for _, pool := range z.serverPools {
		gen, err := pool.getHashedSet(object).readRestoreGeneration(ctx, bucket, object, versionID)
		if errors.Is(err, errFileVersionNotFound) || errors.Is(err, errFileNotFound) {
			continue
		}
		if err == nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			return false, toObjectErr(err, bucket, object, versionID)
		}
		if len(gen.ongoing) > 0 || !gen.split && gen.fi.ToObjectInfo(bucket, object, false).RestoreOngoing {
			return true, nil
		}
	}
	return false, nil
}

// restorePoolIdx returns the pool whose copy the restore rehydrates: the one
// POST marked for its attempt, or for a direct caller the existing version.
func (z *erasureServerPools) restorePoolIdx(ctx context.Context, bucket, object string, opts ObjectOptions) (int, error) {
	a := opts.Transition.attempt
	if a == nil {
		// Restore an existing version, not the latest version's write location.
		lookupOpts := opts
		lookupOpts.MetadataChg = true
		idx, err := z.getPoolIdxExistingWithOpts(ctx, bucket, object, lookupOpts)
		if err != nil && !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
			return idx, restoreResetError{err}
		}
		return idx, err
	}
	found := false
	for idx, pool := range z.serverPools {
		gen, err := pool.getHashedSet(object).readRestoreGeneration(ctx, bucket, object, a.VersionID)
		if errors.Is(err, errFileVersionNotFound) || errors.Is(err, errFileNotFound) {
			continue
		}
		if err != nil {
			return -1, restoreResetError{toObjectErr(err, bucket, object, a.VersionID)}
		}
		found = true
		if !z.IsSuspended(idx) && a.ownsGeneration(gen, bucket, object) {
			return idx, nil
		}
	}
	if !found {
		return -1, VersionNotFound{Bucket: bucket, Object: decodeDirObject(object), VersionID: a.VersionID}
	}
	return -1, errRestoreSuperseded
}

// recoverRestoreStatus retries, in memory and for a bounded time, to clear the
// ongoing marker that a failed restore left behind, so a later POST is not
// refused. Each try takes the object lock afresh and clears the marker only
// while it still belongs to this attempt.
func (z *erasureServerPools) recoverRestoreStatus(bucket, object string, opts ObjectOptions) {
	go func() {
		var err error
		for _, delay := range restoreRecoveryDelays {
			select {
			case <-GlobalContext.Done():
				return
			case <-time.After(delay):
			}
			if err = z.resetRestoreStatus(bucket, object, opts); err == nil {
				return
			}
		}
		storageLogIf(GlobalContext, fmt.Errorf("Unable to clear the restore status of %s/%s(%s): %w", bucket, object, opts.VersionID, err))
	}()
}

// resetRestoreStatus is one try of recoverRestoreStatus.
func (z *erasureServerPools) resetRestoreStatus(bucket, object string, opts ObjectOptions) error {
	ctx, cancel := context.WithTimeout(GlobalContext, restoreCleanupTimeout)
	defer cancel()
	return z.resetRestoreStatusWithContext(ctx, bucket, object, opts)
}

func (z *erasureServerPools) resetRestoreStatusWithContext(ctx context.Context, bucket, object string, opts ObjectOptions) error {
	lk := z.restoreLock(bucket, object)
	lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
	if err != nil {
		return err
	}
	defer lk.Unlock(lkctx)
	ctx = lkctx.Context()

	a := opts.Transition.attempt
	versionID := opts.VersionID
	if a != nil {
		versionID = a.VersionID
	}
	for _, pool := range z.serverPools {
		err := pool.getHashedSet(object).clearRestoreStatus(ctx, bucket, object, versionID, a)
		if err != nil && !isErrObjectNotFound(err) && !isErrVersionNotFound(err) && !isErrMethodNotAllowed(err) && !isErrBucketNotFound(err) {
			return err
		}
	}
	return nil
}
