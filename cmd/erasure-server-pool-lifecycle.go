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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	"github.com/minio/minio/internal/bucket/replication"
	xhttp "github.com/minio/minio/internal/http"
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

// objectVersions returns the versions of object that the drives of the set
// hold authoritatively, newest first, without free versions. It returns no
// versions when the set does not hold the object, and an error when the
// drives cannot tell its complete history.
//
// Expiry deletes by this history, so a revision of a version, its header
// and its metadata (versionRevision), counts only when more than half of
// the configured drives and the read quorum of its metadata hold it. A
// version that some drive shows without such a revision, or too many
// unreadable drives, could hide what an expiry must not delete. Free
// versions are tier GC records and do not count.
func (er erasureObjects) objectVersions(ctx context.Context, bucket, object string) ([]FileInfo, error) {
	disks := er.getDisks()
	rawFileInfos, errs := readAllRawFileInfo(ctx, disks, bucket, object, false)
	majority := len(disks)/2 + 1

	var (
		metas   [][]xlMetaV2ShallowVersion
		metaVs  []uint8
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
		metaVs = append(metaVs, xl.metaV)
		metaV = xl.metaV
	}
	// Without an unknown drive the history is complete, also on one drive.
	if unknown > 0 && unknown >= len(disks)/2 {
		return nil, toObjectErr(errErasureReadQuorum, bucket, object)
	}

	quorumMetas, quorumErrs := make([]FileInfo, len(disks)), make([]error, len(disks))
	merged, err := authoritativeHistory(ctx, metas, metaVs, metaV, majority, func(ver xlMetaV2ShallowVersion, metaV uint8) int {
		return er.versionReadQuorum(ctx, bucket, object, ver, metaV, quorumMetas, quorumErrs)
	})
	if err != nil {
		return nil, toObjectErr(err, bucket, object)
	}
	if merged == nil {
		return nil, nil // not in this set
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

// revisionKey identifies a revision of a version: its header and a strong
// digest of its metadata. The header Signature is a 32-bit fold of weak
// hashes; two revisions can share it.
type revisionKey struct {
	header xlMetaV2VersionHeader
	digest [sha256.Size]byte
}

// versionRevision returns the revision of ver, whose metadata is encoded as
// metaV describes. As Signature does, it leaves out the fields that differ
// between the drives of one write: the erasure index, empty part lists and,
// for legacy versions, the release and the per-shard checksums. The digest
// input is canonical: each map, including the part checksums of a legacy
// version, is its own section with its entry count and sorted,
// length-prefixed entries, since msgp encodes maps in iteration order and an
// entry must not move between maps unnoticed. The header of a
// legacy version carries a signature over its per-shard checksums, so the
// key replaces it with one from the digest.
func versionRevision(ver xlMetaV2ShallowVersion, metaV uint8) revisionKey {
	h := sha256.New()
	writeUint := func(n int) {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], uint64(n))
		h.Write(b[:])
	}
	writeField := func(b []byte) {
		writeUint(len(b))
		h.Write(b)
	}
	section := func(name string, entries int) {
		writeField([]byte(name))
		writeUint(entries)
	}
	writeStrings := func(name string, m map[string]string) {
		section(name, len(m))
		for _, k := range slices.Sorted(maps.Keys(m)) {
			writeField([]byte(k))
			writeField([]byte(m[k]))
		}
	}
	writeBytes := func(name string, m map[string][]byte) {
		section(name, len(m))
		for _, k := range slices.Sorted(maps.Keys(m)) {
			writeField([]byte(k))
			writeField(m[k])
		}
	}
	key := revisionKey{header: ver.header}
	var v xlMetaV2Version
	if _, err := v.unmarshalV(metaV, ver.meta); err == nil {
		var (
			bts []byte
			err error = errFileCorrupt
		)
		section("type", 1)
		writeField([]byte{byte(v.Type)})
		switch {
		case v.Type == ObjectType && v.ObjectV2 != nil:
			c := *v.ObjectV2
			c.ErasureIndex = 0
			if !slices.ContainsFunc(c.PartETags, func(tag string) bool { return tag != "" }) {
				c.PartETags = nil
			}
			if len(c.PartActualSizes) == 0 {
				c.PartActualSizes = nil
			}
			writeStrings("user", c.MetaUser)
			writeBytes("sys", c.MetaSys)
			c.MetaUser, c.MetaSys = nil, nil
			bts, err = c.MarshalMsg(nil)
		case v.Type == DeleteType && v.DeleteMarker != nil:
			c := *v.DeleteMarker
			writeBytes("sys", c.MetaSys)
			c.MetaSys = nil
			bts, err = c.MarshalMsg(nil)
		case v.Type == LegacyType && v.ObjectV1 != nil:
			c := *v.ObjectV1
			c.Erasure.Index = 0
			c.Erasure.Checksums = nil
			c.Minio.Release = ""
			writeStrings("meta", c.Meta)
			c.Meta = nil
			// Part checksums are the only other map: one section per part.
			section("parts", len(c.Parts))
			c.Parts = slices.Clone(c.Parts)
			for i := range c.Parts {
				writeStrings("part-checksums", c.Parts[i].Checksums)
				c.Parts[i].Checksums = nil
			}
			bts, err = c.MarshalMsg(nil)
		}
		if err == nil {
			section("fields", 1)
			writeField(bts)
			h.Sum(key.digest[:0])
			if v.Type == LegacyType {
				copy(key.header.Signature[:], key.digest[:])
			}
			return key
		}
		h.Reset()
	}
	// Undecodable metadata only matches the same bytes.
	section("raw", 1)
	writeField(ver.meta)
	h.Sum(key.digest[:0])
	return key
}

// authoritativeHistory returns the versions of metas, the version lists of
// the drives that answered, as merged newest first, when every version
// that is not a free version has a revision that at least majority drives
// and its readQuorum hold. It returns no versions when none is live,
// errErasureReadQuorum when the drives cannot tell the history, and the
// error of ctx once it ends. metaVs are the metadata versions of metas,
// metaV the one the merged result is decoded with.
func authoritativeHistory(ctx context.Context, metas [][]xlMetaV2ShallowVersion, metaVs []uint8, metaV uint8, majority int, readQuorum func(xlMetaV2ShallowVersion, uint8) int) ([]xlMetaV2ShallowVersion, error) {
	// Count the drives that hold each revision; a drive counts once for each
	// version.
	type revision struct {
		ver   xlMetaV2ShallowVersion
		metaV uint8
		count int
	}
	keys := make([][]revisionKey, len(metas))
	revisions := make(map[[16]byte]map[revisionKey]*revision)
	live := make(map[[16]byte]bool)
	for i, versions := range metas {
		keys[i] = make([]revisionKey, len(versions))
		seen := make(map[[16]byte]bool, len(versions))
		for j, ver := range versions {
			// Decoding and hashing every history has a cost; stop with the
			// request.
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			id := ver.header.VersionID
			if !ver.header.FreeVersion() {
				live[id] = true
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			key := versionRevision(ver, metaVs[i])
			keys[i][j] = key
			if revisions[id] == nil {
				revisions[id] = make(map[revisionKey]*revision)
			}
			r := revisions[id][key]
			if r == nil {
				r = &revision{ver: ver, metaV: metaVs[i]}
				revisions[id][key] = r
			}
			r.count++
		}
	}
	accepted := make(map[[16]byte]revisionKey, len(live))
	for id := range live {
		var best *revision
		var bestKey revisionKey
		for key, r := range revisions[id] {
			if !key.header.FreeVersion() && (best == nil || r.count > best.count) {
				best, bestKey = r, key
			}
		}
		// Only one revision can hold more than half of the drives.
		if best == nil || best.count < majority || best.count < readQuorum(best.ver, best.metaV) {
			return nil, errErasureReadQuorum
		}
		accepted[id] = bestKey
	}

	// The strict merge orders the history. It has to hold exactly the
	// accepted revisions. A minority revision that sorts first would reset
	// its count, and one that shares the header could stand in for the
	// accepted one, so the merge only sees the accepted revision of each
	// version and free versions as they are. It sees the headers of the
	// keys, which do not differ between the drives of a legacy version.
	filtered := make([][]xlMetaV2ShallowVersion, len(metas))
	for i, versions := range metas {
		for j, ver := range versions {
			key, ok := accepted[ver.header.VersionID]
			switch {
			case ver.header.FreeVersion():
			case ok && keys[i][j] == key:
				ver.header = key.header
			default:
				continue
			}
			filtered[i] = append(filtered[i], ver)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	merged := mergeXLV2Versions(majority, true, 0, filtered...)
	emitted := make(map[[16]byte]bool, len(accepted))
	for _, ver := range merged {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if ver.header.FreeVersion() {
			continue
		}
		id := ver.header.VersionID
		if key, ok := accepted[id]; !ok || emitted[id] || versionRevision(ver, metaV) != key {
			return nil, errErasureReadQuorum
		}
		emitted[id] = true
	}
	if len(emitted) != len(accepted) {
		return nil, errErasureReadQuorum
	}
	if len(accepted) == 0 {
		return nil, nil
	}
	return merged, nil
}

// versionReadQuorum returns the read quorum of the metadata of ver, as
// objectQuorumFromMeta derives it when all drives of the set hold it, or
// more than the drives when its metadata cannot be read. metaArr and errs
// have one entry for each drive; errs stays nil.
func (er erasureObjects) versionReadQuorum(ctx context.Context, bucket, object string, ver xlMetaV2ShallowVersion, metaV uint8, metaArr []FileInfo, errs []error) int {
	var v xlMetaV2Version
	if _, err := v.unmarshalV(metaV, ver.meta); err != nil {
		return len(metaArr) + 1
	}
	fi, err := v.ToFileInfo(bucket, object, false)
	if err != nil {
		return len(metaArr) + 1
	}
	for i := range metaArr {
		metaArr[i] = fi
	}
	readQuorum, _, err := objectQuorumFromMeta(ctx, metaArr, errs, er.defaultParityCount)
	if err != nil {
		return len(metaArr) + 1
	}
	return readQuorum
}

// lifecycleEventsAllPools returns the versions of object in all pools,
// newest first, and the lifecycle event of each as the scanner evaluates it
// on them. A version with copies in several pools, as an interrupted move
// leaves it, counts once, and so do other writes of its version ID.
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

	e := lifecycle.NewEvaluator(*lc).WithLockRetention(&lr).WithReplicationConfig(rcfg)
	objInfos := make([]ObjectInfo, len(versions))
	objOpts := make([]lifecycle.ObjectOpts, len(versions))
	for i, copies := range versions {
		// Copies with another ModTime are other writes of the version ID,
		// such as null versions written in several pools, not duplicates of
		// one write. The newest is the version. Data movement writes a new
		// data dir, so only ModTime tells the duplicates of a write apart.
		// An older write that is still protected keeps the whole object.
		newest := 1
		for newest < len(copies) && copies[newest].ObjInfo.ModTime.Equal(copies[0].ObjInfo.ModTime) {
			newest++
		}
		for _, older := range copies[newest:] {
			if opts := older.ObjInfo.ToLifecycleOpts(); e.IsObjectLocked(opts) || e.IsPendingReplication(opts) {
				return nil, nil, errLifecycleNotApplicable
			}
		}
		copies = copies[:newest]
		oi := copies[0].ObjInfo
		if len(copies) > 1 {
			// The copies must tell which protection is the newest, and no
			// copy may carry replication state that the merge would drop.
			if !lockRevisionsOrdered(copies) || !replicationStatesAgree(copies) {
				return nil, nil, errLifecycleNotApplicable
			}
			// Count the version once, but retain independently ordered lock
			// and tag revisions, including explicit removals, from every copy.
			oi = mergedPoolObjectInfo(copies)
			setLifecycleLockState(oi.UserDefined, newestLockState(copies))
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
	events, err := e.Eval(objOpts)
	if err != nil {
		return nil, nil, err
	}
	return objInfos, events, nil
}

// lockRevisionTime parses the timestamp of an Object Lock revision. Unlike
// olderThan, a missing, malformed or zero timestamp orders nothing.
func lockRevisionTime(stamp string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, stamp)
	return t, err == nil && !t.IsZero()
}

// lockRevisionNewer reports whether the revision stamped newer strictly
// supersedes the one stamped older.
func lockRevisionNewer(newer, older string) bool {
	n, ok := lockRevisionTime(newer)
	o, ok2 := lockRevisionTime(older)
	return ok && ok2 && n.After(o)
}

// lifecycleLockState returns the Object Lock state of metadata as the
// lifecycle evaluator reads it (objectlock.GetObjectRetentionMeta and
// GetObjectLegalHoldMeta): a lowercase key before its canonical form. The
// stored state (storedObjectLockState) only has lowercase keys.
func lifecycleLockState(metadata map[string]string) objectLockState {
	get := func(canonical string) string {
		if v, ok := metadata[strings.ToLower(canonical)]; ok {
			return v
		}
		return metadata[canonical]
	}
	return objectLockState{
		mode:               get(objectlock.AmzObjectLockMode),
		retainUntil:        get(objectlock.AmzObjectLockRetainUntilDate),
		retentionTimestamp: get(ReservedMetadataPrefix + ObjectLockRetentionTimestamp),
		legalHold:          get(objectlock.AmzObjectLockLegalHold),
		legalHoldTimestamp: get(ReservedMetadataPrefix + ObjectLockLegalHoldTimestamp),
	}
}

// setLifecycleLockState sets state in metadata so that the evaluator reads
// it: lowercase keys take precedence over canonical ones.
func setLifecycleLockState(metadata map[string]string, state objectLockState) {
	set := func(canonical, value string) {
		lower := strings.ToLower(canonical)
		_, hasLower := metadata[lower]
		_, hasCanonical := metadata[canonical]
		if value != "" || hasLower || hasCanonical {
			metadata[lower] = value
		}
	}
	set(objectlock.AmzObjectLockMode, state.mode)
	set(objectlock.AmzObjectLockRetainUntilDate, state.retainUntil)
	set(ReservedMetadataPrefix+ObjectLockRetentionTimestamp, state.retentionTimestamp)
	set(objectlock.AmzObjectLockLegalHold, state.legalHold)
	set(ReservedMetadataPrefix+ObjectLockLegalHoldTimestamp, state.legalHoldTimestamp)
}

// newestLockState returns the newest hold and the newest retention of the
// copies of a version, which lockRevisionsOrdered found equal or ordered.
func newestLockState(copies []PoolObjInfo) objectLockState {
	state := lifecycleLockState(copies[0].ObjInfo.UserDefined)
	for _, copy := range copies[1:] {
		next := lifecycleLockState(copy.ObjInfo.UserDefined)
		if lockRevisionNewer(next.legalHoldTimestamp, state.legalHoldTimestamp) {
			state.legalHold, state.legalHoldTimestamp = next.legalHold, next.legalHoldTimestamp
		}
		if lockRevisionNewer(next.retentionTimestamp, state.retentionTimestamp) {
			state.mode, state.retainUntil, state.retentionTimestamp = next.mode, next.retainUntil, next.retentionTimestamp
		}
	}
	return state
}

// checkedExpiryRefused reports whether a set must keep a version whose ILM
// expiry the pools approved with the Object Lock state approved, by the
// metadata goi the set reads under the same lock. A pending purge always
// keeps it: its status orders nothing. The approved hold or retention only
// replaces the one the set reads when it is strictly newer; otherwise the
// protection the set reads stands, also when it is newer than the approval.
func checkedExpiryRefused(lc lifecycle.Lifecycle, lr objectlock.Retention, rcfg *replication.Config, goi ObjectInfo, approved objectLockState) bool {
	e := lifecycle.NewEvaluator(lc).WithLockRetention(&lr).WithReplicationConfig(rcfg)
	obj := goi.ToLifecycleOpts()
	if e.IsPendingReplication(obj) {
		return true
	}
	local := lifecycleLockState(goi.UserDefined)
	obj.UserDefined = maps.Clone(goi.UserDefined)
	if obj.UserDefined == nil {
		obj.UserDefined = make(map[string]string)
	}
	if lockRevisionNewer(approved.legalHoldTimestamp, local.legalHoldTimestamp) {
		obj.UserDefined[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = approved.legalHold
	}
	if lockRevisionNewer(approved.retentionTimestamp, local.retentionTimestamp) {
		obj.UserDefined[strings.ToLower(xhttp.AmzObjectLockMode)] = approved.mode
		obj.UserDefined[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = approved.retainUntil
	}
	return e.IsObjectLocked(obj)
}

// lockRevisionsOrdered reports whether the copies of a version agree on the
// legal hold and on the retention, each on its own, or carry revisions with
// distinct valid timestamps, so that the newest one is known.
func lockRevisionsOrdered(copies []PoolObjInfo) bool {
	ordered := func(revision func(objectLockState) (value, stamp string)) bool {
		stamps := make(map[[2]string]string, len(copies))
		for _, copy := range copies {
			value, stamp := revision(lifecycleLockState(copy.ObjInfo.UserDefined))
			stamps[[2]string{value, stamp}] = stamp
		}
		if len(stamps) == 1 {
			return true
		}
		seen := make([]time.Time, 0, len(stamps))
		for _, stamp := range stamps {
			t, ok := lockRevisionTime(stamp)
			if !ok {
				return false
			}
			for _, other := range seen {
				if t.Equal(other) {
					return false
				}
			}
			seen = append(seen, t)
		}
		return true
	}
	return ordered(func(s objectLockState) (string, string) {
		return s.legalHold, s.legalHoldTimestamp
	}) && ordered(func(s objectLockState) (string, string) {
		return s.mode + "\x00" + s.retainUntil, s.retentionTimestamp
	})
}

// replicationStatesAgree reports whether the copies of a version carry the
// same replication and purge state. The per-target states are compared as
// parsed, regardless of their order.
func replicationStatesAgree(copies []PoolObjInfo) bool {
	first := copies[0].ObjInfo
	for _, copy := range copies[1:] {
		oi := copy.ObjInfo
		if oi.ReplicationStatus != first.ReplicationStatus || oi.VersionPurgeStatus != first.VersionPurgeStatus ||
			!maps.Equal(replicationStatusesMap(oi.ReplicationStatusInternal), replicationStatusesMap(first.ReplicationStatusInternal)) ||
			!maps.Equal(versionPurgeStatusesMap(oi.VersionPurgeStatusInternal), versionPurgeStatusesMap(first.VersionPurgeStatusInternal)) {
			return false
		}
	}
	return true
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
// lifecycleAllPools.expiryApplies, and the Object Lock state with which it
// approved the expiry of a version.
func (z *erasureServerPools) checkExpiryAllPools(ctx context.Context, bucket, object string, opts ObjectOptions) (objectLockState, error) {
	var all lifecycleAllPools
	all.versions, all.events, all.err = z.lifecycleEventsAllPools(ctx, bucket, object)
	if err := all.expiryApplies(bucket, object, opts); err != nil {
		return objectLockState{}, err
	}
	return all.protection(opts.VersionID), nil
}

// version returns the index of the version versionID, or -1.
func (all lifecycleAllPools) version(versionID string) int {
	for i, oi := range all.versions {
		if oi.VersionID == versionID || oi.VersionID == "" && versionID == nullVersionID {
			return i
		}
	}
	return -1
}

// protection returns the Object Lock state of the version versionID that
// the evaluator decided on, to be checked against the state the set reads.
func (all lifecycleAllPools) protection(versionID string) objectLockState {
	if versionID == "" {
		return objectLockState{}
	}
	if i := all.version(versionID); i >= 0 {
		return lifecycleLockState(all.versions[i].UserDefined)
	}
	return objectLockState{}
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
		if i := all.version(opts.VersionID); i >= 0 {
			if all.events[i].Action == lifecycle.DeleteVersionAction {
				return nil
			}
			return errLifecycleNotApplicable
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

// recheckReadExpiry only rechecks a local ordinary-delete candidate. The
// global latest expiring does not authorize hiding a different version that
// GET/HEAD has already read. On an incomplete or rejected recheck, keep that
// successful read and do not queue an expiry. Leave response metadata intact.
func recheckReadExpiry(ctx context.Context, objectAPI ObjectLayer, oi ObjectInfo, evt lifecycle.Event) (ObjectInfo, lifecycle.Event) {
	z, ok := objectAPI.(*erasureServerPools)
	if !ok || !evt.Action.Delete() || evt.Action.DeleteRestored() || !z.expiryNeedsAllPools(ObjectOptions{
		Expiration:       ExpirationOptions{Expire: true},
		VersionID:        oi.VersionID,
		Versioned:        globalBucketVersioningSys.PrefixEnabled(oi.Bucket, oi.Name),
		VersionSuspended: globalBucketVersioningSys.PrefixSuspended(oi.Bucket, oi.Name),
		DeletePrefix:     evt.Action.DeleteAll(),
	}) {
		return oi, evt
	}
	versions, events, err := z.lifecycleEventsAllPools(ctx, oi.Bucket, encodeDirObject(oi.Name))
	if err == nil {
		versionID := oi.VersionID
		if versionID == "" {
			versionID = nullVersionID
		}
		for i, version := range versions {
			id := version.VersionID
			if id == "" {
				id = nullVersionID
			}
			if id == versionID {
				if events[i].Action.Delete() && !events[i].Action.DeleteRestored() {
					return version, events[i]
				}
				break
			}
		}
	}
	return oi, lifecycle.Event{Action: lifecycle.NoneAction}
}

// migrationExpiryApplies reports whether the ILM expiry evt, which a
// decommission or rebalance decided for oi on the versions of the pool it
// walks, applies with the versions of the object in all pools too. Only then
// may the walk leave the version to the expiry instead of moving it. A
// version that is the latest in the walked pool can be a noncurrent version
// of the object, and a delete marker alone in that pool can hide versions in
// another one. Such a version is moved like any other, and the scanner
// applies the rule in the pool that holds the object then.
//
// The walk reads the history of a key once, into h, for the prechecks of all
// its versions: this decides only whether a version moves or is left to the
// expiry, which reads the history again under the object lock before it
// deletes anything. A read error is kept, so every due version of that key
// moves.
func (z *erasureServerPools) migrationExpiryApplies(ctx context.Context, oi ObjectInfo, evt lifecycle.Event, h *migrationHistory) bool {
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
	object := encodeDirObject(oi.Name)
	if h == nil {
		h = &migrationHistory{}
	}
	if !h.loaded {
		h.all.versions, h.all.events, h.all.err = z.lifecycleEventsAllPools(ctx, oi.Bucket, object)
		h.loaded = true
		if f := migrationHistoryLoaded; f != nil {
			f(oi.Name)
		}
	}
	return h.all.expiryApplies(oi.Bucket, object, opts) == nil
}

// migrationHistoryLoaded, when a test sets it, is told each time a migration
// walk reads the history of a key.
var migrationHistoryLoaded func(object string)

// migrationHistory is the history of one key in all pools, read once by a
// decommission or rebalance walk for the prechecks of its versions.
type migrationHistory struct {
	loaded bool
	all    lifecycleAllPools
}
