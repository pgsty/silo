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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio/internal/bucket/lifecycle"
	xhttp "github.com/minio/minio/internal/http"
)

// A native restore keeps two private records. The version that POST marks
// ongoing names the attempt that owns the marker; that attempt's multipart
// upload names the attempt and the version it rehydrates. Clients cannot
// set either: requests with reserved metadata are refused, it is never
// extracted from headers, and uploads only get the marker from the restore.
const (
	restoreAttemptKey = ReservedMetadataPrefixLower + "restore-attempt"
	restoreUploadKey  = ReservedMetadataPrefixLower + "restore-upload"
)

const (
	// restoreTakeoverWait bounds how long a POST on an ongoing version waits
	// for the object lock. A running restore holds it for its download.
	restoreTakeoverWait = 2 * time.Second
	// restoreCommitGrace is how long stale cleanup keeps an upload whose
	// completion staged object metadata in it; a commit takes seconds.
	restoreCommitGrace = time.Hour
	// restoreCleanupTimeout bounds each status reset and upload abort.
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
	// errRestoreInProgress: a restore holds the object lock of the version.
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

func parseRestoreAttempt(s string) (*restoreAttempt, bool) {
	var a restoreAttempt
	if s == "" || json.Unmarshal([]byte(s), &a) != nil || a.ID == "" || a.VersionID == "" {
		return nil, false
	}
	return &a, true
}

func (a *restoreAttempt) equal(b *restoreAttempt) bool {
	return a != nil && b != nil && a.ID == b.ID && a.VersionID == b.VersionID &&
		a.ETag == b.ETag && a.Size == b.Size && a.ModTime.Equal(b.ModTime)
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

// rehydrates reports whether completing upload fi, the attempt's private
// upload, writes back the very version current.
func (a *restoreAttempt) rehydrates(current ObjectInfo, fi FileInfo) bool {
	return a.targets(current) && fi.Metadata["etag"] == a.ETag && fi.Size == a.Size && fi.ModTime.Equal(a.ModTime)
}

// restoreUploadView is the restore marker of an upload as the drives of
// its set establish it. A marked upload is written to a write quorum, at
// least a majority of the drives, and its copies never change their marker.
type restoreUploadView struct {
	// marker is the attempt of a native restore's upload: one marker that a
	// majority of the drives hold.
	marker *restoreAttempt
	// marked: some readable drive holds a marker.
	marked bool
	// known: the marker state is established. Without it, callers fail
	// closed: nobody lists, uses, aborts or removes the upload.
	known bool
	// live: enough drives hold the upload or cannot tell that a written
	// upload may exist; otherwise only remnants of one are left.
	live bool
	// committing: some drive holds object metadata in the upload's place.
	// Completion stages the committed version's object metadata there,
	// without the marker, before it renames the upload into the object.
	committing bool
	// bucket and object the upload of an established marker belongs to.
	bucket, object string
}

// restoreUploadState establishes the marker of an upload from the metadata of
// every drive. errs may be nil, then a drive without valid metadata is one
// that cannot tell. A marker is established on a majority of the drives; its
// absence only when no readable drive shows one and the drives that cannot
// tell are too few to hold a marked upload.
func restoreUploadState(metas []FileInfo, errs []error) restoreUploadView {
	n := len(metas)
	majority := n/2 + 1
	markers := make(map[string]int)
	var unmarked, unknown, committing int
	for i, fi := range metas {
		if errs != nil && errs[i] != nil {
			if !errors.Is(errs[i], errFileNotFound) && !errors.Is(errs[i], errFileVersionNotFound) &&
				!errors.Is(errs[i], errVolumeNotFound) && !errors.Is(errs[i], errUploadIDNotFound) {
				unknown++
			}
			continue
		}
		if !fi.IsValid() {
			unknown++
			continue
		}
		if restoreUploadStaged(fi) {
			committing++
			continue
		}
		if m := fi.Metadata[restoreUploadKey]; m != "" {
			markers[m]++
		} else {
			unmarked++
		}
	}
	present := unmarked
	for _, c := range markers {
		present += c
	}
	v := restoreUploadView{marked: len(markers) > 0, live: present+unknown+committing >= majority, committing: committing > 0}
	if v.committing {
		// Nobody but the completion may use or remove it now.
		return v
	}
	for m, c := range markers {
		if c >= majority {
			v.marker, v.known = parseRestoreAttempt(m)
			if v.known {
				// The marker also names the upload's own target.
				for _, fi := range metas {
					if !fi.IsValid() || fi.Metadata[restoreUploadKey] != m {
						continue
					}
					if restoreVersionID(fi.VersionID) != v.marker.VersionID || fi.Metadata["etag"] != v.marker.ETag {
						v.marker, v.known = nil, false
						break
					}
					v.bucket, v.object = fi.Metadata[multipartMetaBucket], fi.Metadata[multipartMetaObject]
				}
			}
			return v
		}
	}
	// A marker without a majority is established only as a remnant.
	v.known = !v.live || (!v.marked && unknown < majority)
	return v
}

// restoreUploadStaged reports whether an upload's record is object metadata
// that a completion staged there: an upload record has no parts and no
// other versions.
func restoreUploadStaged(fi FileInfo) bool {
	return fi.Deleted || len(fi.Parts) > 0 || fi.NumVersions > 1
}

// visible reports whether a caller sees the upload: a native restore its own
// upload, any other caller only an upload established as unmarked.
func (v restoreUploadView) visible(opts ObjectOptions) bool {
	if a := opts.Transition.attempt; a != nil {
		return v.marker.equal(a)
	}
	return v.known && !v.marked
}

// restoreUploadVisible reports whether a caller sees an upload whose metadata
// is metas, one entry for each drive.
func restoreUploadVisible(metas []FileInfo, opts ObjectOptions) bool {
	return restoreUploadState(metas, nil).visible(opts)
}

// readRestoreUpload reads the metadata of an upload from every drive.
func (er erasureObjects) readRestoreUpload(ctx context.Context, bucket, uploadIDPath string) restoreUploadView {
	metas, errs := readAllFileInfo(ctx, er.getDisks(), bucket, minioMetaMultipartBucket, uploadIDPath, "", false, false)
	return restoreUploadState(metas, errs)
}

// restoreCommitLock is held by a completion from staging through its commit;
// it is named by the upload's own path, which an upload whose copies all
// hold staged object metadata still has.
func (er erasureObjects) restoreCommitLock(uploadIDPath string) RWLocker {
	return er.NewNSLock(minioMetaMultipartBucket, uploadIDPath)
}

// restoreCommitAbandoned reports whether an upload holds only what a failed
// commit left: every drive answers, and every copy that is there is staged
// object metadata, see restoreUploadStaged, older than restoreCommitGrace by
// that drive's own metadata file. A copy that cannot be read, or that is not
// staged yet, may belong to a commit still running. The caller holds the
// upload's restoreCommitLock.
func (er erasureObjects) restoreCommitAbandoned(ctx context.Context, bucket, uploadIDPath string) bool {
	disks := er.getDisks()
	metas, errs := readAllFileInfo(ctx, disks, bucket, minioMetaMultipartBucket, uploadIDPath, "", false, false)
	staged := 0
	for i, fi := range metas {
		if errs[i] != nil {
			if errors.Is(errs[i], errFileNotFound) || errors.Is(errs[i], errFileVersionNotFound) {
				continue
			}
			return false
		}
		if !fi.IsValid() || !restoreUploadStaged(fi) {
			return false
		}
		st, err := disks[i].StatInfoFile(ctx, minioMetaMultipartBucket, pathJoin(uploadIDPath, xlStorageFormatFile), false)
		if err != nil || len(st) == 0 || time.Since(st[0].ModTime) < restoreCommitGrace {
			return false
		}
		staged++
	}
	return staged > 0
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
type restoreGeneration struct {
	fi      FileInfo
	drives  []FileInfo
	disks   []StorageAPI
	split   bool
	ongoing map[string]bool
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
	gen := restoreGeneration{drives: make([]FileInfo, n), disks: make([]StorageAPI, n)}
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

// restoreFailed clears the ongoing marker of a failed attempt while the
// object lock is held. A lost lock or an ended context leaves that to the
// bounded retries of the pools layer, which take the lock afresh.
func (er erasureObjects) restoreFailed(ctx context.Context, bucket, object, versionID string, published *restoreAttempt, cause error) error {
	if ctx.Err() != nil {
		return restoreResetError{cause}
	}
	if err := er.clearRestoreStatus(ctx, bucket, object, versionID, published); err != nil {
		storageLogIf(ctx, fmt.Errorf("Unable to clear the restore status of %s/%s(%s): %w", bucket, object, versionID, err))
		return restoreResetError{cause}
	}
	return cause
}

// abortRestoreUpload removes the private upload of a failed attempt, or
// leaves it to stale-upload cleanup. The restore's own context may have
// ended, so it uses a fresh bounded one, and the upload lock as any abort.
// It matches the upload to its own attempt rather than to the version, which
// a newer attempt may own by now, and it never touches the version.
func (er erasureObjects) abortRestoreUpload(bucket, object, uploadID string, a *restoreAttempt) {
	ctx, cancel := context.WithTimeout(GlobalContext, restoreCleanupTimeout)
	defer cancel()
	lk := er.NewNSLock(bucket, pathJoin(object, uploadID))
	lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
	if err == nil {
		defer lk.Unlock(lkctx)
		_, err = er.abortMultipartUpload(lkctx.Context(), bucket, object, uploadID, ObjectOptions{
			NoAuditLog: true,
			Transition: TransitionOptions{attempt: a},
		})
	}
	if err != nil {
		storageLogIf(ctx, fmt.Errorf("Unable to abort the restore upload of %s/%s: %w", bucket, object, err))
	}
}

// restoreUploadActive reports whether the restore that owns a stale-aged
// upload still runs: its attempt owns the version's ongoing marker. A long
// download keeps its upload; one whose attempt ended loses it, and an
// ongoing marker alone keeps nothing.
func (er erasureObjects) restoreUploadActive(ctx context.Context, v restoreUploadView) bool {
	gen, err := er.readRestoreGeneration(ctx, v.bucket, v.object, v.marker.VersionID)
	if err != nil {
		// An unreadable version may still be restoring; retry next round.
		return !errors.Is(err, errFileVersionNotFound) && !errors.Is(err, errFileNotFound)
	}
	if gen.split {
		// Drives disagree on the restore status: that the attempt ended
		// is not established.
		return gen.ongoing[v.marker.ID]
	}
	return v.marker.owns(gen.fi.ToObjectInfo(v.bucket, v.object, false))
}

// restoreLock is the object lock that restores and their status updates
// share: with one pool the set's own lock, as single-pool writes use.
func (z *erasureServerPools) restoreLock(bucket, object string) RWLocker {
	if z.SinglePool() {
		return z.serverPools[0].getHashedSet(object).NewNSLock(bucket, object)
	}
	return z.NewNSLock(bucket, object)
}

// restoreRequestStatus is what a POST restore recorded on its version.
type restoreRequestStatus struct {
	objInfo ObjectInfo
	// attempt is the restore that must rehydrate the version; nil when a
	// restored copy was still there and its expiry was renewed.
	attempt *restoreAttempt
}

// restoreRequest records a POST restore on target, the version that POST
// resolved, on a fresh read under the object lock. The version must still
// be target: a replacement under the same version ID is refused. A copy that
// still holds its restored data is renewed. Otherwise the version is marked
// ongoing for a new attempt; that also takes over a marker no running
// restore holds, as a running restore holds the object lock for its whole
// download. Only the copy that is to be restored is written, so no copy
// claims a restored copy it does not hold.
func (z *erasureServerPools) restoreRequest(ctx context.Context, bucket, object string, opts ObjectOptions, target ObjectInfo) (restoreRequestStatus, error) {
	object = encodeDirObject(object)
	versionID := restoreVersionID(target.VersionID)
	lk := z.restoreLock(bucket, object)
	// Wait only briefly first, whatever the lockless read before saw: a
	// restore of this version holds the lock for its whole download. Then
	// wait as usual only if the drives show no restore of it running.
	lkctx, err := lk.GetLock(ctx, newDynamicTimeout(restoreTakeoverWait, restoreTakeoverWait))
	if errors.As(err, &OperationTimedOut{}) && ctx.Err() == nil {
		running, rerr := z.restoreRunning(ctx, bucket, object, versionID)
		switch {
		case rerr != nil:
			// Whether it is restoring is unknown: answer now, not after
			// the lock frees.
			return restoreRequestStatus{}, rerr
		case running:
			return restoreRequestStatus{}, errRestoreInProgress
		}
		lkctx, err = lk.GetLock(ctx, globalOperationTimeout)
	}
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
	return restoreRequestStatus{objInfo: oi, attempt: attempt}, nil
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
		if !z.IsSuspended(idx) && a.owns(gen.fi.ToObjectInfo(bucket, object, false)) {
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
