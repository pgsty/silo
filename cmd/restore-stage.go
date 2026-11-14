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
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio/internal/bucket/lifecycle"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/sync/errgroup"
)

// A native restore runs in two phases. It downloads the tier copy of a
// version and erasure-codes it into the tmp volume of the version's set
// without the object lock O, then takes O only to check the version again
// and publish the staged copy drive by drive, as heal does. Hot versions of
// the key stay readable and writable during the download.
//
// The restore lock R of the version tells whether a restore of it runs: a
// POST takes R before O, and the worker that rehydrates the version holds R
// for its whole run. Nothing else takes R, so nothing holds O while it waits
// for R. R is a liveness hint, not an exclusion: a lost refresh can let two
// workers overlap. Only the checks under O decide what is written.

// restoreOwnerPrefix names the restore locks under minioMetaBucket.
const restoreOwnerPrefix = "restore"

// restorePublicationDelays are the in-memory retries of a convergence after
// the one under the commit's own lock hold, see recoverRestorePublication.
var restorePublicationDelays = []time.Duration{100 * time.Millisecond, time.Second, 5 * time.Second, 30 * time.Second, 2 * time.Minute}

var (
	// errRestoreMoved: the version moved to another pool after the restore
	// staged its copy in this one.
	errRestoreMoved = errors.New("restored version moved to another pool")
	// errRestoreNotConverged: a publication that reached some drives but not
	// a write quorum could not be brought back to the unrestored version yet.
	errRestoreNotConverged = errors.New("restore publication did not converge")
)

// restoreOwner is the restore lock R of one version, held by a POST that
// registers an attempt and then by the worker that runs it. ctx ends when the
// lock is released or when its holder learns that it lost it.
type restoreOwner struct {
	lk     RWLocker
	lkctx  LockContext
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

// release unlocks R once. It is a no-op on a nil owner.
func (o *restoreOwner) release() {
	if o == nil {
		return
	}
	o.once.Do(func() {
		o.cancel()
		o.lk.Unlock(o.lkctx)
	})
}

// restoreOwnerResource is the name of the restore lock of a version. Bucket
// names hold no slash, object names no ".." element, and the version ID has
// a fixed form, so the name is unambiguous.
func restoreOwnerResource(bucket, object, versionID string) string {
	return pathJoin(restoreOwnerPrefix, bucket, object, restoreVersionID(versionID))
}

// takeRestoreOwner takes the restore lock of a version. With a nil timeout it
// waits for as long as ctx lives, as a direct caller does; otherwise it gives
// up after timeout. ctx must outlive the restore that the lock is held for.
func (z *erasureServerPools) takeRestoreOwner(ctx context.Context, bucket, object, versionID string, timeout *dynamicTimeout) (*restoreOwner, error) {
	for {
		// A new instance for each try: a distributed unlock retries in the
		// background and could release a later try of the same instance.
		lk := z.NewNSLock(minioMetaBucket, restoreOwnerResource(bucket, object, versionID))
		wait := timeout
		if wait == nil {
			wait = globalRestoreLockTimeout
		}
		lkctx, err := lk.GetLock(ctx, wait)
		if err != nil {
			if timeout == nil && errors.As(err, &OperationTimedOut{}) && ctx.Err() == nil {
				continue
			}
			return nil, err
		}
		octx, cancel := context.WithCancel(lkctx.Context())
		return &restoreOwner{lk: lk, lkctx: lkctx, ctx: octx, cancel: cancel}, nil
	}
}

// restoreStage is the copy of one version that a native restore encoded into
// the tmp volume of the version's set, under tmpID/dataDir, before it takes
// the object lock.
type restoreStage struct {
	versionID string
	// fi is the version as the download read it: the commit only publishes
	// the copy for a version that still has this content, see
	// restoreSameContent.
	fi      FileInfo
	tmpID   string
	dataDir string
	// staged tells, in the order of the version's erasure distribution,
	// which drives hold every part of the copy.
	staged []bool
	expiry time.Time
	// request is set for an attempt that POST registered: days and date
	// are what it recorded. A direct caller keeps the version's own.
	request bool
	days    int
	date    string
}

// restoreSameContent reports whether two reads of a version name the same
// encoded bytes, laid out the same way: the version, its tier copy, its parts
// and its erasure layout. The tier copy is never rewritten under the same
// name and remote version, so these decide the bytes. Every other field, such
// as tags, Object Lock, replication state or a rewrapped object key, is taken
// from the version as the commit reads it.
func restoreSameContent(a, b FileInfo) bool {
	if a.VersionID != b.VersionID || a.Deleted || b.Deleted || !a.ModTime.Equal(b.ModTime) ||
		a.Metadata["etag"] != b.Metadata["etag"] || a.Size != b.Size ||
		a.TransitionStatus != lifecycle.TransitionComplete || b.TransitionStatus != lifecycle.TransitionComplete ||
		a.TransitionTier != b.TransitionTier || a.TransitionedObjName != b.TransitionedObjName ||
		a.TransitionVersionID != b.TransitionVersionID {
		return false
	}
	if len(a.Parts) != len(b.Parts) {
		return false
	}
	for i := range a.Parts {
		if a.Parts[i].Number != b.Parts[i].Number || a.Parts[i].Size != b.Parts[i].Size {
			return false
		}
	}
	ea, eb := a.Erasure, b.Erasure
	return ea.Algorithm == eb.Algorithm && ea.DataBlocks == eb.DataBlocks && ea.ParityBlocks == eb.ParityBlocks &&
		ea.BlockSize == eb.BlockSize && slices.Equal(ea.Distribution, eb.Distribution)
}

// restoreInlineKey marks a version whose data lives in its xl.meta.
const restoreInlineKey = ReservedMetadataPrefixLower + "inline-data"

// stageRestore downloads the tier copy of the version opts address and
// erasure-codes it, part by part, into the tmp volume of the drives of this
// set, as heal writes the parts it rebuilds. It holds no object lock. A drive
// that fails to write any part, or that misses a part afterwards, for
// example because its tmp volume was moved away when its server restarted,
// takes no further part and no part in the commit.
func (er erasureObjects) stageRestore(ctx context.Context, bucket, object string, opts ObjectOptions) (*restoreStage, error) {
	rreq := opts.Transition.RestoreRequest
	if rreq == nil {
		return nil, errInvalidArgument
	}
	gen, err := er.readRestoreGeneration(ctx, bucket, object, opts.VersionID)
	if err != nil {
		return nil, toObjectErr(err, bucket, object, opts.VersionID)
	}
	fi := gen.fi
	if fi.Deleted {
		return nil, toObjectErr(errMethodNotAllowed, bucket, object)
	}
	if a := opts.Transition.attempt; a != nil && !a.ownsGeneration(gen, bucket, object) {
		// A later POST took the version over, or it was replaced.
		return nil, errRestoreSuperseded
	}
	disks := er.getDisks()
	var total int64
	for _, p := range fi.Parts {
		if p.Size < 0 {
			return nil, toObjectErr(errFileCorrupt, bucket, object)
		}
		total += p.Size
	}
	if fi.TransitionStatus != lifecycle.TransitionComplete || len(fi.Parts) == 0 || total != fi.Size ||
		len(fi.Erasure.Distribution) != len(disks) {
		return nil, InvalidObjectState{Bucket: bucket, Object: object}
	}
	erasure, err := NewErasure(ctx, fi.Erasure.DataBlocks, fi.Erasure.ParityBlocks, fi.Erasure.BlockSize)
	if err != nil {
		return nil, toObjectErr(err, bucket, object)
	}
	writeQuorum := fi.WriteQuorum(er.defaultWQuorum())
	st := &restoreStage{
		versionID: restoreVersionID(fi.VersionID),
		fi:        fi,
		tmpID:     mustGetUUID(),
		dataDir:   mustGetUUID(),
		expiry:    lifecycle.ExpectedExpiryTime(time.Now().UTC(), rreq.Days),
	}
	if opts.Transition.restoreDate != "" {
		st.request, st.days, st.date = true, rreq.Days, opts.Transition.restoreDate
	}
	staged := false
	defer func() {
		if !staged {
			er.deleteAll(context.Background(), minioMetaTmpBucket, st.tmpID)
		}
	}()

	// The tier copy is the encoded stream of the parts, encrypted or
	// compressed as stored: the parts get exactly these bytes back.
	oi := fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended)
	gr, err := getTransitionedObjectReader(ctx, bucket, object, nil, http.Header{}, oi, opts)
	if err != nil {
		return nil, toObjectErr(err, bucket, object)
	}
	defer gr.Close()

	var buffer []byte
	pool := globalBytePoolCap.Load()
	if int64(pool.Width()) < fi.Erasure.BlockSize {
		buffer = make([]byte, fi.Erasure.BlockSize)
	} else {
		buffer = pool.Get()
		defer pool.Put(buffer)
	}
	buffer = buffer[:fi.Erasure.BlockSize]

	// Slots follow the erasure distribution: the drive in slot s gets shard
	// s+1 of every part, and the commit gives it erasure index s+1.
	slots := shuffleDisks(disks, fi.Erasure.Distribution)
	for _, part := range fi.Parts {
		partPath := pathJoin(st.tmpID, st.dataDir, fmt.Sprintf("part.%d", part.Number))
		writers := make([]io.Writer, len(slots))
		for s, disk := range slots {
			if disk != nil {
				writers[s] = newBitrotWriter(disk, bucket, minioMetaTmpBucket, partPath,
					erasure.ShardFileSize(part.Size), DefaultBitrotAlgorithm, erasure.ShardSize())
			}
		}
		n, err := erasure.Encode(ctx, io.LimitReader(gr, part.Size), writers, buffer, writeQuorum)
		closeErrs := closeBitrotWriters(writers)
		if err != nil {
			return nil, toObjectErr(err, bucket, object)
		}
		if n != part.Size {
			return nil, IncompleteBody{Bucket: bucket, Object: object}
		}
		for s := range slots {
			if writers[s] == nil || closeErrs[s] != nil {
				slots[s] = nil
			}
		}
		if countOnlineDisks(slots) < writeQuorum {
			return nil, toObjectErr(errErasureWriteQuorum, bucket, object)
		}
	}
	// The tier copy must end with the last part.
	var extra [1]byte
	if n, _ := io.ReadFull(gr, extra[:]); n != 0 {
		return nil, InvalidObjectState{Bucket: bucket, Object: object}
	}

	// A tmp volume that was moved away and recreated by a later part lacks the
	// earlier parts: find them before anything is published. CheckParts sees a
	// part that is present and not shorter than its shards; a staged drive
	// that wrote every part without an error has exactly that.
	check := fi
	check.DataDir = st.dataDir
	g := errgroup.WithNErrs(len(slots))
	for s, disk := range slots {
		if disk == nil {
			continue
		}
		g.Go(func() error {
			resp, err := disk.CheckParts(ctx, minioMetaTmpBucket, st.tmpID, check)
			if err != nil {
				return err
			}
			for _, result := range resp.Results {
				if result != checkPartSuccess {
					return errFileCorrupt
				}
			}
			return nil
		}, s)
	}
	st.staged = make([]bool, len(slots))
	count := 0
	for s, err := range g.Wait() {
		if slots[s] != nil && err == nil {
			st.staged[s] = true
			count++
		}
	}
	if count < writeQuorum {
		return nil, toObjectErr(errErasureWriteQuorum, bucket, object)
	}
	staged = true
	return st, nil
}

// fileInfoRevisions are the revisions the entry that writing fi creates can
// have, as readRestoreGeneration and the convergence identify the entries
// they read. versionRevision normalizes the time-derived UsesDataDir flag;
// the stored data directory and restore metadata still have to match.
func fileInfoRevisions(fi FileInfo) ([]revisionKey, error) {
	var x xlMetaV2
	if err := x.AddVersion(fi); err != nil {
		return nil, err
	}
	buf, err := x.AppendTo(nil)
	if err != nil {
		return nil, err
	}
	var y xlMetaV2
	if err := y.Load(buf); err != nil {
		return nil, err
	}
	if len(y.versions) != 1 {
		return nil, errFileCorrupt
	}
	ver := y.versions[0]
	return []revisionKey{versionRevision(ver, y.metaV)}, nil
}

// restorePublication remembers, for a commit that published the staged copy
// on some drives but not on a write quorum, what each drive held before the
// commit (Sᵢ), what the commit wrote there (Pᵢ) and what a convergence writes
// there (Vᵢ), in the order of the version's erasure distribution. Only the
// worker that published knows them; a convergence touches a version only
// while every drive holds one of them.
type restorePublication struct {
	bucket, object string
	versionID      string
	uv             [16]byte
	dataDir        string
	attempt        *restoreAttempt
	quorum         int
	dist           []int
	before         []*revisionKey
	anyBefore      map[revisionKey]bool
	published      map[revisionKey]bool
	conv           []FileInfo
	convKeys       map[revisionKey]bool
}

// restorePublished is the entry a commit publishes on the drive in slot s:
// the version as the commit read it on that drive, with the staged data
// directory and a completed restore. Restore fields are written alike on
// every drive: the request POST recorded, or for a direct caller the one
// the authoritative generation auth holds.
func restorePublished(base, auth FileInfo, st *restoreStage, slot int) FileInfo {
	fi := base
	fi.Metadata = maps.Clone(base.Metadata)
	if fi.Metadata == nil {
		fi.Metadata = make(map[string]string)
	}
	for _, k := range restoreFieldKeys {
		delete(fi.Metadata, k)
	}
	// An earlier restore may have inlined the data, and expiring that copy
	// leaves the inline marker behind; this copy lives in its data directory.
	delete(fi.Metadata, restoreInlineKey)
	fi.Metadata[xhttp.AmzRestore] = completedRestoreObj(st.expiry).String()
	if st.request {
		fi.Metadata[xhttp.AmzRestoreExpiryDays] = strconv.Itoa(st.days)
		fi.Metadata[xhttp.AmzRestoreRequestDate] = st.date
	} else {
		for _, k := range []string{xhttp.AmzRestoreExpiryDays, xhttp.AmzRestoreRequestDate} {
			if v, ok := auth.Metadata[k]; ok {
				fi.Metadata[k] = v
			}
		}
	}
	fi.DataDir = st.dataDir
	fi.Data = nil
	fi.Parts = slices.Clone(base.Parts)
	fi.Erasure.Index = slot + 1
	// The staged parts use the default streaming bitrot algorithm.
	fi.Erasure.Checksums = nil
	return fi
}

// restoreUnrestored is the entry a convergence writes on the drive in slot s:
// the version as the commit read it, with no restore fields, so that its tier
// copy serves reads again and a later POST can restore it.
func restoreUnrestored(base FileInfo, slot int) FileInfo {
	fi := base
	fi.Metadata = maps.Clone(base.Metadata)
	for _, k := range restoreFieldKeys {
		delete(fi.Metadata, k)
	}
	delete(fi.Metadata, restoreInlineKey)
	fi.Data = nil
	fi.Erasure.Index = slot + 1
	return fi
}

// commitRestore publishes a staged copy while the caller holds the object
// lock. It reads the version again, checks that the attempt still owns it and
// that it still has the content the copy was staged for, then publishes the
// copy on every staged drive that holds the version, with RenameData on each
// drive, as heal does: never through erasure renameData, whose undo of a
// replaced version could delete the new data and keep metadata that points
// at it.
//
// It returns nil when the copy reached a write quorum. Otherwise it returns
// an error, and a publication when some drive may already have the copy; the
// caller must then converge, see convergeRestore.
func (er erasureObjects) commitRestore(ctx context.Context, bucket, object string, st *restoreStage, opts ObjectOptions, placed func(context.Context) error) (*restorePublication, error) {
	if placed != nil {
		if err := placed(ctx); err != nil {
			return nil, err
		}
	}
	gen, err := er.readRestoreGeneration(ctx, bucket, object, st.versionID)
	if err != nil {
		return nil, toObjectErr(err, bucket, object, st.versionID)
	}
	if gen.fi.Deleted {
		return nil, toObjectErr(errMethodNotAllowed, bucket, object)
	}
	a := opts.Transition.attempt
	if a != nil && !a.ownsGeneration(gen, bucket, object) {
		return nil, errRestoreSuperseded
	}
	if !restoreSameContent(st.fi, gen.fi) {
		// Replaced, or its tier copy or layout changed since the download.
		return nil, InvalidObjectState{Bucket: bucket, Object: object}
	}
	disks := er.getDisks()
	dist := gen.fi.Erasure.Distribution
	if len(dist) != len(disks) || len(gen.revs) != len(disks) {
		return nil, InvalidObjectState{Bucket: bucket, Object: object}
	}
	n := len(disks)
	writeQuorum := gen.fi.WriteQuorum(er.defaultWQuorum())

	pub := &restorePublication{
		bucket: bucket, object: object, versionID: st.versionID, dataDir: st.dataDir,
		attempt: a, quorum: writeQuorum, dist: slices.Clone(dist),
		before:    make([]*revisionKey, n),
		anyBefore: make(map[revisionKey]bool),
		published: make(map[revisionKey]bool),
		conv:      make([]FileInfo, n),
		convKeys:  make(map[revisionKey]bool),
	}
	if st.versionID != nullVersionID {
		id, err := uuid.Parse(st.versionID)
		if err != nil {
			return nil, toObjectErr(errFileVersionNotFound, bucket, object, st.versionID)
		}
		pub.uv = id
	}
	targets := make([]StorageAPI, n)
	files := make([]FileInfo, n)
	for i := range disks {
		s := dist[i] - 1
		if s < 0 || s >= n {
			return nil, InvalidObjectState{Bucket: bucket, Object: object}
		}
		if gen.revs[i] != nil {
			pub.before[s] = gen.revs[i]
			pub.anyBefore[*gen.revs[i]] = true
		}
		v := restoreUnrestored(gen.fi, s)
		keys, err := fileInfoRevisions(v)
		if err != nil {
			return nil, toObjectErr(err, bucket, object)
		}
		pub.conv[s] = v
		// The unrestored entry has no restore header: its flag never varies.
		pub.convKeys[keys[0]] = true
		if gen.disks[i] == nil || !st.staged[s] {
			continue
		}
		fi := restorePublished(gen.drives[i], gen.fi, st, s)
		if keys, err = fileInfoRevisions(fi); err != nil {
			return nil, toObjectErr(err, bucket, object)
		}
		for _, key := range keys {
			pub.published[key] = true
		}
		targets[s], files[s] = gen.disks[i], fi
	}
	if countOnlineDisks(targets) < writeQuorum {
		// Nothing is published.
		return nil, toObjectErr(errErasureWriteQuorum, bucket, object)
	}

	errs := make([]error, n)
	olds := make([]string, n)
	var wg sync.WaitGroup
	for s, disk := range targets {
		if disk == nil {
			errs[s] = errDiskNotFound
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := disk.RenameData(ctx, minioMetaTmpBucket, st.tmpID, files[s], bucket, object, RenameOptions{})
			olds[s], errs[s] = resp.OldDataDir, err
		}()
	}
	wg.Wait()

	if countErrs(errs, nil) < writeQuorum {
		return pub, toObjectErr(errErasureWriteQuorum, bucket, object)
	}
	// The data directory of the replaced entry, which held a former restored
	// copy, goes only when every drive that published reports the same one:
	// RenameData reports none where another version shares it, and then the
	// directory stays everywhere. It goes only from the drives that reported
	// it.
	old := ""
	cleanup := make([]StorageAPI, n)
	for s := range targets {
		if errs[s] != nil {
			continue
		}
		if olds[s] == "" || (old != "" && olds[s] != old) {
			old = ""
			break
		}
		old = olds[s]
		cleanup[s] = targets[s]
	}
	if old != "" && old != st.dataDir {
		er.commitRenameDataDir(ctx, bucket, object, old, cleanup, 1)
	}
	if countErrs(errs, nil) < n {
		er.addPartial(bucket, object, st.versionID)
	}
	return nil, nil
}

// restoreConvergence is the outcome of one convergence pass.
type restoreConvergence int

const (
	// restoreIncomplete: the drives are not settled yet; try again.
	restoreIncomplete restoreConvergence = iota
	// restoreConverged: every drive that holds the version holds it
	// unrestored again.
	restoreConverged
	// restoreCommitted: the copy reached a write quorum after all, such as
	// when a drive applied a publication whose answer was lost.
	restoreCommitted
	// restoreStopped: some drive holds an entry that neither this attempt
	// nor the version before it wrote: someone else changed the version.
	restoreStopped
)

// classify reads the entry of the version on every drive and sorts it into
// the slot of its drive: held tells which slots hold an entry this
// publication knows, published and converged count the drives that hold
// what the commit and the convergence write. A drive that cannot be read is
// left out. An entry the publication does not know stops it.
func (pub *restorePublication) classify(ctx context.Context, disks []StorageAPI) (held []bool, published, converged int, err error) {
	raws, errs := readAllRawFileInfo(ctx, disks, pub.bucket, pub.object, false)
	held = make([]bool, len(disks))
	for i := range disks {
		if errs[i] != nil || i >= len(pub.dist) {
			continue
		}
		var xl xlMetaV2
		if xl.LoadOrConvert(raws[i].Buf) != nil {
			continue
		}
		s := pub.dist[i] - 1
		for _, ver := range xl.versions {
			if ver.header.VersionID != pub.uv || ver.header.FreeVersion() {
				continue
			}
			key := versionRevision(ver, xl.metaV)
			switch {
			case pub.published[key]:
				published++
			case pub.convKeys[key]:
				converged++
			case pub.before[s] != nil && *pub.before[s] == key:
			case pub.before[s] == nil && pub.anyBefore[key]:
			default:
				return nil, 0, 0, errRestoreSuperseded
			}
			held[s] = true
			break
		}
	}
	return held, published, converged, nil
}

// convergeRestore settles a publication while the caller holds the object
// lock. When every drive still holds what the version held before the commit,
// what the commit wrote, or what an earlier pass wrote, it either finds the
// copy on a write quorum, or writes the unrestored version to every drive
// that holds the version. It deletes no directory: an unreferenced staged
// directory is left to abandoned-data cleanup. Any other entry stops it, so
// that it never overwrites what someone else wrote between two passes.
func (er erasureObjects) convergeRestore(ctx context.Context, pub *restorePublication) (restoreConvergence, error) {
	disks := er.getDisks()
	held, published, _, err := pub.classify(ctx, disks)
	if err != nil {
		return restoreStopped, err
	}
	if published >= pub.quorum {
		er.addPartial(pub.bucket, pub.object, pub.versionID)
		return restoreCommitted, nil
	}
	slots := shuffleDisks(disks, pub.dist)
	files := make([]FileInfo, len(slots))
	for s := range slots {
		if !held[s] {
			slots[s] = nil
			continue
		}
		files[s] = pub.conv[s]
	}
	_, werr := writeUniqueFileInfo(ctx, slots, "", pub.bucket, pub.object, files, pub.quorum)

	held, published, converged, err := pub.classify(ctx, disks)
	if err != nil {
		return restoreStopped, err
	}
	holding := 0
	for _, h := range held {
		if h {
			holding++
		}
	}
	if published == 0 && converged == holding && converged >= pub.quorum {
		return restoreConverged, nil
	}
	if werr == nil {
		werr = errErasureWriteQuorum
	}
	return restoreIncomplete, werr
}

// recoverRestorePublication retries a convergence in memory, for a bounded
// time, each pass under the object lock taken afresh. A restart loses the
// retries; the version then stays as the drives hold it, see the design's
// excluded residuals.
func (er erasureObjects) recoverRestorePublication(pub *restorePublication, lock func(context.Context) (LockContext, func(), error)) {
	go func() {
		err := errRestoreNotConverged
		for _, delay := range restorePublicationDelays {
			select {
			case <-GlobalContext.Done():
				return
			case <-time.After(delay):
			}
			ctx, cancel := context.WithTimeout(GlobalContext, restoreCleanupTimeout)
			lkctx, unlock, lerr := lock(ctx)
			if lerr != nil {
				cancel()
				err = lerr
				continue
			}
			var res restoreConvergence
			res, err = er.convergeRestore(lkctx.Context(), pub)
			unlock()
			cancel()
			if res == restoreConverged || res == restoreCommitted {
				return
			}
			if res == restoreStopped {
				break
			}
		}
		er.logRestoreNotConverged(pub, err)
	}()
}

func (er erasureObjects) logRestoreNotConverged(pub *restorePublication, err error) {
	attempt := ""
	if pub.attempt != nil {
		attempt = pub.attempt.ID
	}
	storageLogIf(GlobalContext, fmt.Errorf("%w: %s/%s(%s), attempt %q, data dir %s: %v",
		errRestoreNotConverged, pub.bucket, pub.object, pub.versionID, attempt, pub.dataDir, err))
}

// restoreHooks tie a restore of one set to its caller.
type restoreHooks struct {
	// lock takes the object lock O of the version, in the lock domain of the
	// object's writes, and returns its release.
	lock func(ctx context.Context) (LockContext, func(), error)
	// placed tells, under O, whether the version still lives in this set.
	placed func(ctx context.Context) error
	// clear clears the attempt's ongoing marker after a failure that
	// published nothing, taking O itself, and retries in the background.
	clear func()
}

// restoreVersion rehydrates the transitioned version opts address in this
// set: it stages the copy without the object lock, then commits it under the
// lock. A failure that published nothing clears the attempt's marker. A
// publication that reached some drives but not a write quorum converges
// under the same lock hold, and in bounded background retries after it.
func (er erasureObjects) restoreVersion(ctx context.Context, bucket, object string, opts ObjectOptions, h restoreHooks) error {
	st, err := er.stageRestore(ctx, bucket, object, opts)
	if err != nil {
		return restoreAbandon(err, h)
	}
	defer er.deleteAll(context.Background(), minioMetaTmpBucket, st.tmpID)

	lkctx, unlock, err := h.lock(ctx)
	if err != nil {
		return restoreAbandon(err, h)
	}
	pub, err := er.commitRestore(lkctx.Context(), bucket, object, st, opts, h.placed)
	if err == nil {
		unlock()
		return nil
	}
	if pub == nil {
		unlock()
		return restoreAbandon(err, h)
	}
	res, cerr := er.convergeRestore(lkctx.Context(), pub)
	unlock()
	switch res {
	case restoreCommitted:
		return nil
	case restoreConverged:
		return err
	case restoreStopped:
		er.logRestoreNotConverged(pub, cerr)
		return err
	default:
		er.recoverRestorePublication(pub, h.lock)
		return err
	}
}

// restoreAbandon clears the marker of an attempt that published nothing,
// unless another attempt owns the version. A not-found error may come from the
// tier rather than from the version, and the clear checks the marker's owner
// and finds nothing to do for a version that is gone, so it runs then too.
func restoreAbandon(err error, h restoreHooks) error {
	if errors.Is(err, errRestoreSuperseded) {
		return err
	}
	if h.clear != nil {
		h.clear()
	}
	return err
}

// RestoreTransitionedObject - restore transitioned object content locally on
// this cluster. This is similar to PostObjectRestore from AWS GLACIER storage
// class. When PostObjectRestore API is called, a temporary copy of the object
// is restored locally to the bucket on source cluster until the restore
// expiry date. The copy that was transitioned continues to reside in the
// transitioned tier.
//
// The set entry serves direct callers of one set. It takes the object lock in
// the set's own domain and no restore lock; native restores of a cluster go
// through erasureServerPools.
func (er erasureObjects) RestoreTransitionedObject(ctx context.Context, bucket, object string, opts ObjectOptions) error {
	lock := func(ctx context.Context) (LockContext, func(), error) {
		lk := er.NewNSLock(bucket, object)
		lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
		if err != nil {
			return LockContext{}, nil, err
		}
		return lkctx, func() { lk.Unlock(lkctx) }, nil
	}
	clearMarker := func() {
		tryClear := func(ctx context.Context) error {
			lkctx, unlock, err := lock(ctx)
			if err != nil {
				return err
			}
			defer unlock()
			versionID := opts.VersionID
			if a := opts.Transition.attempt; a != nil {
				versionID = a.VersionID
			}
			err = er.clearRestoreStatus(lkctx.Context(), bucket, object, versionID, opts.Transition.attempt)
			if isErrObjectNotFound(err) || isErrVersionNotFound(err) || isErrMethodNotAllowed(err) {
				return nil
			}
			return err
		}

		ctx, cancel := context.WithTimeout(GlobalContext, restoreResetAttemptTimeout)
		err := tryClear(ctx)
		cancel()
		if err == nil {
			return
		}

		go func() {
			var lastErr error
			for _, delay := range restoreRecoveryDelays {
				select {
				case <-GlobalContext.Done():
					return
				case <-time.After(delay):
				}
				ctx, cancel := context.WithTimeout(GlobalContext, restoreCleanupTimeout)
				lastErr = tryClear(ctx)
				cancel()
				if lastErr == nil {
					return
				}
			}
			storageLogIf(GlobalContext, fmt.Errorf("Unable to clear the restore status of %s/%s(%s): %w", bucket, object, opts.VersionID, lastErr))
		}()
	}
	return er.restoreVersion(ctx, bucket, object, opts, restoreHooks{lock: lock, clear: clearMarker})
}

// RestoreTransitionedObject - restore transitioned object content locally on
// this cluster, see erasureObjects.RestoreTransitionedObject.
//
// A POST hands over the restore lock R of the version it registered in
// opts.Transition.owner; a direct caller takes R here, waiting while ctx
// lives. The restore runs while R is held, and releases it when it returns.
func (z *erasureServerPools) RestoreTransitionedObject(ctx context.Context, bucket, object string, opts ObjectOptions) error {
	object = encodeDirObject(object)
	owner := opts.Transition.owner
	opts.Transition.owner = nil
	if owner != nil && owner.ctx.Err() != nil {
		// The lock POST handed over ended before the restore ran, such as
		// when its holder lost it while the restore was queued: take it again
		// as a direct caller does. The attempt still has to own the version.
		owner = nil
	}
	defer func() { owner.release() }()

	// Avoid restoring object from a pool being decommissioned.
	opts.SkipDecommissioned = true
	opts.NoLock = true
	clearMarker := func() {
		ctx, cancel := context.WithTimeout(GlobalContext, restoreResetAttemptTimeout)
		err := z.resetRestoreStatusWithContext(ctx, bucket, object, opts)
		cancel()
		if err != nil {
			z.recoverRestoreStatus(bucket, object, opts)
		}
	}
	idx, err := z.restorePoolIdx(ctx, bucket, object, opts)
	if err != nil {
		var reset restoreResetError
		if errors.As(err, &reset) {
			clearMarker()
			return reset.error
		}
		if isErrObjectNotFound(err) && opts.VersionID != "" {
			err = VersionNotFound{Bucket: bucket, Object: decodeDirObject(object), VersionID: opts.VersionID}
		}
		return err
	}
	// A server may have been replaced by an older binary while the restore
	// was queued: such a server knows neither the restore lock nor the
	// staged commit.
	if err := nativeRestoreAvailable(ctx); err != nil {
		clearMarker()
		return err
	}
	er := z.serverPools[idx].getHashedSet(object)
	if owner == nil {
		if opts.VersionID == "" {
			// Restore the version that is latest now, by its own ID.
			gen, err := er.readRestoreGeneration(ctx, bucket, object, "")
			if err != nil {
				return toObjectErr(err, bucket, object)
			}
			opts.VersionID = restoreVersionID(gen.fi.VersionID)
		}
		if owner, err = z.takeRestoreOwner(ctx, bucket, object, opts.VersionID, nil); err != nil {
			return err
		}
	}
	return er.restoreVersion(owner.ctx, bucket, object, opts, restoreHooks{
		lock: func(ctx context.Context) (LockContext, func(), error) {
			lk := z.restoreLock(bucket, object)
			lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
			if err != nil {
				return LockContext{}, nil, err
			}
			return lkctx, func() { lk.Unlock(lkctx) }, nil
		},
		placed: func(ctx context.Context) error {
			got, err := z.restorePoolIdx(ctx, bucket, object, opts)
			var reset restoreResetError
			if errors.As(err, &reset) {
				return reset.error
			}
			if err != nil {
				return err
			}
			if got != idx {
				return errRestoreMoved
			}
			return nil
		},
		clear: clearMarker,
	})
}
