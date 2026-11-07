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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/replication"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/config/storageclass"
	"github.com/minio/minio/internal/event"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/pubsub"
)

// An all-pools ILM approval is only as sound as the history each set reports
// and the protection it reads under the lock. These cases leave drives with
// stale, partial or unreadable metadata, as failed or interrupted writes and
// offline drives do, and check that no expiry deletes what they hide.

const authorityNoncurrentRule = `<Rule><ID>ncv</ID><Status>Enabled</Status><Filter><Prefix>ncv-</Prefix></Filter><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>`

var authorityHoldKey = strings.ToLower(xhttp.AmzObjectLockLegalHold)

func newLockedSplitILM(t *testing.T, rules string) *splitILM {
	t.Helper()
	return &splitILM{migrationILM: newMigrationILM(t, versioning.Enabled, true, rules), ids: map[string]string{}, bodies: map[string]string{}}
}

// authorityParity pins new objects to 12+4 on the 16 drives of a set. Other
// tests can leave another storage class configured. Without one, 4 is the
// default; Update cannot restore an unconfigured class, so leave it then.
func authorityParity(t *testing.T) {
	t.Helper()
	if globalStorageClass.GetParityForSC("") < 0 {
		return
	}
	previous := globalStorageClass
	globalStorageClass.Update(storageclass.Config{Standard: storageclass.StorageClass{Parity: 4}})
	t.Cleanup(func() { globalStorageClass.Update(previous) })
}

// authorityDisk fails the history scan (ReadXL) or the version removal of
// one key on a drive.
type authorityDisk struct {
	StorageAPI
	bucket, key         string
	failRead, failWrite bool
}

func (d authorityDisk) ReadXL(ctx context.Context, bucket, key string, data bool) (RawFileInfo, error) {
	if d.failRead && bucket == d.bucket && key == d.key {
		return RawFileInfo{}, errDiskNotFound
	}
	return d.StorageAPI.ReadXL(ctx, bucket, key, data)
}

func (d authorityDisk) DeleteVersion(ctx context.Context, volume, path string, fi FileInfo, forceDelMarker bool, opts DeleteOptions) error {
	if d.failWrite && volume == d.bucket && path == d.key {
		return errDiskNotFound
	}
	return d.StorageAPI.DeleteVersion(ctx, volume, path, fi, forceDelMarker, opts)
}

func (d authorityDisk) DeleteVersions(ctx context.Context, volume string, versions []FileInfoVersions, opts DeleteOptions) []error {
	errs := make([]error, len(versions))
	var pass []FileInfoVersions
	var idx []int
	for i, v := range versions {
		if d.failWrite && volume == d.bucket && v.Name == d.key {
			errs[i] = errDiskNotFound
			continue
		}
		pass = append(pass, v)
		idx = append(idx, i)
	}
	if len(pass) > 0 {
		for j, err := range d.StorageAPI.DeleteVersions(ctx, volume, pass, opts) {
			errs[idx[j]] = err
		}
	}
	return errs
}

// wrapAuthorityDisks makes the drives of pool that drive selects fail reads
// or writes of key.
func wrapAuthorityDisks(t *testing.T, s *splitILM, pool int, key string, failRead, failWrite bool, drive func(int) bool) {
	t.Helper()
	p := s.z.serverPools[pool]
	p.erasureDisksMu.Lock()
	prior := p.erasureDisks
	wrapped := make([][]StorageAPI, len(prior))
	for i, disks := range prior {
		wrapped[i] = append([]StorageAPI(nil), disks...)
		for j := range disks {
			if drive(j) {
				wrapped[i][j] = authorityDisk{StorageAPI: disks[j], bucket: s.bucket, key: key, failRead: failRead, failWrite: failWrite}
			}
		}
	}
	p.erasureDisks = wrapped
	p.erasureDisksMu.Unlock()
	t.Cleanup(func() {
		p.erasureDisksMu.Lock()
		p.erasureDisks = prior
		p.erasureDisksMu.Unlock()
	})
}

func authorityDrives(from, to int) func(int) bool {
	return func(i int) bool { return i >= from && i < to }
}

// removeAuthorityCopies removes version id of key from the drives of pool
// that drive selects, as a write that did not reach them leaves it.
func removeAuthorityCopies(t *testing.T, s *splitILM, pool int, key, id string, drive func(int) bool) {
	t.Helper()
	for i, disk := range s.z.serverPools[pool].getHashedSet(key).getDisks() {
		if !drive(i) {
			continue
		}
		fi := FileInfo{VersionID: id}
		fi.SetSkipTierFreeVersion()
		if err := disk.DeleteVersion(t.Context(), s.bucket, key, fi, false, DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func authorityHeader(t *testing.T, disk StorageAPI, bucket, key, id string) xlMetaV2VersionHeader {
	t.Helper()
	rf, err := disk.ReadXL(t.Context(), bucket, key, false)
	if err != nil {
		t.Fatal(err)
	}
	var xl xlMetaV2
	if err := xl.LoadOrConvert(rf.Buf); err != nil {
		t.Fatal(err)
	}
	for _, ver := range xl.versions {
		if uuid.UUID(ver.header.VersionID).String() == id {
			return ver.header
		}
	}
	t.Fatalf("drive has no version %s", id)
	return xlMetaV2VersionHeader{}
}

func authorityExpireVersion(t *testing.T, s *splitILM, key, id string) error {
	t.Helper()
	_, err := s.z.DeleteObject(t.Context(), s.bucket, key, ObjectOptions{Versioned: true, VersionID: id, Expiration: ExpirationOptions{Expire: true}})
	return err
}

func authorityPresent(t *testing.T, s *splitILM, pool int, key, id string) {
	t.Helper()
	if _, err := s.z.serverPools[pool].GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: id}); err != nil {
		t.Fatalf("pool %d lost version %s: %v", pool, id, err)
	}
}

// minorityRevision writes the versions old and new of key to pool 0, applies
// metadata to old, and leaves its last drive with the revision before, as a
// drive that missed the update does. It reports whether that stale revision
// sorts before the fifteen others.
func minorityRevision(t *testing.T, s *splitILM, key string, metadata map[string]string) (id string, staleFirst bool) {
	t.Helper()
	ctx := t.Context()
	s.write(key, splitAt("old", 5, 0))
	s.write(key, splitAt("new", 3, 0))
	id = s.ids[key+" old"]
	disks := s.z.serverPools[0].getHashedSet(key).getDisks()
	last := disks[len(disks)-1]
	stale, err := last.ReadVersion(ctx, "", s.bucket, key, id, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	setLifecycleCopyMetadata(t, s, key, id, 0, metadata, false)
	if err := last.WriteMetadata(ctx, "", s.bucket, key, stale); err != nil {
		t.Fatal(err)
	}
	return id, authorityHeader(t, last, s.bucket, key, id).sortsBefore(authorityHeader(t, disks[0], s.bucket, key, id))
}

// One drive missed a legal hold that the other fifteen committed. Its stale
// revision must not be selected, and must not keep the fifteen from
// deciding, whichever signature sorts first.
func TestPoolsLifecycleMinorityLockRevision(t *testing.T) {
	authorityParity(t)
	s := newLockedSplitILM(t, authorityNoncurrentRule)
	ctx := t.Context()
	for attempt := range 32 {
		key := fmt.Sprintf("ncv-lock-%d", attempt)
		stamp := UTCNow().Format(time.RFC3339Nano)
		id, staleFirst := minorityRevision(t, s, key, poolLockMetadata("", "ON", stamp, stamp))
		versions, events, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key)
		switch {
		case err != nil:
			t.Errorf("attempt %d (stale sorts first: %t): history: %v", attempt, staleFirst, err)
		case len(versions) != 2:
			t.Fatalf("attempt %d: merged %d versions", attempt, len(versions))
		case versions[1].UserDefined[authorityHoldKey] != "ON" || events[1].Action != lifecycle.NoneAction:
			t.Errorf("attempt %d (stale sorts first: %t): merged hold=%q event=%s", attempt, staleFirst, versions[1].UserDefined[authorityHoldKey], events[1].Action)
		}
		if err := authorityExpireVersion(t, s, key, id); !errors.Is(err, errLifecycleNotApplicable) {
			t.Errorf("attempt %d (stale sorts first: %t): expiry of a held version: %v", attempt, staleFirst, err)
		}
		oi, err := s.z.serverPools[0].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id})
		if err != nil || oi.UserDefined[authorityHoldKey] != "ON" {
			t.Fatalf("held version changed: hold=%q err=%v", oi.UserDefined[authorityHoldKey], err)
		}
		if staleFirst {
			return
		}
	}
	t.Fatal("no attempt where the stale revision sorts first")
}

// The same layout without protection: a drive missed an ordinary metadata
// update of a version that expires. The fifteen still decide its expiry.
func TestPoolsLifecycleMinorityStaleRevision(t *testing.T) {
	authorityParity(t)
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	ctx := t.Context()
	for attempt := range 32 {
		key := fmt.Sprintf("ncv-stale-%d", attempt)
		id, staleFirst := minorityRevision(t, s, key, map[string]string{"x-amz-meta-note": fmt.Sprint(attempt)})
		_, events, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key)
		if err != nil || len(events) != 2 || events[1].Action != lifecycle.DeleteVersionAction {
			t.Errorf("attempt %d (stale sorts first: %t): events=%v err=%v", attempt, staleFirst, events, err)
		}
		if err := authorityExpireVersion(t, s, key, id); err != nil {
			t.Fatalf("attempt %d (stale sorts first: %t): expiry: %v", attempt, staleFirst, err)
		}
		for i, disk := range s.z.serverPools[0].getHashedSet(key).getDisks() {
			if _, err := disk.ReadVersion(ctx, "", s.bucket, key, id, ReadOptions{}); !errors.Is(err, errFileVersionNotFound) {
				t.Fatalf("attempt %d: drive %d still holds the expired version: %v", attempt, i, err)
			}
		}
		if staleFirst {
			return
		}
	}
	t.Fatal("no attempt where the stale revision sorts first")
}

// authorityRevision encodes a 12+4 object version as drive index holds it,
// with the legal hold status hold.
func authorityRevision(t *testing.T, id [16]byte, modTime int64, index int, hold string) xlMetaV2ShallowVersion {
	t.Helper()
	v := xlMetaV2Version{Type: ObjectType, ObjectV2: &xlMetaV2Object{
		VersionID: id, DataDir: [16]byte{1}, ErasureAlgorithm: ReedSolomon, ErasureM: 12, ErasureN: 4,
		ErasureBlockSize: blockSizeV2, ErasureIndex: index, ErasureDist: make([]uint8, 16), BitrotChecksumAlgo: HighwayHash,
		PartNumbers: []int{1}, PartSizes: []int64{5}, Size: 5, ModTime: modTime,
		MetaUser: map[string]string{authorityHoldKey: hold, "etag": "e", "content-type": "text/plain"},
		MetaSys:  map[string][]byte{"x-minio-internal-a": {1}, "x-minio-internal-b": {2}, "x-minio-internal-c": {3}},
	}}
	for i := range v.ObjectV2.ErasureDist {
		v.ObjectV2.ErasureDist[i] = uint8(i + 1)
	}
	meta, err := v.MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	return xlMetaV2ShallowVersion{header: v.header(), meta: meta}
}

// The header Signature is a 32-bit fold of weak hashes, so two revisions can
// share a header. Revisions are told apart by their metadata: drives that
// hold byte-for-byte different metadata under one header are not one
// revision, and the merged history only carries the accepted metadata.
func TestPoolsLifecycleRevisionIdentity(t *testing.T) {
	newID, oldID := [16]byte{2}, [16]byte{1}
	history := func(off func(drive int) bool) [][]xlMetaV2ShallowVersion {
		metas := make([][]xlMetaV2ShallowVersion, 16)
		for i := range metas {
			old := authorityRevision(t, oldID, 1, i+1, "ON")
			if off(i) {
				// The stale revision under the header of the held one.
				header := old.header
				old = authorityRevision(t, oldID, 1, i+1, "OFF")
				old.header = header
			}
			metas[i] = []xlMetaV2ShallowVersion{authorityRevision(t, newID, 2, i+1, ""), old}
		}
		return metas
	}
	metaVs := slices.Repeat([]uint8{xlMetaVersion}, 16)
	readQuorum := func(xlMetaV2ShallowVersion, uint8) int { return 12 }

	t.Run("revision-key", func(t *testing.T) {
		on, onOther := authorityRevision(t, oldID, 1, 1, "ON"), authorityRevision(t, oldID, 1, 7, "ON")
		off := authorityRevision(t, oldID, 1, 1, "OFF")
		off.header = on.header
		if versionRevision(on, xlMetaVersion) != versionRevision(onOther, xlMetaVersion) {
			t.Error("one revision on two drives has two keys")
		}
		if versionRevision(on, xlMetaVersion) == versionRevision(off, xlMetaVersion) {
			t.Error("different metadata under one header has one key")
		}
	})
	t.Run("stale-minority-first", func(t *testing.T) {
		merged, err := authoritativeHistory(t.Context(), history(func(i int) bool { return i == 0 }), metaVs, xlMetaVersion, 9, readQuorum)
		if err != nil || len(merged) != 2 {
			t.Fatalf("history: err=%v versions=%d", err, len(merged))
		}
		var v xlMetaV2Version
		if _, err := v.unmarshalV(xlMetaVersion, merged[1].meta); err != nil {
			t.Fatal(err)
		}
		if hold := v.ObjectV2.MetaUser[authorityHoldKey]; hold != "ON" {
			t.Fatalf("merged history carries hold=%q", hold)
		}
	})
	t.Run("split-8-8", func(t *testing.T) {
		if merged, err := authoritativeHistory(t.Context(), history(func(i int) bool { return i%2 == 0 }), metaVs, xlMetaVersion, 9, readQuorum); !errors.Is(err, errErasureReadQuorum) {
			t.Fatalf("8/8 metadata split: %d versions, err=%v", len(merged), err)
		}
	})
	// The user and the system map are separate sections of the digest: an
	// entry that moves between them changes what the evaluator reads.
	t.Run("map-boundary", func(t *testing.T) {
		for _, entry := range [][2]string{
			{authorityHoldKey, "ON"},
			{strings.ToLower(xhttp.AmzObjectLockRetainUntilDate), "2099-01-01T00:00:00Z"},
			{xhttp.AmzObjectTagging, "expire=yes"},
		} {
			ver := authorityRevision(t, oldID, 1, 1, "")
			var v xlMetaV2Version
			if _, err := v.unmarshalV(xlMetaVersion, ver.meta); err != nil {
				t.Fatal(err)
			}
			v.ObjectV2.MetaUser, v.ObjectV2.MetaSys = map[string]string{entry[0]: entry[1]}, nil
			user, err := v.MarshalMsg(nil)
			if err != nil {
				t.Fatal(err)
			}
			v.ObjectV2.MetaUser, v.ObjectV2.MetaSys = nil, map[string][]byte{entry[0]: []byte(entry[1])}
			sys, err := v.MarshalMsg(nil)
			if err != nil {
				t.Fatal(err)
			}
			if versionRevision(xlMetaV2ShallowVersion{header: ver.header, meta: user}, xlMetaVersion) ==
				versionRevision(xlMetaV2ShallowVersion{header: ver.header, meta: sys}, xlMetaVersion) {
				t.Errorf("%s moved between the maps keeps the revision", entry[0])
			}
		}
	})
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := authoritativeHistory(ctx, history(func(int) bool { return false }), metaVs, xlMetaVersion, 9, readQuorum); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled history: %v", err)
		}
	})
}

// authorityMarker encodes a delete marker of version id at modTime.
func authorityMarker(t *testing.T, id [16]byte, modTime int64) xlMetaV2ShallowVersion {
	t.Helper()
	v := xlMetaV2Version{Type: DeleteType, DeleteMarker: &xlMetaV2DeleteMarker{VersionID: id, ModTime: modTime, MetaSys: map[string][]byte{}}}
	meta, err := v.MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	return xlMetaV2ShallowVersion{header: v.header(), meta: meta}
}

// A revision counts only on more than half of the drives, whatever read
// quorum its metadata has. A delete marker that a DELETE left on exactly
// half of the drives, which is the read quorum of a marker, is not part of
// the history: the drives cannot tell whether the version it hides is the
// latest one, and no expiry is decided on them. One more drive decides.
func TestPoolsLifecycleHalfDriveMarker(t *testing.T) {
	markerID, objectID := [16]byte{2}, [16]byte{1}
	history := func(drives int) [][]xlMetaV2ShallowVersion {
		metas := make([][]xlMetaV2ShallowVersion, 16)
		for i := range metas {
			if i < drives {
				metas[i] = append(metas[i], authorityMarker(t, markerID, 2))
			}
			metas[i] = append(metas[i], authorityRevision(t, objectID, 1, i+1, ""))
		}
		return metas
	}
	metaVs := slices.Repeat([]uint8{xlMetaVersion}, 16)
	readQuorum := func(ver xlMetaV2ShallowVersion, _ uint8) int {
		if ver.header.Type == DeleteType {
			return 8
		}
		return 12
	}
	t.Run("half", func(t *testing.T) {
		if merged, err := authoritativeHistory(t.Context(), history(8), metaVs, xlMetaVersion, 9, readQuorum); !errors.Is(err, errErasureReadQuorum) {
			t.Fatalf("marker on 8 of 16 drives: %d versions, err=%v", len(merged), err)
		}
	})
	t.Run("majority", func(t *testing.T) {
		merged, err := authoritativeHistory(t.Context(), history(9), metaVs, xlMetaVersion, 9, readQuorum)
		if err != nil || len(merged) != 2 || merged[0].header.VersionID != markerID || merged[1].header.VersionID != objectID {
			t.Fatalf("marker on 9 of 16 drives: %d versions, err=%v", len(merged), err)
		}
	})

	// On the drives: an expired version under a marker that reached half of
	// them. The expiry of the version, which the marker hides on those
	// drives, and of the key are refused, and every drive keeps what it has.
	t.Run("drives", func(t *testing.T) {
		authorityParity(t)
		s := newSplitILM(t, versioning.Enabled, splitILMRules)
		ctx := t.Context()
		const key = "exp-half-marker"
		s.write(key, splitAt("v1", 5, 0))
		s.write(key, splitMarker("dm", 0.01, 0))
		id, marker := s.ids[key+" v1"], s.ids[key+" dm"]
		removeAuthorityCopies(t, s, 0, key, marker, authorityDrives(8, 16))

		if _, _, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key); !isErrReadQuorum(err) {
			t.Errorf("history with a marker on half of the drives: %v", err)
		}
		if err := authorityExpireVersion(t, s, key, id); !isErrWriteQuorum(err) {
			t.Errorf("expiry of the version under the marker: %v", err)
		}
		if _, err := s.z.DeleteObject(ctx, s.bucket, key, authorityDeleteAll); !isErrWriteQuorum(err) {
			t.Errorf("expiry of all versions: %v", err)
		}
		authorityPresent(t, s, 0, key, id)
		for i, disk := range s.z.serverPools[0].getHashedSet(key).getDisks() {
			_, err := disk.ReadVersion(ctx, "", s.bucket, key, marker, ReadOptions{})
			if i < 8 && err != nil {
				t.Fatalf("drive %d lost the marker: %v", i, err)
			}
			if i >= 8 && !errors.Is(err, errFileVersionNotFound) {
				t.Fatalf("drive %d: marker %v", i, err)
			}
		}

		// Control: the marker on one more drive decides, and the version
		// under it is noncurrent, which the rule of exp- does not expire.
		const whole = "exp-majority-marker"
		s.write(whole, splitAt("v1", 5, 0))
		s.write(whole, splitMarker("dm", 0.01, 0))
		removeAuthorityCopies(t, s, 0, whole, s.ids[whole+" dm"], authorityDrives(9, 16))
		versions, events, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, whole)
		if err != nil || len(versions) != 2 || !versions[0].DeleteMarker || events[1].Action != lifecycle.NoneAction {
			t.Fatalf("history with a marker on 9 drives: %d versions, events %v, err=%v", len(versions), events, err)
		}
	})
}

// authorityMovedHold serves a drive whose metadata of version id carries the
// legal hold in the system map instead of the user map, under the header it
// had: the evaluator no longer reads the hold there.
type authorityMovedHold struct {
	StorageAPI
	bucket, key, id string
}

func (d authorityMovedHold) ReadXL(ctx context.Context, bucket, key string, data bool) (RawFileInfo, error) {
	rf, err := d.StorageAPI.ReadXL(ctx, bucket, key, data)
	if err != nil || bucket != d.bucket || key != d.key {
		return rf, err
	}
	var xl xlMetaV2
	if err = xl.LoadOrConvert(rf.Buf); err != nil {
		return rf, err
	}
	for i := range xl.versions {
		if uuid.UUID(xl.versions[i].header.VersionID).String() != d.id {
			continue
		}
		var v xlMetaV2Version
		if _, err = v.unmarshalV(xl.metaV, xl.versions[i].meta); err != nil {
			return rf, err
		}
		v.ObjectV2.MetaSys[authorityHoldKey] = []byte(v.ObjectV2.MetaUser[authorityHoldKey])
		delete(v.ObjectV2.MetaUser, authorityHoldKey)
		if xl.versions[i].meta, err = v.MarshalMsg(nil); err != nil {
			return rf, err
		}
	}
	rf.Buf, err = xl.AppendTo(nil)
	return rf, err
}

// One drive's metadata moves the hold of a held version to the system map
// under the same header. Its revision is not the held one, and the bulk
// expiry keeps the version.
func TestPoolsLifecycleMovedHoldKeepsVersion(t *testing.T) {
	s := newLockedSplitILM(t, authorityNoncurrentRule)
	ctx := t.Context()
	const key = "ncv-moved-hold"
	s.write(key, splitAt("old", 5, 0))
	s.write(key, splitAt("new", 3, 0))
	id := s.ids[key+" old"]
	stamp := UTCNow().Format(time.RFC3339Nano)
	setLifecycleCopyMetadata(t, s, key, id, 0, map[string]string{authorityHoldKey: "ON", ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: stamp}, false)
	p := s.z.serverPools[0]
	p.erasureDisksMu.Lock()
	prior := p.erasureDisks
	wrapped := make([][]StorageAPI, len(prior))
	for i, disks := range prior {
		wrapped[i] = append([]StorageAPI(nil), disks...)
		wrapped[i][0] = authorityMovedHold{StorageAPI: disks[0], bucket: s.bucket, key: key, id: id}
	}
	p.erasureDisks = wrapped
	p.erasureDisksMu.Unlock()
	t.Cleanup(func() { p.erasureDisksMu.Lock(); p.erasureDisks = prior; p.erasureDisksMu.Unlock() })

	versions, events, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key)
	if err != nil || versions[1].UserDefined[authorityHoldKey] != "ON" || events[1].Action != lifecycle.NoneAction {
		t.Errorf("history: events=%v err=%v", events, err)
	}
	if err := authorityDeletePath(t, s, key, id, "bulk"); !errors.Is(err, errLifecycleNotApplicable) {
		t.Errorf("bulk expiry of a held version: %v", err)
	}
	authorityPresent(t, s, 0, key, id)
}

// A legacy version can carry several content checksums for each part. The
// map is encoded in iteration order, and must not change the revision of
// identical metadata; a different checksum does change it (control).
func TestPoolsLifecycleLegacyPartChecksums(t *testing.T) {
	legacy := func(index int, sha256Value string) []byte {
		m := getSampleXLMeta(1)
		m.Stat.ModTime, m.Stat.Size, m.Parts[0].Size = time.Unix(1700000000, 0).UTC(), 20, 20
		m.Erasure.DataBlocks, m.Erasure.ParityBlocks, m.Erasure.Index = 12, 4, index
		m.Erasure.Distribution = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		m.Parts[0].Checksums = map[string]string{"CRC32": "AAAAAA==", "CRC32C": "AAAAAQ==", "SHA1": "AAAAAg==", "SHA256": sha256Value}
		buf, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return buf
	}
	revision := func(buf []byte) revisionKey {
		var xl xlMetaV2
		if err := xl.LoadOrConvert(buf); err != nil {
			t.Fatal(err)
		}
		return versionRevision(xl.versions[0], xl.metaV)
	}
	keys := make(map[revisionKey]bool)
	for i := range 32 {
		keys[revision(legacy(i%16+1, "AAAAAw=="))] = true
	}
	if len(keys) != 1 {
		t.Fatalf("identical legacy metadata has %d revisions", len(keys))
	}
	if revision(legacy(1, "AAAABA==")) == revision(legacy(1, "AAAAAw==")) {
		t.Fatal("a different part checksum keeps the revision")
	}
	disks := make([]StorageAPI, 16)
	for i := range disks {
		disks[i] = authorityRawDisk{buf: legacy(i+1, "AAAAAw==")}
	}
	er := erasureObjects{getDisks: func() []StorageAPI { return disks }, defaultParityCount: 4}
	if versions, err := er.objectVersions(t.Context(), "bucket", "key"); err != nil || len(versions) != 1 {
		t.Fatalf("healthy legacy history: %d versions, err=%v", len(versions), err)
	}
}

// authorityRawDisk serves the same xl.meta for every key.
type authorityRawDisk struct {
	StorageAPI
	buf []byte
}

func (d authorityRawDisk) ReadXL(context.Context, string, string, bool) (RawFileInfo, error) {
	return RawFileInfo{Buf: d.buf}, nil
}

// A legacy (xl.json) version stores the bitrot checksum of each drive's own
// shard. Healthy drives differ there and still hold one revision.
func TestPoolsLifecycleLegacyHistory(t *testing.T) {
	for _, distinct := range []bool{false, true} {
		name := "same-checksums" // control
		if distinct {
			name = "per-shard-checksums"
		}
		t.Run(name, func(t *testing.T) {
			disks := make([]StorageAPI, 16)
			for i := range disks {
				m := getSampleXLMeta(1)
				m.Stat.ModTime, m.Stat.Size, m.Parts[0].Size = time.Unix(1700000000, 0).UTC(), 20, 20
				m.Erasure.DataBlocks, m.Erasure.ParityBlocks, m.Erasure.Index = 12, 4, i+1
				m.Erasure.Distribution = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				shard := []byte{1, 1}
				if distinct {
					shard[0] = byte(i + 1)
				}
				sum := sha256.Sum256(shard)
				m.Erasure.Checksums[0] = ChecksumInfo{PartNumber: 1, Algorithm: SHA256, Hash: sum[:]}
				buf, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				disks[i] = authorityRawDisk{buf: buf}
			}
			er := erasureObjects{getDisks: func() []StorageAPI { return disks }, defaultParityCount: 4}
			if versions, err := er.objectVersions(t.Context(), "bucket", "key"); err != nil || len(versions) != 1 {
				t.Fatalf("healthy legacy history: %d versions, err=%v", len(versions), err)
			}
		})
	}
}

// authorityDeleteAll is the expiry of all versions of a key as the expiry
// worker sends it: a purge of all versions, approved by the lifecycle.
var authorityDeleteAll = ObjectOptions{DeleteAllVersions: true, Expiration: ExpirationOptions{Expire: true}}

// A fresh version committed to 15 of 16 drives, with eight other drives
// unreadable: only seven answering drives show it.
func TestPoolsLifecyclePartialHistory(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	ctx := t.Context()
	const key = "eav-partial-history"
	s.write(key, splitAt("old", 5, 0, 1))
	s.write(key, splitAt("fresh", 0, 1))
	id := s.ids[key+" fresh"]
	removeAuthorityCopies(t, s, 1, key, id, authorityDrives(0, 1))
	wrapAuthorityDisks(t, s, 1, key, true, false, authorityDrives(1, 9))

	if _, _, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key); !isErrReadQuorum(err) {
		t.Errorf("partial history: %v", err)
	}
	_, err := s.z.DeleteObject(ctx, s.bucket, key, authorityDeleteAll)
	if !isErrWriteQuorum(err) {
		t.Errorf("DeleteAll on a partial history: %v", err)
	}
	authorityPresent(t, s, 1, key, id)
}

// Eight drives hold one revision of a version and eight another. Neither is
// authoritative, so neither may decide the expiry.
func TestPoolsLifecycleConflictingRevisions(t *testing.T) {
	s := newLockedSplitILM(t, authorityNoncurrentRule)
	ctx := t.Context()
	const key = "ncv-split-revision"
	s.write(key, splitAt("old", 5, 0))
	s.write(key, splitAt("new", 3, 0))
	id := s.ids[key+" old"]
	disks := s.z.serverPools[0].getHashedSet(key).getDisks()
	half := len(disks) / 2
	stale := make([]FileInfo, len(disks))
	for i := half; i < len(disks); i++ {
		fi, err := disks[i].ReadVersion(ctx, "", s.bucket, key, id, ReadOptions{})
		if err != nil {
			t.Fatal(err)
		}
		stale[i] = fi
	}
	stamp := UTCNow().Format(time.RFC3339Nano)
	setLifecycleCopyMetadata(t, s, key, id, 0, poolLockMetadata("", "ON", stamp, stamp), false)
	for i := half; i < len(disks); i++ {
		if err := disks[i].WriteMetadata(ctx, "", s.bucket, key, stale[i]); err != nil {
			t.Fatal(err)
		}
	}

	if _, _, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key); !isErrReadQuorum(err) {
		t.Errorf("8/8 revisions: %v", err)
	}
	if err := authorityExpireVersion(t, s, key, id); !isErrWriteQuorum(err) {
		t.Errorf("expiry on 8/8 revisions: %v", err)
	}
	for i, disk := range disks {
		if _, err := disk.ReadVersion(ctx, "", s.bucket, key, id, ReadOptions{}); err != nil {
			t.Fatalf("drive %d lost the version: %v", i, err)
		}
	}
}

// Every drive answers and the old version is complete, but a fresh version
// that some drives show reached too few of them to be authoritative.
func TestPoolsLifecycleMissingVersion(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	ctx := t.Context()
	const key = "eav-missing-version"
	s.write(key, splitAt("old", 5, 0, 1))
	s.write(key, splitAt("fresh", 0, 1))
	id := s.ids[key+" fresh"]
	removeAuthorityCopies(t, s, 1, key, id, authorityDrives(0, 9))

	if _, _, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key); !isErrReadQuorum(err) {
		t.Errorf("history without an observed version: %v", err)
	}
	_, err := s.z.DeleteObject(ctx, s.bucket, key, authorityDeleteAll)
	if !isErrWriteQuorum(err) {
		t.Errorf("DeleteAll: %v", err)
	}
	disks := s.z.serverPools[1].getHashedSet(key).getDisks()
	for i := 9; i < len(disks); i++ {
		if _, err := disks[i].ReadVersion(ctx, "", s.bucket, key, id, ReadOptions{}); err != nil {
			t.Fatalf("drive %d lost the fresh version: %v", i, err)
		}
	}
}

// The completeness checks also hold where a set has fewer answering drives
// than a read quorum or no version reaches one.
func TestPoolsLifecycleHistoryEarlyReturns(t *testing.T) {
	// Seven drives hold the key, the other nine do not have it at all.
	t.Run("minority-copy-only", func(t *testing.T) {
		s := newSplitILM(t, versioning.Enabled, splitILMRules)
		ctx := t.Context()
		const key = "eav-minority-only"
		s.write(key, splitAt("old", 5, 0))
		s.write(key, splitAt("fresh", 0, 1))
		id := s.ids[key+" fresh"]
		removeAuthorityCopies(t, s, 1, key, id, authorityDrives(0, 9))
		disks := s.z.serverPools[1].getHashedSet(key).getDisks()
		if _, err := disks[0].ReadXL(ctx, s.bucket, key, false); !errors.Is(err, errFileNotFound) {
			t.Fatalf("fixture: drive 0 still holds the key: %v", err)
		}
		if _, _, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key); !isErrReadQuorum(err) {
			t.Errorf("minority copy: %v", err)
		}
		if _, err := s.z.DeleteObject(ctx, s.bucket, key, authorityDeleteAll); !isErrWriteQuorum(err) {
			t.Errorf("DeleteAll: %v", err)
		}
		for i := 9; i < len(disks); i++ {
			if _, err := disks[i].ReadVersion(ctx, "", s.bucket, key, id, ReadOptions{}); err != nil {
				t.Fatalf("drive %d lost the fresh version: %v", i, err)
			}
		}
	})

	// Control: two versions on seven drives each, none reaches a quorum.
	t.Run("disjoint-minorities", func(t *testing.T) {
		s := newSplitILM(t, versioning.Enabled, splitILMRules)
		ctx := t.Context()
		const key = "eav-disjoint"
		s.write(key, splitAt("old", 5, 0))
		s.write(key, splitAt("a", 2, 1))
		s.write(key, splitAt("b", 1, 1))
		removeAuthorityCopies(t, s, 1, key, s.ids[key+" a"], authorityDrives(7, 16))
		removeAuthorityCopies(t, s, 1, key, s.ids[key+" b"], func(i int) bool { return i < 7 || i >= 14 })
		if _, _, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key); !isErrReadQuorum(err) {
			t.Fatalf("disjoint minorities: %v", err)
		}
		if _, err := s.z.DeleteObject(ctx, s.bucket, key, authorityDeleteAll); !isErrWriteQuorum(err) {
			t.Fatalf("DeleteAll: %v", err)
		}
	})
}

// A set without an unknown drive less than half of its drives still tells
// its history; half of them unknown could hide a version.
func TestPoolsLifecycleUnknownDriveThreshold(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pool    int // the pool with unreadable drives
		unknown int
		refused bool
	}{
		{"history/7", 0, 7, false},
		{"history/8", 0, 8, true},
		{"absent/7", 1, 7, false},
		{"absent/8", 1, 8, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			ctx := t.Context()
			const key = "ncv-threshold"
			// Empty versions need only a simple majority of the drives, so
			// seven unknown drives leave enough copies.
			var ids []string
			for _, days := range []int{5, 3} {
				id := mustGetUUID()
				putConsistencyObject(t, s.z, s.bucket, key, 0, "", ObjectOptions{Versioned: true, VersionID: id, MTime: UTCNow().AddDate(0, 0, -days)})
				ids = append(ids, id)
			}
			wrapAuthorityDisks(t, s, tc.pool, key, true, false, authorityDrives(0, tc.unknown))
			err := authorityExpireVersion(t, s, key, ids[0])
			if tc.refused {
				if !isErrWriteQuorum(err) {
					t.Errorf("%d unknown drives: %v", tc.unknown, err)
				}
				authorityPresent(t, s, 0, key, ids[0])
				return
			}
			if err != nil {
				t.Fatalf("%d unknown drives: %v", tc.unknown, err)
			}
			if _, err := s.z.serverPools[0].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: ids[0]}); !isErrVersionNotFound(err) {
				t.Fatalf("expired version remains: %v", err)
			}
		})
	}
}

// Control: free versions are tier GC records. Residue of one on a few drives
// must not block an expiry.
func TestPoolsLifecycleFreeVersionResidue(t *testing.T) {
	for _, tc := range []struct {
		name    string
		residue int // the pool with the residue
	}{
		{"beside-history", 0},
		{"alone", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			ctx := t.Context()
			const key = "ncv-free-residue"
			s.write(key, splitTiered("gone", 6, tc.residue))
			s.write(key, splitAt("old", 5, 0))
			s.write(key, splitAt("new", 3, 0))
			gone := s.ids[key+" gone"]
			disks := s.z.serverPools[tc.residue].getHashedSet(key).getDisks()
			fvID := mustGetUUID()
			for i, disk := range disks {
				fi := FileInfo{VersionID: gone}
				if i < 3 {
					fi.SetTierFreeVersionID(fvID)
				} else {
					fi.SetSkipTierFreeVersion()
				}
				if err := disk.DeleteVersion(ctx, s.bucket, key, fi, false, DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			if h := authorityHeader(t, disks[0], s.bucket, key, fvID); !h.FreeVersion() {
				t.Fatalf("fixture lacks a free version: %v", h)
			}
			versions, events, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key)
			if err != nil || len(versions) != 2 || events[1].Action != lifecycle.DeleteVersionAction {
				t.Fatalf("history with free-version residue: %d versions, events=%v, err=%v", len(versions), events, err)
			}
			if err := authorityExpireVersion(t, s, key, s.ids[key+" old"]); err != nil {
				t.Fatalf("expiry beside free-version residue: %v", err)
			}
		})
	}
}

// An interrupted 12+4 write left nine matching copies of a newer version:
// a majority of the drives, but less than its read quorum. It must not make
// the last committed version noncurrent.
func TestPoolsLifecycleReducedParityPartialVersion(t *testing.T) {
	for _, path := range []string{"single", "bulk"} {
		t.Run(path, func(t *testing.T) {
			authorityParity(t)
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			ctx := t.Context()
			const key = "ncv-partial-write"
			s.write(key, splitAt("committed", 5, 0))
			s.write(key, splitAt("partial", 3, 0))
			committed, partial := s.ids[key+" committed"], s.ids[key+" partial"]
			oi, err := s.z.serverPools[0].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: partial})
			if err != nil || oi.DataBlocks != 12 || oi.ParityBlocks != 4 {
				t.Fatalf("fixture is not 12+4: data=%d parity=%d err=%v", oi.DataBlocks, oi.ParityBlocks, err)
			}
			removeAuthorityCopies(t, s, 0, key, partial, authorityDrives(9, 16))

			if _, _, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key); !isErrReadQuorum(err) {
				t.Errorf("history with a partial version: %v", err)
			}
			if err := authorityDeletePath(t, s, key, committed, path); !isErrWriteQuorum(err) {
				t.Errorf("expiry of the last committed version: %v", err)
			}
			authorityPresent(t, s, 0, key, committed)
		})
	}
}

// Control: two drives do not answer, every version still has its quorum.
func TestPoolsLifecycleDegradedHistory(t *testing.T) {
	authorityParity(t)
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	ctx := t.Context()
	const key = "ncv-degraded"
	s.write(key, splitAt("old", 5, 0))
	s.write(key, splitAt("new", 3, 0))
	id := s.ids[key+" old"]
	wrapAuthorityDisks(t, s, 0, key, true, false, authorityDrives(0, 2))
	if err := authorityExpireVersion(t, s, key, id); err != nil {
		t.Fatalf("degraded expiry: %v", err)
	}
	if _, err := s.z.serverPools[0].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id}); !isErrVersionNotFound(err) {
		t.Fatalf("expired version remains: %v", err)
	}
}

// authorityPoolLock sets the Object Lock metadata of the copy of version id
// in pool.
func authorityPoolLock(t *testing.T, s *splitILM, key, id string, pool int, metadata map[string]string) {
	t.Helper()
	metadata = maps.Clone(metadata)
	if metadata[strings.ToLower(xhttp.AmzObjectLockMode)] != "" {
		metadata[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = UTCNow().AddDate(1, 0, 0).Format(time.RFC3339)
	} else {
		metadata[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = ""
	}
	setLifecycleCopyMetadata(t, s, key, id, pool, metadata, false)
}

// authorityDeletePath expires version id by the single path or by the bulk
// path, which takes the ordinary or the tiered route as the version is.
func authorityDeletePath(t *testing.T, s *splitILM, key, id, path string) error {
	t.Helper()
	if path == "single" {
		return authorityExpireVersion(t, s, key, id)
	}
	_, errs := s.z.DeleteObjects(t.Context(), s.bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: key, VersionID: id}}}, ObjectOptions{Versioned: true, Expiration: ExpirationOptions{Expire: true}})
	return errs[0]
}

var authorityPaths = []string{"single", "bulk", "tiered-bulk"}

// The copies of a version in two pools carry protection revisions that do not
// tell which is the newest. Refuse instead of guessing.
func TestPoolsLifecycleAmbiguousProtection(t *testing.T) {
	stamp := UTCNow().Add(-time.Hour).Format(time.RFC3339Nano)
	old := UTCNow().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name   string
		copies [2]map[string]string
	}{
		{"hold-equal-stamps", [2]map[string]string{poolLockMetadata("", "OFF", old, stamp), poolLockMetadata("", "ON", old, stamp)}},
		{"hold-missing-stamp", [2]map[string]string{poolLockMetadata("", "ON", old, ""), poolLockMetadata("", "OFF", old, stamp)}},
		{"hold-malformed-stamp", [2]map[string]string{poolLockMetadata("", "ON", old, "yesterday"), poolLockMetadata("", "OFF", old, stamp)}},
		{"retention-equal-stamps", [2]map[string]string{poolLockMetadata("", "OFF", stamp, old), poolLockMetadata("GOVERNANCE", "OFF", stamp, old)}},
	} {
		for _, path := range authorityPaths {
			t.Run(tc.name+"/"+path, func(t *testing.T) {
				s := newLockedSplitILM(t, authorityNoncurrentRule)
				const key = "ncv-ambiguous"
				v := splitAt("old", 5, 0, 1)
				v.tiered = path == "tiered-bulk"
				s.write(key, v)
				s.write(key, splitAt("new", 3, 0, 1))
				id := s.ids[key+" old"]
				for pool, metadata := range tc.copies {
					authorityPoolLock(t, s, key, id, pool, metadata)
				}
				if _, _, err := s.z.lifecycleEventsAllPools(t.Context(), s.bucket, key); !errors.Is(err, errLifecycleNotApplicable) {
					t.Errorf("ambiguous protection: %v", err)
				}
				if err := authorityDeletePath(t, s, key, id, path); !errors.Is(err, errLifecycleNotApplicable) {
					t.Errorf("expiry with ambiguous protection: %v", err)
				}
				for pool := range s.z.serverPools {
					authorityPresent(t, s, pool, key, id)
				}
			})
		}
	}
}

// Protection stored under canonical-case keys counts as the evaluator reads
// it, in the comparison of copies, in the merged version and in the set.
func TestPoolsLifecycleCanonicalProtection(t *testing.T) {
	older := UTCNow().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	recent := UTCNow().Add(-time.Hour).Format(time.RFC3339Nano)
	until := UTCNow().AddDate(1, 0, 0).Format(time.RFC3339)
	hold := func(status, stamp string) map[string]string {
		return map[string]string{xhttp.AmzObjectLockLegalHold: status, ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: stamp}
	}
	retention := func(mode, stamp string) map[string]string {
		m := map[string]string{ReservedMetadataPrefixLower + ObjectLockRetentionTimestamp: stamp}
		if mode != "" {
			m[xhttp.AmzObjectLockMode], m[xhttp.AmzObjectLockRetainUntilDate] = mode, until
		}
		return m
	}
	for _, tc := range []struct {
		name    string
		copies  [2]map[string]string
		expires bool
	}{
		{"hold-equal-stamps", [2]map[string]string{hold("OFF", recent), hold("ON", recent)}, false},
		{"hold-newer", [2]map[string]string{hold("OFF", older), hold("ON", recent)}, false},
		{"retention-equal-stamps", [2]map[string]string{retention("", recent), retention("COMPLIANCE", recent)}, false},
		{"retention-newer", [2]map[string]string{retention("", older), retention("GOVERNANCE", recent)}, false},
		{"hold-released", [2]map[string]string{hold("ON", older), hold("OFF", recent)}, true}, // control
	} {
		for _, path := range []string{"single", "bulk"} {
			t.Run(tc.name+"/"+path, func(t *testing.T) {
				s := newLockedSplitILM(t, authorityNoncurrentRule)
				const key = "ncv-canonical"
				id, mtime := mustGetUUID(), UTCNow().AddDate(0, 0, -5)
				for pool, metadata := range tc.copies {
					putConsistencyObject(t, s.z, s.bucket, key, pool, "old", ObjectOptions{Versioned: true, VersionID: id, MTime: mtime, UserDefined: maps.Clone(metadata)})
				}
				s.write(key, splitAt("new", 3, 0, 1))
				_, events, err := s.z.lifecycleEventsAllPools(t.Context(), s.bucket, key)
				if !tc.expires && err == nil && events[1].Action != lifecycle.NoneAction {
					t.Errorf("protected version approved: %s", events[1].Action)
				}
				err = authorityDeletePath(t, s, key, id, path)
				if tc.expires {
					if err != nil {
						t.Fatalf("released version: %v", err)
					}
					if _, err := s.z.serverPools[0].GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: id}); !isErrVersionNotFound(err) {
						t.Fatalf("released version remains: %v", err)
					}
					return
				}
				if !errors.Is(err, errLifecycleNotApplicable) {
					t.Errorf("expiry of a protected version: %v", err)
				}
				for pool := range s.z.serverPools {
					authorityPresent(t, s, pool, key, id)
				}
			})
		}
	}
}

// Control: a strictly newer release in another pool still expires the
// version by the ordinary bulk path too, beside the single and tiered bulk
// paths of TestPoolsLifecycleDuplicateLockMetadata.
func TestPoolsLifecycleProtectionReleaseBulk(t *testing.T) {
	old := UTCNow().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	recent := UTCNow().Add(-time.Hour).Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name   string
		copies [2]map[string]string
	}{
		{"hold-released", [2]map[string]string{poolLockMetadata("", "ON", old, old), poolLockMetadata("", "OFF", old, recent)}},
		{"retention-released", [2]map[string]string{poolLockMetadata("GOVERNANCE", "OFF", old, old), poolLockMetadata("", "OFF", recent, old)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newLockedSplitILM(t, authorityNoncurrentRule)
			const key = "ncv-released"
			s.write(key, splitAt("old", 5, 0, 1))
			s.write(key, splitAt("new", 3, 0, 1))
			id := s.ids[key+" old"]
			for pool, metadata := range tc.copies {
				authorityPoolLock(t, s, key, id, pool, metadata)
			}
			if err := authorityDeletePath(t, s, key, id, "bulk"); err != nil {
				t.Fatalf("released version: %v", err)
			}
			for pool := range s.z.serverPools {
				if _, err := s.z.serverPools[pool].GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: id}); !isErrVersionNotFound(err) {
					t.Errorf("pool %d still holds the released version: %v", pool, err)
				}
			}
		})
	}
}

// A set takes an all-pools approval only with the protection it was approved
// with. Protection that the set reads and the approval does not strictly
// supersede keeps the version.
func TestPoolsLifecycleCheckedExpirySafeguard(t *testing.T) {
	old := UTCNow().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	recent := UTCNow().Add(-time.Hour).Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name     string
		local    map[string]string
		approved objectLockState
		deleted  bool
	}{
		{"hold-newer-locally", poolLockMetadata("", "ON", old, recent), objectLockState{legalHold: "OFF", legalHoldTimestamp: old}, false},
		{"hold-missing-local-stamp", poolLockMetadata("", "ON", old, ""), objectLockState{legalHold: "OFF", legalHoldTimestamp: recent}, false},
		{"hold-equal-stamps", poolLockMetadata("", "ON", old, recent), objectLockState{legalHold: "OFF", legalHoldTimestamp: recent}, false},
		{"hold-missing-approved-stamp", poolLockMetadata("", "ON", old, old), objectLockState{legalHold: "OFF"}, false},
		{"retention-newer-locally", poolLockMetadata("GOVERNANCE", "OFF", recent, old), objectLockState{retentionTimestamp: old, legalHold: "OFF", legalHoldTimestamp: old}, false},
		// Controls: the approval strictly supersedes the local protection.
		{"hold-released", poolLockMetadata("", "ON", old, old), objectLockState{legalHold: "OFF", legalHoldTimestamp: recent}, true},
		{"retention-released", poolLockMetadata("GOVERNANCE", "OFF", old, old), objectLockState{retentionTimestamp: recent, legalHold: "OFF", legalHoldTimestamp: old}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newLockedSplitILM(t, authorityNoncurrentRule)
			ctx := t.Context()
			const key = "ncv-safeguard"
			s.write(key, splitAt("old", 5, 0))
			s.write(key, splitAt("new", 3, 0))
			id := s.ids[key+" old"]
			authorityPoolLock(t, s, key, id, 0, tc.local)
			opts := ObjectOptions{Versioned: true, VersionID: id, Expiration: ExpirationOptions{Expire: true, CheckedAllPools: true}}
			opts.Expiration.ApprovedProtection = tc.approved
			_, err := s.z.serverPools[0].DeleteObject(ctx, s.bucket, key, opts)
			if !tc.deleted {
				if !errors.Is(err, errLifecycleNotApplicable) {
					t.Errorf("protected version: %v", err)
				}
				authorityPresent(t, s, 0, key, id)
				return
			}
			if err != nil {
				t.Fatalf("released version: %v", err)
			}
			if _, err := s.z.serverPools[0].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id}); !isErrVersionNotFound(err) {
				t.Fatalf("released version remains: %v", err)
			}
		})
	}
}

// A pending purge vetoes an approved expiry in the set, also when the read
// returns it with MethodNotAllowed, as for a delete marker.
func TestPoolsLifecycleCheckedExpiryPendingPurge(t *testing.T) {
	for _, marker := range []bool{false, true} {
		name := "version"
		if marker {
			name = "delete-marker"
		}
		t.Run(name, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			ctx := t.Context()
			const key = "ncv-pending-purge"
			label := "old"
			s.write(key, splitAt("first", 6, 0))
			if marker {
				label = "dm"
				s.write(key, splitMarker(label, 5, 0))
			} else {
				s.write(key, splitAt(label, 5, 0))
			}
			s.write(key, splitAt("new", 3, 0))
			id := s.ids[key+" "+label]
			target := newILMTestTarget(t)
			setILMTestReplicationConfig(t, s.bucket, target.arn, target.bucket)
			oi, err := s.z.serverPools[0].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id})
			if oi.DeleteMarker != marker || (err != nil) != marker || marker && !isErrMethodNotAllowed(err) {
				t.Fatalf("fixture: marker=%t err=%v", oi.DeleteMarker, err)
			}
			_, err = s.z.serverPools[0].DeleteObject(ctx, s.bucket, key, ObjectOptions{
				VersionID: id, Versioned: true, MTime: oi.ModTime,
				DeleteReplication: ReplicationState{
					VersionPurgeStatusInternal: target.arn + "=PENDING;",
					PurgeTargets:               map[string]VersionPurgeStatusType{target.arn: replication.VersionPurgePending},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			pending, err := s.z.serverPools[0].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id})
			if !isErrMethodNotAllowed(err) || pending.VersionPurgeStatus != replication.VersionPurgePending {
				t.Fatalf("fixture: purge=%q err=%v", pending.VersionPurgeStatus, err)
			}
			_, err = s.z.serverPools[0].DeleteObject(ctx, s.bucket, key, ObjectOptions{Versioned: true, VersionID: id, Expiration: ExpirationOptions{Expire: true, CheckedAllPools: true}})
			if !errors.Is(err, errLifecycleNotApplicable) {
				t.Errorf("approved expiry of a pending purge: %v", err)
			}
			after, err := s.z.serverPools[0].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id})
			if !isErrMethodNotAllowed(err) || after.VersionPurgeStatus != replication.VersionPurgePending {
				t.Fatalf("pending purge changed: purge=%q err=%v", after.VersionPurgeStatus, err)
			}
		})
	}
}

// The copy of a version in another pool carries a pending purge that the
// merge would drop with the replication state of the first copy.
func TestPoolsLifecycleDuplicatePendingPurge(t *testing.T) {
	for _, path := range []string{"single", "bulk"} {
		t.Run(path, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			ctx := t.Context()
			const key = "ncv-pending-copy"
			s.write(key, splitAt("old", 5, 0, 1))
			s.write(key, splitAt("new", 3, 0, 1))
			id := s.ids[key+" old"]
			target := newILMTestTarget(t)
			setILMTestReplicationConfig(t, s.bucket, target.arn, target.bucket)
			oi, err := s.z.serverPools[1].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id})
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.z.serverPools[1].DeleteObject(ctx, s.bucket, key, ObjectOptions{
				VersionID: id, Versioned: true, MTime: oi.ModTime,
				DeleteReplication: ReplicationState{
					VersionPurgeStatusInternal: target.arn + "=PENDING;",
					PurgeTargets:               map[string]VersionPurgeStatusType{target.arn: replication.VersionPurgePending},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			files, err := s.z.serverPools[1].getHashedSet(key).objectVersions(ctx, s.bucket, key)
			if err != nil || len(files) != 2 || files[1].ToObjectInfo(s.bucket, key, true).VersionPurgeStatus != replication.VersionPurgePending {
				t.Fatalf("fixture lacks the pending copy: %d versions, err=%v", len(files), err)
			}
			if _, _, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key); !errors.Is(err, errLifecycleNotApplicable) {
				t.Errorf("copies with a different purge state: %v", err)
			}
			if err := authorityDeletePath(t, s, key, id, path); !errors.Is(err, errLifecycleNotApplicable) {
				t.Errorf("expiry beside a pending purge: %v", err)
			}
			stored, err := s.z.serverPools[0].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id})
			if err != nil || stored.VersionPurgeStatus != "" {
				t.Fatalf("first copy changed: purge=%q err=%v", stored.VersionPurgeStatus, err)
			}
			if _, err := s.z.serverPools[1].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id}); !isErrMethodNotAllowed(err) {
				t.Fatalf("pending copy changed: %v", err)
			}
		})
	}
}

// Copies of a version compare their per-target replication state as parsed:
// the order of the serialized targets does not count, a target does.
func TestPoolsLifecycleDuplicateReplicationTargets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses [2]string
		refused  bool
	}{
		{"reordered", [2]string{"arn:a=COMPLETED;arn:b=COMPLETED;", "arn:b=COMPLETED;arn:a=COMPLETED;"}, false}, // control
		{"other-targets", [2]string{"arn:a=COMPLETED;", "arn:a=COMPLETED;arn:b=COMPLETED;"}, true},
		{"other-status", [2]string{"arn:a=COMPLETED;arn:b=COMPLETED;", "arn:a=COMPLETED;arn:b=FAILED;"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			ctx := t.Context()
			const key = "ncv-replicated-copies"
			id, mtime := mustGetUUID(), UTCNow().AddDate(0, 0, -5)
			for pool, status := range tc.statuses {
				putConsistencyObject(t, s.z, s.bucket, key, pool, "old", ObjectOptions{
					Versioned: true, VersionID: id, MTime: mtime,
					UserDefined: map[string]string{ReservedMetadataPrefixLower + ReplicationStatus: status},
				})
			}
			s.write(key, splitAt("new", 3, 0, 1))
			for pool, status := range tc.statuses {
				oi, err := s.z.serverPools[pool].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id})
				if err != nil || oi.ReplicationStatusInternal != status {
					t.Fatalf("fixture pool %d: status=%q err=%v", pool, oi.ReplicationStatusInternal, err)
				}
			}
			_, events, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key)
			if tc.refused {
				if !errors.Is(err, errLifecycleNotApplicable) {
					t.Errorf("copies with other replication targets: %v", err)
				}
				if err := authorityExpireVersion(t, s, key, id); !errors.Is(err, errLifecycleNotApplicable) {
					t.Errorf("expiry: %v", err)
				}
				authorityPresent(t, s, 0, key, id)
				return
			}
			if err != nil || events[1].Action != lifecycle.DeleteVersionAction {
				t.Fatalf("equivalent copies: events=%v err=%v", events, err)
			}
			if err := authorityExpireVersion(t, s, key, id); err != nil {
				t.Fatalf("expiry of equivalent copies: %v", err)
			}
		})
	}
}

// Null versions written in two pools of a suspended bucket share a version
// ID without being one write. Copies with another ModTime are older writes:
// the newest decides, unless an older one is still protected. Copies with
// the same ModTime are duplicates and must still agree.
func TestPoolsLifecycleNullGenerations(t *testing.T) {
	hold := func(status, stamp string) map[string]string {
		return map[string]string{authorityHoldKey: status, ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp: stamp}
	}
	older := UTCNow().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	recent := UTCNow().Add(-time.Hour).Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name         string
		lock         bool
		old, new     map[string]string
		sameModTime  bool
		wantNewest   bool // evaluated on the newer write, else refused
		replicateOld bool
	}{
		{"older-unprotected", false, hold("OFF", ""), nil, false, true, true},
		{"older-held", true, hold("ON", older), hold("OFF", recent), false, false, false},
		{"same-modtime-duplicates", false, hold("OFF", ""), nil, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &splitILM{migrationILM: newMigrationILM(t, versioning.Suspended, tc.lock, splitILMRules), ids: map[string]string{}, bodies: map[string]string{}}
			ctx := t.Context()
			const key = "exp-null-generations"
			oldTime, newTime := UTCNow().AddDate(0, 0, -5), UTCNow().AddDate(0, 0, -3)
			if tc.sameModTime {
				newTime = oldTime
			}
			oldMeta := maps.Clone(tc.old)
			if tc.replicateOld {
				oldMeta[ReservedMetadataPrefixLower+ReplicationStatus] = "arn:a=COMPLETED;"
			}
			putConsistencyObject(t, s.z, s.bucket, key, 0, "old", ObjectOptions{VersionSuspended: true, MTime: oldTime, UserDefined: oldMeta})
			newest := putConsistencyObject(t, s.z, s.bucket, key, 1, "new", ObjectOptions{VersionSuspended: true, MTime: newTime, UserDefined: maps.Clone(tc.new)})

			versions, events, err := s.z.lifecycleEventsAllPools(ctx, s.bucket, key)
			opts := ObjectOptions{VersionSuspended: true, Expiration: ExpirationOptions{Expire: true}}
			if !tc.wantNewest {
				if !errors.Is(err, errLifecycleNotApplicable) {
					t.Errorf("history: %d versions, events=%v, err=%v", len(versions), events, err)
				}
				if _, err := s.z.DeleteObject(ctx, s.bucket, key, opts); !errors.Is(err, errLifecycleNotApplicable) {
					t.Errorf("expiry: %v", err)
				}
				for pool := range s.z.serverPools {
					oi, err := s.z.serverPools[pool].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: nullVersionID})
					if err != nil || oi.DeleteMarker {
						t.Fatalf("pool %d lost its null version: marker=%t err=%v", pool, oi.DeleteMarker, err)
					}
				}
				return
			}
			if err != nil || len(versions) != 1 || !versions[0].ModTime.Equal(newest.ModTime) || events[0].Action != lifecycle.DeleteAction {
				t.Fatalf("history: %d versions, events=%v, err=%v", len(versions), events, err)
			}
			if _, err := s.z.DeleteObject(ctx, s.bucket, key, opts); err != nil {
				t.Fatalf("expiry of the newest null write: %v", err)
			}
		})
	}
}

// authoritySideEffectsAll also returns, by version ID, the result an ILM
// trace reports for an expiry that did not remove its version: "refused" or
// "failed". Such traces are not removal traces.
func authoritySideEffectsAll(t *testing.T, run func()) (notified, traced []string, incomplete map[string]string) {
	t.Helper()
	done := make(chan struct{})
	defer close(done)
	events := make(chan event.Event, 16)
	if err := globalHTTPListen.Subscribe(pubsub.MaskFromMaskable(event.ObjectRemovedDelete), events, done, nil); err != nil {
		t.Fatal(err)
	}
	traces := make(chan madmin.TraceInfo, 16)
	if err := globalTrace.Subscribe(madmin.TraceILM, traces, done, nil); err != nil {
		t.Fatal(err)
	}
	run()
	incomplete = map[string]string{}
	// Both publishers deliver synchronously, so everything sent is buffered.
	for {
		select {
		case ev := <-events:
			notified = append(notified, ev.S3.Object.VersionID)
		case tr := <-traces:
			if tr.FuncName != ILMExpiry {
				continue
			}
			if r := tr.Custom["result"]; r != "" {
				incomplete[tr.Custom["version-id"]] = r
				continue
			}
			traced = append(traced, tr.Custom["version-id"])
		default:
			slices.Sort(notified)
			slices.Sort(traced)
			return notified, traced, incomplete
		}
	}
}

// A batch expiry that another pool cannot read is not a removal.
func TestPoolsLifecycleBatchQuorumNotAnnounced(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	const key = "ncv-quorum-event"
	s.write(key, splitAt("old", 5, 0))
	s.write(key, splitAt("new", 3, 0))
	id := s.ids[key+" old"]
	lifecycleReadDisks(t, s, key, 1, errDiskNotFound)
	result := &lifecycleBatchResult{ObjectLayer: s.z}
	notified, traced, incomplete := authoritySideEffectsAll(t, func() {
		deleteObjectVersions(t.Context(), result, s.bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: key, VersionID: id}}}, []lifecycle.Event{{Action: lifecycle.DeleteVersionAction}})
	})
	if incomplete[id] != "failed" {
		t.Errorf("unapplied expiry not reported as failed: %v", incomplete)
	}
	if !isErrWriteQuorum(result.errs[0]) {
		t.Fatalf("fixture result: %v", result.errs[0])
	}
	authorityPresent(t, s, 0, key, id)
	if len(notified) != 0 || len(traced) != 0 {
		t.Fatalf("unapplied expiry announced: notifications=%v traces=%v", notified, traced)
	}
}

// Each entry of a batch gets the side effects of its own result: a completed
// or already absent delete is announced and audited, a refused or failed one
// is not.
func TestPoolsLifecycleBatchSideEffects(t *testing.T) {
	for _, path := range []string{"single-pool", "bulk", "tiered-bulk"} {
		t.Run(path, func(t *testing.T) {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			const key, failing = "ncv-side-effects", "ncv-side-effects-failing"
			for _, k := range []string{key, failing} {
				v := splitAt("old", 5, 0)
				v.tiered = path == "tiered-bulk"
				s.write(k, v)
				s.write(k, splitAt("new", 3, 0))
			}
			if path == "single-pool" {
				prior := s.z.serverPools
				t.Cleanup(func() { s.z.serverPools = prior })
				s.z.serverPools = s.z.serverPools[:1]
			}
			wrapAuthorityDisks(t, s, 0, failing, false, true, authorityDrives(0, 9))
			success, absent := s.ids[key+" old"], mustGetUUID()
			entries := []ObjectToDelete{
				{ObjectV: ObjectV{ObjectName: key, VersionID: success}},
				{ObjectV: ObjectV{ObjectName: failing, VersionID: s.ids[failing+" old"]}},
				{ObjectV: ObjectV{ObjectName: key, VersionID: absent}},
			}
			if path != "single-pool" {
				// A single pool has no all-pools check to refuse a bulk entry.
				entries = append(entries, ObjectToDelete{ObjectV: ObjectV{ObjectName: key, VersionID: s.ids[key+" new"]}})
			}
			evts := make([]lifecycle.Event, len(entries))
			for i := range evts {
				evts[i] = lifecycle.Event{Action: lifecycle.DeleteVersionAction}
			}
			result := &lifecycleBatchResult{ObjectLayer: s.z}
			notified, traced, incomplete := authoritySideEffectsAll(t, func() {
				deleteObjectVersions(t.Context(), result, s.bucket, entries, evts)
			})
			if incomplete[entries[1].VersionID] != "failed" {
				t.Errorf("failed entry: %v", incomplete)
			}
			if len(entries) > 3 && incomplete[entries[3].VersionID] != "refused" {
				t.Errorf("refused entry: %v", incomplete)
			}
			if result.errs[0] != nil || !isErrWriteQuorum(result.errs[1]) ||
				result.errs[2] != nil && !isErrVersionNotFound(result.errs[2]) ||
				len(entries) > 3 && !errors.Is(result.errs[3], errLifecycleNotApplicable) {
				t.Fatalf("fixture results: %v", result.errs)
			}
			want := []string{success, absent}
			slices.Sort(want)
			if !slices.Equal(notified, want) {
				t.Errorf("removal notifications for %v, want %v", notified, want)
			}
			if !slices.Equal(traced, want) {
				t.Errorf("ILM expiry audit for %v, want %v", traced, want)
			}
		})
	}
}

// A single pool keeps the explicit refusal rather than a not-found result.
func TestPoolsLifecycleSinglePoolRefusal(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	s.write("exp-new", splitAt("fresh", 0, 0))
	prior := s.z.serverPools
	t.Cleanup(func() { s.z.serverPools = prior })
	s.z.serverPools = s.z.serverPools[:1]
	_, err := s.z.DeleteObject(t.Context(), s.bucket, "exp-new", ObjectOptions{Versioned: true, Expiration: ExpirationOptions{Expire: true}})
	if !errors.Is(err, errLifecycleNotApplicable) || isErrObjectNotFound(err) || isErrVersionNotFound(err) {
		t.Fatalf("single-pool stale expiry: %v", err)
	}
}

// Migration leaves a version to the logical expiry. When that expiry is
// refused at retirement while the source still holds the version, the source
// is kept: a refusal is never absence. Decommission and rebalance both
// retire through removeMovedVersions.
func TestPoolsMigrationLifecycleRefusedExpiryKeepsSource(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	ctx := t.Context()
	const key = "exp-moved"
	s.write(key, splitAt("old", 5, 0, 1))
	s.write(key, splitAt("new", 0.01, 1))
	id := s.ids[key+" old"]
	source, err := s.z.serverPools[0].GetObjectInfo(ctx, s.bucket, key, ObjectOptions{VersionID: id})
	if err != nil {
		t.Fatal(err)
	}
	_, updatedAt, err := globalBucketMetadataSys.GetLifecycleConfig(s.bucket)
	if err != nil {
		t.Fatal(err)
	}
	version := FileInfo{Name: key, VersionID: id, ModTime: source.ModTime}
	err = s.z.removeMovedVersions(ctx, s.bucket, key, 0, []FileInfo{version}, []migrationExpiredVersion{{
		version:            version,
		event:              lifecycle.Event{Action: lifecycle.DeleteAction},
		lifecycleUpdatedAt: updatedAt,
		source:             lcEventSrc_Decom,
	}})
	if _, ok := err.(PreConditionFailed); !ok {
		t.Fatalf("retirement after a refused expiry: %v", err)
	}
	authorityPresent(t, s, 0, key, id)
	if views := s.views(); !slices.Equal(views[0][key], []string{"old"}) || !slices.Equal(views[1][key], []string{"new", "old"}) {
		t.Fatalf("refused expiry changed the pools: %v", views)
	}
}
