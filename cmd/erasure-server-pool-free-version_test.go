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
	"slices"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
)

// Deleting a version whose data is in a remote tier leaves a free version in
// its place: a record of the remote object, kept until the scanner removes
// both. A free version is not a version of the object. There is no delete
// marker, and the version below it is the latest one; reads already skip it.

// freeVersionNoncurrent expires versions one day after they become noncurrent.
const freeVersionNoncurrent = "<Rule><ID>noncurrent</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>" +
	"<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>"

// freeVersionTier is a remote tier held in memory whose removals can fail.
type freeVersionTier struct {
	*tierExpiryTestBackend
	removeErr error
}

func (b *freeVersionTier) Remove(ctx context.Context, object string, rv remoteVersionID) error {
	if b.removeErr != nil {
		return b.removeErr
	}
	return b.tierExpiryTestBackend.Remove(ctx, object, rv)
}

type freeVersionTest struct {
	t      *testing.T
	z      *erasureServerPools
	bucket string
	tier   *freeVersionTier
	labels map[string]string // version ID -> label
}

// newFreeVersionTest returns two pools with a versioned bucket under rules and
// a remote tier WARM. In pool 0, obj-01 has v1 and v2 and a tiered v3, written
// five, four and three days ago; the client deleted v3. obj-02 had only a
// tiered v1, deleted as well.
func newFreeVersionTest(t *testing.T, rules string) *freeVersionTest {
	t.Helper()
	z, _ := migrationTestPools(t)
	ctx := t.Context()
	f := &freeVersionTest{t: t, z: z, bucket: "free-version", labels: map[string]string{}}
	if err := z.MakeBucket(ctx, f.bucket, MakeBucketOptions{VersioningEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if rules != "" {
		meta, err := globalBucketMetadataSys.Get(f.bucket)
		if err != nil {
			t.Fatal(err)
		}
		meta.LifecycleConfigXML = []byte("<LifecycleConfiguration>" + rules + "</LifecycleConfiguration>")
		if err := meta.Save(ctx, z); err != nil {
			t.Fatal(err)
		}
		globalBucketMetadataSys.Set(f.bucket, meta)
	}
	f.tier = &freeVersionTier{tierExpiryTestBackend: &tierExpiryTestBackend{objects: map[string][]byte{}}}
	prevTier := globalTierConfigMgr
	globalTierConfigMgr = NewTierConfigMgr()
	globalTierConfigMgr.drivercache["WARM"] = f.tier
	t.Cleanup(func() { globalTierConfigMgr = prevTier })

	now := UTCNow()
	f.put("obj-01", "v1", now.AddDate(0, 0, -5))
	f.put("obj-01", "v2", now.AddDate(0, 0, -4))
	f.deleteVersion(f.tiered("obj-01", "v3", now.AddDate(0, 0, -3)))
	f.deleteVersion(f.tiered("obj-02", "v1", now.AddDate(0, 0, -3)))
	return f
}

// put writes a version of object to pool 0.
func (f *freeVersionTest) put(object, label string, mtime time.Time) ObjectInfo {
	f.t.Helper()
	oi := putConsistencyObject(f.t, f.z, f.bucket, object, 0, object+" "+label, ObjectOptions{Versioned: true, MTime: mtime})
	f.labels[oi.VersionID] = label
	return oi
}

// tiered writes a version of object to pool 0 whose data is in the tier.
func (f *freeVersionTest) tiered(object, label string, mtime time.Time) ObjectInfo {
	f.t.Helper()
	oi := f.put(object, label, mtime)
	infos, errs := readAllFileInfo(f.t.Context(), f.z.serverPools[0].getHashedSet(object).getDisks(), "", f.bucket, object, oi.VersionID, false, false)
	if errs[0] != nil {
		f.t.Fatal(errs[0])
	}
	fi := infos[0]
	fi.TransitionStatus, fi.TransitionTier, fi.TransitionedObjName = lifecycle.TransitionComplete, "WARM", f.remote(object, label)
	f.tier.objects[fi.TransitionedObjName] = []byte(object + " " + label)
	if err := f.z.serverPools[0].DecomTieredObject(f.t.Context(), f.bucket, object, fi, ObjectOptions{}); err != nil {
		f.t.Fatal(err)
	}
	return oi
}

// remote is the name of the remote object of a tiered version.
func (f *freeVersionTest) remote(object, label string) string {
	return f.bucket + "/" + object + "/" + label
}

// deleteVersion deletes a tiered version by its ID, as a client does, which
// leaves a free version in its place.
func (f *freeVersionTest) deleteVersion(oi ObjectInfo) {
	f.t.Helper()
	if _, err := f.z.DeleteObject(f.t.Context(), f.bucket, oi.Name, ObjectOptions{Versioned: true, VersionID: oi.VersionID}); err != nil {
		f.t.Fatal(err)
	}
	if got := f.stored(0, oi.Name); len(got) == 0 || got[0] != "free" {
		f.t.Fatalf("fixture: %s holds %v, want a free version on top", oi.Name, got)
	}
}

func (f *freeVersionTest) label(fi FileInfo) string {
	switch {
	case fi.TierFreeVersion():
		return "free"
	case fi.Deleted:
		return "DM"
	case f.labels[fi.VersionID] != "":
		return f.labels[fi.VersionID]
	}
	return "?"
}

// xlMeta reads the metadata of object in pool from its first drive, nil if
// the pool has none.
func (f *freeVersionTest) xlMeta(pool int, object string) []byte {
	f.t.Helper()
	disk := f.z.serverPools[pool].getHashedSet(object).getDisks()[0]
	buf, err := disk.ReadAll(f.t.Context(), f.bucket, pathJoin(object, xlStorageFormatFile))
	if errors.Is(err, errFileNotFound) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return buf
}

// stored returns what pool holds of object, newest first, free versions
// included.
func (f *freeVersionTest) stored(pool int, object string) []string {
	f.t.Helper()
	buf := f.xlMeta(pool, object)
	if buf == nil {
		return nil
	}
	fivs, err := getFileInfoVersions(buf, f.bucket, object, true)
	if err != nil {
		f.t.Fatal(err)
	}
	var got []string
	for _, fi := range fivs.Versions {
		got = append(got, f.label(fi))
	}
	return got
}

// expiryQueue replaces the expiry workers with a queue for the test.
func (f *freeVersionTest) expiryQueue() chan expiryOp {
	queue := make(chan expiryOp, 100)
	es := &expiryState{ctx: f.t.Context(), objAPI: f.z}
	workers := []chan expiryOp{queue}
	es.workers.Store(&workers)
	prev := globalExpiryState
	globalExpiryState = es
	f.t.Cleanup(func() { globalExpiryState = prev })
	return queue
}

// expired returns the labels of the versions queued for expiry.
func (f *freeVersionTest) expired(queue chan expiryOp) []string {
	var got []string
	for len(queue) > 0 {
		switch task := (<-queue).(type) {
		case expiryTask:
			got = append(got, f.labels[task.objInfo.VersionID])
		case noncurrentVersionsTask:
			for _, v := range task.versions {
				got = append(got, f.labels[v.VersionID])
			}
		}
	}
	return got
}

// The scanner reads the versions of obj-01 without the free version. v2 is the
// latest version, and a noncurrent expiry must not count it as noncurrent
// since the deleted v3 was written. Otherwise the scanner deletes it.
func TestFreeVersionScannerLatestVersion(t *testing.T) {
	f := newFreeVersionTest(t, freeVersionNoncurrent)
	fivs, err := getFileInfoVersions(f.xlMeta(0, "obj-01"), f.bucket, "obj-01", false)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, fi := range fivs.Versions {
		got = append(got, f.label(fi))
	}
	if want := []string{"v2", "v1"}; !slices.Equal(got, want) || len(fivs.FreeVersions) != 1 {
		t.Fatalf("scanner versions %v with %d free versions, want %v with 1", got, len(fivs.FreeVersions), want)
	}
	v2, v1 := fivs.Versions[0], fivs.Versions[1]
	if !v2.IsLatest || !v2.SuccessorModTime.IsZero() {
		t.Errorf("v2: latest %v, successor mod time %v; want latest without a successor", v2.IsLatest, v2.SuccessorModTime)
	}
	if v1.IsLatest || !v1.SuccessorModTime.Equal(v2.ModTime) {
		t.Errorf("v1: latest %v, successor mod time %v; want noncurrent since v2 at %v", v1.IsLatest, v1.SuccessorModTime, v2.ModTime)
	}
	if !fivs.LatestModTime.Equal(v2.ModTime) {
		t.Errorf("latest mod time %v, want that of v2 %v", fivs.LatestModTime, v2.ModTime)
	}

	// Apply the rules to these versions as the scanner does.
	lc, err := globalLifecycleSys.Get(f.bucket)
	if err != nil {
		t.Fatal(err)
	}
	objInfos := make([]ObjectInfo, len(fivs.Versions))
	for i, fi := range fivs.Versions {
		objInfos[i] = fi.ToObjectInfo(f.bucket, "obj-01", true)
	}
	queue := f.expiryQueue()
	item := scannerItem{Path: "obj-01", bucket: f.bucket, objectName: "obj-01", lifeCycle: lc}
	item.applyActions(t.Context(), f.z, objInfos, objectlock.Retention{}, &sizeSummary{}, nil)
	if expired, want := f.expired(queue), []string{"v1"}; !slices.Equal(expired, want) {
		t.Errorf("scanner queued %v for expiry, want %v", expired, want)
	}
}
