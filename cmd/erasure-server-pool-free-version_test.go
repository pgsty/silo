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

	madmin "github.com/minio/madmin-go/v3"
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

// versions labels the versions of a listing as "<object> <label>[ latest]".
func (f *freeVersionTest) versions(objects []ObjectInfo) []string {
	var got []string
	for _, oi := range objects {
		label := oi.Name + " " + f.label(FileInfo{VersionID: oi.VersionID, Deleted: oi.DeleteMarker})
		if oi.IsLatest {
			label += " latest"
		}
		got = append(got, label)
	}
	return got
}

// listVersions returns the versions ListObjectVersions lists in one page.
func (f *freeVersionTest) listVersions() []string {
	f.t.Helper()
	lv, err := f.z.ListObjectVersions(f.t.Context(), f.bucket, "", "", "", "", 100)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.versions(lv.Objects)
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

// ListObjectsV2 lists obj-01: its latest version is v2, not a delete marker.
// obj-02 has no versions left.
func TestFreeVersionListObjects(t *testing.T) {
	f := newFreeVersionTest(t, "")
	lo, err := f.z.ListObjectsV2(t.Context(), f.bucket, "", "", "", 100, false, "")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, oi := range lo.Objects {
		got = append(got, oi.Name)
	}
	if want := []string{"obj-01"}; !slices.Equal(got, want) {
		t.Errorf("ListObjectsV2: %v, want %v", got, want)
	}
}

// The listing checks of the latest version skip the free version: obj-01 is
// shown, obj-02 has nothing to show. Both the encoded metadata and the
// decoded form, which the listing caches, are checked.
func TestFreeVersionLatestDeleteMarker(t *testing.T) {
	f := newFreeVersionTest(t, "")
	for _, tc := range []struct {
		object string
		hidden bool
	}{{"obj-01", false}, {"obj-02", true}} {
		entry := metaCacheEntry{name: tc.object, metadata: f.xlMeta(0, tc.object)}
		meta, _, err := isIndexedMetaV2(entry.metadata)
		if err != nil || meta == nil {
			t.Fatalf("%s: metadata is not indexed: %v", tc.object, err)
		}
		if got := meta.IsLatestDeleteMarker(); got != tc.hidden {
			t.Errorf("%s: IsLatestDeleteMarker %v, want %v", tc.object, got, tc.hidden)
		}
		if got := meta.AllHidden(true); got != tc.hidden {
			t.Errorf("%s: AllHidden(true) %v, want %v", tc.object, got, tc.hidden)
		}
		if got := meta.AllHidden(false); got != tc.hidden {
			t.Errorf("%s: AllHidden(false) %v, want %v", tc.object, got, tc.hidden)
		}
		if got := entry.isLatestDeletemarker(); got != tc.hidden {
			t.Errorf("%s: isLatestDeletemarker %v, want %v", tc.object, got, tc.hidden)
		}
		if _, err := entry.xlmeta(); err != nil {
			t.Fatal(err)
		}
		if got := entry.isLatestDeletemarker(); got != tc.hidden {
			t.Errorf("%s: isLatestDeletemarker of the decoded metadata %v, want %v", tc.object, got, tc.hidden)
		}
	}
}

// ListObjectVersions lists v2 as the latest version of obj-01 and no delete
// markers. Keys with nothing but a free version have no versions to list and
// do not take up a page. Walk returns the same versions.
func TestFreeVersionListObjectVersions(t *testing.T) {
	f := newFreeVersionTest(t, "")
	f.deleteVersion(f.tiered("obj-00", "v1", UTCNow().AddDate(0, 0, -3)))
	want := []string{"obj-01 v2 latest", "obj-01 v1"}
	if got := f.listVersions(); !slices.Equal(got, want) {
		t.Errorf("ListObjectVersions: %v, want %v", got, want)
	}

	results := make(chan itemOrErr[ObjectInfo], 100)
	if err := f.z.Walk(t.Context(), f.bucket, "", results, WalkOptions{}); err != nil {
		t.Fatal(err)
	}
	var walked []ObjectInfo
	for r := range results {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		walked = append(walked, r.Item)
	}
	if got, want := f.versions(walked), []string{"obj-01 v1", "obj-01 v2 latest"}; !slices.Equal(got, want) {
		t.Errorf("Walk: %v, want %v", got, want)
	}

	// Page by page, one version a page.
	for _, delimiter := range []string{"", "/"} {
		var got []string
		marker, versionMarker := "", ""
		for range 10 {
			lv, err := f.z.ListObjectVersions(t.Context(), f.bucket, "", marker, versionMarker, delimiter, 1)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, f.versions(lv.Objects)...)
			if !lv.IsTruncated {
				break
			}
			marker, versionMarker = lv.NextMarker, lv.NextVersionIDMarker
		}
		if !slices.Equal(got, want) {
			t.Errorf("ListObjectVersions page by page, delimiter %q: %v, want %v", delimiter, got, want)
		}
	}
}

// Healing still visits the free versions, so a free version lost on some
// drives is healed and the scanner still finds it.
func TestFreeVersionHealObjects(t *testing.T) {
	f := newFreeVersionTest(t, "")
	var got []string
	err := f.z.HealObjects(t.Context(), f.bucket, "", madmin.HealOpts{Recursive: true}, func(_, object, versionID string, _ madmin.HealScanMode) error {
		label := f.labels[versionID]
		if label == "" {
			label = "free"
		}
		got = append(got, object+" "+label)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if want := []string{"obj-01 free", "obj-01 v1", "obj-01 v2", "obj-02 free"}; !slices.Equal(got, want) {
		t.Errorf("healed versions %v, want %v", got, want)
	}
}

// Decommission and rebalance do not move a free version: in another pool it
// would be a delete marker that hides v2. Decommission removes the remote
// object and the free version, as the scanner would before the pool is
// removed. Rebalance leaves both to the scanner of the source pool.
func TestFreeVersionDataMovement(t *testing.T) {
	for _, kind := range []string{"decommission", "rebalance"} {
		for _, rules := range []string{"", freeVersionNoncurrent} {
			name := kind
			if rules != "" {
				name += "/noncurrent-expiry"
			}
			t.Run(name, func(t *testing.T) {
				f := newFreeVersionTest(t, rules)
				queue := f.expiryQueue()
				if failed := migrationTestWalk(t, f.z, f.bucket, 0, kind); failed != 0 {
					t.Fatalf("%d versions failed to move", failed)
				}
				if expired := f.expired(queue); slices.Contains(expired, "v2") {
					t.Errorf("%s queued the latest version v2 for expiry: %v", kind, expired)
				}

				// v1 has been noncurrent for days; whether a move skips an
				// expired version is out of scope here.
				if got := f.stored(1, "obj-01"); len(got) == 0 || got[0] != "v2" || slices.Contains(got, "DM") {
					t.Errorf("pool 1 holds %v of obj-01, want v2 on top and no delete marker", got)
				}
				if got := f.stored(1, "obj-02"); len(got) != 0 {
					t.Errorf("pool 1 holds %v of obj-02, want nothing", got)
				}
				if body := migrationTestBody(t, f.z.GetObjectNInfo, f.bucket, "obj-01", ""); body != "obj-01 v2" {
					t.Errorf("obj-01 reads %q, want %q", body, "obj-01 v2")
				}
				if got := f.listVersions(); len(got) == 0 || got[0] != "obj-01 v2 latest" || slices.Contains(got, "obj-02 DM latest") {
					t.Errorf("ListObjectVersions after %s: %v", kind, got)
				}

				if rules != "" {
					// The expired v1 is not moved, so its source is kept.
					return
				}
				var wantSource []string // decommission
				removed := true
				if kind == "rebalance" {
					wantSource, removed = []string{"free"}, false
				}
				for _, object := range []string{"obj-01", "obj-02"} {
					if got := f.stored(0, object); !slices.Equal(got, wantSource) {
						t.Errorf("pool 0 holds %v of %s, want %v", got, object, wantSource)
					}
				}
				for _, remote := range []string{f.remote("obj-01", "v3"), f.remote("obj-02", "v1")} {
					if slices.Contains(f.tier.removed, remote) != removed {
						t.Errorf("remote object %s of a deleted version removed: %v, want %v", remote, !removed, removed)
					}
				}
			})
		}
	}
}

// decommission decommissions pool 0 as the admin API does, including the check
// for versions left behind, and returns its state.
func (f *freeVersionTest) decommission() PoolDecommissionInfo {
	f.t.Helper()
	ctx := f.t.Context()
	if err := f.z.StartDecommission(ctx, 0); err != nil {
		f.t.Fatal(err)
	}
	f.z.doDecommissionInRoutine(ctx, 0)
	f.z.poolMetaMutex.RLock()
	defer f.z.poolMetaMutex.RUnlock()
	return *f.z.poolMeta.Pools[0].Decommission
}

// While the tier is unavailable, the decommission moves the versions but keeps
// the free versions, and the check for versions left behind fails it. A retry
// with the tier back completes it.
func TestFreeVersionDecommissionTierUnavailable(t *testing.T) {
	f := newFreeVersionTest(t, "")
	f.tier.removeErr = errors.New("tier unavailable")
	if info := f.decommission(); info.Complete || !info.Failed {
		t.Fatalf("decommission with the tier unavailable: complete %v, failed %v; want failed", info.Complete, info.Failed)
	}
	if got, want := f.stored(1, "obj-01"), []string{"v2", "v1"}; !slices.Equal(got, want) {
		t.Errorf("pool 1 holds %v of obj-01, want %v", got, want)
	}
	for _, object := range []string{"obj-01", "obj-02"} {
		if got, want := f.stored(0, object), []string{"free"}; !slices.Equal(got, want) {
			t.Errorf("pool 0 holds %v of %s, want %v", got, object, want)
		}
	}
	if body := migrationTestBody(t, f.z.GetObjectNInfo, f.bucket, "obj-01", ""); body != "obj-01 v2" {
		t.Errorf("obj-01 reads %q, want %q", body, "obj-01 v2")
	}
	if len(f.tier.removed) != 0 {
		t.Errorf("remote objects removed: %v", f.tier.removed)
	}

	// The failed decommission moved the bucket metadata, so pool 0 has no
	// .minio.sys/buckets left. On a server the scanner recreates it when it
	// saves its usage cache there; it does not run here.
	for _, set := range f.z.serverPools[0].sets {
		for _, disk := range set.getDisks() {
			if err := disk.MakeVol(t.Context(), pathJoin(minioMetaBucket, bucketMetaPrefix)); err != nil && !errors.Is(err, errVolumeExists) {
				t.Fatal(err)
			}
		}
	}
	f.tier.removeErr = nil
	if info := f.decommission(); !info.Complete || info.Failed {
		t.Fatalf("retry: complete %v, failed %v; want complete", info.Complete, info.Failed)
	}
	if got, want := f.stored(1, "obj-01"), []string{"v2", "v1"}; !slices.Equal(got, want) {
		t.Errorf("pool 1 holds %v of obj-01 after the retry, want %v", got, want)
	}
	for _, object := range []string{"obj-01", "obj-02"} {
		if got := f.stored(0, object); len(got) != 0 {
			t.Errorf("pool 0 holds %v of %s after the retry", got, object)
		}
	}
	if want := []string{f.remote("obj-01", "v3"), f.remote("obj-02", "v1")}; !slices.Equal(slices.Sorted(slices.Values(f.tier.removed)), want) {
		t.Errorf("remote objects removed: %v, want %v", f.tier.removed, want)
	}
}
