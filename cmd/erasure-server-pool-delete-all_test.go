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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/amztime"
	"github.com/minio/minio/internal/bucket/lifecycle"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/event"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/pubsub"
	"github.com/pgsty/silo-pkg/v3/workers"
)

// An expiry of all versions of a key must remove the versions of that key
// and nothing else. On the drives, the keys under K/ live inside the
// directory of K, in the same erasure set or another one, and in other
// pools the same name is a directory too.

const purgeRules = "<Rule><ID>eav</ID><Status>Enabled</Status><Filter><Prefix>ea/</Prefix></Filter>" +
	"<Expiration><Days>1</Days><ExpiredObjectAllVersions>true</ExpiredObjectAllVersions></Expiration></Rule>" +
	"<Rule><ID>dme</ID><Status>Enabled</Status><Filter><Prefix>dm/</Prefix></Filter>" +
	"<DelMarkerExpiration><Days>1</Days></DelMarkerExpiration></Rule>"

// purgeTest is a bucket with purgeRules and a remote tier WARM.
type purgeTest struct {
	t      *testing.T
	z      *erasureServerPools
	bucket string
	tier   *tierExpiryTestBackend
	bodies map[string]string // body -> label
}

// purgeSinglePool returns one pool of drives drives, two erasure sets for 32.
func purgeSinglePool(t *testing.T, drives int) *erasureServerPools {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	obj, dirs, err := prepareErasure(ctx, drives)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	t.Cleanup(func() { cancel(); z.Shutdown(context.Background()); removeRoots(dirs); setObjectLayer(previous) })
	return z
}

func newPurgeTest(t *testing.T, z *erasureServerPools, bucket string, opts MakeBucketOptions, rules string) *purgeTest {
	t.Helper()
	ctx := t.Context()
	if err := z.MakeBucket(ctx, bucket, opts); err != nil {
		t.Fatal(err)
	}
	if rules != "" {
		meta, err := globalBucketMetadataSys.Get(bucket)
		if err != nil {
			t.Fatal(err)
		}
		meta.LifecycleConfigXML = []byte("<LifecycleConfiguration>" + rules + "</LifecycleConfiguration>")
		if err := meta.Save(ctx, z); err != nil {
			t.Fatal(err)
		}
		globalBucketMetadataSys.Set(bucket, meta)
	}
	p := &purgeTest{t: t, z: z, bucket: bucket, tier: &tierExpiryTestBackend{objects: map[string][]byte{}}, bodies: map[string]string{}}
	prevTier := globalTierConfigMgr
	globalTierConfigMgr = NewTierConfigMgr()
	globalTierConfigMgr.drivercache["WARM"] = p.tier
	t.Cleanup(func() { globalTierConfigMgr = prevTier })
	return p
}

func daysAgo(days float64) time.Time {
	return UTCNow().Add(-time.Duration(days * float64(24*time.Hour)))
}

// put writes a version of name to pool with opts, at mtime.
func (p *purgeTest) put(pool int, name, label string, mtime time.Time, opts ObjectOptions) ObjectInfo {
	p.t.Helper()
	body := name + " " + label
	if HasSuffix(name, SlashSeparator) {
		body = ""
	}
	opts.MTime = mtime
	oi, err := p.z.serverPools[pool].PutObject(p.t.Context(), p.bucket, encodeDirObject(name),
		mustGetPutObjReader(p.t, bytes.NewBufferString(body), int64(len(body)), "", ""), opts)
	if err != nil {
		p.t.Fatalf("put %s %s: %v", name, label, err)
	}
	p.bodies[body] = label
	return oi
}

func (p *purgeTest) version(pool int, name, label string, days float64) ObjectInfo {
	p.t.Helper()
	return p.put(pool, name, label, daysAgo(days), ObjectOptions{Versioned: true})
}

func (p *purgeTest) marker(pool int, name string, days float64) {
	p.t.Helper()
	if _, err := p.z.serverPools[pool].DeleteObject(p.t.Context(), p.bucket, encodeDirObject(name),
		ObjectOptions{Versioned: true, VersionID: mustGetUUID(), DeleteMarker: true, MTime: daysAgo(days)}); err != nil {
		p.t.Fatal(err)
	}
}

// tiered writes a version of name to pool whose data is in the remote tier.
func (p *purgeTest) tiered(pool int, name, label string, days float64) ObjectInfo {
	p.t.Helper()
	ctx := p.t.Context()
	oi := p.version(pool, name, label, days)
	infos, errs := readAllFileInfo(ctx, p.z.serverPools[pool].getHashedSet(name).getDisks(), "", p.bucket, name, oi.VersionID, false, false)
	if errs[0] != nil {
		p.t.Fatal(errs[0])
	}
	fi := infos[0]
	remote := "remote/" + name + "/" + label
	fi.TransitionStatus, fi.TransitionTier, fi.TransitionedObjName = lifecycle.TransitionComplete, "WARM", remote
	p.tier.mu.Lock()
	p.tier.objects[remote] = []byte(name)
	p.tier.mu.Unlock()
	if err := p.z.serverPools[pool].DecomTieredObject(ctx, p.bucket, name, fi, ObjectOptions{}); err != nil {
		p.t.Fatal(err)
	}
	return oi
}

func (p *purgeTest) remotes() int {
	p.tier.mu.Lock()
	defer p.tier.mu.Unlock()
	return len(p.tier.objects)
}

// held returns what every drive of the set of name in pool holds, newest
// first, free versions included, as they agree, or nil without xl.meta.
func (p *purgeTest) held(pool int, name string) []string {
	p.t.Helper()
	enc := encodeDirObject(name)
	var first []string
	for i, disk := range p.z.serverPools[pool].getHashedSet(enc).getDisks() {
		var got []string
		buf, err := disk.ReadAll(p.t.Context(), p.bucket, pathJoin(enc, xlStorageFormatFile))
		if err == nil {
			fivs, err := getFileInfoVersions(buf, p.bucket, enc, true)
			if err != nil {
				p.t.Fatal(err)
			}
			for _, fi := range fivs.Versions {
				switch {
				case fi.TierFreeVersion():
					got = append(got, "free")
				case fi.Deleted:
					got = append(got, "DM")
				case fi.TransitionStatus == lifecycle.TransitionComplete:
					got = append(got, "tiered")
				default:
					got = append(got, "hot")
				}
			}
		} else if !errors.Is(err, errFileNotFound) {
			p.t.Fatalf("drive %d of %s: %v", i, name, err)
		}
		if i == 0 {
			first = got
		} else if !slices.Equal(got, first) {
			p.t.Fatalf("%s in pool %d: drive %d holds %v, drive 0 %v", name, pool, i, got, first)
		}
	}
	return first
}

// get returns the label of the version a GET of name reads, or "-".
func (p *purgeTest) get(name string) string {
	p.t.Helper()
	gr, err := p.z.GetObjectNInfo(p.t.Context(), p.bucket, name, nil, nil, ObjectOptions{})
	if err != nil {
		if isErrObjectNotFound(err) || isErrVersionNotFound(err) || isErrMethodNotAllowed(err) {
			return "-"
		}
		return fmt.Sprintf("<%v>", err)
	}
	defer gr.Close()
	data, err := io.ReadAll(gr)
	if err != nil {
		p.t.Fatal(err)
	}
	if l, ok := p.bodies[string(data)]; ok {
		return l
	}
	return "?" + string(data)
}

// childIn returns a key under parent/ in the same or another erasure set of
// pool than parent.
func (p *purgeTest) childIn(pool int, parent string, same bool) string {
	sets := p.z.serverPools[pool]
	for i := 0; ; i++ {
		name := fmt.Sprintf("%s/c%03d", parent, i)
		if (sets.getHashedSetIndex(name) == sets.getHashedSetIndex(parent)) == same {
			return name
		}
	}
}

// scanQueue applies the lifecycle of the bucket to the versions that pool
// holds of name, as the scanner does, and returns what it queued.
func (p *purgeTest) scanQueue(pool int, name string) []expiryOp {
	p.t.Helper()
	ctx := p.t.Context()
	enc := encodeDirObject(name)
	disk := p.z.serverPools[pool].getHashedSet(enc).getDisks()[0]
	buf, err := disk.ReadAll(ctx, p.bucket, pathJoin(enc, xlStorageFormatFile))
	if err != nil {
		p.t.Fatalf("read %s: %v", name, err)
	}
	fivs, err := getFileInfoVersions(buf, p.bucket, enc, false)
	if err != nil {
		p.t.Fatal(err)
	}
	vc, _ := globalBucketVersioningSys.Get(p.bucket)
	objInfos := make([]ObjectInfo, len(fivs.Versions))
	for i, fi := range fivs.Versions {
		objInfos[i] = fi.ToObjectInfo(p.bucket, name, vc != nil && vc.Versioned(name))
	}
	lc, err := globalLifecycleSys.Get(p.bucket)
	if err != nil {
		p.t.Fatal(err)
	}
	lr, err := globalBucketObjectLockSys.Get(p.bucket)
	if err != nil {
		p.t.Fatal(err)
	}
	queue := make(chan expiryOp, 100)
	es := &expiryState{ctx: ctx, objAPI: p.z}
	workers := []chan expiryOp{queue}
	es.workers.Store(&workers)
	prev := globalExpiryState
	globalExpiryState = es
	defer func() { globalExpiryState = prev }()
	item := scannerItem{Path: enc, bucket: p.bucket, objectName: path.Base(enc), lifeCycle: lc}
	item.applyActions(ctx, p.z, objInfos, lr, &sizeSummary{}, nil)
	var ops []expiryOp
	for len(queue) > 0 {
		ops = append(ops, <-queue)
	}
	return ops
}

// expire runs what the scanner queues for name in pool with an expiry
// worker, and fails unless it queued an expiry of all versions.
func (p *purgeTest) expire(pool int, name string) {
	p.t.Helper()
	ops := p.scanQueue(pool, name)
	if !slices.ContainsFunc(ops, func(op expiryOp) bool {
		task, ok := op.(expiryTask)
		return ok && task.event.Action.DeleteAll()
	}) {
		p.t.Fatalf("the scanner queued no expiry of all versions of %s: %v", name, ops)
	}
	p.run(ops)
}

func (p *purgeTest) run(ops []expiryOp) {
	ch := make(chan expiryOp, len(ops))
	for _, op := range ops {
		ch <- op
	}
	close(ch)
	es := &expiryState{ctx: p.t.Context(), objAPI: p.z}
	es.Worker(ch)
}

// matched returns the latest version of name in all pools, with the number
// of its versions and delete markers, as the walk of a batch expiration
// matches it for a purge of all versions.
func (p *purgeTest) matched(name string) expireObjInfo {
	p.t.Helper()
	var latest FileInfo
	ids := map[string]bool{}
	var markers int64
	for _, pool := range p.z.serverPools {
		versions, err := pool.getHashedSet(name).objectVersions(p.t.Context(), p.bucket, encodeDirObject(name))
		if err != nil {
			p.t.Fatalf("versions of %s: %v", name, err)
		}
		for _, fi := range versions {
			if fi.ModTime.After(latest.ModTime) {
				latest = fi
			}
			if !ids[fi.VersionID] && fi.Deleted {
				markers++
			}
			ids[fi.VersionID] = true
		}
	}
	if len(ids) == 0 {
		p.t.Fatalf("%s has no versions", name)
	}
	vc, _ := globalBucketVersioningSys.Get(p.bucket)
	oi := latest.ToObjectInfo(p.bucket, name, vc != nil && vc.Versioned(name))
	oi.IsLatest, oi.NumVersions = true, len(ids)
	return expireObjInfo{ObjectInfo: oi, ExpireAll: true, DeleteMarkerCount: markers}
}

// batch runs the deletes of a batch expiration job for walked, the keys its
// walk matched, and returns the counts of the job.
func (p *purgeTest) batch(walked ...expireObjInfo) *batchJobInfo {
	p.t.Helper()
	globalBatchJobsMetrics.Lock()
	if globalBatchJobsMetrics.metrics == nil {
		globalBatchJobsMetrics.metrics = make(map[string]*batchJobInfo)
	}
	globalBatchJobsMetrics.Unlock()
	job := BatchJobRequest{ID: "purge-" + mustGetUUID(), Started: time.Now(), Expire: &BatchJobExpire{Bucket: p.bucket}}
	ri := &batchJobInfo{JobID: job.ID}
	wk, err := workers.New(1)
	if err != nil {
		p.t.Fatal(err)
	}
	ch := make(chan []expireObjInfo, 1)
	ch <- walked
	close(ch)
	batchObjsForDelete(p.t.Context(), job.Expire, ri, job, p.z, wk, ch)
	wk.Wait()
	return ri
}

// purgeObserver collects the removal events and ILM expiry traces.
type purgeObserver struct {
	events chan event.Event
	traces chan madmin.TraceInfo
}

func observePurges(t *testing.T) *purgeObserver {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	o := &purgeObserver{events: make(chan event.Event, 64), traces: make(chan madmin.TraceInfo, 64)}
	var mask pubsub.Mask
	mask.MergeMaskable(event.ObjectRemovedAll)
	mask.MergeMaskable(event.ILMDelMarkerExpirationDelete)
	if err := globalHTTPListen.Subscribe(mask, o.events, done, nil); err != nil {
		t.Fatal(err)
	}
	if err := globalTrace.Subscribe(madmin.TraceILM, o.traces, done, nil); err != nil {
		t.Fatal(err)
	}
	return o
}

// drain returns the removal events and the custom fields of the ILM expiry
// traces published so far. Both publishers deliver synchronously.
func (o *purgeObserver) drain() (events []string, traces []map[string]string) {
	for {
		select {
		case ev := <-o.events:
			events = append(events, ev.EventName.String()+" "+ev.S3.Object.Key)
		case tr := <-o.traces:
			if tr.FuncName == ILMExpiry {
				traces = append(traces, tr.Custom)
			}
		default:
			return events, traces
		}
	}
}

// purgeFaultDisk fails the version deletes of one key, or of one of its
// versions.
type purgeFaultDisk struct {
	StorageAPI
	bucket, object, versionID string
}

func (d purgeFaultDisk) fails(volume, path, versionID string) bool {
	return volume == d.bucket && path == d.object && (d.versionID == "" || versionID == d.versionID)
}

func (d purgeFaultDisk) DeleteVersion(ctx context.Context, volume, path string, fi FileInfo, forceDelMarker bool, opts DeleteOptions) error {
	if d.fails(volume, path, fi.VersionID) {
		return errFaultyDisk
	}
	return d.StorageAPI.DeleteVersion(ctx, volume, path, fi, forceDelMarker, opts)
}

func (d purgeFaultDisk) DeleteVersions(ctx context.Context, volume string, versions []FileInfoVersions, opts DeleteOptions) []error {
	errs := make([]error, len(versions))
	for i, v := range versions {
		for _, fi := range v.Versions {
			if d.fails(volume, v.Name, fi.VersionID) {
				errs[i] = errFaultyDisk
			}
		}
		if errs[i] == nil {
			errs[i] = d.StorageAPI.DeleteVersions(ctx, volume, []FileInfoVersions{v}, opts)[0]
		}
	}
	return errs
}

// failVersionDeletes makes every drive of pool fail the version deletes of
// object, of versionID only when set, until the returned function runs.
func (p *purgeTest) failVersionDeletes(pool int, object, versionID string) func() {
	p.t.Helper()
	sets := p.z.serverPools[pool]
	sets.erasureDisksMu.Lock()
	prior := sets.erasureDisks
	wrapped := make([][]StorageAPI, len(prior))
	for i, disks := range prior {
		wrapped[i] = append([]StorageAPI(nil), disks...)
		for j := range disks {
			wrapped[i][j] = purgeFaultDisk{StorageAPI: disks[j], bucket: p.bucket, object: object, versionID: versionID}
		}
	}
	sets.erasureDisks = wrapped
	sets.erasureDisksMu.Unlock()
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		sets.erasureDisksMu.Lock()
		sets.erasureDisks = prior
		sets.erasureDisksMu.Unlock()
	}
	p.t.Cleanup(restore)
	return restore
}

// Children of the key in its own erasure set and in the other one keep all
// their versions, for both lifecycle actions that remove all versions.
func TestPurgeAllVersionsKeepsKeysUnderTheKey(t *testing.T) {
	z := purgeSinglePool(t, 32)
	p := newPurgeTest(t, z, "purge-children", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	if len(z.serverPools[0].sets) < 2 {
		t.Fatalf("fixture needs two erasure sets, has %d", len(z.serverPools[0].sets))
	}
	for _, parent := range []string{"ea/parent", "dm/parent"} {
		p.version(0, parent, "v1", 5)
		if strings.HasPrefix(parent, "dm/") {
			p.marker(0, parent, 3)
		} else {
			p.version(0, parent, "v2", 4)
		}
		children := []string{p.childIn(0, parent, true), p.childIn(0, parent, false), parent + "/deep/grandchild"}
		for _, child := range children {
			p.version(0, child, "old", 5)
			p.version(0, child, "new", 0)
		}
		p.expire(0, parent)
		if got := p.held(0, parent); got != nil {
			t.Errorf("%s keeps %v after the expiry of all its versions", parent, got)
		}
		for _, child := range children {
			if got := p.held(0, child); !slices.Equal(got, []string{"hot", "hot"}) {
				t.Errorf("%s in set %d (parent in set %d) holds %v, want both versions",
					child, z.serverPools[0].getHashedSetIndex(child), z.serverPools[0].getHashedSetIndex(parent), got)
			}
			if got := p.get(child); got != "new" {
				t.Errorf("%s reads %s, want new", child, got)
			}
		}
	}
}

// A child in another pool, and copies of the key in both pools.
func TestPurgeAllVersionsKeepsKeysInOtherPools(t *testing.T) {
	z, _ := consistencyPools(t)
	p := newPurgeTest(t, z, "purge-pools", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	const parent = "ea/parent"
	p.version(0, parent, "v1", 6)
	moved := p.version(1, parent, "v2", 5)
	// A copy of v2 in pool 0 as an interrupted move leaves it.
	p.put(0, parent, "v2", moved.ModTime, ObjectOptions{Versioned: true, VersionID: moved.VersionID})
	p.version(1, parent+"/child", "new", 0)
	p.version(0, parent+"/child0", "new", 0)

	p.expire(1, parent)
	for pool := range z.serverPools {
		if got := p.held(pool, parent); got != nil {
			t.Errorf("pool %d keeps %v of %s", pool, got, parent)
		}
	}
	if got := p.held(1, parent+"/child"); !slices.Equal(got, []string{"hot"}) {
		t.Errorf("child in the other pool holds %v", got)
	}
	if got := p.held(0, parent+"/child0"); !slices.Equal(got, []string{"hot"}) {
		t.Errorf("child in the key's pool holds %v", got)
	}
}

// Controls: a key without children loses all its versions, and neighbors
// and directory objects behave as before.
func TestPurgeAllVersionsControls(t *testing.T) {
	z := purgeSinglePool(t, 32)
	p := newPurgeTest(t, z, "purge-controls", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	p.version(0, "ea/plain", "v1", 6)
	p.marker(0, "ea/plain", 5)
	p.version(0, "ea/plain", "v2", 4)
	for _, n := range []string{"ea/plainx", "ea/plain-1"} {
		p.version(0, n, "new", 0)
	}
	p.version(0, "ea/dir/", "", 5)
	p.version(0, "ea/dir/kid", "new", 0)

	p.expire(0, "ea/plain")
	p.expire(0, "ea/dir/")
	for _, n := range []string{"ea/plain", "ea/dir/"} {
		if got := p.held(0, n); got != nil {
			t.Errorf("%s keeps %v", n, got)
		}
	}
	for _, n := range []string{"ea/plainx", "ea/plain-1", "ea/dir/kid"} {
		if got := p.get(n); got != "new" {
			t.Errorf("%s reads %s, want new", n, got)
		}
	}
}

// The directory of a directory object K/ can hold keys whose names contain
// its encoded name. They stay too.
func TestPurgeAllVersionsKeepsKeysUnderDirectoryObject(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-dir-encoded", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	p.version(0, "ea/dir/", "", 5)
	if _, err := z.PutObject(t.Context(), p.bucket, "ea/dir"+globalDirSuffix+"/odd",
		mustGetPutObjReader(t, bytes.NewBufferString("odd"), 3, "", ""), ObjectOptions{Versioned: true}); err != nil {
		t.Fatal(err)
	}
	p.expire(0, "ea/dir/")
	if got := p.held(0, "ea/dir/"); got != nil {
		t.Errorf("ea/dir/ keeps %v", got)
	}
	if _, err := z.GetObjectInfo(t.Context(), p.bucket, "ea/dir"+globalDirSuffix+"/odd", ObjectOptions{}); err != nil {
		t.Errorf("the key inside the directory object's directory: %v", err)
	}
}

// Force delete stays a prefix delete.
func TestPurgeAllVersionsForceDeleteControl(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-force", MakeBucketOptions{VersioningEnabled: true}, "")
	for _, n := range []string{"fd/parent", "fd/parent/child", "fd/parentx"} {
		p.version(0, n, "v1", 0)
	}
	if _, err := z.DeleteObject(t.Context(), p.bucket, "fd/parent", ObjectOptions{DeletePrefix: true}); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]string{"fd/parent": "-", "fd/parent/child": "-", "fd/parentx": "v1"} {
		if got := p.get(n); got != want {
			t.Errorf("%s reads %s after a force delete of fd/parent, want %s", n, got, want)
		}
	}
}

// A batch expiry that keeps no versions purges the key it matched and
// counts what it removed.
func TestPurgeAllVersionsBatchKeepsKeysUnderTheKey(t *testing.T) {
	z := purgeSinglePool(t, 32)
	p := newPurgeTest(t, z, "purge-batch", MakeBucketOptions{VersioningEnabled: true}, "")
	const parent = "bx/parent"
	p.version(0, parent, "v1", 5)
	p.marker(0, parent, 4)
	p.version(0, parent, "v2", 3)
	others := []string{p.childIn(0, parent, true), p.childIn(0, parent, false), "bx/parentx"}
	for _, n := range others {
		p.version(0, n, "old", 5)
	}
	ri := p.batch(p.matched(parent))
	if got := p.held(0, parent); got != nil {
		t.Errorf("%s keeps %v", parent, got)
	}
	for _, n := range others {
		if got := p.get(n); got != "old" {
			t.Errorf("%s reads %s, want old", n, got)
		}
	}
	if ri.Objects != 2 || ri.DeleteMarkers != 1 || ri.ObjectsFailed != 0 || ri.DeleteMarkersFailed != 0 {
		t.Errorf("job counts objects=%d markers=%d failed=%d/%d, want 2, 1, 0/0", ri.Objects, ri.DeleteMarkers, ri.ObjectsFailed, ri.DeleteMarkersFailed)
	}
}

// Decommission and rebalance run the expiry of all versions of a key whose
// child is new; the child stays. A walk does not list keys under an object
// key, so the child is left for a later pass, as without ILM.
func TestPurgeAllVersionsMigrationKeepsKeysUnderTheKey(t *testing.T) {
	for _, kind := range []string{"decommission", "rebalance"} {
		t.Run(kind, func(t *testing.T) {
			m := newMigrationILM(t, versioning.Enabled, false,
				migrationILMRule("<Expiration><Days>1</Days><ExpiredObjectAllVersions>true</ExpiredObjectAllVersions></Expiration>"))
			m.aged(3, "obj-01")
			m.put("obj-01/child", "v1", ObjectOptions{Versioned: true})
			m.put("obj-01x", "v1", ObjectOptions{Versioned: true})
			if kind == "rebalance" {
				migrationTestWalk(t, m.z, m.bucket, 0, kind)
			} else {
				if err := m.z.StartDecommission(t.Context(), 0); err != nil {
					t.Fatal(err)
				}
				m.z.doDecommissionInRoutine(t.Context(), 0)
			}
			for _, n := range []string{"obj-01/child", "obj-01x"} {
				if _, err := m.z.GetObjectInfo(t.Context(), m.bucket, n, ObjectOptions{}); err != nil {
					t.Errorf("%s after %s: %v", n, kind, err)
				}
			}
			if _, err := m.z.GetObjectInfo(t.Context(), m.bucket, "obj-01", ObjectOptions{}); !isErrObjectNotFound(err) {
				t.Errorf("obj-01 after %s: %v", kind, err)
			}
			for pool := range m.z.serverPools {
				if v := m.view(pool)["obj-01"]; len(v) > 0 {
					t.Errorf("pool %d keeps %v of obj-01", pool, v)
				}
			}
		})
	}
}

// A version written after the decision is kept: the expiry is decided again
// on the history under the lock, also on one pool, and a batch expiry only
// purges while the version it matched is the latest.
func TestPurgeAllVersionsRefusesStaleDecision(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-stale", MakeBucketOptions{VersioningEnabled: true}, purgeRules)

	p.version(0, "ea/stale", "old", 5)
	ops := p.scanQueue(0, "ea/stale")
	p.version(0, "ea/stale", "fresh", 0)
	p.run(ops)
	if got := p.held(0, "ea/stale"); !slices.Equal(got, []string{"hot", "hot"}) {
		t.Errorf("lifecycle: ea/stale holds %v, want both versions", got)
	}

	p.version(0, "bx/stale", "old", 5)
	walked := p.matched("bx/stale")
	p.version(0, "bx/stale", "fresh", 0)
	ri := p.batch(walked)
	if got := p.held(0, "bx/stale"); !slices.Equal(got, []string{"hot", "hot"}) {
		t.Errorf("batch: bx/stale holds %v, want both versions", got)
	}
	if ri.Objects != 0 || ri.ObjectsFailed != 0 {
		t.Errorf("batch counts a stale match: objects=%d failed=%d", ri.Objects, ri.ObjectsFailed)
	}
}

// Control: on two pools the stale decision was already refused.
func TestPurgeAllVersionsStaleDecisionTwoPoolsControl(t *testing.T) {
	z, _ := consistencyPools(t)
	p := newPurgeTest(t, z, "purge-stale-pools", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	p.version(0, "ea/stale", "old", 5)
	ops := p.scanQueue(0, "ea/stale")
	p.version(1, "ea/stale", "fresh", 0)
	p.run(ops)
	if got := p.get("ea/stale"); got != "fresh" {
		t.Errorf("ea/stale reads %s, want fresh", got)
	}
}

// When an older version cannot be deleted, the latest version stays and so
// the read result does not change. The worker audits the partial purge and
// sends no removal event; the next expiry completes it.
func TestPurgeAllVersionsDeletesLatestLast(t *testing.T) {
	z, _ := consistencyPools(t)
	p := newPurgeTest(t, z, "purge-barrier", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	const key = "ea/barrier"
	p.version(0, key, "v1", 6)
	v2 := p.version(1, key, "v2", 5)
	p.version(0, key, "v3", 4)
	o := observePurges(t)
	restore := p.failVersionDeletes(1, key, v2.VersionID)

	p.expire(0, key)
	if got := p.get(key); got != "v3" {
		t.Errorf("reads %s after a failed purge, want v3", got)
	}
	if got := p.held(0, key); !slices.Equal(got, []string{"hot"}) {
		t.Errorf("pool 0 holds %v, want only the latest version", got)
	}
	if got := p.held(1, key); !slices.Equal(got, []string{"hot"}) {
		t.Errorf("pool 1 holds %v, want the version that failed", got)
	}
	events, traces := o.drain()
	if len(events) != 0 {
		t.Errorf("a partial purge sent removal events %v", events)
	}
	if len(traces) != 1 || traces[0]["ilm-partial"] != "true" || traces[0]["ilm-versions-removed"] != "1" {
		t.Errorf("a partial purge traced %v, want one partial expiry that removed 1 version", traces)
	}

	restore()
	p.expire(0, key)
	for pool := range z.serverPools {
		if got := p.held(pool, key); got != nil {
			t.Errorf("pool %d keeps %v once the purge completed", pool, got)
		}
	}
	events, traces = o.drain()
	if !slices.Equal(events, []string{event.ObjectRemovedDeleteAllVersions.String() + " " + key}) {
		t.Errorf("completed purge sent %v", events)
	}
	if len(traces) != 1 || traces[0]["ilm-partial"] != "" || traces[0]["ilm-versions-removed"] != "2" {
		t.Errorf("completed purge traced %v, want one expiry that removed 2 versions", traces)
	}
}

// A key with a transitioned version is refused, whether the latest version
// is hot or tiered; its versions and remote objects stay.
func TestPurgeAllVersionsRefusesTieredKeys(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-tiered", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	p.tiered(0, "ea/tiered-older", "v1", 6)
	p.version(0, "ea/tiered-older", "v2", 5)
	p.version(0, "bx/tiered-older", "v1", 6)
	p.tiered(0, "bx/tiered-older", "v2", 5)
	p.version(0, "bx/tiered-older", "v3", 4)
	p.version(0, "bx/tiered-latest", "v1", 6)
	p.tiered(0, "bx/tiered-latest", "v2", 5)
	remotes := p.remotes()

	p.expire(0, "ea/tiered-older")
	ri := p.batch(p.matched("bx/tiered-older"), p.matched("bx/tiered-latest"))
	for name, want := range map[string][]string{
		"ea/tiered-older":  {"hot", "tiered"},
		"bx/tiered-older":  {"hot", "tiered", "hot"},
		"bx/tiered-latest": {"tiered", "hot"},
	} {
		if got := p.held(0, name); !slices.Equal(got, want) {
			t.Errorf("%s holds %v, want %v", name, got, want)
		}
	}
	if got := p.remotes(); got != remotes {
		t.Errorf("tier holds %d remote objects, want %d", got, remotes)
	}
	if ri.Objects != 0 || ri.ObjectsFailed == 0 {
		t.Errorf("refused batch purges counted objects=%d failed=%d", ri.Objects, ri.ObjectsFailed)
	}
}

// Control: an expiry of all versions of a transitioned latest version takes
// the transitioned path as before.
func TestPurgeAllVersionsTieredLatestControl(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-tiered-latest", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	p.version(0, "ea/obj", "v1", 6)
	p.tiered(0, "ea/obj", "v2", 5)
	p.expire(0, "ea/obj")
	if got := p.held(0, "ea/obj"); !slices.Equal(got, []string{"DM", "tiered", "hot"}) {
		t.Errorf("holds %v, want a delete marker over both versions", got)
	}
	if got := p.remotes(); got != 1 {
		t.Errorf("tier holds %d remote objects, want 1", got)
	}
}

// A free version that an earlier delete of a tiered version left stays for
// the tier cleanup.
func TestPurgeAllVersionsKeepsFreeVersions(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-free", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	tv := p.tiered(0, "ea/obj", "v1", 6)
	if _, err := z.DeleteObject(t.Context(), p.bucket, "ea/obj", ObjectOptions{Versioned: true, VersionID: tv.VersionID}); err != nil {
		t.Fatal(err)
	}
	p.version(0, "ea/obj", "v2", 5)
	p.expire(0, "ea/obj")
	if got := p.held(0, "ea/obj"); !slices.Equal(got, []string{"free"}) {
		t.Errorf("holds %v, want only the free version", got)
	}
	if got := p.get("ea/obj"); got != "-" {
		t.Errorf("reads %s", got)
	}
}

// Retention and legal hold protect every write that the purge would delete.
func TestPurgeAllVersionsKeepsProtectedWrites(t *testing.T) {
	z, _ := consistencyPools(t)
	p := newPurgeTest(t, z, "purge-protected", MakeBucketOptions{VersioningEnabled: true, LockEnabled: true}, "")
	retained := map[string]string{
		strings.ToLower(xhttp.AmzObjectLockMode):            string(objectlock.RetCompliance),
		strings.ToLower(xhttp.AmzObjectLockRetainUntilDate): amztime.ISO8601Format(UTCNow().Add(24 * time.Hour)),
	}
	held := map[string]string{strings.ToLower(xhttp.AmzObjectLockLegalHold): string(objectlock.LegalHoldOn)}
	p.put(0, "lk/retained", "v1", daysAgo(5), ObjectOptions{Versioned: true, UserDefined: retained})
	p.version(0, "lk/retained", "v2", 4)
	p.put(0, "lk/held", "v1", daysAgo(5), ObjectOptions{Versioned: true, UserDefined: held})
	p.version(0, "lk/held", "v2", 4)
	// An older null write in another pool shares the ID of the latest.
	p.put(0, "lk/null", "old", daysAgo(5), ObjectOptions{UserDefined: retained})
	p.put(1, "lk/null", "new", daysAgo(4), ObjectOptions{})
	p.version(0, "lk/free", "v1", 5)
	p.version(0, "lk/free", "v2", 4)

	ri := p.batch(p.matched("lk/retained"), p.matched("lk/held"), p.matched("lk/null"), p.matched("lk/free"))
	for name, want := range map[string]string{"lk/retained": "v2", "lk/held": "v2", "lk/null": "new", "lk/free": "-"} {
		if got := p.get(name); got != want {
			t.Errorf("%s reads %s, want %s", name, got, want)
		}
	}
	for pool, want := range [][]string{{"hot"}, {"hot"}} {
		if got := p.held(pool, "lk/null"); !slices.Equal(got, want) {
			t.Errorf("lk/null: pool %d holds %v, want %v", pool, got, want)
		}
	}
	for _, name := range []string{"lk/retained", "lk/held"} {
		if got := p.held(0, name); !slices.Equal(got, []string{"hot", "hot"}) {
			t.Errorf("%s holds %v, want both versions", name, got)
		}
	}
	if ri.Objects != 2 || ri.ObjectsFailed == 0 {
		t.Errorf("job counts objects=%d failed=%d, want 2 and the refusals", ri.Objects, ri.ObjectsFailed)
	}
}

// Writes that share a version ID: the older null write in another pool goes
// first, so that a failure keeps what reads return, and the copies of one
// version count once.
func TestPurgeAllVersionsRetiresOlderWritesFirst(t *testing.T) {
	z, _ := consistencyPools(t)
	p := newPurgeTest(t, z, "purge-writes", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	const null, dup = "ea/null", "ea/dup"
	p.put(0, null, "old", daysAgo(6), ObjectOptions{})
	p.put(1, null, "new", daysAgo(5), ObjectOptions{})
	if got := p.get(null); got != "new" {
		t.Fatalf("fixture reads %s", got)
	}
	v1 := p.version(0, dup, "v1", 5)
	p.put(1, dup, "v1", v1.ModTime, ObjectOptions{Versioned: true, VersionID: v1.VersionID})
	o := observePurges(t)

	restore := p.failVersionDeletes(1, null, "")
	p.expire(1, null)
	if got := p.get(null); got != "new" {
		t.Errorf("reads %s after the newer write failed, want new", got)
	}
	if got := p.held(0, null); got != nil {
		t.Errorf("the older write is still in pool 0: %v", got)
	}
	// A copy is gone, though no version is: the purge is partial.
	if events, traces := o.drain(); len(events) != 0 || len(traces) != 1 ||
		traces[0]["ilm-partial"] != "true" || traces[0]["ilm-versions-removed"] != "0" {
		t.Errorf("a purge that removed a copy sent %v and traced %v, want one partial expiry of 0 versions", events, traces)
	}
	restore()
	p.expire(1, null)
	if got := p.held(1, null); got != nil {
		t.Errorf("pool 1 keeps %v", got)
	}

	o.drain()
	p.expire(0, dup)
	for pool := range z.serverPools {
		if got := p.held(pool, dup); got != nil {
			t.Errorf("pool %d keeps %v of %s", pool, got, dup)
		}
	}
	if _, traces := o.drain(); len(traces) != 1 || traces[0]["ilm-versions-removed"] != "1" {
		t.Errorf("copies of one version traced %v, want 1 version removed", traces)
	}
}

// A minority of drives can hold another revision of a version than the
// accepted one. The purge checks every revision on every drive it deletes
// on: a transitioned or a protected one refuses the key.
func TestPurgeAllVersionsChecksEveryDrive(t *testing.T) {
	z := purgeSinglePool(t, 16)
	rewrite := func(p *purgeTest, name, versionID string, metadata map[string]string) {
		t.Helper()
		disk := z.serverPools[0].getHashedSet(name).getDisks()[0]
		if err := disk.UpdateMetadata(t.Context(), p.bucket, name, FileInfo{VersionID: versionID, Metadata: metadata}, UpdateMetadataOpts{}); err != nil {
			t.Fatal(err)
		}
	}
	tiered := newPurgeTest(t, z, "purge-drive-tier", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	v := tiered.version(0, "ea/minority", "v1", 5)
	tiered.version(0, "ea/minority", "v2", 4)
	rewrite(tiered, "ea/minority", v.VersionID, map[string]string{
		metaTierStatus:  lifecycle.TransitionComplete,
		metaTierName:    "WARM",
		metaTierObjName: "remote/ea/minority/v1",
	})
	tiered.expire(0, "ea/minority")
	if got := tiered.get("ea/minority"); got != "v2" {
		t.Errorf("a key with a transitioned revision on one drive reads %s, want v2", got)
	}

	locked := newPurgeTest(t, z, "purge-drive-hold", MakeBucketOptions{VersioningEnabled: true, LockEnabled: true}, "")
	v = locked.version(0, "lk/minority", "v1", 5)
	locked.version(0, "lk/minority", "v2", 4)
	rewrite(locked, "lk/minority", v.VersionID, map[string]string{
		strings.ToLower(xhttp.AmzObjectLockLegalHold): string(objectlock.LegalHoldOn),
	})
	locked.batch(locked.matched("lk/minority"))
	if got := locked.get("lk/minority"); got != "v2" {
		t.Errorf("a key with a legal hold on one drive reads %s, want v2", got)
	}
	disk := z.serverPools[0].getHashedSet("lk/minority").getDisks()[0]
	if fi, err := disk.ReadVersion(t.Context(), "", locked.bucket, "lk/minority", v.VersionID, ReadOptions{}); err != nil ||
		fi.Metadata[strings.ToLower(xhttp.AmzObjectLockLegalHold)] != string(objectlock.LegalHoldOn) {
		t.Errorf("the held revision: %v", err)
	}
}

// A drive that cannot be read may hold a protected or transitioned revision,
// and heal would remove what the purge leaves there. It refuses the key.
func TestPurgeAllVersionsRefusesUnreadableDrive(t *testing.T) {
	z := purgeSinglePool(t, 16)
	failRead := func(bucket, name string) {
		t.Helper()
		sets := z.serverPools[0]
		index := sets.getHashedSetIndex(name)
		sets.erasureDisksMu.Lock()
		prior := sets.erasureDisks[index][0]
		sets.erasureDisks[index][0] = authorityDisk{StorageAPI: prior, bucket: bucket, key: name, failRead: true}
		sets.erasureDisksMu.Unlock()
		t.Cleanup(func() {
			sets.erasureDisksMu.Lock()
			sets.erasureDisks[index][0] = prior
			sets.erasureDisksMu.Unlock()
		})
	}

	locked := newPurgeTest(t, z, "purge-unreadable-hold", MakeBucketOptions{VersioningEnabled: true, LockEnabled: true}, "")
	v := locked.version(0, "lk/hidden", "v1", 5)
	locked.version(0, "lk/hidden", "v2", 4)
	disk := z.serverPools[0].getHashedSet("lk/hidden").getDisks()[0]
	if err := disk.UpdateMetadata(t.Context(), locked.bucket, "lk/hidden", FileInfo{VersionID: v.VersionID, Metadata: map[string]string{
		strings.ToLower(xhttp.AmzObjectLockLegalHold): string(objectlock.LegalHoldOn),
	}}, UpdateMetadataOpts{}); err != nil {
		t.Fatal(err)
	}
	exp := locked.matched("lk/hidden")
	failRead(locked.bucket, "lk/hidden")
	ri := locked.batch(exp)
	if fi, err := disk.ReadVersion(t.Context(), "", locked.bucket, "lk/hidden", v.VersionID, ReadOptions{}); err != nil ||
		fi.Metadata[strings.ToLower(xhttp.AmzObjectLockLegalHold)] != string(objectlock.LegalHoldOn) {
		t.Errorf("the held revision on the unreadable drive: %v", err)
	}
	if got := locked.get("lk/hidden"); got != "v2" || ri.Objects != 0 || ri.ObjectsFailed == 0 {
		t.Errorf("reads %s; job counts objects=%d failed=%d", got, ri.Objects, ri.ObjectsFailed)
	}

	plain := newPurgeTest(t, z, "purge-unreadable-drive", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	plain.version(0, "ea/unreadable-drive", "v1", 5)
	ops := plain.scanQueue(0, "ea/unreadable-drive")
	failRead(plain.bucket, "ea/unreadable-drive")
	plain.run(ops)
	if got := plain.get("ea/unreadable-drive"); got != "v1" {
		t.Errorf("a key with one unreadable drive reads %s, want v1", got)
	}
}

// A batch purge that fails on the latest delete marker counts that marker
// as failed.
func TestPurgeAllVersionsBatchCountsFailedMarker(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-batch-marker", MakeBucketOptions{VersioningEnabled: true}, "")
	const key = "bx/marker"
	p.version(0, key, "old", 5)
	p.marker(0, key, 4)
	exp := p.matched(key)
	p.failVersionDeletes(0, key, exp.VersionID)
	ri := p.batch(exp)
	if got := p.held(0, key); !slices.Equal(got, []string{"DM"}) {
		t.Errorf("holds %v, want the latest marker alone", got)
	}
	if ri.Objects != 1 || ri.DeleteMarkers != 0 || ri.DeleteMarkersFailed != 1 {
		t.Errorf("job counts objects=%d markers=%d failed=%d/%d, want 1, 0, 0/1", ri.Objects, ri.DeleteMarkers, ri.ObjectsFailed, ri.DeleteMarkersFailed)
	}
}

// Unreadable drives are never absence: an expiry of all versions on a history
// that the drives cannot tell deletes nothing, also on one pool.
func TestPurgeAllVersionsRefusesUnreadableHistory(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-unreadable", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	const key = "ea/unreadable"
	p.version(0, key, "v1", 5)
	ops := p.scanQueue(0, key)
	sets := z.serverPools[0]
	sets.erasureDisksMu.Lock()
	prior := sets.erasureDisks
	wrapped := make([][]StorageAPI, len(prior))
	for i, disks := range prior {
		wrapped[i] = append([]StorageAPI(nil), disks...)
		for j := 0; j < len(disks)/2; j++ {
			wrapped[i][j] = authorityDisk{StorageAPI: disks[j], bucket: p.bucket, key: key, failRead: true}
		}
	}
	sets.erasureDisks = wrapped
	sets.erasureDisksMu.Unlock()
	p.run(ops)
	sets.erasureDisksMu.Lock()
	sets.erasureDisks = prior
	sets.erasureDisksMu.Unlock()
	if got := p.held(0, key); !slices.Equal(got, []string{"hot"}) {
		t.Errorf("holds %v after an expiry on an unreadable history", got)
	}
}
