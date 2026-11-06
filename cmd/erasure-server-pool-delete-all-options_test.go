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
	"sync/atomic"
	"testing"
	"time"

	xhttp "github.com/minio/minio/internal/http"
)

// The parts of the purge of all versions that need its own options.

// A purge stops at its budget before the latest version.
func TestPurgeAllVersionsStopsAtBudget(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-budget", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	prev := deleteAllBudget
	deleteAllBudget.versions = 2
	t.Cleanup(func() { deleteAllBudget = prev })
	const key = "ea/long"
	for i, days := range []float64{8, 7, 6, 5} {
		p.version(0, key, fmt.Sprintf("v%d", i+1), days)
	}
	o := observePurges(t)
	p.expire(0, key)
	if got := p.held(0, key); !slices.Equal(got, []string{"hot", "hot"}) {
		t.Errorf("holds %v after a purge stopped at its budget, want the two newest versions", got)
	}
	if got := p.get(key); got != "v4" {
		t.Errorf("reads %s, want v4", got)
	}
	events, traces := o.drain()
	if len(events) != 0 || len(traces) != 1 || traces[0]["ilm-partial"] != "true" || traces[0]["ilm-versions-removed"] != "2" {
		t.Errorf("stopped purge sent %v and traced %v", events, traces)
	}
	p.expire(0, key)
	if got := p.held(0, key); got != nil {
		t.Errorf("keeps %v once the purge continued", got)
	}
}

// The option admits no other delete.
func TestPurgeAllVersionsOptions(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-options", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	p.version(0, "ea/key", "v1", 5)
	match := &deleteAllMatch{}
	expire := ExpirationOptions{Expire: true}
	allow := func([]ObjectInfo) error { return nil }
	for name, opts := range map[string]ObjectOptions{
		"no approval":   {DeleteAllVersions: true},
		"two approvals": {DeleteAllVersions: true, Expiration: expire, DeleteAllLatest: match, deleteAllAuthorize: allow},
		// A batch purge deletes as the submitter of its job, an ILM purge
		// as the server, and no other delete takes an authorization.
		"batch unauthorized": {DeleteAllVersions: true, DeleteAllLatest: match},
		"ilm authorized":     {DeleteAllVersions: true, Expiration: expire, deleteAllAuthorize: allow},
		"authorized delete":  {deleteAllAuthorize: allow},
		"prefix":             {DeleteAllVersions: true, Expiration: expire, DeletePrefix: true},
		"prefix object":      {DeleteAllVersions: true, Expiration: expire, DeletePrefixObject: true},
		"version":            {DeleteAllVersions: true, Expiration: expire, VersionID: mustGetUUID()},
		"movement":           {DeleteAllVersions: true, Expiration: expire, DataMovement: true},
		"marker":             {DeleteAllVersions: true, Expiration: expire, DeleteMarker: true},
		"versioned":          {DeleteAllVersions: true, Expiration: expire, Versioned: true},
		"suspended":          {DeleteAllVersions: true, Expiration: expire, VersionSuspended: true},
	} {
		if _, err := z.DeleteObject(t.Context(), p.bucket, "ea/key", opts); !errors.As(err, new(InvalidArgument)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	opts := ObjectOptions{DeleteAllVersions: true, Expiration: expire}
	if _, err := z.serverPools[0].DeleteObject(t.Context(), p.bucket, "ea/key", opts); !errors.As(err, new(NotImplemented)) {
		t.Errorf("erasure sets: %v", err)
	}
	if _, errs := z.DeleteObjects(t.Context(), p.bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: "ea/key"}}}, opts); !errors.As(errs[0], new(NotImplemented)) {
		t.Errorf("bulk delete: %v", errs[0])
	}
	if got := p.held(0, "ea/key"); !slices.Equal(got, []string{"hot"}) {
		t.Errorf("holds %v after rejected requests", got)
	}
	// An absent key is a success that removes nothing.
	var res deleteAllResult
	if _, err := z.DeleteObject(t.Context(), p.bucket, "ea/absent", ObjectOptions{DeleteAllVersions: true, Expiration: expire, DeleteAllResult: &res}); err != nil || res.Removed != 0 || !res.Complete {
		t.Errorf("absent key: %v %+v", err, res)
	}
}

type purgeSlowDisk struct {
	StorageAPI
	bucket, object string
}

func (d purgeSlowDisk) ReadXL(ctx context.Context, bucket, object string, data bool) (RawFileInfo, error) {
	if bucket == d.bucket && object == d.object {
		time.Sleep(20 * time.Millisecond)
	}
	return d.StorageAPI.ReadXL(ctx, bucket, object, data)
}

// The time budget covers the reads and checks before the first delete.
func TestPurgeAllVersionsBudgetCoversReads(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-budget-reads", MakeBucketOptions{VersioningEnabled: true}, "")
	const key = "bx/slow"
	p.version(0, key, "v1", 5)
	exp := p.matched(key)
	prev := deleteAllBudget
	deleteAllBudget.duration = 10 * time.Millisecond
	t.Cleanup(func() { deleteAllBudget = prev })
	pool := z.serverPools[0]
	pool.erasureDisksMu.Lock()
	prior := pool.erasureDisks
	wrapped := make([][]StorageAPI, len(prior))
	for i, disks := range prior {
		wrapped[i] = make([]StorageAPI, len(disks))
		for j, disk := range disks {
			wrapped[i][j] = purgeSlowDisk{StorageAPI: disk, bucket: p.bucket, object: key}
		}
	}
	pool.erasureDisks = wrapped
	pool.erasureDisksMu.Unlock()
	t.Cleanup(func() { pool.erasureDisksMu.Lock(); pool.erasureDisks = prior; pool.erasureDisksMu.Unlock() })
	var res deleteAllResult
	_, err := z.DeleteObject(t.Context(), p.bucket, key, ObjectOptions{
		DeleteAllVersions:  true,
		DeleteAllLatest:    &deleteAllMatch{VersionID: exp.VersionID, ModTime: exp.ModTime},
		DeleteAllResult:    &res,
		deleteAllAuthorize: func([]ObjectInfo) error { return nil },
	})
	if !errors.Is(err, errDeleteAllBudget) || res.Started || res.Removed != 0 {
		t.Errorf("purge after its budget ran out on reads: err=%v %+v", err, res)
	}
	if got := p.held(0, key); !slices.Equal(got, []string{"hot"}) {
		t.Errorf("holds %v", got)
	}
}

// A marker that an expiration job failed to remove fails the job.
func TestPurgeAllVersionsMarkerFailureFailsJob(t *testing.T) {
	ri := &batchJobInfo{}
	var res batchCounts
	res.expireAllFailed(expireObjInfo{ObjectInfo: ObjectInfo{Name: "key", NumVersions: 2}, DeleteMarkerCount: 1}, 1, 0)
	progress := newBatchProgress(ri, "bucket")
	progress.done(progress.begin(), "key", res)
	progress.finish()
	if ri.ObjectsFailed != 0 || ri.DeleteMarkersFailed != 1 || !ri.expireFailures() {
		t.Errorf("failed=%d/%d failures=%t", ri.ObjectsFailed, ri.DeleteMarkersFailed, ri.expireFailures())
	}
}

// purgeSwapDisk replaces itself in its slot once the purge has read it
// twice, for the history and for the drive check, as a reconnect does.
type purgeSwapDisk struct {
	StorageAPI
	bucket, object string
	reads          *atomic.Int32
	swap           func()
}

func (d purgeSwapDisk) ReadXL(ctx context.Context, bucket, object string, data bool) (RawFileInfo, error) {
	rf, err := d.StorageAPI.ReadXL(ctx, bucket, object, data)
	if bucket == d.bucket && object == d.object && d.reads.Add(1) == 2 {
		d.swap()
	}
	return rf, err
}

// purgeCountDisk counts the version deletes it receives.
type purgeCountDisk struct {
	StorageAPI
	deletes *atomic.Int32
}

func (d purgeCountDisk) DeleteVersion(ctx context.Context, volume, path string, fi FileInfo, forceDelMarker bool, opts DeleteOptions) error {
	d.deletes.Add(1)
	return d.StorageAPI.DeleteVersion(ctx, volume, path, fi, forceDelMarker, opts)
}

// The purge deletes on the drive handles it checked, not on a handle that
// replaced one of them since.
func TestPurgeAllVersionsDeletesOnCheckedDrives(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-checked-drives", MakeBucketOptions{VersioningEnabled: true}, "")
	const key = "bx/swap"
	p.version(0, key, "v1", 5)
	exp := p.matched(key)
	sets := z.serverPools[0]
	index := sets.getHashedSetIndex(key)
	var reads, deletes atomic.Int32
	sets.erasureDisksMu.Lock()
	original := sets.erasureDisks[index][0]
	sets.erasureDisks[index][0] = purgeSwapDisk{StorageAPI: original, bucket: p.bucket, object: key, reads: &reads, swap: func() {
		sets.erasureDisksMu.Lock()
		sets.erasureDisks[index][0] = purgeCountDisk{StorageAPI: original, deletes: &deletes}
		sets.erasureDisksMu.Unlock()
	}}
	sets.erasureDisksMu.Unlock()
	t.Cleanup(func() {
		sets.erasureDisksMu.Lock()
		sets.erasureDisks[index][0] = original
		sets.erasureDisksMu.Unlock()
	})
	var res deleteAllResult
	if _, err := z.DeleteObject(t.Context(), p.bucket, key, ObjectOptions{
		DeleteAllVersions:  true,
		DeleteAllLatest:    &deleteAllMatch{VersionID: exp.VersionID, ModTime: exp.ModTime},
		DeleteAllResult:    &res,
		deleteAllAuthorize: func([]ObjectInfo) error { return nil },
	}); err != nil || !res.Complete {
		t.Fatalf("purge: %v %+v", err, res)
	}
	if reads.Load() != 2 || deletes.Load() != 0 {
		t.Errorf("reads=%d deletes on the replacement handle=%d", reads.Load(), deletes.Load())
	}
}

// A batch purge has every copy of every version it approved authorized, as
// the copy is now, before it deletes any; an authorization error deletes
// nothing and is returned as it is.
func TestPurgeAllVersionsAuthorizesEveryCopy(t *testing.T) {
	z, _ := consistencyPools(t)
	p := newPurgeTest(t, z, "purge-authorize", MakeBucketOptions{VersioningEnabled: true}, "")
	const key = "bx/authorize"
	p.put(0, key, "old", daysAgo(6), ObjectOptions{})
	p.put(1, key, "new", daysAgo(5), ObjectOptions{UserDefined: map[string]string{xhttp.AmzObjectTagging: "copy=new"}})
	tagged := p.put(0, key, "v1", daysAgo(4), ObjectOptions{Versioned: true, UserDefined: map[string]string{xhttp.AmzObjectTagging: "keep=yes"}})
	exp := p.matched(key)
	denied := errors.New("denied")
	var seen []string // the distinct versions and tags authorized
	purge := func(authorize func([]ObjectInfo) error) (deleteAllResult, error) {
		var res deleteAllResult
		_, err := z.DeleteObject(t.Context(), p.bucket, key, ObjectOptions{
			DeleteAllVersions:  true,
			DeleteAllLatest:    &deleteAllMatch{VersionID: exp.VersionID, ModTime: exp.ModTime},
			DeleteAllResult:    &res,
			deleteAllAuthorize: authorize,
		})
		return res, err
	}
	res, err := purge(func(versions []ObjectInfo) error {
		for _, v := range versions {
			if got := v.VersionID + " " + v.UserTags; !slices.Contains(seen, got) {
				seen = append(seen, got)
			}
		}
		return denied
	})
	if !errors.Is(err, denied) || res.Started || res.Removed != 0 {
		t.Errorf("denied purge: err=%v %+v", err, res)
	}
	want := []string{"null ", "null copy=new", tagged.VersionID + " keep=yes"}
	slices.Sort(seen)
	slices.Sort(want)
	if !slices.Equal(seen, want) {
		t.Errorf("authorized %q, want every copy %q", seen, want)
	}
	for pool := range z.serverPools {
		if got := p.held(pool, key); len(got) == 0 {
			t.Errorf("pool %d lost its copies to a denied purge", pool)
		}
	}
	if got := p.get(key); got != "v1" {
		t.Errorf("reads %s after a denied purge, want v1", got)
	}
	// Control: an allowed purge deletes them all.
	if res, err = purge(func([]ObjectInfo) error { return nil }); err != nil || !res.Complete {
		t.Fatalf("allowed purge: %v %+v", err, res)
	}
	for pool := range z.serverPools {
		if got := p.held(pool, key); got != nil {
			t.Errorf("pool %d keeps %v", pool, got)
		}
	}
}
