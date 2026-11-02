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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
	xhttp "github.com/minio/minio/internal/http"
)

// restoreTestTier is a remote tier held in memory that counts its reads.
type restoreTestTier struct {
	*tierExpiryTestBackend
	gets atomic.Int64
}

func (b *restoreTestTier) Get(ctx context.Context, object string, rv remoteVersionID, opts WarmBackendGetOpts) (io.ReadCloser, error) {
	b.gets.Add(1)
	return b.tierExpiryTestBackend.Get(ctx, object, rv, opts)
}

// restoreTest is a cluster with a remote tier WARM and a bucket whose
// versions are transitioned to it and restored.
type restoreTest struct {
	t      *testing.T
	z      *erasureServerPools
	bucket string
	object string
	queue  chan expiryOp
	labels map[string]string // version ID ("null" for the null version) -> label
	bodies map[string][]byte // label -> data
}

func restoreTestVersionKey(versionID string) string {
	if versionID == "" {
		return nullVersionID
	}
	return versionID
}

// put writes a version of the object to the first pool. A restored version
// is 1 MiB, so that its restored copy has a data directory of its own.
func (r *restoreTest) put(label string, null, restored bool) ObjectInfo {
	r.t.Helper()
	body := []byte(r.object + " " + label)
	if restored {
		body = bytes.Repeat(body, (1<<20)/len(body)+1)
	}
	opts := ObjectOptions{Versioned: !null}
	if null {
		opts.VersionSuspended = globalBucketVersioningSys.PrefixSuspended(r.bucket, r.object)
	}
	oi, err := r.z.serverPools[0].PutObject(r.t.Context(), r.bucket, r.object,
		mustGetPutObjReader(r.t, bytes.NewReader(body), int64(len(body)), "", ""), opts)
	if err != nil {
		r.t.Fatal(err)
	}
	r.labels[restoreTestVersionKey(oi.VersionID)] = label
	r.bodies[label] = body
	return oi
}

// opts returns the options of a request on a version of the object, as the
// S3 handlers set them.
func (r *restoreTest) opts(versionID string) ObjectOptions {
	return ObjectOptions{
		VersionID:        versionID,
		Versioned:        globalBucketVersioningSys.PrefixEnabled(r.bucket, r.object),
		VersionSuspended: globalBucketVersioningSys.PrefixSuspended(r.bucket, r.object),
	}
}

// restore transitions a version to the tier, restores it, and moves the
// expiry date of the restore into the past.
func (r *restoreTest) restore(oi ObjectInfo) {
	r.t.Helper()
	ctx := r.t.Context()
	vopts := r.opts(oi.VersionID)
	topts := vopts
	topts.MTime = oi.ModTime
	topts.Transition = TransitionOptions{Tier: "WARM", ETag: oi.ETag}
	if err := r.z.TransitionObject(ctx, r.bucket, r.object, topts); err != nil {
		r.t.Fatal(err)
	}
	ropts := vopts
	ropts.Transition = TransitionOptions{RestoreRequest: &RestoreObjectRequest{Days: 1}}
	// Through the pool, as with a single pool: with more than one pool the
	// pools layer holds the object lock that the write of the restored copy
	// waits for.
	if err := r.z.serverPools[0].RestoreTransitionedObject(ctx, r.bucket, r.object, ropts); err != nil {
		r.t.Fatal(err)
	}
	expired := completedRestoreObj(time.Now().Add(-24 * time.Hour).UTC()).String()
	mopts := vopts
	mopts.MTime = oi.ModTime
	mopts.EvalMetadataFn = func(o *ObjectInfo, _ error) (ReplicateDecision, error) {
		o.UserDefined[xhttp.AmzRestore] = expired
		return ReplicateDecision{}, nil
	}
	if _, err := r.z.PutObjectMetadata(ctx, r.bucket, r.object, mopts); err != nil {
		r.t.Fatal(err)
	}
}

// fileInfo returns the version of the object from a drive of the first pool.
func (r *restoreTest) fileInfo(versionID string) FileInfo {
	r.t.Helper()
	infos, errs := readAllFileInfo(r.t.Context(), r.z.serverPools[0].getHashedSet(r.object).getDisks(), "", r.bucket, r.object, restoreTestVersionKey(versionID), false, false)
	if errs[0] != nil {
		r.t.Fatal(errs[0])
	}
	return infos[0]
}

// dataDirs returns how many drives of the first pool hold the data
// directory of a version.
func (r *restoreTest) dataDirs(dataDir string) int {
	r.t.Helper()
	n := 0
	for _, disk := range r.z.serverPools[0].getHashedSet(r.object).getDisks() {
		_, err := os.Stat(filepath.Join(disk.Endpoint().Path, r.bucket, r.object, dataDir))
		if err == nil {
			n++
		} else if !os.IsNotExist(err) {
			r.t.Fatal(err)
		}
	}
	return n
}

// versions returns the versions of the object in each pool, newest first,
// and its free versions in all pools.
func (r *restoreTest) versions() (views []string, free int) {
	r.t.Helper()
	for _, pool := range r.z.serverPools {
		rf, err := pool.getHashedSet(r.object).getDisks()[0].ReadXL(r.t.Context(), r.bucket, r.object, false)
		if errors.Is(err, errFileNotFound) {
			views = append(views, "")
			continue
		}
		if err != nil {
			r.t.Fatal(err)
		}
		fivs, err := getFileInfoVersions(rf.Buf, r.bucket, r.object, false)
		if err != nil {
			r.t.Fatal(err)
		}
		var labels []string
		for _, fi := range fivs.Versions {
			if fi.Deleted {
				labels = append(labels, "DM")
			} else {
				labels = append(labels, r.labels[restoreTestVersionKey(fi.VersionID)])
			}
		}
		views = append(views, strings.Join(labels, " "))
		free += len(fivs.FreeVersions)
	}
	return views, free
}

// read returns the label and the data of a version, or of the latest version
// when versionID is empty, or the error of the read.
func (r *restoreTest) read(versionID string) (string, []byte, error) {
	r.t.Helper()
	gr, err := r.z.GetObjectNInfo(r.t.Context(), r.bucket, r.object, nil, nil, ObjectOptions{VersionID: versionID})
	if err != nil {
		return "", nil, err
	}
	defer gr.Close()
	data, err := io.ReadAll(gr)
	if err != nil {
		return "", nil, err
	}
	return r.labels[restoreTestVersionKey(gr.ObjInfo.VersionID)], data, nil
}

// runQueue runs the queued expiries with an expiry worker.
func (r *restoreTest) runQueue() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		globalExpiryState.Worker(r.queue)
	}()
	r.queue <- nil // the worker returns once it ran every expiry queued before
	<-done
}

// objInfos returns the versions of the object as a drive of the
// first pool holds them, as the scanner and the walks of decommission and
// the drive heal see them.
func (r *restoreTest) objInfos() []ObjectInfo {
	r.t.Helper()
	rf, err := r.z.serverPools[0].getHashedSet(r.object).getDisks()[0].ReadXL(r.t.Context(), r.bucket, r.object, false)
	if err != nil {
		r.t.Fatal(err)
	}
	fivs, err := getFileInfoVersions(rf.Buf, r.bucket, r.object, false)
	if err != nil {
		r.t.Fatal(err)
	}
	versioned := globalBucketVersioningSys.PrefixEnabled(r.bucket, r.object) || globalBucketVersioningSys.PrefixSuspended(r.bucket, r.object)
	objInfos := make([]ObjectInfo, len(fivs.Versions))
	for i, fi := range fivs.Versions {
		objInfos[i] = fi.ToObjectInfo(r.bucket, r.object, versioned)
	}
	return objInfos
}

// The restored copy of a transitioned version expires on the expiry date of
// its restore. The expiry removes the copy and nothing else: the version
// stays where it is in the version stack, transitioned, and is read from the
// tier again. Every path that applies ILM runs the expiry: the scanner and a
// GET or HEAD queue it for an expiry worker, decommission and the drive heal
// run it at once. The expiry of the restored copy of the latest version used
// to delete the object instead: a versioned bucket got a delete marker that
// hid it. With versioning suspended it went to the null version, removed its
// data if there was one and failed if not, and the restored copy stayed.
func TestExpireRestoredCopy(t *testing.T) {
	prevTier := globalTierConfigMgr
	t.Cleanup(func() { globalTierConfigMgr = prevTier })
	prevExpiry := globalExpiryState
	t.Cleanup(func() { globalExpiryState = prevExpiry })

	// Nothing here is old enough to transition; the rule makes the bucket
	// one with a tier, as restored versions are in.
	const rules = `<LifecycleConfiguration><Rule><ID>tier</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>` +
		`<Transition><Days>1000</Days><StorageClass>WARM</StorageClass></Transition></Rule></LifecycleConfiguration>`

	type version struct {
		label    string
		null     bool // the null version
		restored bool // transitioned and restored, the restore has expired
	}
	testCases := []struct {
		name       string
		versioning versioning.State // "", Enabled or Suspended
		versions   []version        // oldest first
	}{
		{name: "versioned", versioning: versioning.Enabled, versions: []version{{label: "v1"}, {label: "v2", restored: true}}},
		{name: "versioned-noncurrent", versioning: versioning.Enabled, versions: []version{{label: "v1", restored: true}, {label: "v2"}}},
		{name: "versioned-null", versioning: versioning.Enabled, versions: []version{{label: "v1", null: true, restored: true}}},
		{name: "suspended", versioning: versioning.Suspended, versions: []version{{label: "v1", null: true}, {label: "v2", restored: true}}},
		{name: "suspended-no-null", versioning: versioning.Suspended, versions: []version{{label: "v1"}, {label: "v2", restored: true}}},
		{name: "suspended-null", versioning: versioning.Suspended, versions: []version{{label: "v1"}, {label: "v2", null: true, restored: true}}},
		{name: "unversioned", versions: []version{{label: "v1", null: true, restored: true}}},
	}

	sources := []struct {
		name   string
		expire func(r *restoreTest, oi ObjectInfo, evt lifecycle.Event)
	}{
		{"scanner", func(r *restoreTest, _ ObjectInfo, _ lifecycle.Event) {
			lc, err := globalLifecycleSys.Get(r.bucket)
			if err != nil {
				r.t.Fatal(err)
			}
			lr, err := globalBucketObjectLockSys.Get(r.bucket)
			if err != nil {
				r.t.Fatal(err)
			}
			item := scannerItem{bucket: r.bucket, objectName: r.object, lifeCycle: lc}
			item.applyActions(r.t.Context(), r.z, r.objInfos(), lr, &sizeSummary{}, nil)
			r.runQueue()
		}},
		{"head", func(r *restoreTest, oi ObjectInfo, evt lifecycle.Event) {
			applyExpiryRule(evt, lcEventSrc_s3HeadObject, oi)
			r.runQueue()
		}},
		{"list", func(r *restoreTest, _ ObjectInfo, _ lifecycle.Event) {
			// ListObjects of the key with max-keys=1 reads its latest
			// version without the versioning of the bucket, a listing of
			// versions reads them all.
			if _, err := r.z.ListObjects(r.t.Context(), r.bucket, r.object, "", "", 1); err != nil {
				r.t.Fatal(err)
			}
			if _, err := r.z.ListObjectVersions(r.t.Context(), r.bucket, r.object, "", "", "", 100); err != nil {
				r.t.Fatal(err)
			}
			r.runQueue()
		}},
		{"decom", func(r *restoreTest, oi ObjectInfo, evt lifecycle.Event) {
			for _, o := range r.objInfos() {
				if o.VersionID == oi.VersionID {
					applyExpiryOnTransitionedObject(r.t.Context(), r.z, o, evt, lcEventSrc_Decom)
					return
				}
			}
			r.t.Fatal("version not found on the drive")
		}},
	}

	for _, pools := range []int{1, 2} {
		t.Run(fmt.Sprintf("pools=%d", pools), func(t *testing.T) {
			ctx := t.Context()
			dirs, err := getRandomDisks(4 * pools)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { removeRoots(dirs) })
			var endpoints EndpointServerPools
			for i := range pools {
				endpoints = append(endpoints, mustGetPoolEndpoints(i, dirs[4*i:4*i+4]...)...)
			}
			obj, _, err := initObjectLayer(ctx, endpoints)
			if err != nil {
				t.Fatal(err)
			}
			z := obj.(*erasureServerPools)
			// After initObjectLayer, which sets up a new tier config.
			tier := &restoreTestTier{tierExpiryTestBackend: &tierExpiryTestBackend{objects: map[string][]byte{}}}
			globalTierConfigMgr = NewTierConfigMgr()
			globalTierConfigMgr.drivercache["WARM"] = tier

			for _, tc := range testCases {
				for _, src := range sources {
					t.Run(tc.name+"/"+src.name, func(t *testing.T) {
						r := &restoreTest{
							t: t, z: z,
							bucket: "restore-" + tc.name + "-" + src.name, object: "obj",
							queue:  make(chan expiryOp, 100),
							labels: map[string]string{}, bodies: map[string][]byte{},
						}
						if err := z.MakeBucket(ctx, r.bucket, MakeBucketOptions{VersioningEnabled: tc.versioning != ""}); err != nil {
							t.Fatal(err)
						}
						meta, err := globalBucketMetadataSys.Get(r.bucket)
						if err != nil {
							t.Fatal(err)
						}
						if tc.versioning == versioning.Suspended {
							meta.VersioningConfigXML = []byte("<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>")
						}
						meta.LifecycleConfigXML = []byte(rules)
						if err := meta.Save(ctx, z); err != nil {
							t.Fatal(err)
						}
						globalBucketMetadataSys.Set(r.bucket, meta)
						es := &expiryState{ctx: ctx, objAPI: z}
						workers := []chan expiryOp{r.queue}
						es.workers.Store(&workers)
						globalExpiryState = es

						var restored ObjectInfo
						for _, v := range tc.versions {
							oi := r.put(v.label, v.null, v.restored)
							if v.restored {
								r.restore(oi)
								restored = oi
							}
						}
						rlabel := r.labels[restoreTestVersionKey(restored.VersionID)]

						// The fixture: the restored copy is on the drives,
						// its restore has expired, ILM expires it.
						fi := r.fileInfo(restored.VersionID)
						if fi.TransitionStatus != lifecycle.TransitionComplete || fi.DataDir == "" || r.dataDirs(fi.DataDir) == 0 {
							t.Fatalf("fixture: %s transition status %q, restored copy on %d drives", rlabel, fi.TransitionStatus, r.dataDirs(fi.DataDir))
						}
						oi, err := z.GetObjectInfo(ctx, r.bucket, r.object, r.opts(restored.VersionID))
						if err != nil {
							t.Fatal(err)
						}
						lc, err := globalLifecycleSys.Get(r.bucket)
						if err != nil {
							t.Fatal(err)
						}
						lr, err := globalBucketObjectLockSys.Get(r.bucket)
						if err != nil {
							t.Fatal(err)
						}
						evt := evalActionFromLifecycle(ctx, *lc, lr, nil, oi)
						if !evt.Action.DeleteRestored() || oi.RestoreExpires.IsZero() {
							t.Fatalf("fixture: %s restore expires %v, action %v", rlabel, oi.RestoreExpires, evt.Action)
						}
						before, _ := r.versions()
						for key, label := range r.labels {
							if _, data, err := r.read(key); err != nil || !bytes.Equal(data, r.bodies[label]) {
								t.Fatalf("fixture: GET %s: %v", label, err)
							}
						}

						src.expire(r, oi, evt)

						after, free := r.versions()
						if fmt.Sprint(after) != fmt.Sprint(before) || free != 0 {
							t.Errorf("versions in each pool: before %q, after %q with %d free versions", before, after, free)
						}
						if label, _, err := r.read(""); err != nil || label != tc.versions[len(tc.versions)-1].label {
							t.Errorf("GET reads %q, %v; want %q", label, err, tc.versions[len(tc.versions)-1].label)
						}
						if n := r.dataDirs(fi.DataDir); n != 0 {
							t.Errorf("restored copy of %s still on %d drives", rlabel, n)
						}
						oi, err = z.GetObjectInfo(ctx, r.bucket, r.object, r.opts(restored.VersionID))
						if err != nil {
							t.Fatalf("HEAD %s: %v", rlabel, err)
						}
						if oi.TransitionedObject.Status != lifecycle.TransitionComplete || oi.UserDefined[xhttp.AmzRestore] != "" || !oi.RestoreExpires.IsZero() {
							t.Errorf("HEAD %s: transition status %q, x-amz-restore %q", rlabel, oi.TransitionedObject.Status, oi.UserDefined[xhttp.AmzRestore])
						}
						for _, v := range tc.versions {
							for key, label := range r.labels {
								if label != v.label {
									continue
								}
								gets := tier.gets.Load()
								_, data, err := r.read(key)
								switch {
								case err != nil:
									t.Errorf("GET %s: %v", v.label, err)
								case !bytes.Equal(data, r.bodies[v.label]):
									t.Errorf("GET %s reads %d bytes that differ", v.label, len(data))
								case v.restored && tier.gets.Load() == gets:
									t.Errorf("GET %s does not read the tier", v.label)
								}
							}
						}
					})
				}
			}
		})
	}
}
