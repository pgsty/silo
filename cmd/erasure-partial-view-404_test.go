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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/minio/minio/internal/bucket/versioning"
)

// downTier is a remote tier that is unreachable, as a warm backend reports a
// refused connection after ErrorRespToObjectError.
type downTier struct{ *tierExpiryTestBackend }

func (downTier) Get(context.Context, string, remoteVersionID, WarmBackendGetOpts) (io.ReadCloser, error) {
	return nil, BackendDown{Err: "dial tcp 127.0.0.1:9710: connect: connection refused"}
}

// partialView is an 8-drive, EC 4+4 erasure set (the layout of the 4-node x
// 2-drive acceptance cluster: positions 0,1 = n1; 2,3 = n2; 4,5 = n3;
// 6,7 = n4) with an in-memory tier WARM.
type partialView struct {
	*restoreTest
	er       *erasureObjects
	original func() []StorageAPI
	all      []StorageAPI
}

func newPartialView(t *testing.T, state versioning.State) *partialView {
	t.Helper()
	prevTier := globalTierConfigMgr
	t.Cleanup(func() { globalTierConfigMgr = prevTier })
	dirs, err := getRandomDisks(8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeRoots(dirs) })
	obj, _, err := initObjectLayer(t.Context(), mustGetPoolEndpoints(0, dirs...))
	if err != nil {
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	t.Cleanup(func() { z.Shutdown(context.Background()) })
	if n := len(z.serverPools[0].sets); n != 1 {
		t.Fatalf("want one erasure set, got %d", n)
	}
	globalTierConfigMgr = NewTierConfigMgr()
	backend := &tierExpiryTestBackend{objects: map[string][]byte{}}
	globalTierConfigMgr.drivercache["WARM"] = &restoreTestTier{tierExpiryTestBackend: backend}
	r := &restoreTest{t: t, z: z, bucket: getRandomBucketName(), object: "t1", labels: map[string]string{}, bodies: map[string][]byte{}}
	if err := z.MakeBucket(t.Context(), r.bucket, MakeBucketOptions{VersioningEnabled: state == versioning.Enabled}); err != nil {
		t.Fatal(err)
	}
	meta, err := globalBucketMetadataSys.Get(r.bucket)
	if err != nil {
		t.Fatal(err)
	}
	meta.LifecycleConfigXML = []byte(restoreSafetyRules)
	if err := meta.Save(t.Context(), z); err != nil {
		t.Fatal(err)
	}
	globalBucketMetadataSys.Set(r.bucket, meta)
	er := z.serverPools[0].getHashedSet(r.object)
	if er.setDriveCount != 8 || er.defaultParityCount != 4 {
		t.Fatalf("want EC 4+4 on 8 drives, got %d drives parity %d", er.setDriveCount, er.defaultParityCount)
	}
	p := &partialView{restoreTest: r, er: er, original: er.getDisks, all: er.getDisks()}
	t.Cleanup(func() { er.getDisks = p.original })
	return p
}

// see makes only the drives at the given positions reachable from the
// erasure set, as for a node whose connections to the others are not yet up.
func (p *partialView) see(positions ...int) {
	visible := make([]StorageAPI, len(p.all))
	for _, i := range positions {
		visible[i] = p.all[i]
	}
	p.er.getDisks = func() []StorageAPI { return visible }
}

func (p *partialView) seeAll() { p.er.getDisks = p.original }

func (p *partialView) tierDown() {
	globalTierConfigMgr.drivercache["WARM"] = downTier{&tierExpiryTestBackend{objects: map[string][]byte{}}}
}

// drives describes the version on each drive: R restored, T transitioned
// (not restored), L local, - missing.
func (p *partialView) drives(versionID string) string {
	p.t.Helper()
	infos, errs := readAllFileInfo(p.t.Context(), p.all, "", p.bucket, p.object, restoreTestVersionKey(versionID), false, false)
	var b bytes.Buffer
	for i := range infos {
		switch {
		case errs[i] != nil:
			b.WriteByte('-')
		case infos[i].IsRemote():
			b.WriteByte('T')
		case infos[i].TransitionStatus != "":
			b.WriteByte('R')
		default:
			b.WriteByte('L')
		}
	}
	return b.String()
}

func (p *partialView) transition(oi ObjectInfo) {
	p.t.Helper()
	topts := p.opts(oi.VersionID)
	topts.MTime = oi.ModTime
	topts.Transition = TransitionOptions{Tier: "WARM", ETag: oi.ETag}
	if err := p.z.TransitionObject(p.t.Context(), p.bucket, p.object, topts); err != nil {
		p.t.Fatal(err)
	}
}

func (p *partialView) restoreObject(oi ObjectInfo) {
	p.t.Helper()
	ropts := p.opts(oi.VersionID)
	ropts.Transition = TransitionOptions{RestoreRequest: &RestoreObjectRequest{Days: 1}}
	if err := p.z.serverPools[0].RestoreTransitionedObject(p.t.Context(), p.bucket, p.object, ropts); err != nil {
		p.t.Fatal(err)
	}
}

// getAndHead reads the latest version as an S3 GET and HEAD without a
// version ID would.
func (p *partialView) getAndHead() (data []byte, getErr, headErr error) {
	opts := p.opts("")
	gr, getErr := p.z.GetObjectNInfo(p.t.Context(), p.bucket, p.object, nil, nil, opts)
	if getErr == nil {
		data, getErr = io.ReadAll(gr)
		gr.Close()
	}
	_, headErr = p.z.GetObjectInfo(p.t.Context(), p.bucket, p.object, opts)
	return data, getErr, headErr
}

// wantRetryable requires the answer of a read that cannot reach quorum from a
// partial view: a read-quorum error, which the API returns as 503 SlowDownRead,
// never a 404 for an object that exists.
func wantRetryable(t *testing.T, what string, err error) {
	t.Helper()
	var rq InsufficientReadQuorum
	if !errors.As(err, &rq) {
		t.Errorf("%s: got %T %v, want InsufficientReadQuorum", what, err, err)
		return
	}
	if code := toAPIError(context.Background(), err).HTTPStatusCode; code != http.StatusServiceUnavailable {
		t.Errorf("%s: HTTP %d, want 503", what, code)
	}
}

// The acceptance failure: node1 restores t1 while node2's drives are not
// reachable, so the restore commits on 6 of 8 drives (write quorum 5). node2
// then restarts and reaches only its own drives and node4's (n1 and n3 not yet
// reconnected), with the tier down. The 4 visible xl.meta are 2 transitioned
// and 2 restored copies of the same version and mod time.
func TestPartialViewRestoreSplitIsRetryable(t *testing.T) {
	for _, state := range []versioning.State{versioning.Enabled, ""} {
		t.Run(fmt.Sprintf("versioning=%q", state), func(t *testing.T) {
			p := newPartialView(t, state)
			oi := p.put("v1", state == "", true)
			p.transition(oi)
			p.see(0, 1, 4, 5, 6, 7) // node1's view: n2 not reachable
			p.restoreObject(oi)
			p.seeAll()
			if got, want := p.drives(oi.VersionID), "RRTTRRRR"; got != want {
				t.Fatalf("drive states %s, want %s", got, want)
			}

			p.tierDown()
			p.see(2, 3, 6, 7) // node2's view after its restart
			_, getErr, headErr := p.getAndHead()
			wantRetryable(t, "GET", getErr)
			wantRetryable(t, "HEAD", headErr)

			// Every view that contains a quorum of the restored copy reads it.
			p.see(0, 1, 4, 5, 6, 7)
			data, getErr, headErr := p.getAndHead()
			if getErr != nil || headErr != nil || !bytes.Equal(data, p.bodies["v1"]) {
				t.Errorf("node1 view: GET err=%v HEAD err=%v bytes=%d", getErr, headErr, len(data))
			}
		})
	}
}

// The same split, made by a transition instead of a restore: a node that sees
// 2 local and 2 transitioned copies.
func TestPartialViewTransitionSplitIsRetryable(t *testing.T) {
	p := newPartialView(t, versioning.Enabled)
	oi := p.put("v1", false, true)
	p.see(0, 1, 4, 5, 6, 7)
	p.transition(oi)
	p.seeAll()
	if got, want := p.drives(oi.VersionID), "TTLLTTTT"; got != want {
		t.Fatalf("drive states %s, want %s", got, want)
	}
	p.see(2, 3, 6, 7)
	_, getErr, headErr := p.getAndHead()
	wantRetryable(t, "GET", getErr)
	wantRetryable(t, "HEAD", headErr)
}

// Generic, without tiering: an overwrite committed on 6 of 8 drives, read by
// a node that sees 2 old and 2 new copies.
func TestPartialViewOverwriteSplit(t *testing.T) {
	for _, state := range []versioning.State{versioning.Enabled, ""} {
		t.Run(fmt.Sprintf("versioning=%q", state), func(t *testing.T) {
			p := newPartialView(t, state)
			p.put("old", state == "", true)
			p.see(0, 1, 4, 5, 6, 7)
			p.put("new", state == "", true)
			p.seeAll()
			p.see(2, 3, 6, 7)
			data, getErr, headErr := p.getAndHead()
			if state == "" {
				wantRetryable(t, "GET", getErr)
				wantRetryable(t, "HEAD", headErr)
				return
			}
			// A versioned overwrite can be served from the older version
			// through such a view (existing behavior, out of scope here),
			// but must never be reported missing.
			for what, err := range map[string]error{"GET": getErr, "HEAD": headErr} {
				if err != nil {
					wantRetryable(t, what, err)
				}
			}
			if getErr == nil && !bytes.Equal(data, p.bodies["old"]) && !bytes.Equal(data, p.bodies["new"]) {
				t.Errorf("GET returned neither version (%d bytes)", len(data))
			}
		})
	}
}

// Controls: what must not change.
func TestPartialViewControls(t *testing.T) {
	p := newPartialView(t, versioning.Enabled)
	// A key that never existed is still 404 from a partial view.
	p.see(2, 3, 6, 7)
	if _, getErr, headErr := p.getAndHead(); !isErrObjectNotFound(getErr) || !isErrObjectNotFound(headErr) {
		t.Errorf("absent key: GET err=%v HEAD err=%v, want ObjectNotFound", getErr, headErr)
	}
	// A consistent object is readable from exactly a read quorum of drives.
	p.seeAll()
	p.put("v1", false, true)
	p.see(2, 3, 6, 7)
	if data, getErr, headErr := p.getAndHead(); getErr != nil || headErr != nil || !bytes.Equal(data, p.bodies["v1"]) {
		t.Errorf("consistent object: GET err=%v HEAD err=%v", getErr, headErr)
	}
}

// Upstream behavior that must stay: when every drive answered and no
// metadata reaches read quorum, the object is reported missing (#20522).
func TestAllDrivesAnsweredInconsistentStays404(t *testing.T) {
	wipe := func(p *partialView, positions ...int) {
		for _, i := range positions {
			if err := p.all[i].Delete(t.Context(), p.bucket, p.object, DeleteOptions{Recursive: true, Immediate: true}); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("restore", func(t *testing.T) {
		p := newPartialView(t, versioning.Enabled)
		oi := p.put("v1", false, true)
		p.transition(oi)
		p.see(0, 1, 5, 6, 7)
		p.restoreObject(oi)
		p.seeAll()
		wipe(p, 0, 1)
		if got, want := p.drives(oi.VersionID), "--TTTRRR"; got != want {
			t.Fatalf("drive states %s, want %s", got, want)
		}
		_, getErr, headErr := p.getAndHead()
		if !isErrObjectNotFound(getErr) || !isErrObjectNotFound(headErr) {
			t.Errorf("GET err=%v HEAD err=%v, want ObjectNotFound", getErr, headErr)
		}
	})
	t.Run("unversioned-overwrite", func(t *testing.T) {
		p := newPartialView(t, "")
		p.put("old", true, true)
		p.see(0, 1, 5, 6, 7)
		p.put("new", true, true)
		p.seeAll()
		wipe(p, 0, 1)
		_, getErr, headErr := p.getAndHead()
		if !isErrObjectNotFound(getErr) || !isErrObjectNotFound(headErr) {
			t.Errorf("GET err=%v HEAD err=%v, want ObjectNotFound", getErr, headErr)
		}
	})
}
