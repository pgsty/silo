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
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	xhttp "github.com/minio/minio/internal/http"
)

// restoreHoldTier is a remote tier held in memory that counts its reads. Its
// reads can be made to fail, and the next read to wait until it is released.
type restoreHoldTier struct {
	*tierExpiryTestBackend
	gets    atomic.Int64
	mu      sync.Mutex
	err     error         // reads fail with err
	held    chan struct{} // the next read sends here, then waits until release is closed
	release chan struct{}
}

func (b *restoreHoldTier) set(err error, held, release chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.err, b.held, b.release = err, held, release
}

func (b *restoreHoldTier) Get(ctx context.Context, object string, rv remoteVersionID, opts WarmBackendGetOpts) (io.ReadCloser, error) {
	b.mu.Lock()
	err, held, release := b.err, b.held, b.release
	b.held, b.release = nil, nil // only the next read waits
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if held != nil {
		held <- struct{}{}
		<-release
	}
	b.gets.Add(1)
	return b.tierExpiryTestBackend.Get(ctx, object, rv, opts)
}

// restoreTestTimeouts shortens the lock timeouts: a request that waits for a
// lock that a restore holds gives up after two seconds instead of minutes.
func restoreTestTimeouts(t *testing.T) {
	prev, prevDel := globalOperationTimeout, globalDeleteOperationTimeout
	globalOperationTimeout = newDynamicTimeout(2*time.Second, 2*time.Second)
	globalDeleteOperationTimeout = newDynamicTimeout(2*time.Second, 2*time.Second)
	t.Cleanup(func() { globalOperationTimeout, globalDeleteOperationTimeout = prev, prevDel })
}

// restoreTestLayer returns an object layer of pools of four drives each on a
// single server.
func restoreTestLayer(t *testing.T, pools int) *erasureServerPools {
	t.Helper()
	dirs, err := getRandomDisks(4 * pools)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeRoots(dirs) })
	var endpoints EndpointServerPools
	for i := range pools {
		endpoints = append(endpoints, mustGetPoolEndpoints(i, dirs[4*i:4*i+4]...)...)
	}
	obj, _, err := initObjectLayer(t.Context(), endpoints)
	if err != nil {
		t.Fatal(err)
	}
	return obj.(*erasureServerPools)
}

// restoreFixture writes versions to the pools of an object layer, transitions
// them to the remote tier WARM and restores them.
type restoreFixture struct {
	z         *erasureServerPools
	tier      *restoreHoldTier
	versioned map[string]bool
}

// newRestoreFixture makes a new in-memory tier the remote tier WARM. It comes
// after the object layer and the API handlers are set up, as they set up a new
// tier configuration.
func newRestoreFixture(t *testing.T, z *erasureServerPools) *restoreFixture {
	prev := globalTierConfigMgr
	t.Cleanup(func() { globalTierConfigMgr = prev })
	tier := &restoreHoldTier{tierExpiryTestBackend: &tierExpiryTestBackend{objects: map[string][]byte{}}}
	globalTierConfigMgr = NewTierConfigMgr()
	globalTierConfigMgr.drivercache["WARM"] = tier
	return &restoreFixture{z: z, tier: tier, versioned: map[string]bool{}}
}

func (f *restoreFixture) makeBucket(t *testing.T, bucket string, versioned bool) {
	t.Helper()
	if err := f.z.MakeBucket(t.Context(), bucket, MakeBucketOptions{VersioningEnabled: versioned}); err != nil {
		t.Fatal(err)
	}
	f.versioned[bucket] = versioned
}

func (f *restoreFixture) opts(bucket, versionID string) ObjectOptions {
	return ObjectOptions{VersionID: versionID, Versioned: f.versioned[bucket]}
}

// put writes an object of one part or of two with the given metadata to a
// pool.
func (f *restoreFixture) put(t *testing.T, bucket, object string, pool, parts int, meta map[string]string) (ObjectInfo, []byte) {
	t.Helper()
	ctx := t.Context()
	p := f.z.serverPools[pool]
	opts := f.opts(bucket, "")
	opts.UserDefined = cloneMSS(meta)
	body := bytes.Repeat([]byte(object+" "), (1<<20)/(len(object)+1)+1)
	var oi ObjectInfo
	var err error
	if parts == 1 {
		oi, err = p.PutObject(ctx, bucket, object, mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), opts)
	} else {
		body = append(bytes.Repeat([]byte{'p'}, globalMinPartSize), body...)
		res, err := p.NewMultipartUpload(ctx, bucket, object, opts)
		if err != nil {
			t.Fatal(err)
		}
		var cparts []CompletePart
		for i, data := range [][]byte{body[:globalMinPartSize], body[globalMinPartSize:]} {
			pi, err := p.PutObjectPart(ctx, bucket, object, res.UploadID, i+1, mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			cparts = append(cparts, CompletePart{PartNumber: pi.PartNumber, ETag: pi.ETag})
		}
		oi, err = p.CompleteMultipartUpload(ctx, bucket, object, res.UploadID, cparts, f.opts(bucket, ""))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(oi.Parts) != parts {
		t.Fatalf("fixture: %d parts, want %d", len(oi.Parts), parts)
	}
	if idx, err := f.z.getPoolIdxExistingNoLock(ctx, bucket, object); err != nil || idx != pool {
		t.Fatalf("fixture: object in pool %d, %v; want pool %d", idx, err, pool)
	}
	return oi, body
}

// transition transitions a version to the tier WARM. With ongoing it marks the
// restore of the version ongoing, as POST ?restore does before it restores the
// version in the background. It returns the version as HEAD does.
func (f *restoreFixture) transition(t *testing.T, bucket string, oi ObjectInfo, ongoing bool) ObjectInfo {
	t.Helper()
	ctx := t.Context()
	topts := f.opts(bucket, oi.VersionID)
	topts.MTime = oi.ModTime
	topts.Transition = TransitionOptions{Tier: "WARM", ETag: oi.ETag}
	if err := f.z.TransitionObject(ctx, bucket, oi.Name, topts); err != nil {
		t.Fatal(err)
	}
	if ongoing {
		mopts := f.opts(bucket, oi.VersionID)
		mopts.EvalMetadataFn = func(o *ObjectInfo, _ error) (ReplicateDecision, error) {
			o.UserDefined[xhttp.AmzRestoreExpiryDays] = "1"
			o.UserDefined[xhttp.AmzRestoreRequestDate] = time.Now().UTC().Format(http.TimeFormat)
			o.UserDefined[xhttp.AmzRestore] = ongoingRestoreObj().String()
			return ReplicateDecision{}, nil
		}
		if _, err := f.z.PutObjectMetadata(ctx, bucket, oi.Name, mopts); err != nil {
			t.Fatal(err)
		}
	}
	hi := f.head(t, bucket, oi.Name, oi.VersionID)
	if hi.TransitionedObject.Status != lifecycle.TransitionComplete || hi.RestoreOngoing != ongoing {
		t.Fatalf("fixture: transition status %q, x-amz-restore %q", hi.TransitionedObject.Status, hi.UserDefined[xhttp.AmzRestore])
	}
	return hi
}

func (f *restoreFixture) head(t *testing.T, bucket, object, versionID string) ObjectInfo {
	t.Helper()
	oi, err := f.z.GetObjectInfo(t.Context(), bucket, object, f.opts(bucket, versionID))
	if err != nil {
		t.Fatalf("HEAD %s/%s (%s): %v", bucket, object, versionID, err)
	}
	return oi
}

func (f *restoreFixture) get(ctx context.Context, bucket, object, versionID string) ([]byte, error) {
	gr, err := f.z.GetObjectNInfo(ctx, bucket, object, nil, nil, f.opts(bucket, versionID))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(gr)
}

// restore restores a version through the pools layer with the options that
// POST ?restore passes.
func (f *restoreFixture) restore(ctx context.Context, bucket string, oi ObjectInfo) error {
	return f.z.RestoreTransitionedObject(ctx, bucket, oi.Name, ObjectOptions{
		VersionID: oi.VersionID,
		Transition: TransitionOptions{
			RestoreRequest: &RestoreObjectRequest{Days: 1},
			RestoreExpiry:  lifecycle.ExpectedExpiryTime(time.Now().UTC(), 1),
		},
	})
}

// onDrive returns a version as the drives of its pool hold it, read without
// the object lock that a restore may hold.
func (f *restoreFixture) onDrive(t *testing.T, bucket string, pool int, oi ObjectInfo) ObjectInfo {
	t.Helper()
	disks := f.z.serverPools[pool].getHashedSet(oi.Name).getDisks()
	fis, errs := readAllFileInfo(t.Context(), disks, "", bucket, oi.Name, oi.VersionID, false, false)
	for i := range fis {
		if errs[i] == nil {
			return fis[i].ToObjectInfo(bucket, oi.Name, f.versioned[bucket])
		}
	}
	t.Fatalf("%s/%s not on the drives: %v", bucket, oi.Name, errs)
	return ObjectInfo{}
}

// post sends POST ?restore for a version through the API handlers and returns
// the status and the error code.
func restoreTestPost(router http.Handler, bucket string, oi ObjectInfo, days int) (int, string, error) {
	body := fmt.Sprintf(`<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>%d</Days></RestoreRequest>`, days)
	q := url.Values{"restore": {""}}
	if oi.VersionID != "" {
		q.Set("versionId", oi.VersionID)
	}
	cred := globalActiveCred
	req, err := newTestSignedRequestV4(http.MethodPost, makeTestTargetURL("http://127.0.0.1:9000", bucket, oi.Name, q), int64(len(body)), strings.NewReader(body), cred.AccessKey, cred.SecretKey, nil)
	if err != nil {
		return 0, "", err
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var apiErr APIErrorResponse
	if rec.Code >= 300 {
		_ = xml.Unmarshal(rec.Body.Bytes(), &apiErr)
	}
	return rec.Code, apiErr.Code, nil
}

// A restore through the pools layer, as POST ?restore runs it, restores a
// version in any pool. With more than one pool the pools layer holds the
// object lock for the whole restore, and the write of the restored copy, of
// one part or of several, and the reset of the restore status of a restore
// that failed took the lock once more and waited for it until the lock timed
// out: on a single server for every object of the first pool, whose lock map
// the pools layer locks in. The restore failed and its status stayed ongoing.
func TestRestoreTransitionedObjectPools(t *testing.T) {
	restoreTestTimeouts(t)
	for _, pools := range []int{1, 2} {
		t.Run(fmt.Sprintf("pools=%d", pools), func(t *testing.T) {
			ctx := t.Context()
			z := restoreTestLayer(t, pools)
			f := newRestoreFixture(t, z)
			const bucket = "restore-pools"
			f.makeBucket(t, bucket, false)

			for pool := range pools {
				for _, parts := range []int{1, 2} {
					t.Run(fmt.Sprintf("pool=%d/parts=%d", pool, parts), func(t *testing.T) {
						oi, body := f.put(t, bucket, fmt.Sprintf("pool%d-parts%d", pool, parts), pool, parts, nil)
						oi = f.transition(t, bucket, oi, true)
						start := time.Now()
						if err := f.restore(ctx, bucket, oi); err != nil {
							t.Fatalf("restore failed after %v: %v", time.Since(start).Round(time.Millisecond), err)
						}
						hi := f.head(t, bucket, oi.Name, oi.VersionID)
						if hi.RestoreOngoing || hi.RestoreExpires.IsZero() || !strings.HasPrefix(hi.UserDefined[xhttp.AmzRestore], `ongoing-request="false"`) {
							t.Errorf("HEAD after the restore: x-amz-restore %q", hi.UserDefined[xhttp.AmzRestore])
						}
						gets := f.tier.gets.Load()
						if data, err := f.get(ctx, bucket, oi.Name, oi.VersionID); err != nil || !bytes.Equal(data, body) {
							t.Errorf("GET reads %d bytes that differ, %v", len(data), err)
						}
						if f.tier.gets.Load() != gets {
							t.Errorf("GET reads the tier, not the restored copy")
						}
					})
				}

				t.Run(fmt.Sprintf("pool=%d/failed", pool), func(t *testing.T) {
					oi, body := f.put(t, bucket, fmt.Sprintf("pool%d-failed", pool), pool, 1, nil)
					oi = f.transition(t, bucket, oi, true)
					f.tier.set(errors.New("tier offline"), nil, nil)
					err := f.restore(ctx, bucket, oi)
					f.tier.set(nil, nil, nil)
					if err == nil {
						t.Fatal("restore of an object whose tier fails succeeded")
					}
					// The restore status is reset, so that the restore can be
					// requested again.
					if hi := f.head(t, bucket, oi.Name, oi.VersionID); hi.RestoreOngoing || hi.UserDefined[xhttp.AmzRestore] != "" {
						t.Errorf("HEAD after the failed restore: x-amz-restore %q", hi.UserDefined[xhttp.AmzRestore])
					}
					if data, err := f.get(ctx, bucket, oi.Name, oi.VersionID); err != nil || !bytes.Equal(data, body) {
						t.Errorf("GET reads %d bytes that differ, %v", len(data), err)
					}
				})

				t.Run(fmt.Sprintf("pool=%d/locked", pool), func(t *testing.T) {
					// The restore waits for the object lock.
					oi, _ := f.put(t, bucket, fmt.Sprintf("pool%d-locked", pool), pool, 1, nil)
					oi = f.transition(t, bucket, oi, true)
					lk := z.NewNSLock(bucket, oi.Name)
					lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
					if err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					go func() { done <- f.restore(ctx, bucket, oi) }()
					select {
					case err := <-done:
						lk.Unlock(lkctx)
						t.Fatalf("restore did not wait for the lock of the object: %v", err)
					case <-time.After(500 * time.Millisecond):
					}
					lk.Unlock(lkctx)
					if err := <-done; err != nil {
						t.Fatalf("restore after the lock was released: %v", err)
					}

					// With more than one pool the pools layer holds the object
					// lock for the whole restore, as for an upload. A single
					// pool takes it only to commit the restored copy.
					oi, _ = f.put(t, bucket, fmt.Sprintf("pool%d-holds", pool), pool, 1, nil)
					oi = f.transition(t, bucket, oi, true)
					held, release := make(chan struct{}), make(chan struct{})
					f.tier.set(nil, held, release)
					go func() { done <- f.restore(ctx, bucket, oi) }()
					select {
					case <-held:
					case err := <-done:
						f.tier.set(nil, nil, nil)
						t.Fatalf("restore did not read the tier: %v", err)
					}
					lk = z.NewNSLock(bucket, oi.Name)
					lkctx, err = lk.GetLock(ctx, newDynamicTimeout(300*time.Millisecond, 300*time.Millisecond))
					if err == nil {
						lk.Unlock(lkctx)
					}
					switch {
					case pools > 1 && err == nil:
						t.Errorf("the object is not locked while it is restored")
					case pools == 1 && err != nil:
						t.Errorf("the object is locked while the tier is read: %v", err)
					}
					close(release)
					if err := <-done; err != nil {
						t.Fatalf("restore: %v", err)
					}
					if hi := f.head(t, bucket, oi.Name, oi.VersionID); hi.RestoreOngoing || hi.RestoreExpires.IsZero() {
						t.Errorf("HEAD after the restore: x-amz-restore %q", hi.UserDefined[xhttp.AmzRestore])
					}
				})
			}
		})
	}
}

// restoreTestMeta is metadata of an object that a restore must keep: content
// headers, a user key, tags and Expires.
func restoreTestMeta(label string) map[string]string {
	return map[string]string{
		"content-type":                 "text/" + label,
		xhttp.CacheControl:             "max-age=60",
		"X-Amz-Meta-Label":             label,
		xhttp.AmzObjectTagging:         "label=" + label,
		strings.ToLower(xhttp.Expires): time.Now().Add(time.Hour).UTC().Format(http.TimeFormat),
	}
}

// A restore that fails removes the ongoing restore status from the version it
// was for, and changes nothing else. It used to write back the metadata that
// the restore had read, as an ObjectInfo carries it, without the tags and
// Expires, or none at all when the restore could not read the version: a
// restore of a version deleted after POST ?restore wrote a new null version
// with empty metadata over the latest version, one of an object uploaded again
// since removed the tags and Expires of the new object, and every reset moved
// the modification time of the version to now.
func TestRestoreTransitionedObjectFailed(t *testing.T) {
	restoreTestTimeouts(t)

	// snapshot is what a failed restore must not change in a version.
	snapshot := func(oi ObjectInfo) string {
		meta := cloneMSS(oi.UserDefined)
		for _, k := range []string{xhttp.AmzRestore, xhttp.AmzRestoreExpiryDays, xhttp.AmzRestoreRequestDate} {
			delete(meta, k)
		}
		return fmt.Sprintf("version %q mtime %v etag %q content-type %q expires %v tags %q meta %v",
			oi.VersionID, oi.ModTime.UTC(), oi.ETag, oi.ContentType, oi.Expires.UTC(), oi.UserTags, meta)
	}

	for _, pools := range []int{1, 2} {
		t.Run(fmt.Sprintf("pools=%d", pools), func(t *testing.T) {
			ctx := t.Context()
			z := restoreTestLayer(t, pools)
			f := newRestoreFixture(t, z)
			const versioned, unversioned = "restore-failed-versioned", "restore-failed-unversioned"
			f.makeBucket(t, versioned, true)
			f.makeBucket(t, unversioned, false)

			versions := func(t *testing.T, bucket, object string) []string {
				t.Helper()
				res, err := z.ListObjectVersions(ctx, bucket, object, "", "", "", 100)
				if err != nil {
					t.Fatal(err)
				}
				var ids []string
				for _, o := range res.Objects {
					ids = append(ids, o.VersionID)
				}
				return ids
			}

			for pool := range pools {
				// The tier fails: the restore status is removed, nothing else.
				t.Run(fmt.Sprintf("pool=%d/tier-failed", pool), func(t *testing.T) {
					for _, bucket := range []string{versioned, unversioned} {
						object := fmt.Sprintf("pool%d-tier-failed", pool)
						oi, _ := f.put(t, bucket, object, pool, 1, restoreTestMeta("v1"))
						oi = f.transition(t, bucket, oi, true)
						f.tier.set(errors.New("tier offline"), nil, nil)
						err := f.restore(ctx, bucket, oi)
						f.tier.set(nil, nil, nil)
						if err == nil {
							t.Fatalf("%s: restore with the tier offline succeeded", bucket)
						}
						after := f.head(t, bucket, object, oi.VersionID)
						if after.RestoreOngoing || after.UserDefined[xhttp.AmzRestore] != "" {
							t.Errorf("%s: x-amz-restore %q after the failed restore", bucket, after.UserDefined[xhttp.AmzRestore])
						}
						if want, got := snapshot(oi), snapshot(after); got != want {
							t.Errorf("%s: the failed restore changed the version:\n got %s\nwant %s", bucket, got, want)
						}
					}
				})

				// The reset waits for the object lock.
				t.Run(fmt.Sprintf("pool=%d/locked", pool), func(t *testing.T) {
					object := fmt.Sprintf("pool%d-locked", pool)
					oi, _ := f.put(t, versioned, object, pool, 1, nil)
					oi = f.transition(t, versioned, oi, true)
					lk := z.NewNSLock(versioned, object)
					lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
					if err != nil {
						t.Fatal(err)
					}
					f.tier.set(errors.New("tier offline"), nil, nil)
					defer f.tier.set(nil, nil, nil)
					done := make(chan error, 1)
					go func() { done <- f.restore(ctx, versioned, oi) }()
					select {
					case <-done:
						lk.Unlock(lkctx)
						t.Fatal("the failed restore did not wait for the lock of the object")
					case <-time.After(500 * time.Millisecond):
					}
					lk.Unlock(lkctx)
					if err := <-done; err == nil {
						t.Fatal("restore with the tier offline succeeded")
					}
					if after := f.head(t, versioned, object, oi.VersionID); after.RestoreOngoing {
						t.Errorf("x-amz-restore %q after the failed restore", after.UserDefined[xhttp.AmzRestore])
					}
				})

				// The version is deleted after POST ?restore: the latest version
				// is not touched.
				t.Run(fmt.Sprintf("pool=%d/version-deleted", pool), func(t *testing.T) {
					object := fmt.Sprintf("pool%d-version-deleted", pool)
					v1, _ := f.put(t, versioned, object, pool, 1, restoreTestMeta("v1"))
					v1 = f.transition(t, versioned, v1, true)
					v2, body := f.put(t, versioned, object, pool, 1, restoreTestMeta("v2"))
					v2 = f.head(t, versioned, object, v2.VersionID)
					if _, err := z.DeleteObject(ctx, versioned, object, f.opts(versioned, v1.VersionID)); err != nil {
						t.Fatal(err)
					}
					if err := f.restore(ctx, versioned, v1); err == nil {
						t.Fatal("restore of a deleted version succeeded")
					}
					if ids := versions(t, versioned, object); fmt.Sprint(ids) != fmt.Sprint([]string{v2.VersionID}) {
						t.Errorf("versions %q, want only %q", ids, v2.VersionID)
					}
					if want, got := snapshot(v2), snapshot(f.head(t, versioned, object, "")); got != want {
						t.Errorf("the failed restore changed the latest version:\n got %s\nwant %s", got, want)
					}
					if data, err := f.get(ctx, versioned, object, ""); err != nil || !bytes.Equal(data, body) {
						t.Errorf("GET reads %d bytes, %v; want the data of v2", len(data), err)
					}
				})

				// The object is uploaded again after POST ?restore: the new
				// object is not touched.
				t.Run(fmt.Sprintf("pool=%d/object-replaced", pool), func(t *testing.T) {
					object := fmt.Sprintf("pool%d-object-replaced", pool)
					old, _ := f.put(t, unversioned, object, pool, 1, restoreTestMeta("old"))
					old = f.transition(t, unversioned, old, true)
					f.put(t, unversioned, object, pool, 1, restoreTestMeta("new"))
					cur := f.head(t, unversioned, object, "")
					if err := f.restore(ctx, unversioned, old); err == nil {
						t.Fatal("restore of a replaced object succeeded")
					}
					if want, got := snapshot(cur), snapshot(f.head(t, unversioned, object, "")); got != want {
						t.Errorf("the failed restore changed the new object:\n got %s\nwant %s", got, want)
					}
				})
			}
		})
	}
}

// POST ?restore refuses a restore of a version as one in progress only while
// a restore of the version runs. A restore that does not run any more left
// its restore status ongoing, as one that failed to reset it did, or one whose
// server went down: such a version used to be refused for good.
func TestPostRestoreObjectInProgress(t *testing.T) {
	restoreTestTimeouts(t)
	for _, pools := range []int{1, 2} {
		t.Run(fmt.Sprintf("pools=%d", pools), func(t *testing.T) {
			ctx := t.Context()
			z := restoreTestLayer(t, pools)
			bucket, router, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{VersioningEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := newTestConfig(globalMinioDefaultRegion, z); err != nil {
				t.Fatal(err)
			}
			f := newRestoreFixture(t, z)
			f.versioned[bucket] = true

			post := func(t *testing.T, oi ObjectInfo, days int) (int, string) {
				t.Helper()
				code, apiCode, err := restoreTestPost(router, bucket, oi, days)
				if err != nil {
					t.Fatal(err)
				}
				return code, apiCode
			}
			// restored waits until the background restore of a version
			// completed.
			restored := func(t *testing.T, oi ObjectInfo) {
				t.Helper()
				for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
					hi := f.head(t, bucket, oi.Name, oi.VersionID)
					if !hi.RestoreOngoing && !hi.RestoreExpires.IsZero() {
						return
					}
					if time.Now().After(deadline) {
						t.Fatalf("the restore did not complete: x-amz-restore %q", hi.UserDefined[xhttp.AmzRestore])
					}
				}
			}

			for pool := range pools {
				// The restore status of the version is ongoing, but no restore
				// of it runs.
				t.Run(fmt.Sprintf("pool=%d/left-ongoing", pool), func(t *testing.T) {
					oi, _ := f.put(t, bucket, fmt.Sprintf("pool%d-left-ongoing", pool), pool, 1, nil)
					oi = f.transition(t, bucket, oi, true)
					gets := f.tier.gets.Load()
					if code, apiCode := post(t, oi, 1); code != http.StatusOK {
						t.Fatalf("POST ?restore of a version whose restore does not run: %d %s", code, apiCode)
					}
					restored(t, oi)
					if n := f.tier.gets.Load() - gets; n != 1 {
						t.Errorf("the restore read the tier %d times, want 1", n)
					}
				})

				// A second request while the restore runs does not restore
				// again. With one pool it is refused; with more than one it
				// waits for the object lock that the restore holds, and then
				// extends the restore that is done.
				t.Run(fmt.Sprintf("pool=%d/running", pool), func(t *testing.T) {
					oi, _ := f.put(t, bucket, fmt.Sprintf("pool%d-running", pool), pool, 1, nil)
					oi = f.transition(t, bucket, oi, false)
					held, release := make(chan struct{}), make(chan struct{})
					f.tier.set(nil, held, release)
					gets := f.tier.gets.Load()
					if code, apiCode := post(t, oi, 1); code != http.StatusOK {
						f.tier.set(nil, nil, nil)
						t.Fatalf("POST ?restore: %d %s", code, apiCode)
					}
					select {
					case <-held:
					case <-time.After(10 * time.Second):
						f.tier.set(nil, nil, nil)
						t.Fatal("the restore did not read the tier")
					}
					type result struct {
						code    int
						apiCode string
						err     error
					}
					second := make(chan result, 1)
					go func() {
						code, apiCode, err := restoreTestPost(router, bucket, oi, 1)
						second <- result{code, apiCode, err}
					}()
					var r result
					if pools == 1 {
						r = <-second
						close(release)
						if r.code != http.StatusConflict || r.apiCode != "RestoreAlreadyInProgress" {
							t.Errorf("POST ?restore while the restore runs: %d %s %v, want 409 RestoreAlreadyInProgress", r.code, r.apiCode, r.err)
						}
					} else {
						time.Sleep(300 * time.Millisecond)
						close(release)
						r = <-second
						if r.code != http.StatusOK {
							t.Errorf("POST ?restore while the restore runs: %d %s %v, want 200 once the restore is done", r.code, r.apiCode, r.err)
						}
					}
					restored(t, oi)
					if n := f.tier.gets.Load() - gets; n != 1 {
						t.Errorf("the tier was read %d times, want 1", n)
					}
					// The restore is done: a new request extends it.
					if code, apiCode := post(t, oi, 2); code != http.StatusOK {
						t.Errorf("POST ?restore after the restore: %d %s", code, apiCode)
					}
					if hi := f.head(t, bucket, oi.Name, oi.VersionID); !strings.Contains(hi.UserDefined[xhttp.AmzRestore], lifecycle.ExpectedExpiryTime(time.Now().UTC(), 2).Format(http.TimeFormat)) {
						t.Errorf("x-amz-restore %q after a restore for 2 days", hi.UserDefined[xhttp.AmzRestore])
					}
				})
			}
		})
	}
}

// A restore changes only the restore status of the version: its metadata,
// tags, Expires, replication status and modification time stay as they are,
// when POST ?restore marks the restore ongoing, in the restored copy, after a
// failed restore and when a new request extends a completed restore. POST
// ?restore wrote the metadata of the version as an ObjectInfo carries it,
// without the tags and Expires, and the restored copy was made from that.
func TestPostRestoreObjectKeepsMetadata(t *testing.T) {
	restoreTestTimeouts(t)

	restoreKeys := []string{xhttp.AmzRestore, xhttp.AmzRestoreExpiryDays, xhttp.AmzRestoreRequestDate, strings.ToLower(xhttp.AmzStorageClass)}
	// snapshot is what a restore must not change in a version.
	snapshot := func(oi ObjectInfo) string {
		meta := cloneMSS(oi.UserDefined)
		for _, k := range restoreKeys {
			delete(meta, k)
		}
		return fmt.Sprintf("version %q mtime %v etag %q class %q content-type %q expires %v tags %q replication %q/%q meta %v",
			oi.VersionID, oi.ModTime.UTC(), oi.ETag, oi.StorageClass, oi.ContentType, oi.Expires.UTC(), oi.UserTags,
			oi.ReplicationStatus, oi.ReplicationStatusInternal, meta)
	}

	for _, pools := range []int{1, 2} {
		t.Run(fmt.Sprintf("pools=%d", pools), func(t *testing.T) {
			ctx := t.Context()
			z := restoreTestLayer(t, pools)
			versioned, router, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{VersioningEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := newTestConfig(globalMinioDefaultRegion, z); err != nil {
				t.Fatal(err)
			}
			f := newRestoreFixture(t, z)
			f.versioned[versioned] = true
			unversioned := "unversioned-" + versioned[:20]
			f.makeBucket(t, unversioned, false)

			// transitioned writes an object of one part or two with metadata,
			// tags, Expires and a replication status to a pool, and
			// transitions it.
			transitioned := func(t *testing.T, bucket, object string, pool, parts int) (ObjectInfo, []byte) {
				t.Helper()
				meta := restoreTestMeta("plain")
				meta[xhttp.AmzBucketReplicationStatus] = "COMPLETED"
				meta[ReservedMetadataPrefixLower+ReplicationStatus] = "arn:minio:replication::id:bucket=COMPLETED;"
				meta[ReservedMetadataPrefixLower+ReplicationTimestamp] = time.Now().UTC().Format(time.RFC3339Nano)
				oi, body := f.put(t, bucket, object, pool, parts, meta)
				f.transition(t, bucket, oi, false)
				oi = f.onDrive(t, bucket, pool, oi)
				if oi.UserTags != "label=plain" || oi.Expires.IsZero() || oi.ReplicationStatusInternal == "" {
					t.Fatalf("fixture: %s", snapshot(oi))
				}
				return oi, body
			}
			post := func(t *testing.T, bucket string, oi ObjectInfo, days int) {
				t.Helper()
				code, apiCode, err := restoreTestPost(router, bucket, oi, days)
				if err != nil || code != http.StatusOK {
					t.Fatalf("POST ?restore: %d %s %v", code, apiCode, err)
				}
			}
			// settled waits until the background restore of a version is not
			// ongoing any more.
			settled := func(t *testing.T, bucket string, pool int, oi ObjectInfo) ObjectInfo {
				t.Helper()
				for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
					if di := f.onDrive(t, bucket, pool, oi); !di.RestoreOngoing {
						return di
					}
					if time.Now().After(deadline) {
						t.Fatal("the restore did not end")
					}
				}
			}
			check := func(t *testing.T, step string, want, got ObjectInfo) {
				t.Helper()
				if w, g := snapshot(want), snapshot(got); g != w {
					t.Errorf("%s changed the version:\n got %s\nwant %s", step, g, w)
				}
			}

			for _, bucket := range []string{versioned, unversioned} {
				for pool := range pools {
					for _, parts := range []int{1, 2} {
						t.Run(fmt.Sprintf("versioned=%v/pool=%d/parts=%d", bucket == versioned, pool, parts), func(t *testing.T) {
							oi, body := transitioned(t, bucket, fmt.Sprintf("pool%d-parts%d", pool, parts), pool, parts)

							// POST ?restore marks the restore ongoing.
							held, release := make(chan struct{}), make(chan struct{})
							f.tier.set(nil, held, release)
							post(t, bucket, oi, 1)
							select {
							case <-held:
							case <-time.After(10 * time.Second):
								f.tier.set(nil, nil, nil)
								t.Fatal("the restore did not read the tier")
							}
							if di := f.onDrive(t, bucket, pool, oi); !di.RestoreOngoing {
								t.Errorf("x-amz-restore %q after POST", di.UserDefined[xhttp.AmzRestore])
							} else {
								check(t, "POST ?restore", oi, di)
							}
							close(release)

							// The restored copy.
							di := settled(t, bucket, pool, oi)
							if di.RestoreExpires.IsZero() {
								t.Fatalf("the restore failed: x-amz-restore %q", di.UserDefined[xhttp.AmzRestore])
							}
							check(t, "the restore", oi, di)
							gets := f.tier.gets.Load()
							data, err := f.get(ctx, bucket, oi.Name, oi.VersionID)
							if err != nil || !bytes.Equal(data, body) || f.tier.gets.Load() != gets {
								t.Errorf("GET of the restored copy: %d bytes, %v, equal %v, from the tier %v", len(data), err, bytes.Equal(data, body), f.tier.gets.Load() != gets)
							}

							// A new request extends the restore.
							post(t, bucket, oi, 2)
							di = f.onDrive(t, bucket, pool, oi)
							if !strings.Contains(di.UserDefined[xhttp.AmzRestore], lifecycle.ExpectedExpiryTime(time.Now().UTC(), 2).Format(http.TimeFormat)) {
								t.Errorf("x-amz-restore %q after a restore for 2 days", di.UserDefined[xhttp.AmzRestore])
							}
							check(t, "extending the restore", oi, di)
						})
					}

					t.Run(fmt.Sprintf("versioned=%v/pool=%d/failed", bucket == versioned, pool), func(t *testing.T) {
						oi, _ := transitioned(t, bucket, fmt.Sprintf("pool%d-failed", pool), pool, 1)
						f.tier.set(errors.New("tier offline"), nil, nil)
						defer f.tier.set(nil, nil, nil)
						post(t, bucket, oi, 1)
						di := settled(t, bucket, pool, oi)
						if di.UserDefined[xhttp.AmzRestore] != "" {
							t.Errorf("x-amz-restore %q after the failed restore", di.UserDefined[xhttp.AmzRestore])
						}
						check(t, "the failed restore", oi, di)
					})
				}
			}
		})
	}
}

// The restored copy is written only over the version as the restore read it.
// With one pool no lock is held while a restore reads the tier, so the version
// can be uploaded over, deleted or changed meanwhile: the restored copy used
// to be written over whatever the version had become, so an object uploaded
// again got its old data back, a deleted object or version came back and tags
// set meanwhile were lost. With more than one pool the pools layer holds the
// object lock for the whole restore and these requests wait for it. A restore
// of a multipart version in a versioned bucket used to fail: the commit of the
// restored copy was refused as a write over an existing version. A failed
// restore of a multipart version left its upload behind.
func TestRestoreTransitionedObjectChanged(t *testing.T) {
	restoreTestTimeouts(t)
	for _, pools := range []int{1, 2} {
		t.Run(fmt.Sprintf("pools=%d", pools), func(t *testing.T) {
			ctx := t.Context()
			z := restoreTestLayer(t, pools)
			f := newRestoreFixture(t, z)
			const versioned, unversioned = "restore-changed-versioned", "restore-changed-unversioned"
			f.makeBucket(t, versioned, true)
			f.makeBucket(t, unversioned, false)

			// during runs op while the restore of a version reads the tier
			// and returns the result of the restore once both are done.
			during := func(t *testing.T, bucket string, oi ObjectInfo, what string, op func() error) error {
				t.Helper()
				held, release := make(chan struct{}), make(chan struct{})
				f.tier.set(nil, held, release)
				done := make(chan error, 1)
				go func() { done <- f.restore(ctx, bucket, oi) }()
				select {
				case <-held:
				case err := <-done:
					f.tier.set(nil, nil, nil)
					t.Fatalf("restore did not read the tier: %v", err)
				}
				opDone := make(chan error, 1)
				go func() { opDone <- op() }()
				if pools == 1 {
					if err := <-opDone; err != nil {
						t.Errorf("%s while the restore reads the tier: %v", what, err)
					}
					close(release)
					return <-done
				}
				var opErr error
				waited := true
				select {
				case opErr = <-opDone:
					waited = false
					t.Errorf("%s did not wait for the restore", what)
				case <-time.After(300 * time.Millisecond):
				}
				close(release)
				rerr := <-done
				if waited {
					opErr = <-opDone
				}
				if opErr != nil {
					t.Errorf("%s: %v", what, opErr)
				}
				return rerr
			}
			uploads := func(t *testing.T, bucket, object string) int {
				t.Helper()
				res, err := z.ListMultipartUploads(ctx, bucket, object, "", "", "", 100)
				if err != nil {
					t.Fatal(err)
				}
				return len(res.Uploads)
			}

			for _, bucket := range []string{versioned, unversioned} {
				for pool := range pools {
					name := fmt.Sprintf("versioned=%v/pool=%d", f.versioned[bucket], pool)

					t.Run(name+"/parts=2", func(t *testing.T) {
						oi, body := f.put(t, bucket, fmt.Sprintf("pool%d-parts2", pool), pool, 2, nil)
						oi = f.transition(t, bucket, oi, true)
						if err := f.restore(ctx, bucket, oi); err != nil {
							t.Fatalf("restore: %v", err)
						}
						if hi := f.head(t, bucket, oi.Name, oi.VersionID); hi.RestoreOngoing || hi.RestoreExpires.IsZero() {
							t.Errorf("HEAD after the restore: x-amz-restore %q", hi.UserDefined[xhttp.AmzRestore])
						}
						if data, err := f.get(ctx, bucket, oi.Name, oi.VersionID); err != nil || !bytes.Equal(data, body) {
							t.Errorf("GET reads %d bytes that differ, %v", len(data), err)
						}
					})

					for _, parts := range []int{1, 2} {
						t.Run(fmt.Sprintf("%s/parts=%d/overwritten", name, parts), func(t *testing.T) {
							oi, _ := f.put(t, bucket, fmt.Sprintf("pool%d-parts%d-overwritten", pool, parts), pool, parts, nil)
							oi = f.transition(t, bucket, oi, true)
							body := []byte("uploaded while the restore reads the tier")
							var nobj ObjectInfo
							err := during(t, bucket, oi, "PUT", func() (err error) {
								nobj, err = z.PutObject(ctx, bucket, oi.Name, mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), f.opts(bucket, ""))
								return err
							})
							switch {
							case pools == 1 && bucket == unversioned && err == nil:
								t.Errorf("restore of an object uploaded again succeeded")
							case (pools > 1 || bucket == versioned) && err != nil:
								t.Errorf("restore: %v", err)
							}
							if data, err := f.get(ctx, bucket, oi.Name, ""); err != nil || !bytes.Equal(data, body) {
								t.Errorf("GET of the object uploaded again: %q, %v", data, err)
							}
							hi := f.head(t, bucket, oi.Name, "")
							if hi.VersionID != nobj.VersionID || !hi.ModTime.Equal(nobj.ModTime) || hi.TransitionedObject.Status != "" || hi.UserDefined[xhttp.AmzRestore] != "" {
								t.Errorf("HEAD of the object uploaded again: version %q mtime %v transition %q x-amz-restore %q", hi.VersionID, hi.ModTime, hi.TransitionedObject.Status, hi.UserDefined[xhttp.AmzRestore])
							}
							if bucket == versioned {
								// With more than one pool the upload may go to
								// another pool, which HEAD of the version does
								// not see.
								if hi := f.head(t, bucket, oi.Name, oi.VersionID); hi.RestoreExpires.IsZero() || (pools == 1 && hi.IsLatest) {
									t.Errorf("HEAD of the restored noncurrent version: x-amz-restore %q, latest %v", hi.UserDefined[xhttp.AmzRestore], hi.IsLatest)
								}
							}
							if n := uploads(t, bucket, oi.Name); n != 0 {
								t.Errorf("%d multipart uploads left", n)
							}
						})
					}

					t.Run(name+"/deleted", func(t *testing.T) {
						oi, _ := f.put(t, bucket, fmt.Sprintf("pool%d-deleted", pool), pool, 1, nil)
						oi = f.transition(t, bucket, oi, true)
						var dm ObjectInfo
						err := during(t, bucket, oi, "DELETE", func() (err error) {
							dm, err = z.DeleteObject(ctx, bucket, oi.Name, f.opts(bucket, ""))
							return err
						})
						if bucket == unversioned {
							if pools == 1 && err == nil {
								t.Errorf("restore of a deleted object succeeded")
							}
							if _, err := z.GetObjectInfo(ctx, bucket, oi.Name, ObjectOptions{}); !isErrObjectNotFound(err) {
								t.Errorf("HEAD of the deleted object: %v", err)
							}
							return
						}
						if err != nil {
							t.Errorf("restore of a noncurrent version: %v", err)
						}
						if hi, err := z.GetObjectInfo(ctx, bucket, oi.Name, f.opts(bucket, "")); !hi.DeleteMarker || hi.VersionID != dm.VersionID {
							t.Errorf("HEAD of the deleted object: %v, delete marker %v version %q, want %q", err, hi.DeleteMarker, hi.VersionID, dm.VersionID)
						}
					})

					if bucket == versioned {
						t.Run(name+"/version-deleted", func(t *testing.T) {
							oi, _ := f.put(t, bucket, fmt.Sprintf("pool%d-version-deleted", pool), pool, 1, nil)
							oi = f.transition(t, bucket, oi, true)
							err := during(t, bucket, oi, "DELETE of the version", func() error {
								_, err := z.DeleteObject(ctx, bucket, oi.Name, f.opts(bucket, oi.VersionID))
								return err
							})
							if pools == 1 && err == nil {
								t.Errorf("restore of a deleted version succeeded")
							}
							if _, err := z.GetObjectInfo(ctx, bucket, oi.Name, f.opts(bucket, oi.VersionID)); !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
								t.Errorf("HEAD of the deleted version: %v", err)
							}
						})
					}

					t.Run(name+"/tagged", func(t *testing.T) {
						oi, _ := f.put(t, bucket, fmt.Sprintf("pool%d-tagged", pool), pool, 1, map[string]string{xhttp.AmzObjectTagging: "k=old"})
						oi = f.transition(t, bucket, oi, true)
						err := during(t, bucket, oi, "PUT ?tagging", func() error {
							_, err := z.PutObjectTags(ctx, bucket, oi.Name, "k=new", f.opts(bucket, oi.VersionID))
							return err
						})
						if pools == 1 && err == nil {
							t.Errorf("restore of a version tagged meanwhile succeeded")
						}
						hi := f.head(t, bucket, oi.Name, oi.VersionID)
						if hi.UserTags != "k=new" {
							t.Errorf("tags %q after the restore, want k=new", hi.UserTags)
						}
						if hi.RestoreOngoing {
							t.Errorf("x-amz-restore %q after the restore", hi.UserDefined[xhttp.AmzRestore])
						}
					})

					t.Run(name+"/parts=2/failed", func(t *testing.T) {
						oi, _ := f.put(t, bucket, fmt.Sprintf("pool%d-failed", pool), pool, 2, nil)
						oi = f.transition(t, bucket, oi, true)
						f.tier.set(errors.New("tier offline"), nil, nil)
						err := f.restore(ctx, bucket, oi)
						f.tier.set(nil, nil, nil)
						if err == nil {
							t.Fatal("restore with the tier offline succeeded")
						}
						if n := uploads(t, bucket, oi.Name); n != 0 {
							t.Errorf("%d multipart uploads left", n)
						}
					})
				}
			}
		})
	}
}
