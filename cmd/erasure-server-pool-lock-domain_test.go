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
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/amztime"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/crypto"
	"github.com/minio/minio/internal/dsync"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
)

// A single pool whose two erasure sets share the test drives, but lock as the
// sets of a distributed pool do whose sets use different hosts. With one
// shared local table the sets are one lock domain, as on a single node.
const (
	ldShared  = "shared"         // one local lock table for both sets
	ldLocal   = "local-split"    // a local lock table per set
	ldDsync   = "dsync-disjoint" // in-process dsync, no locker in common
	ldOverlap = "dsync-overlap"  // in-process dsync, one of three lockers in common
)

var ldModes = []string{ldShared, ldLocal, ldDsync, ldOverlap}

// ldWait is how long an operation must stay blocked behind a held commit.
const ldWait = 400 * time.Millisecond

type ldGateKey struct{}

// ldGate holds the storage commit of the operation whose context carries it.
type ldGate struct {
	entered, release chan struct{}
	once, open       sync.Once
}

func newLDGate() *ldGate {
	return &ldGate{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *ldGate) let() { g.open.Do(func() { close(g.release) }) }

func ldHold(ctx context.Context) {
	g, _ := ctx.Value(ldGateKey{}).(*ldGate)
	if g == nil {
		return
	}
	g.once.Do(func() { close(g.entered) })
	select {
	case <-g.release:
	case <-ctx.Done():
	}
}

// ldGateDisk holds every metadata commit of a gated operation.
type ldGateDisk struct{ StorageAPI }

func (d ldGateDisk) RenameData(ctx context.Context, srcVolume, srcPath string, fi FileInfo, dstVolume, dstPath string, opts RenameOptions) (RenameDataResp, error) {
	ldHold(ctx)
	return d.StorageAPI.RenameData(ctx, srcVolume, srcPath, fi, dstVolume, dstPath, opts)
}

func (d ldGateDisk) RenamePart(ctx context.Context, srcVolume, srcPath, dstVolume, dstPath string, meta []byte, skipParent string) error {
	ldHold(ctx)
	return d.StorageAPI.RenamePart(ctx, srcVolume, srcPath, dstVolume, dstPath, meta, skipParent)
}

func (d ldGateDisk) DeleteVersion(ctx context.Context, volume, path string, fi FileInfo, forceDelMarker bool, opts DeleteOptions) error {
	ldHold(ctx)
	return d.StorageAPI.DeleteVersion(ctx, volume, path, fi, forceDelMarker, opts)
}

func (d ldGateDisk) DeleteVersions(ctx context.Context, volume string, versions []FileInfoVersions, opts DeleteOptions) []error {
	ldHold(ctx)
	return d.StorageAPI.DeleteVersions(ctx, volume, versions, opts)
}

func (d ldGateDisk) WriteMetadata(ctx context.Context, origvolume, volume, path string, fi FileInfo) error {
	ldHold(ctx)
	return d.StorageAPI.WriteMetadata(ctx, origvolume, volume, path, fi)
}

func (d ldGateDisk) UpdateMetadata(ctx context.Context, volume, path string, fi FileInfo, opts UpdateMetadataOpts) error {
	ldHold(ctx)
	return d.StorageAPI.UpdateMetadata(ctx, volume, path, fi, opts)
}

// ldSplit turns the single pool of z into two sets that share its drives and
// lock as mode says. Their drives hold gated commits.
func ldSplit(t *testing.T, z *erasureServerPools, mode string) {
	t.Helper()
	pool := z.serverPools[0]
	sets, count := pool.sets, pool.setCount
	t.Cleanup(func() { pool.sets, pool.setCount = sets, count })
	first, second := *sets[0], *sets[0]
	second.setIndex = 1
	switch mode {
	case ldShared:
	case ldLocal:
		first.nsMutex, second.nsMutex = newNSLock(false), newNSLock(false)
	case ldDsync, ldOverlap:
		l := make([]dsync.NetLocker, 8)
		for i := range l {
			l[i] = newLocker()
		}
		a, b := l[:4], l[4:]
		if mode == ldOverlap {
			// Each set can grant its quorum of two without the shared one.
			a, b = l[:3], l[2:5]
		}
		first.nsMutex, second.nsMutex = newNSLock(true), newNSLock(true)
		first.getLockers = func() ([]dsync.NetLocker, string) { return slices.Clone(a), "lock-domain-test" }
		second.getLockers = func() ([]dsync.NetLocker, string) { return slices.Clone(b), "lock-domain-test" }
	default:
		t.Fatalf("unknown mode %q", mode)
	}
	disks := sets[0].getDisks
	gated := func() []StorageAPI {
		ds := disks()
		for i, d := range ds {
			if d != nil {
				ds[i] = ldGateDisk{d}
			}
		}
		return ds
	}
	first.getDisks, second.getDisks = gated, gated
	pool.sets, pool.setCount = []*erasureObjects{&first, &second}, 2
}

// ldPool returns a split single pool and its unversioned test bucket.
func ldPool(t *testing.T, mode string) (*erasureServerPools, string) {
	t.Helper()
	z, bucket := bulkDeletePools(t, 1)
	ldSplit(t, z, mode)
	return z, bucket
}

// ldKey returns a name with prefix that hashes to set.
func ldKey(t *testing.T, z *erasureServerPools, prefix string, set int) string {
	t.Helper()
	for i := range 1000 {
		key := fmt.Sprintf("%s-%d", prefix, i)
		if z.serverPools[0].getHashedSetIndex(key) == set {
			return key
		}
	}
	t.Fatalf("no name with prefix %q hashes to set %d", prefix, set)
	return ""
}

// ldOverlap runs hold until it is inside its storage commit, then runs other.
// It reports whether other was still waiting after ldWait, then lets hold
// commit and returns both results.
func ldOverlapRun(t *testing.T, hold, other func(context.Context) error) (waited bool, holdErr, otherErr error) {
	t.Helper()
	g := newLDGate()
	defer g.let()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	held := make(chan error, 1)
	go func() { held <- hold(context.WithValue(ctx, ldGateKey{}, g)) }()
	select {
	case <-g.entered:
	case err := <-held:
		t.Fatalf("held operation finished before its commit: %v", err)
	case <-ctx.Done():
		t.Fatal("held operation never reached its commit")
	}
	done := make(chan error, 1)
	go func() { done <- other(ctx) }()
	select {
	case otherErr = <-done:
	case <-time.After(ldWait):
		waited = true
	}
	g.let()
	holdErr = <-held
	if waited {
		otherErr = <-done
	}
	return waited, holdErr, otherErr
}

func ldReader(r io.Reader, size int64) *PutObjReader {
	hr, err := hash.NewReader(context.Background(), r, size, "", "", size)
	if err != nil {
		panic(err)
	}
	return NewPutObjReader(hr)
}

func ldPut(ctx context.Context, z *erasureServerPools, bucket, key, body string) error {
	_, err := z.PutObject(ctx, bucket, key, ldReader(strings.NewReader(body), int64(len(body))), ObjectOptions{})
	return err
}

func ldMustPut(t *testing.T, z *erasureServerPools, bucket, key, body string) {
	t.Helper()
	if err := ldPut(t.Context(), z, bucket, key, body); err != nil {
		t.Fatal(err)
	}
}

func ldBody(t *testing.T, z *erasureServerPools, bucket, key string) (string, ObjectInfo) {
	t.Helper()
	gr, err := z.GetObjectNInfo(t.Context(), bucket, key, nil, nil, ObjectOptions{})
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	defer gr.Close()
	body, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	return string(body), gr.ObjInfo
}

func ldAbsent(t *testing.T, z *erasureServerPools, bucket, key string) {
	t.Helper()
	if _, err := z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{}); !isErrObjectNotFound(err) {
		t.Errorf("%s: %v, want not found", key, err)
	}
}

// ldMetadataCopy is a metadata-only self copy of key from a snapshot read
// without its lock, as the COPY handler read a copy onto itself.
func ldMetadataCopy(ctx context.Context, z *erasureServerPools, bucket, key, meta string) error {
	oi, err := z.GetObjectInfo(ctx, bucket, key, ObjectOptions{NoLock: true})
	if err != nil {
		return err
	}
	oi.metadataOnly = true
	oi.UserDefined = cloneMSS(oi.UserDefined)
	oi.UserDefined["x-amz-meta-copied"] = meta
	_, err = z.CopyObject(ctx, bucket, key, bucket, key, oi, ObjectOptions{}, ObjectOptions{})
	return err
}

// In one pool, a DELETE, bulk DELETE, COPY or tag update of a key must wait for
// a write of the same key that is inside its commit, and the reverse, whatever
// the hosts of the key's set are.
func TestLockDomainSinglePoolWritersExclude(t *testing.T) {
	type tc struct {
		name        string
		setup       func(t *testing.T, z *erasureServerPools, bucket, key string)
		hold, other func(ctx context.Context, z *erasureServerPools, bucket, key string) error
		check       func(t *testing.T, z *erasureServerPools, bucket, key string, holdErr, otherErr error)
	}
	seed := func(t *testing.T, z *erasureServerPools, bucket, key string) { ldMustPut(t, z, bucket, key, "seed") }
	put := func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
		return ldPut(ctx, z, bucket, key, "written")
	}
	noErrs := func(t *testing.T, holdErr, otherErr error) {
		t.Helper()
		if holdErr != nil || otherErr != nil {
			t.Fatalf("held: %v, other: %v", holdErr, otherErr)
		}
	}
	cases := []tc{{
		name:  "put/delete",
		setup: seed,
		hold:  put,
		other: func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
			_, err := z.DeleteObject(ctx, bucket, key, ObjectOptions{})
			return err
		},
		check: func(t *testing.T, z *erasureServerPools, bucket, key string, holdErr, otherErr error) {
			noErrs(t, holdErr, otherErr)
			ldAbsent(t, z, bucket, key)
		},
	}, {
		// The If-Match check and the delete are atomic with writers: the
		// condition is checked against the PUT's version.
		name:  "put/delete-if-match",
		setup: seed,
		hold:  put,
		other: func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
			seedETag := getMD5Hash([]byte("seed"))
			_, err := z.DeleteObject(ctx, bucket, key, ObjectOptions{CheckPrecondFn: func(oi ObjectInfo) bool { return oi.ETag != seedETag }})
			return err
		},
		check: func(t *testing.T, z *erasureServerPools, bucket, key string, holdErr, otherErr error) {
			if holdErr != nil || !isErrPreconditionFailed(otherErr) {
				t.Fatalf("put: %v; If-Match delete of the replaced version: %v, want precondition failed", holdErr, otherErr)
			}
			if body, _ := ldBody(t, z, bucket, key); body != "written" {
				t.Errorf("body %q, want the PUT's", body)
			}
		},
	}, {
		// ILM's delete-all deletes one key through prefix deletion.
		name:  "put/delete-all",
		setup: seed,
		hold:  put,
		other: func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
			_, err := z.DeleteObject(ctx, bucket, key, ObjectOptions{DeletePrefix: true, DeletePrefixObject: true})
			return err
		},
		check: func(t *testing.T, z *erasureServerPools, bucket, key string, holdErr, otherErr error) {
			noErrs(t, holdErr, otherErr)
			ldAbsent(t, z, bucket, key)
		},
	}, {
		name:  "put/bulk-delete",
		setup: seed,
		hold:  put,
		other: func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
			_, errs := z.DeleteObjects(ctx, bucket, []ObjectToDelete{{ObjectV: ObjectV{ObjectName: key}}}, ObjectOptions{})
			return errs[0]
		},
		check: func(t *testing.T, z *erasureServerPools, bucket, key string, holdErr, otherErr error) {
			noErrs(t, holdErr, otherErr)
			ldAbsent(t, z, bucket, key)
		},
	}, {
		name:  "put/copy-metadata",
		setup: seed,
		hold:  put,
		other: func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
			return ldMetadataCopy(ctx, z, bucket, key, "1")
		},
		check: func(t *testing.T, z *erasureServerPools, bucket, key string, holdErr, otherErr error) {
			noErrs(t, holdErr, otherErr)
			if body, _ := ldBody(t, z, bucket, key); body != "written" {
				t.Errorf("body %q after copy, want the PUT's", body)
			}
		},
	}, {
		name: "put/copy-rewrite",
		setup: func(t *testing.T, z *erasureServerPools, bucket, key string) {
			ldMustPut(t, z, bucket, key, "seed")
			ldMustPut(t, z, bucket, key+"-src", "copied")
		},
		hold: put,
		other: func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
			gr, err := z.GetObjectNInfo(ctx, bucket, key+"-src", nil, nil, ObjectOptions{})
			if err != nil {
				return err
			}
			defer gr.Close()
			src := gr.ObjInfo
			src.PutObjReader = ldReader(gr, src.Size)
			_, err = z.CopyObject(ctx, bucket, key+"-src", bucket, key, src, ObjectOptions{}, ObjectOptions{})
			return err
		},
		check: func(t *testing.T, z *erasureServerPools, bucket, key string, holdErr, otherErr error) {
			noErrs(t, holdErr, otherErr)
			if body, _ := ldBody(t, z, bucket, key); body != "copied" {
				t.Errorf("body %q, want the copy's, which ran after the PUT", body)
			}
		},
	}, {
		name:  "delete/tags",
		setup: seed,
		hold: func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
			_, err := z.DeleteObject(ctx, bucket, key, ObjectOptions{})
			return err
		},
		other: func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
			_, err := z.PutObjectTags(ctx, bucket, key, "k=v", ObjectOptions{})
			return err
		},
		check: func(t *testing.T, z *erasureServerPools, bucket, key string, holdErr, otherErr error) {
			if holdErr != nil || !isErrObjectNotFound(otherErr) {
				t.Fatalf("delete: %v; tags: %v, want not found", holdErr, otherErr)
			}
			ldAbsent(t, z, bucket, key)
		},
	}, {
		name:  "copy/tags",
		setup: seed,
		hold: func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
			return ldMetadataCopy(ctx, z, bucket, key, "1")
		},
		other: func(ctx context.Context, z *erasureServerPools, bucket, key string) error {
			_, err := z.PutObjectTags(ctx, bucket, key, "k=v", ObjectOptions{})
			return err
		},
		check: func(t *testing.T, z *erasureServerPools, bucket, key string, holdErr, otherErr error) {
			noErrs(t, holdErr, otherErr)
			oi, err := z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{})
			if err != nil || oi.UserTags != "k=v" || oi.UserDefined["x-amz-meta-copied"] != "1" {
				t.Errorf("after copy then tags: tags %q, meta %q, %v", oi.UserTags, oi.UserDefined["x-amz-meta-copied"], err)
			}
		},
	}}
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket := ldPool(t, mode)
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					key := ldKey(t, z, strings.ReplaceAll(c.name, "/", "-"), 1)
					c.setup(t, z, bucket, key)
					waited, holdErr, otherErr := ldOverlapRun(t,
						func(ctx context.Context) error { return c.hold(ctx, z, bucket, key) },
						func(ctx context.Context) error { return c.other(ctx, z, bucket, key) })
					if !waited {
						holder, contender, _ := strings.Cut(c.name, "/")
						t.Errorf("%s ran while %s held its commit (other: %v)", contender, holder, otherErr)
					}
					c.check(t, z, bucket, key, holdErr, otherErr)
				})
			}
		})
	}
}

// ldUpload starts an upload of key whose upload resource, and that of its
// first part, hash to the set of key when sameSet is set.
func ldUpload(t *testing.T, z *erasureServerPools, bucket, key string, sameSet bool) string {
	t.Helper()
	pool := z.serverPools[0]
	for range 64 {
		res, err := z.NewMultipartUpload(t.Context(), bucket, key, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		set := pool.getHashedSetIndex(key)
		if !sameSet || (pool.getHashedSetIndex(pathJoin(key, res.UploadID)) == set &&
			pool.getHashedSetIndex(pathJoin(key, res.UploadID, "1")) == set) {
			return res.UploadID
		}
		if err := z.AbortMultipartUpload(t.Context(), bucket, key, res.UploadID, ObjectOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("no upload ID with the wanted hashes")
	return ""
}

// The upload-ID guards of complete and abort exclude a PutObjectPart of the
// same upload. Get-info and list-parts read, as PutObjectPart's own guard
// does, and do not wait for it.
func TestLockDomainUploadGuards(t *testing.T) {
	part := []byte("the only part")
	partETag := getMD5Hash(part)
	putPart := func(ctx context.Context, z *erasureServerPools, bucket, key, id string) error {
		_, err := z.PutObjectPart(ctx, bucket, key, id, 1, ldReader(bytes.NewReader(part), int64(len(part))), ObjectOptions{})
		return err
	}
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket := ldPool(t, mode)
			for _, op := range []string{"complete", "abort", "info", "list"} {
				t.Run(op, func(t *testing.T) {
					key := ldKey(t, z, "upload-"+op, 1)
					id := ldUpload(t, z, bucket, key, false)
					waited, holdErr, otherErr := ldOverlapRun(t,
						func(ctx context.Context) error { return putPart(ctx, z, bucket, key, id) },
						func(ctx context.Context) error {
							var err error
							switch op {
							case "complete":
								_, err = z.CompleteMultipartUpload(ctx, bucket, key, id, []CompletePart{{PartNumber: 1, ETag: partETag}}, ObjectOptions{})
							case "abort":
								err = z.AbortMultipartUpload(ctx, bucket, key, id, ObjectOptions{})
							case "info":
								_, err = z.GetMultipartInfo(ctx, bucket, key, id, ObjectOptions{})
							case "list":
								_, err = z.ListObjectParts(ctx, bucket, key, id, 0, 10, ObjectOptions{})
							}
							return err
						})
					exclusive := op == "complete" || op == "abort"
					if waited != exclusive {
						t.Errorf("%s waited=%v for a part upload inside its commit, want %v (err %v)", op, waited, exclusive, otherErr)
					}
					if holdErr != nil || otherErr != nil {
						t.Fatalf("part: %v, %s: %v", holdErr, op, otherErr)
					}
					switch op {
					case "complete":
						if body, _ := ldBody(t, z, bucket, key); body != string(part) {
							t.Errorf("completed object %q", body)
						}
					case "abort":
						if _, err := z.GetMultipartInfo(t.Context(), bucket, key, id, ObjectOptions{}); !errors.As(err, &InvalidUploadID{}) {
							t.Errorf("upload after abort: %v", err)
						}
					}
				})
			}
		})
	}
}

// Bulk delete groups its names by set and must still wait for a completion
// of one of them, also when the batch names the completion's upload
// resource itself; neither may hold the other.
func TestLockDomainBulkDeleteAgainstUploads(t *testing.T) {
	part := []byte("the only part")
	partETag := getMD5Hash(part)
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket := ldPool(t, mode)
			for _, alias := range []bool{false, true} {
				t.Run(fmt.Sprintf("complete/alias=%v", alias), func(t *testing.T) {
					key := ldKey(t, z, fmt.Sprintf("bulk-complete-%v", alias), 1)
					id := ldUpload(t, z, bucket, key, false)
					if _, err := z.PutObjectPart(t.Context(), bucket, key, id, 1, mustGetPutObjReader(t, bytes.NewReader(part), int64(len(part)), "", ""), ObjectOptions{}); err != nil {
						t.Fatal(err)
					}
					names := []ObjectToDelete{{ObjectV: ObjectV{ObjectName: key}}}
					if alias {
						names = append(names, ObjectToDelete{ObjectV: ObjectV{ObjectName: pathJoin(key, id)}})
					}
					waited, holdErr, otherErr := ldOverlapRun(t,
						func(ctx context.Context) error {
							_, err := z.CompleteMultipartUpload(ctx, bucket, key, id, []CompletePart{{PartNumber: 1, ETag: partETag}}, ObjectOptions{})
							return err
						},
						func(ctx context.Context) error {
							_, errs := z.DeleteObjects(ctx, bucket, names, ObjectOptions{})
							return errors.Join(errs...)
						})
					if !waited {
						t.Errorf("bulk delete ran while the completion held its commit (%v)", otherErr)
					}
					if holdErr != nil || otherErr != nil {
						t.Fatalf("complete: %v, bulk: %v", holdErr, otherErr)
					}
					ldAbsent(t, z, bucket, key)
				})
			}
			// The names alias the locks of a part upload; they are other keys
			// and need not wait, but neither side may block the other.
			t.Run("put-part/alias", func(t *testing.T) {
				key := ldKey(t, z, "bulk-part", 1)
				id := ldUpload(t, z, bucket, key, true)
				names := []ObjectToDelete{{ObjectV: ObjectV{ObjectName: pathJoin(key, id)}}, {ObjectV: ObjectV{ObjectName: pathJoin(key, id, "1")}}}
				_, holdErr, otherErr := ldOverlapRun(t,
					func(ctx context.Context) error {
						_, err := z.PutObjectPart(ctx, bucket, key, id, 1, ldReader(bytes.NewReader(part), int64(len(part))), ObjectOptions{})
						return err
					},
					func(ctx context.Context) error {
						_, errs := z.DeleteObjects(ctx, bucket, names, ObjectOptions{})
						return errors.Join(errs...)
					})
				if holdErr != nil || otherErr != nil {
					t.Fatalf("part: %v, bulk: %v", holdErr, otherErr)
				}
				if _, err := z.CompleteMultipartUpload(t.Context(), bucket, key, id, []CompletePart{{PartNumber: 1, ETag: partETag}}, ObjectOptions{}); err != nil {
					t.Fatalf("upload after the bulk delete: %v", err)
				}
			})
		})
	}
}

// A group of a bulk delete whose lock is held by a writer of its set fails
// alone; the other set's group commits. A canceled request fails the groups it
// has not run, keeps the ones it has, and leaves no lock behind.
func TestLockDomainBulkDeleteGroups(t *testing.T) {
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket := ldPool(t, mode)
			split := mode != ldShared
			for _, cancelIt := range []bool{false, true} {
				t.Run(fmt.Sprintf("cancel=%v", cancelIt), func(t *testing.T) {
					k0 := ldKey(t, z, fmt.Sprintf("group-%v", cancelIt), 0)
					k1 := ldKey(t, z, fmt.Sprintf("group-%v", cancelIt), 1)
					ldMustPut(t, z, bucket, k0, "zero")
					ldMustPut(t, z, bucket, k1, "one")
					// A writer of k1 in the lock domain of its writes.
					writer := z.serverPools[0].getHashedSet(k1).NewNSLock(bucket, k1)
					wctx, err := writer.GetLock(t.Context(), globalOperationTimeout)
					if err != nil {
						t.Fatal(err)
					}
					var once sync.Once
					unlock := func() { once.Do(func() { writer.Unlock(wctx) }) }
					defer unlock()

					ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
					defer cancel()
					names := []ObjectToDelete{{ObjectV: ObjectV{ObjectName: k1}}, {ObjectV: ObjectV{ObjectName: k0}}}
					type result struct {
						objs []DeletedObject
						errs []error
					}
					done := make(chan result, 1)
					go func() {
						objs, errs := z.DeleteObjects(ctx, bucket, names, ObjectOptions{})
						done <- result{objs, errs}
					}()
					if cancelIt {
						if split {
							// Cancel once the first group has committed.
							deadline := time.Now().Add(5 * time.Second)
							for {
								if _, err := z.GetObjectInfo(t.Context(), bucket, k0, ObjectOptions{}); isErrObjectNotFound(err) {
									break
								}
								if time.Now().After(deadline) {
									t.Fatal("set 0's group did not commit")
								}
								time.Sleep(5 * time.Millisecond)
							}
						} else {
							time.Sleep(200 * time.Millisecond)
						}
						cancel()
					}
					res := <-done
					if res.objs[0].ObjectName != k1 || res.objs[1].ObjectName != k0 {
						t.Fatalf("results out of order: %+v", res.objs)
					}
					if res.errs[0] == nil {
						t.Errorf("k1 deleted while its writer held the lock")
					}
					if cancelIt && !errors.Is(res.errs[0], context.Canceled) {
						t.Errorf("k1 after cancellation: %v", res.errs[0])
					}
					if split != (res.errs[1] == nil) {
						t.Errorf("k0 (other set): %v, want committed=%v", res.errs[1], split)
					}
					unlock()
					if body, _ := ldBody(t, z, bucket, k1); body != "one" {
						t.Errorf("k1 = %q", body)
					}
					if split {
						ldAbsent(t, z, bucket, k0)
					}
					// No lock is left behind.
					lk := z.serverPools[0].getHashedSet(k1).NewNSLock(bucket, k1)
					lctx, err := lk.GetLock(t.Context(), newDynamicTimeout(5*time.Second, 5*time.Second))
					if err != nil {
						t.Fatalf("lock left behind: %v", err)
					}
					lk.Unlock(lctx)
				})
			}
		})
	}
}

// ldBulkScenario runs one versioned bulk delete over names of both sets and
// describes its results and the versions left, without generated version IDs.
func ldBulkScenario(t *testing.T, mode string) []string {
	t.Helper()
	z, _ := ldPool(t, mode)
	bucket := "lock-domain-versioned"
	if err := z.MakeBucket(t.Context(), bucket, MakeBucketOptions{VersioningEnabled: true}); err != nil {
		t.Fatal(err)
	}
	vput := func(key, body string) ObjectInfo {
		oi, err := z.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, strings.NewReader(body), int64(len(body)), "", ""), ObjectOptions{Versioned: true})
		if err != nil {
			t.Fatal(err)
		}
		return oi
	}
	a, b, c := ldKey(t, z, "map-a", 1), ldKey(t, z, "map-b", 0), ldKey(t, z, "map-c", 1)
	dir := ldKey(t, z, "map-dir", 0) + "/"
	va1, va2 := vput(a, "a1"), vput(a, "a2")
	vb := vput(b, "b1")
	vput(c, "c1")
	if _, err := z.PutObject(t.Context(), bucket, dir, mustGetPutObjReader(t, strings.NewReader(""), 0, "", ""), ObjectOptions{Versioned: true}); err != nil {
		t.Fatal(err)
	}
	absent := mustGetUUID()
	invalid := strings.Repeat("x", 1100)
	names := []ObjectToDelete{
		{ObjectV: ObjectV{ObjectName: a}},                           // marker
		{ObjectV: ObjectV{ObjectName: b, VersionID: vb.VersionID}},  // purge
		{ObjectV: ObjectV{ObjectName: invalid}},                     // invalid
		{ObjectV: ObjectV{ObjectName: a, VersionID: va1.VersionID}}, // purge, same key
		{ObjectV: ObjectV{ObjectName: c}},                           // marker
		{ObjectV: ObjectV{ObjectName: dir}},                         // directory marker
		{ObjectV: ObjectV{ObjectName: "map-missing"}},               // absent
		{ObjectV: ObjectV{ObjectName: a, VersionID: va1.VersionID}}, // duplicate
		{ObjectV: ObjectV{ObjectName: b, VersionID: absent}},        // absent version
	}
	// Names hash with the deployment ID: compare them by role.
	label := strings.NewReplacer(dir, "DIR/", a, "A", b, "B", c, "C", invalid, "INVALID",
		va1.VersionID, "a1", va2.VersionID, "a2", vb.VersionID, "b1", absent, "absent")
	objs, errs := z.DeleteObjects(t.Context(), bucket, names, ObjectOptions{Versioned: true})
	var out []string
	for i := range names {
		o := objs[i]
		vid := label.Replace(o.VersionID)
		if len(vid) > 10 {
			vid = "generated"
		}
		out = append(out, label.Replace(fmt.Sprintf("%d %s vid=%q marker=%v markerVid=%v found=%v err=%v",
			i, o.ObjectName, vid, o.DeleteMarker, o.DeleteMarkerVersionID != "", o.found, errs[i])))
	}
	for _, key := range []string{a, b, c, dir} {
		info, err := z.ListObjectVersions(t.Context(), bucket, key, "", "", "", 100)
		if err != nil {
			t.Fatal(err)
		}
		var vs []string
		for _, v := range info.Objects {
			if v.Name != key {
				continue
			}
			id := "other"
			switch v.VersionID {
			case va2.VersionID:
				id = "a2"
			case va1.VersionID:
				id = "a1"
			case vb.VersionID:
				id = "b1"
			}
			vs = append(vs, fmt.Sprintf("%s:marker=%v:latest=%v", id, v.DeleteMarker, v.IsLatest))
		}
		out = append(out, label.Replace(key)+" "+strings.Join(vs, ","))
	}
	return out
}

// Grouping by set keeps every result where its name was and gives the same
// results and the same versions as the one bulk lock of a single node.
func TestLockDomainBulkDeleteMapping(t *testing.T) {
	want := ldBulkScenario(t, ldShared)
	for _, mode := range ldModes[1:] {
		t.Run(mode, func(t *testing.T) {
			got := ldBulkScenario(t, mode)
			if !slices.Equal(got, want) {
				t.Errorf("results differ from the single bulk lock:\n got %q\nwant %q", got, want)
			}
		})
	}
}

// A restore holds the object lock of its set for its download. DELETE and COPY
// of the object must wait for it.
func TestLockDomainRestoreExcludesDeleteAndCopy(t *testing.T) {
	for _, mode := range ldModes {
		for _, op := range []string{"delete", "copy"} {
			t.Run(mode+"/"+op, func(t *testing.T) {
				r := newRestoreSafetyTest(t, 1, versioning.Enabled)
				ldSplit(t, r.z, mode)
				r.object = ldKey(t, r.z, "restore-"+op, 1)
				oi, _ := nativeRestoreSeed(t, r, 0, false, false)
				blocked := &nativeRestoreBlockedTier{WarmBackend: globalTierConfigMgr.drivercache["WARM"], entered: make(chan struct{}), release: make(chan struct{})}
				globalTierConfigMgr.drivercache["WARM"] = blocked
				var once sync.Once
				unblock := func() { once.Do(func() { close(blocked.release) }) }
				defer unblock()
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				restored := make(chan error, 1)
				go func() {
					restored <- r.z.RestoreTransitionedObject(ctx, r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
				}()
				select {
				case <-blocked.entered:
				case <-ctx.Done():
					t.Fatal("restore never started its download")
				}
				done := make(chan error, 1)
				go func() {
					switch op {
					case "delete":
						_, err := r.z.DeleteObject(ctx, r.bucket, r.object, r.opts(""))
						done <- err
					case "copy":
						ropts := r.opts(oi.VersionID)
						ropts.NoLock = true
						cur, err := r.z.GetObjectInfo(ctx, r.bucket, r.object, ropts)
						if err != nil {
							done <- err
							return
						}
						cur.metadataOnly = true
						cur.UserDefined = cloneMSS(cur.UserDefined)
						cur.UserDefined["x-amz-meta-copied"] = "1"
						vopts := r.opts(oi.VersionID)
						_, err = r.z.CopyObject(ctx, r.bucket, r.object, r.bucket, r.object, cur, vopts, vopts)
						done <- err
					}
				}()
				var opErr error
				select {
				case opErr = <-done:
					t.Errorf("%s ran during the restore (%v)", op, opErr)
				case <-time.After(ldWait):
					unblock()
					opErr = <-done
				}
				unblock()
				if err := <-restored; err != nil {
					t.Fatalf("restore: %v", err)
				}
				if opErr != nil {
					t.Fatalf("%s after the restore: %v", op, opErr)
				}
			})
		}
	}
}

// ldAPI is a split single pool served by the S3 API router.
func ldAPI(t *testing.T, mode string) (*erasureServerPools, string, http.Handler) {
	t.Helper()
	z, bucket := ldPool(t, mode)
	if err := newTestConfig(globalMinioDefaultRegion, z); err != nil {
		t.Fatal(err)
	}
	return z, bucket, initTestAPIEndPoints(z, nil)
}

func ldRequest(ctx context.Context, t *testing.T, router http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := newTestSignedRequestV4(method, path, int64(len(body)), strings.NewReader(body), globalActiveCred.AccessKey, globalActiveCred.SecretKey, headers)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))
	return rec
}

func ldCopyRequest(ctx context.Context, t *testing.T, router http.Handler, bucket, src, dst string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	h := map[string]string{xhttp.AmzCopySource: "/" + bucket + "/" + src}
	for k, v := range headers {
		h[k] = v
	}
	return ldRequest(ctx, t, router, http.MethodPut, "/"+bucket+"/"+dst, "", h)
}

// The COPY handler locks its destination, and a copy onto itself reads its
// source, in the lock domain of the object's writes. A copy onto itself must
// read the version that the PUT before it committed.
func TestLockDomainCopyHandler(t *testing.T) {
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket, router := ldAPI(t, mode)
			for _, self := range []bool{false, true} {
				t.Run(fmt.Sprintf("self=%v", self), func(t *testing.T) {
					key := ldKey(t, z, fmt.Sprintf("copy-handler-%v", self), 1)
					src := key + "-src"
					ldMustPut(t, z, bucket, key, "seed")
					ldMustPut(t, z, bucket, src, "source")
					var rec *httptest.ResponseRecorder
					waited, holdErr, _ := ldOverlapRun(t,
						func(ctx context.Context) error { return ldPut(ctx, z, bucket, key, "written") },
						func(ctx context.Context) error {
							if self {
								rec = ldCopyRequest(ctx, t, router, bucket, key, key, map[string]string{
									xhttp.AmzMetadataDirective: "REPLACE", "x-amz-meta-copied": "1",
								})
							} else {
								rec = ldCopyRequest(ctx, t, router, bucket, src, key, nil)
							}
							return nil
						})
					if !waited {
						t.Errorf("COPY ran while a PUT of its destination held its commit")
					}
					if holdErr != nil || rec.Code != http.StatusOK {
						t.Fatalf("put: %v; copy: %d %s", holdErr, rec.Code, rec.Body.String())
					}
					body, oi := ldBody(t, z, bucket, key)
					want := "source"
					if self {
						want = "written"
						if oi.UserDefined["X-Amz-Meta-Copied"] != "1" {
							t.Errorf("copied metadata missing: %v", oi.UserDefined)
						}
					}
					if body != want || oi.ETag != getMD5Hash([]byte(want)) {
						t.Errorf("after the copy: body %q etag %q, want %q with its own ETag", body, oi.ETag, want)
					}
				})
			}
		})
	}
}

// Copies in opposite directions always make progress: between keys of
// different sets, and where both locks share one domain, as on a single node
// or with several pools.
func TestLockDomainCopyHandlerReciprocal(t *testing.T) {
	for _, mode := range append(slices.Clone(ldModes), "pools") {
		t.Run(mode, func(t *testing.T) {
			var z *erasureServerPools
			var bucket string
			var router http.Handler
			keys := [2]string{"reciprocal-a", "reciprocal-b"}
			if mode == "pools" {
				z, bucket = bulkDeletePools(t, 2)
				if err := newTestConfig(globalMinioDefaultRegion, z); err != nil {
					t.Fatal(err)
				}
				router = initTestAPIEndPoints(z, nil)
			} else {
				z, bucket, router = ldAPI(t, mode)
				keys = [2]string{ldKey(t, z, "reciprocal", 0), ldKey(t, z, "reciprocal", 1)}
			}
			// Not inlined: the source is read while the destination is written.
			body := strings.Repeat("reciprocal copy source ", 1<<14)
			for _, k := range keys {
				ldMustPut(t, z, bucket, k, body)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			for round := range 8 {
				var wg sync.WaitGroup
				codes := make([]int, 2)
				start := make(chan struct{})
				for i := range keys {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						codes[i] = ldCopyRequest(ctx, t, router, bucket, keys[i], keys[1-i], nil).Code
					}()
				}
				close(start)
				wg.Wait()
				if codes[0] != http.StatusOK || codes[1] != http.StatusOK {
					t.Fatalf("round %d: reciprocal copies returned %v", round, codes)
				}
			}
		})
	}
}

// The COPY handler looks up its destination while it holds the destination's
// lock: Object Lock's retention check and the tier sweeper's lookup must not
// take that lock again.
func TestLockDomainCopyHandlerDestinationLookups(t *testing.T) {
	prevTier := globalTierConfigMgr
	t.Cleanup(func() { globalTierConfigMgr = prevTier })
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, _, router := ldAPI(t, mode)
			globalTierConfigMgr = NewTierConfigMgr()
			globalTierConfigMgr.Tiers["WARM"] = madmin.TierConfig{Version: madmin.TierConfigVer, Type: madmin.S3, Name: "WARM", S3: &madmin.TierS3{Bucket: "warm"}}
			bucket := "lock-domain-worm"
			if err := z.MakeBucket(t.Context(), bucket, MakeBucketOptions{LockEnabled: true, VersioningEnabled: true}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			src := ldKey(t, z, "lookup-src", 0)
			if _, err := z.PutObject(t.Context(), bucket, src, mustGetPutObjReader(t, strings.NewReader(""), 0, "", ""), ObjectOptions{Versioned: true}); err != nil {
				t.Fatal(err)
			}
			for _, dst := range []string{ldKey(t, z, "lookup-dst", 1), ldKey(t, z, "lookup-dir", 1) + "/"} {
				if rec := ldCopyRequest(ctx, t, router, bucket, src, dst, nil); rec.Code != http.StatusOK {
					t.Fatalf("copy to %s: %d %s", dst, rec.Code, rec.Body.String())
				}
				// Self copy, metadata only.
				if rec := ldCopyRequest(ctx, t, router, bucket, dst, dst, map[string]string{
					xhttp.AmzMetadataDirective: "REPLACE", "x-amz-meta-copied": "1",
				}); rec.Code != http.StatusOK {
					t.Fatalf("self copy of %s: %d %s", dst, rec.Code, rec.Body.String())
				}
			}
		})
	}
}

// SelectObjectContent reads under the lock of the object's writes.
func TestLockDomainSelectWaitsForWriter(t *testing.T) {
	const request = `<SelectObjectContentRequest><Expression>SELECT * FROM S3Object</Expression><ExpressionType>SQL</ExpressionType>` +
		`<InputSerialization><CSV><FileHeaderInfo>NONE</FileHeaderInfo></CSV></InputSerialization>` +
		`<OutputSerialization><CSV/></OutputSerialization></SelectObjectContentRequest>`
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket, router := ldAPI(t, mode)
			key := ldKey(t, z, "select", 1)
			ldMustPut(t, z, bucket, key, "seed,1\n")
			var rec *httptest.ResponseRecorder
			waited, holdErr, _ := ldOverlapRun(t,
				func(ctx context.Context) error { return ldPut(ctx, z, bucket, key, "written,2\n") },
				func(ctx context.Context) error {
					rec = ldRequest(ctx, t, router, http.MethodPost, "/"+bucket+"/"+key+"?select&select-type=2", request, nil)
					return nil
				})
			if !waited {
				t.Errorf("SELECT ran while a PUT held its commit")
			}
			if holdErr != nil || rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("written,2")) {
				t.Fatalf("put: %v; select: %d %q", holdErr, rec.Code, rec.Body.String())
			}
		})
	}
}

// Batch key rotation locks the object in the lock domain of its writes.
func TestLockDomainKeyRotationWaitsForWriter(t *testing.T) {
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket := ldPool(t, mode)
			key := ldKey(t, z, "rotate", 1)
			ldMustPut(t, z, bucket, key, "seed")
			job := &BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: sses3}}
			// The rotation's listing found an SSE-S3 object; it reads it again
			// under the lock.
			listed := ObjectInfo{Bucket: bucket, Name: key, UserDefined: map[string]string{crypto.MetaSealedKeyS3: "listed"}}
			waited, _, _ := ldOverlapRun(t,
				func(ctx context.Context) error { return ldPut(ctx, z, bucket, key, "written") },
				func(ctx context.Context) error { return job.KeyRotate(ctx, z, listed) })
			if !waited {
				t.Errorf("key rotation ran while a PUT held its commit")
			}
		})
	}
}

// ldCopyGate holds a COPY of one destination inside the object layer's
// CopyObject, after the handler's Object Lock check, and reports when a
// metadata update of that destination reaches the object layer.
type ldCopyGate struct {
	ObjectLayer
	bucket, object         string
	copying, updating      chan struct{}
	release                chan struct{}
	copyOnce, updatingOnce sync.Once
}

func (g *ldCopyGate) CopyObject(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string, info ObjectInfo, srcOpts, dstOpts ObjectOptions) (ObjectInfo, error) {
	if dstBucket == g.bucket && dstObject == g.object {
		g.copyOnce.Do(func() { close(g.copying) })
		select {
		case <-g.release:
		case <-ctx.Done():
			return ObjectInfo{}, ctx.Err()
		}
	}
	return g.ObjectLayer.CopyObject(ctx, srcBucket, srcObject, dstBucket, dstObject, info, srcOpts, dstOpts)
}

func (g *ldCopyGate) PutObjectMetadata(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	if bucket == g.bucket && object == g.object {
		g.updatingOnce.Do(func() { close(g.updating) })
	}
	return g.ObjectLayer.PutObjectMetadata(ctx, bucket, object, opts)
}

// A retention or legal-hold update of a COPY destination cannot land between
// the handler's Object Lock check and the copy: it waits for the copy, which
// then succeeds, and is applied after it.
func TestLockDomainCopyExcludesObjectLockUpdates(t *testing.T) {
	for _, mode := range append(slices.Clone(ldModes), "pools") {
		t.Run(mode, func(t *testing.T) {
			var z *erasureServerPools
			if mode == "pools" {
				z, _ = bulkDeletePools(t, 2)
			} else {
				z, _ = ldPool(t, mode)
			}
			if err := newTestConfig(globalMinioDefaultRegion, z); err != nil {
				t.Fatal(err)
			}
			bucket := "lock-domain-worm-copy"
			if err := z.MakeBucket(t.Context(), bucket, MakeBucketOptions{LockEnabled: true, VersioningEnabled: true}); err != nil {
				t.Fatal(err)
			}
			plain := initTestAPIEndPoints(z, nil)
			put := func(key string) {
				t.Helper()
				if rec := ldRequest(t.Context(), t, plain, http.MethodPut, "/"+bucket+"/"+key, "", nil); rec.Code != http.StatusOK {
					t.Fatalf("PUT %s: %d %s", key, rec.Code, rec.Body.String())
				}
			}
			put("copy-source/")
			for _, self := range []bool{false, true} {
				for _, state := range []string{"GOVERNANCE", "COMPLIANCE", "LEGAL-HOLD"} {
					t.Run(fmt.Sprintf("self=%v/%s", self, state), func(t *testing.T) {
						// Directory objects: Object Lock checks their null version.
						key := fmt.Sprintf("copy-destination-%v-%s/", self, state)
						if mode != "pools" {
							for z.serverPools[0].getHashedSetIndex(encodeDirObject(key)) != 1 {
								key = "x" + key
							}
						}
						put(key)
						g := &ldCopyGate{
							ObjectLayer: z, bucket: bucket, object: key,
							copying: make(chan struct{}), updating: make(chan struct{}), release: make(chan struct{}),
						}
						setObjectLayer(g)
						defer setObjectLayer(z)
						router := initTestAPIEndPoints(g, nil)
						ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
						release := sync.OnceFunc(func() { close(g.release) })
						var wg sync.WaitGroup
						defer func() { release(); cancel(); wg.Wait() }()

						src := "copy-source/"
						if self {
							src = key
						}
						copied, updated := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
						wg.Add(1)
						go func() {
							defer wg.Done()
							copied <- ldCopyRequest(ctx, t, router, bucket, src, key, map[string]string{
								xhttp.AmzMetadataDirective: "REPLACE", "x-amz-meta-copied": "1",
							})
						}()
						select {
						case <-g.copying:
						case rec := <-copied:
							t.Fatalf("COPY returned before its write: %d %s", rec.Code, rec.Body.String())
						case <-ctx.Done():
							t.Fatal("COPY never reached its write")
						}

						query := url.Values{"versionId": {nullVersionID}}
						body := `<LegalHold><Status>ON</Status></LegalHold>`
						if state == "LEGAL-HOLD" {
							query.Set("legal-hold", "")
						} else {
							query.Set("retention", "")
							body = fmt.Sprintf(`<Retention><Mode>%s</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`,
								state, amztime.ISO8601Format(UTCNow().Add(365*24*time.Hour)))
						}
						sum := md5.Sum([]byte(body))
						wg.Add(1)
						go func() {
							defer wg.Done()
							updated <- ldRequest(ctx, t, router, http.MethodPut, makeTestTargetURL("", bucket, key, query), body,
								map[string]string{xhttp.ContentMD5: base64.StdEncoding.EncodeToString(sum[:])})
						}()
						select {
						case <-g.updating:
						case rec := <-updated:
							t.Fatalf("update returned before reaching the object layer: %d %s", rec.Code, rec.Body.String())
						case <-ctx.Done():
							t.Fatal("update never reached the object layer")
						}
						select {
						case rec := <-updated:
							t.Errorf("%s update ran between the COPY's Object Lock check and its write: %d", state, rec.Code)
							updated <- rec
						case <-time.After(ldWait):
						}
						release()
						for name, result := range map[string]chan *httptest.ResponseRecorder{"COPY": copied, "update": updated} {
							select {
							case rec := <-result:
								if rec.Code != http.StatusOK {
									t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
								}
							case <-ctx.Done():
								t.Fatalf("%s did not finish", name)
							}
						}
						after, err := z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: nullVersionID})
						if err != nil {
							t.Fatal(err)
						}
						if after.UserDefined["X-Amz-Meta-Copied"] != "1" {
							t.Errorf("copied metadata missing: %v", after.UserDefined)
						}
						if state == "LEGAL-HOLD" {
							if objectlock.GetObjectLegalHoldMeta(after.UserDefined).Status != objectlock.LegalHoldOn {
								t.Error("legal hold applied before the copy was lost")
							}
						} else if string(objectlock.GetObjectRetentionMeta(after.UserDefined).Mode) != state {
							t.Error("retention applied before the copy was lost")
						}
					})
				}
			}
		})
	}
}
