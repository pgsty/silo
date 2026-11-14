// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
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
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	xioutil "github.com/minio/minio/internal/ioutil"
)

func TestSysErrors(t *testing.T) {
	pathErr := &os.PathError{Err: syscall.ENAMETOOLONG}
	ok := isSysErrTooLong(pathErr)
	if !ok {
		t.Fatalf("Unexpected error expecting %s", syscall.ENAMETOOLONG)
	}
	pathErr = &os.PathError{Err: syscall.ENOTDIR}
	ok = isSysErrNotDir(pathErr)
	if !ok {
		t.Fatalf("Unexpected error expecting %s", syscall.ENOTDIR)
	}
	if runtime.GOOS != globalWindowsOSName {
		pathErr = &os.PathError{Err: syscall.ENOTEMPTY}
		ok = isSysErrNotEmpty(pathErr)
		if !ok {
			t.Fatalf("Unexpected error expecting %s", syscall.ENOTEMPTY)
		}
	} else {
		pathErr = &os.PathError{Err: syscall.Errno(0x91)}
		ok = isSysErrNotEmpty(pathErr)
		if !ok {
			t.Fatal("Unexpected error expecting 0x91")
		}
	}
	if runtime.GOOS == globalWindowsOSName {
		pathErr = &os.PathError{Err: syscall.Errno(0x03)}
		ok = isSysErrPathNotFound(pathErr)
		if !ok {
			t.Fatal("Unexpected error expecting 0x03")
		}
	}
}

// TestCommitMetaMissingMapping verifies the RPC and object-layer mapping
// of errCommitMetaMissing, returned when the staged xl.meta disappears
// between the data rename and the meta-file commit in RenameData().
func TestCommitMetaMissingMapping(t *testing.T) {
	// The sentinel must survive a storage REST/grid round-trip; errors
	// cross the wire as strings and are remapped by toStorageErr().
	if got := toStorageErr(errors.New(errCommitMetaMissing.Error())); !errors.Is(got, errCommitMetaMissing) {
		t.Fatalf("expected %s, got %s", errCommitMetaMissing, got)
	}
	if got := toStorageErr(errCommitMetaMissing); got != errCommitMetaMissing {
		t.Fatalf("expected %s, got %s", errCommitMetaMissing, got)
	}

	// toObjectErr() must map the sentinel to InsufficientWriteQuorum
	// (503), never to ObjectNotFound (404).
	err := toObjectErr(errCommitMetaMissing, "bucket", "object")
	qerr, ok := err.(InsufficientWriteQuorum)
	if !ok {
		t.Fatalf("expected InsufficientWriteQuorum, got %s (%T)", err, err)
	}
	if qerr.Bucket != "bucket" || qerr.Object != "object" {
		t.Fatalf("unexpected bucket/object %s/%s", qerr.Bucket, qerr.Object)
	}
	apiErr := toAPIError(t.Context(), err)
	if apiErr.Code != "SlowDownWrite" || apiErr.HTTPStatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected SlowDownWrite/503, got %+v", apiErr)
	}
}

// missingCommitMetaContext removes staged metadata at an existing cancellation
// check, after WriteAll and (for non-inline objects) the data rename succeeded.
// This deterministically models concurrent cleanup without changing production
// code or relying on a filesystem race. The context itself remains live.
type missingCommitMetaContext struct {
	context.Context
	mu             sync.Mutex
	meta, dataDest string
	removed        bool
	removeErr      error
}

func (c *missingCommitMetaContext) Done() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.removed {
		if _, err := os.Stat(c.meta); err == nil {
			dataMoved := c.dataDest == ""
			if !dataMoved {
				_, err = os.Stat(c.dataDest)
				dataMoved = err == nil
			}
			if dataMoved {
				c.removeErr = os.Remove(c.meta)
				c.removed = c.removeErr == nil
			}
		}
	}
	return c.Context.Done()
}

func TestXLStorageRenameDataCommitMetaMissing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dataFile bool
	}{
		{"empty_object", false},
		{"data_directory", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disk, root, err := newXLStorageTestSetup(t)
			if err != nil {
				t.Fatal(err)
			}
			defer disk.Close()
			s := disk.storage
			if err := s.MakeVol(t.Context(), "bucket"); err != nil {
				t.Fatal(err)
			}
			fi := newFileInfo("object", 2, 2)
			fi.DataDir, fi.VersionID = mustGetUUID(), mustGetUUID()
			fi.Erasure.Index = 1
			fi.ModTime = time.Now().UTC()
			fi.Fresh = true
			ctx := &missingCommitMetaContext{
				Context: t.Context(),
				meta:    filepath.Join(root, minioMetaTmpBucket, "staged", xlStorageFormatFile),
			}
			if tc.dataFile {
				fi.Size = 1
				fi.AddObjectPart(1, "", 1, 1, fi.ModTime, nil, nil)
				part := filepath.Join(root, minioMetaTmpBucket, "staged", fi.DataDir, "part.1")
				if err := os.MkdirAll(filepath.Dir(part), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(part, []byte("a"), 0o644); err != nil {
					t.Fatal(err)
				}
				ctx.dataDest = filepath.Join(root, "bucket", "object", fi.DataDir)
			}
			_, err = s.RenameData(ctx, minioMetaTmpBucket, "staged", fi, "bucket", "object", RenameOptions{})
			if !ctx.removed {
				t.Fatalf("metadata removal did not execute: removal error = %v, RenameData error = %v", ctx.removeErr, err)
			}
			if !errors.Is(err, errCommitMetaMissing) {
				t.Fatalf("expected commit metadata missing, got %v", err)
			}
			apiErr := toAPIError(t.Context(), toObjectErr(err, "bucket", "object"))
			if apiErr.Code != "SlowDownWrite" || apiErr.HTTPStatusCode != http.StatusServiceUnavailable {
				t.Fatalf("expected SlowDownWrite/503, got %+v", apiErr)
			}
			if _, err := os.Stat(filepath.Join(root, "bucket", "object", xlStorageFormatFile)); !os.IsNotExist(err) {
				t.Fatalf("failed commit must not produce destination metadata: %v", err)
			}
		})
	}
}

// A failed commit must not leave behind the object directory that renameAll()
// created for it when nothing was moved into it: once the other objects under
// its parent are gone, it keeps the parent and every ancestor listed as an
// empty prefix. A data directory that was already moved keeps the directory.
func TestXLStorageRenameDataCommitMetaMissingRemovesEmptyDirs(t *testing.T) {
	const object = "day=1/b=9/object"
	for _, tc := range []struct {
		name    string
		data    string // "" (zero bytes), "inline" or "dir"
		sibling bool   // another object under day=1/b=9/
	}{
		{"empty_object", "", false},
		{"inline_object_with_sibling", "inline", true},
		{"data_directory", "dir", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disk, root, err := newXLStorageTestSetup(t)
			if err != nil {
				t.Fatal(err)
			}
			defer disk.Close()
			s := disk.storage
			if err := s.MakeVol(t.Context(), "bucket"); err != nil {
				t.Fatal(err)
			}
			bucketDir := filepath.Join(root, "bucket")
			objDir := filepath.Join(bucketDir, filepath.FromSlash(object))
			siblingMeta := filepath.Join(bucketDir, "day=1", "b=9", "sibling", xlStorageFormatFile)
			if tc.sibling {
				if err := os.MkdirAll(filepath.Dir(siblingMeta), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(siblingMeta, []byte("sibling"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			fi := newFileInfo(object, 2, 2)
			fi.DataDir, fi.VersionID = mustGetUUID(), mustGetUUID()
			fi.Erasure.Index = 1
			fi.ModTime = time.Now().UTC()
			fi.Fresh = true
			ctx := &missingCommitMetaContext{
				Context: t.Context(),
				meta:    filepath.Join(root, minioMetaTmpBucket, "staged", xlStorageFormatFile),
			}
			switch tc.data {
			case "inline":
				fi.Size = 1
				fi.Data = []byte("a")
			case "dir":
				fi.Size = 1
				fi.AddObjectPart(1, "", 1, 1, fi.ModTime, nil, nil)
				part := filepath.Join(root, minioMetaTmpBucket, "staged", fi.DataDir, "part.1")
				if err := os.MkdirAll(filepath.Dir(part), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(part, []byte("a"), 0o644); err != nil {
					t.Fatal(err)
				}
				ctx.dataDest = filepath.Join(objDir, fi.DataDir)
			}
			_, err = s.RenameData(ctx, minioMetaTmpBucket, "staged", fi, "bucket", object, RenameOptions{})
			if !ctx.removed {
				t.Fatalf("metadata removal did not execute: removal error = %v, RenameData error = %v", ctx.removeErr, err)
			}
			if !errors.Is(err, errCommitMetaMissing) {
				t.Fatalf("expected commit metadata missing, got %v", err)
			}

			if tc.data == "dir" {
				// The moved data directory is not deleted, so the object
				// directory stays and holds only it.
				entries, err := os.ReadDir(objDir)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 1 || entries[0].Name() != fi.DataDir {
					t.Fatalf("object directory holds %v, want only data directory %s", entries, fi.DataDir)
				}
				if _, err := os.Stat(filepath.Join(objDir, fi.DataDir, "part.1")); err != nil {
					t.Fatalf("moved data must be kept: %v", err)
				}
				return
			}
			if _, err := os.Stat(objDir); !os.IsNotExist(err) {
				t.Fatalf("empty object directory left after a failed commit (%v)", err)
			}
			if tc.sibling {
				if _, err := os.Stat(siblingMeta); err != nil {
					t.Fatalf("sibling object must be kept: %v", err)
				}
			} else if _, err := os.Stat(filepath.Join(bucketDir, "day=1")); !os.IsNotExist(err) {
				t.Fatalf("empty parent day=1 left after a failed commit (%v)", err)
			}
			if _, err := os.Stat(bucketDir); err != nil {
				t.Fatalf("bucket directory must be kept: %v", err)
			}
		})
	}
}

// traceOSCalls calls hook synchronously after every instrumented OS call
// until the test ends, so that a test can run other storage calls at an
// exact point inside a storage call without changing production code.
func traceOSCalls(t *testing.T, hook func(madmin.TraceInfo)) {
	t.Helper()
	before := globalTrace.Subscribers()
	done := make(chan struct{})
	if err := globalTrace.Subscribe(madmin.TraceOS, make(chan madmin.TraceInfo, 1), done, func(tr madmin.TraceInfo) bool {
		hook(tr)
		return false
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		close(done)
		// Wait for the unsubscribe, which takes the pubsub write lock, so
		// that it cannot block a nested trace of a later test.
		for globalTrace.Subscribers() > before {
			time.Sleep(time.Millisecond)
		}
	})
}

// The walk up from a removed path removes only empty directories. Another
// walk, for example the cleanup of a second failed write of the same key,
// can remove the rest of the chain while this one is between two steps, and
// a writer can then commit an object whose xl.meta is the path this walk
// removes next. That object must stay.
func TestXLStorageWalkUpKeepsCommittedObject(t *testing.T) {
	const nested, parent = "parent/xl.meta/child", "parent"
	for _, tc := range []string{"delete_version", "data_rename", "commit"} {
		t.Run(tc, func(t *testing.T) {
			disk, root, err := newXLStorageTestSetup(t)
			if err != nil {
				t.Fatal(err)
			}
			defer disk.Close()
			s := disk.storage
			ctx := t.Context()
			if err := s.MakeVol(ctx, "bucket"); err != nil {
				t.Fatal(err)
			}
			newFI := func(object string) FileInfo {
				fi := newFileInfo(object, 2, 2)
				fi.DataDir, fi.VersionID = mustGetUUID(), mustGetUUID()
				fi.Erasure.Index = 1
				fi.ModTime = time.Now().UTC()
				fi.Fresh = true
				return fi
			}
			inline := func(object string) FileInfo {
				fi := newFI(object)
				fi.Size, fi.Data = 1, []byte("x")
				fi.AddObjectPart(1, "", 1, 1, fi.ModTime, nil, nil)
				fi.SetInlineData()
				return fi
			}
			childDir := filepath.Join(root, "bucket", filepath.FromSlash(nested))
			metaDir := filepath.Dir(childDir)
			parentDir := filepath.Dir(metaDir)

			var nestedFI FileInfo
			if tc == "delete_version" {
				nestedFI = inline(nested)
				if _, err := s.RenameData(ctx, minioMetaTmpBucket, "nested", nestedFI, "bucket", nested, RenameOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			parentFI := inline(parent)
			var fired atomic.Bool
			var hookErr error
			traceOSCalls(t, func(tr madmin.TraceInfo) {
				if tr.FuncName != "os.Remove" || tr.Error != "" || filepath.Clean(tr.Path) != childDir || !fired.CompareAndSwap(false, true) {
					return
				}
				// This walk has removed child/. Another one removes the rest
				// of the chain, then a writer commits the object parent,
				// whose metadata file is parent/xl.meta.
				for _, dir := range []string{metaDir, parentDir} {
					if err := os.Remove(dir); err != nil {
						hookErr = err
						return
					}
				}
				if _, err := s.RenameData(context.Background(), minioMetaTmpBucket, "writer", parentFI, "bucket", parent, RenameOptions{}); err != nil {
					hookErr = err
				}
			})

			switch tc {
			case "delete_version":
				err = s.DeleteVersion(ctx, "bucket", nested, nestedFI, false, DeleteOptions{})
			case "data_rename":
				// The staged data directory is gone.
				fi := newFI(nested)
				fi.Size = 1
				fi.AddObjectPart(1, "", 1, 1, fi.ModTime, nil, nil)
				_, err = s.RenameData(ctx, minioMetaTmpBucket, "late", fi, "bucket", nested, RenameOptions{})
			case "commit":
				mctx := &missingCommitMetaContext{
					Context: ctx,
					meta:    filepath.Join(root, minioMetaTmpBucket, "late", xlStorageFormatFile),
				}
				_, err = s.RenameData(mctx, minioMetaTmpBucket, "late", newFI(nested), "bucket", nested, RenameOptions{})
			}
			if tc == "delete_version" && err != nil {
				t.Fatal(err)
			}
			if tc != "delete_version" && err == nil {
				t.Fatal("RenameData succeeded without its staged data")
			}
			if !fired.Load() {
				t.Fatalf("%s did not remove the empty directory %s", tc, nested)
			}
			if hookErr != nil {
				t.Fatal(hookErr)
			}
			got, err := s.ReadVersion(ctx, "", "bucket", parent, parentFI.VersionID, ReadOptions{ReadData: true})
			if err != nil {
				t.Fatalf("committed object %s lost: %v", parent, err)
			}
			if !bytes.Equal(got.Data, parentFI.Data) {
				t.Fatalf("committed object %s has data %q, want %q", parent, got.Data, parentFI.Data)
			}
		})
	}
}

// A cleanup that walks up removes each empty directory of a write's
// destination path once. When it removes them one by one while the write
// creates them, so that every directory the write has just made or found is
// gone before it uses it, the write must keep retrying until the walk has
// passed and then succeed. That holds also when another write recreates the
// directories after a failed attempt, which must not hide the failure.
func TestXLStorageRenameDataRetriesWhileCleanupWalksUp(t *testing.T) {
	if runtime.GOOS == globalWindowsOSName {
		t.Skip("directory creation is not traced on Windows")
	}
	const object = "a/b/object"
	for _, tc := range []struct {
		name           string
		inline, nested bool
	}{
		{"data_dir", false, false},
		{"inline", true, false},
		{"data_dir_nested_writer", false, true},
	} {
		inline := tc.inline
		t.Run(tc.name, func(t *testing.T) {
			disk, root, err := newXLStorageTestSetup(t)
			if err != nil {
				t.Fatal(err)
			}
			defer disk.Close()
			s := disk.storage
			ctx := t.Context()
			if err := s.MakeVol(ctx, "bucket"); err != nil {
				t.Fatal(err)
			}
			fi := newFileInfo(object, 2, 2)
			fi.DataDir, fi.VersionID = mustGetUUID(), mustGetUUID()
			fi.Erasure.Index = 1
			fi.ModTime = time.Now().UTC()
			fi.Fresh = true
			fi.Size = 1
			fi.AddObjectPart(1, "", 1, 1, fi.ModTime, nil, nil)
			if inline {
				fi.Data = []byte("x")
				fi.SetInlineData()
			} else {
				part := filepath.Join(root, minioMetaTmpBucket, "staged", fi.DataDir, "part.1")
				if err := os.MkdirAll(filepath.Dir(part), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(part, []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			objDir := filepath.Join(root, "bucket", filepath.FromSlash(object))
			bDir := filepath.Dir(objDir)
			aDir := filepath.Dir(bDir)
			// The walk removes object/, then b/, then a/. Each step happens
			// right after the write's next directory creation reached the
			// directory, whether it created it or found it in place.
			remove := func(dir string) func() error { return func() error { return os.Remove(dir) } }
			steps := []struct {
				after string
				do    func() error
			}{
				{objDir, remove(objDir)},
				{bDir, remove(bDir)},
				{aDir, remove(aDir)},
			}
			if tc.nested {
				// The next creation of b/ fails. A write of the key
				// a/b/object/child then creates the directories again.
				steps = append(steps, struct {
					after string
					do    func() error
				}{bDir, func() error { return os.MkdirAll(filepath.Join(objDir, "child"), 0o755) }})
			}
			var mu sync.Mutex
			step := 0
			var hookErr error
			traceOSCalls(t, func(tr madmin.TraceInfo) {
				if tr.FuncName != "os.Mkdir" {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if step == len(steps) || filepath.Clean(tr.Path) != steps[step].after {
					return
				}
				if err := steps[step].do(); err != nil && hookErr == nil {
					hookErr = err
				}
				step++
			})
			_, err = s.RenameData(ctx, minioMetaTmpBucket, "staged", fi, "bucket", object, RenameOptions{})
			mu.Lock()
			done := step
			mu.Unlock()
			if hookErr != nil {
				t.Fatal(hookErr)
			}
			if done != len(steps) {
				t.Fatalf("the walk made %d of %d steps", done, len(steps))
			}
			if err != nil {
				t.Fatalf("write failed while a cleanup walked up its path: %v", err)
			}
			got, err := s.ReadVersion(ctx, "", "bucket", object, fi.VersionID, ReadOptions{ReadData: true})
			if err != nil {
				t.Fatal(err)
			}
			if got.Size != fi.Size {
				t.Fatalf("committed size %d, want %d", got.Size, fi.Size)
			}
		})
	}
}

// A failed RenameData that runs late, after its caller gave up, removes its
// empty object directory and the empty parents. When it does so right after
// another write of the same key created the object directory, that write
// must create the directory again and succeed, whichever way it writes its
// metadata file: a fresh xl.meta opened in place (a delete marker on an
// absent key), a first version of a key without xl.meta, or a large xl.meta
// written directly. A cleanup that walks up the whole path, one directory
// per step, is survived as well. UpdateMetadata renames over an existing
// xl.meta, so its directory is never empty and the cleanup cannot remove it.
func TestXLStorageMetadataWriteSurvivesLateCleanup(t *testing.T) {
	if runtime.GOOS == globalWindowsOSName {
		t.Skip("directory creation is not traced on Windows")
	}
	const object = "a/b/object"
	writers := []struct {
		name  string
		write func(ctx context.Context, s *xlStorage, fi FileInfo) (FileInfo, error)
	}{
		{"delete_marker", func(ctx context.Context, s *xlStorage, fi FileInfo) (FileInfo, error) {
			// DeleteVersion with forceDelMarker on a key without xl.meta.
			fi.Deleted, fi.Fresh = true, true
			return fi, s.WriteMetadata(ctx, "", "bucket", object, fi)
		}},
		{"first_version", func(ctx context.Context, s *xlStorage, fi FileInfo) (FileInfo, error) {
			// Not fresh: the missing xl.meta is read first.
			fi.Size, fi.Data = 1, []byte("x")
			fi.AddObjectPart(1, "", 1, 1, fi.ModTime, nil, nil)
			fi.SetInlineData()
			return fi, s.WriteMetadata(ctx, "", "bucket", object, fi)
		}},
		{"direct_write", func(ctx context.Context, s *xlStorage, fi FileInfo) (FileInfo, error) {
			// Larger than the direct I/O alignment: written through
			// writeAllDirect, with O_DIRECT where supported.
			fi.Metadata = map[string]string{"x-amz-meta-pad": strings.Repeat("p", 2*xioutil.DirectioAlignSize)}
			var xlMeta xlMetaV2
			if err := xlMeta.AddVersion(fi); err != nil {
				return fi, err
			}
			buf, err := xlMeta.AppendTo(nil)
			if err != nil {
				return fi, err
			}
			return fi, s.WriteAll(ctx, "bucket", pathJoin(object, xlStorageFormatFile), buf)
		}},
	}
	for _, wr := range writers {
		for _, walkUp := range []bool{false, true} {
			name := wr.name + "/late_rename_data"
			if walkUp {
				name = wr.name + "/walk_up"
			}
			t.Run(name, func(t *testing.T) {
				disk, root, err := newXLStorageTestSetup(t)
				if err != nil {
					t.Fatal(err)
				}
				defer disk.Close()
				s := disk.storage
				ctx := t.Context()
				if err := s.MakeVol(ctx, "bucket"); err != nil {
					t.Fatal(err)
				}
				objDir := filepath.Join(root, "bucket", filepath.FromSlash(object))
				bDir := filepath.Dir(objDir)
				aDir := filepath.Dir(bDir)
				fi := newFileInfo(object, 2, 2)
				fi.DataDir, fi.VersionID = mustGetUUID(), mustGetUUID()
				fi.Erasure.Index = 1
				fi.ModTime = time.Now().UTC()

				// The walk removes object/, then b/, then a/, each right after
				// the write's next directory creation reached it, whether it
				// created the directory or found it in place.
				walk := []string{objDir, bDir, aDir}
				var mu sync.Mutex
				steps := 0
				var hookErrs []error
				var fired atomic.Bool
				traceOSCalls(t, func(tr madmin.TraceInfo) {
					if tr.FuncName != "os.Mkdir" {
						return
					}
					if walkUp {
						mu.Lock()
						defer mu.Unlock()
						if steps == len(walk) || filepath.Clean(tr.Path) != walk[steps] {
							return
						}
						if err := os.Remove(walk[steps]); err != nil {
							hookErrs = append(hookErrs, err)
						}
						steps++
						return
					}
					if tr.Error != "" || filepath.Clean(tr.Path) != objDir || !fired.CompareAndSwap(false, true) {
						return
					}
					// The write has just created the object directory. A late
					// RenameData of the same key, whose staged data is gone,
					// fails now and removes the directory and its empty parents.
					late := newFileInfo(object, 2, 2)
					late.DataDir, late.VersionID = mustGetUUID(), mustGetUUID()
					late.Erasure.Index = 1
					late.ModTime = time.Now().UTC()
					late.Size = 1
					late.AddObjectPart(1, "", 1, 1, late.ModTime, nil, nil)
					_, err := s.RenameData(context.Background(), minioMetaTmpBucket, mustGetUUID(), late, "bucket", object, RenameOptions{})
					var errs []error
					if !errors.Is(err, errFileNotFound) {
						errs = append(errs, fmt.Errorf("late RenameData returned %v, want %v", err, errFileNotFound))
					}
					if _, serr := os.Stat(objDir); !os.IsNotExist(serr) {
						errs = append(errs, fmt.Errorf("late RenameData left %s (%v)", objDir, serr))
					}
					mu.Lock()
					hookErrs = append(hookErrs, errs...)
					steps++
					mu.Unlock()
				})

				fi, err = wr.write(ctx, s, fi)
				mu.Lock()
				done, errs := steps, hookErrs
				mu.Unlock()
				for _, herr := range errs {
					t.Error(herr)
				}
				if err != nil {
					t.Fatalf("%s failed after a concurrent cleanup: %v", wr.name, err)
				}
				want := 1
				if walkUp {
					want = len(walk)
				}
				if done != want {
					t.Fatalf("the cleanup made %d of %d steps", done, want)
				}
				got, err := s.ReadVersion(ctx, "", "bucket", object, fi.VersionID, ReadOptions{ReadData: true})
				if err != nil {
					t.Fatalf("written version lost: %v", err)
				}
				if got.VersionID != fi.VersionID || got.Deleted != fi.Deleted || !bytes.Equal(got.Data, fi.Data) {
					t.Fatalf("read back version %s deleted=%v data=%q, want %s deleted=%v data=%q",
						got.VersionID, got.Deleted, got.Data, fi.VersionID, fi.Deleted, fi.Data)
				}
			})
		}
	}
}
