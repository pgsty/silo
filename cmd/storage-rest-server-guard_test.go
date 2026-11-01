// Copyright (c) 2015-2026 MinIO, Inc.
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
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7/pkg/s3utils"
)

// poisonStorage implements StorageAPI with a nil embedded interface, so any
// call that reaches it panics. guardedStorage must never delegate a traversing
// path to it.
type poisonStorage struct {
	StorageAPI
}

// volumeOnlyOrPathless lists the StorageAPI methods guardedStorage
// deliberately does not override, with the reason each is safe.
//
// Adding a method to StorageAPI without either guarding it or adding it here
// with a reason makes TestGuardedStorageCoversEveryPathMethod fail.
var volumeOnlyOrPathless = map[string]string{
	// No filesystem path in the signature at all.
	"String": "identity", "IsOnline": "status", "LastConn": "status",
	"IsLocal": "topology", "Hostname": "topology", "Endpoint": "topology",
	"Close": "lifecycle", "GetDiskID": "identity", "SetDiskID": "identity",
	"Healing": "status", "GetDiskLoc": "topology", "DiskInfo": "no path field",
	"ListVols": "no argument",

	// Volume-only. xlStorage.getVolDir validates the volume at the sink, which
	// also covers the peer-S3 callers that never pass through this wrapper.
	"MakeVol":     "volume-only, guarded by getVolDir",
	"MakeVolBulk": "volume-only, guarded by getVolDir",
	"StatVol":     "volume-only, guarded by getVolDir",
	"DeleteVol":   "volume-only, guarded by getVolDir",
}

// TestGuardedStorageCoversEveryPathMethod calls every StorageAPI method on a
// guardedStorage whose embedded storage panics, passing "../evil" in every
// string it can reach - including strings nested inside structs and slices,
// which is where a hand-written check is most likely to miss one.
//
// A method that returns without panicking rejected the path. A method that
// panics delegated it.
func TestGuardedStorageCoversEveryPathMethod(t *testing.T) {
	g := reflect.ValueOf(guardedStorage{poisonStorage{}})
	iface := reflect.TypeOf((*StorageAPI)(nil)).Elem()

	for i := range iface.NumMethod() {
		name := iface.Method(i).Name
		if reason, ok := volumeOnlyOrPathless[name]; ok {
			t.Logf("skipping %s: %s", name, reason)
			continue
		}
		m := g.MethodByName(name)
		if !m.IsValid() {
			t.Errorf("%s: not found on guardedStorage", name)
			continue
		}
		mt := m.Type()
		args := make([]reflect.Value, mt.NumIn())
		for j := range args {
			args[j] = poisonArg(t, mt.In(j))
		}
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s delegated a traversing path to the underlying storage "+
						"- it is not guarded. Add a guardedStorage override, or add it to "+
						"volumeOnlyOrPathless with a reason. (%v)", name, r)
				}
			}()
			if mt.IsVariadic() {
				m.CallSlice(args)
			} else {
				m.Call(args)
			}
		})
	}
}

// OldDataDir can reach renameAll during rollback. Guard it independently of
// which handlers currently forward deletion options.
func TestGuardChecksDeleteOptionPaths(t *testing.T) {
	g := guardedStorage{poisonStorage{}}
	ctx := context.Background()

	if err := g.DeleteVersion(ctx, "foo", "obj", FileInfo{}, false,
		DeleteOptions{OldDataDir: poisonPath}); !errors.Is(err, errFileAccessDenied) {
		t.Errorf("DeleteVersion with a traversing OldDataDir: got %v, want %v", err, errFileAccessDenied)
	}

	errs := g.DeleteVersions(ctx, "foo", []FileInfoVersions{{Name: "obj"}},
		DeleteOptions{OldDataDir: poisonPath})
	if len(errs) != 1 || !errors.Is(errs[0], errFileAccessDenied) {
		t.Errorf("DeleteVersions with a traversing OldDataDir: got %v, want %v", errs, errFileAccessDenied)
	}

	if err := g.Delete(ctx, "foo", "obj", DeleteOptions{OldDataDir: poisonPath}); !errors.Is(err, errFileAccessDenied) {
		t.Errorf("Delete with a traversing OldDataDir: got %v, want %v", err, errFileAccessDenied)
	}
}

const poisonPath = "../evil"

func poisonArg(t *testing.T, typ reflect.Type) reflect.Value {
	t.Helper()
	switch typ {
	case reflect.TypeOf((*context.Context)(nil)).Elem():
		return reflect.ValueOf(context.Background())
	case reflect.TypeOf((*io.Writer)(nil)).Elem():
		return reflect.ValueOf(io.Discard)
	case reflect.TypeOf((*io.Reader)(nil)).Elem():
		return reflect.ValueOf(bytes.NewReader(nil))
	}
	if typ.Kind() == reflect.Chan {
		// NSScanner's updates channel: the guard is required to close it.
		return reflect.MakeChan(reflect.ChanOf(reflect.BothDir, typ.Elem()), 1).Convert(typ)
	}
	return poisonValue(typ, 0)
}

// poisonValue builds a value of typ with every settable string set to
// poisonPath, recursing into structs, slices and pointers.
func poisonValue(typ reflect.Type, depth int) reflect.Value {
	v := reflect.New(typ).Elem()
	if depth > 4 {
		return v
	}
	switch typ.Kind() {
	case reflect.String:
		v.SetString(poisonPath)
	case reflect.Struct:
		for i := range typ.NumField() {
			f := v.Field(i)
			if !f.CanSet() {
				continue // unexported
			}
			// Skip self-referential and container types we cannot poison
			// meaningfully; the fields that matter are plain strings.
			switch f.Kind() {
			case reflect.Map, reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
				continue
			}
			f.Set(poisonValue(f.Type(), depth+1))
		}
	case reflect.Slice:
		s := reflect.MakeSlice(typ, 1, 1)
		s.Index(0).Set(poisonValue(typ.Elem(), depth+1))
		v.Set(s)
	case reflect.Pointer:
		p := reflect.New(typ.Elem())
		p.Elem().Set(poisonValue(typ.Elem(), depth+1))
		v.Set(p)
	}
	return v
}

func TestIsVolumeRootAlias(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		// Collapse back to the volume directory.
		{"", true},
		{"/", true},
		{"//", true},
		// Backslash is platform-dependent; see TestIsVolumeRootAliasIsPlatformCorrect.
		// Whitespace is NOT a separator. path.Clean leaves it alone, so these
		// name real directories and are legal S3 object keys.
		{" ", false},
		{"  ", false},
		{"\t", false},
		{"\n", false},
		{" / ", false},
		{"/ ", false},
		{"a", false},
		{"/a", false},
		{"..", false},
		{" a ", false},
		{"obj/part.1", false},
	} {
		if got := isVolumeRootAlias(tc.path); got != tc.want {
			t.Errorf("isVolumeRootAlias(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// guardMayRefuse reports whether the guards are permitted to refuse a name that
// IsValidObjectName accepts. On Unix the answer is never: no legal object name
// is made up entirely of '/', so the invariant below carries NO exceptions.
//
// Stated in terms of the separator set rather than by calling isVolumeRootAlias,
// so that widening that function cannot silently widen what the test forgives.
// Two regressions have already hidden in exactly that gap: whitespace was once
// counted as a separator (refusing the legal key "  "), and an earlier version
// of this helper excused every backslash-only name on every platform, which is
// why the fuzzer could not see that bug at all.
func guardMayRefuse(name string) bool {
	if runtime.GOOS != globalWindowsOSName {
		return false
	}
	// Mirrors the Windows branch of isVolumeRootAliasOn: separators plus the
	// characters Win32 strips from a component.
	return strings.Trim(name, "/\\ .") == ""
}

func TestIsVolumeRootAliasIsPlatformCorrect(t *testing.T) {
	for _, tc := range []struct {
		path              string
		unix, windowsWant bool
	}{
		{"", true, true},
		{"/", true, true},
		{"//", true, true},
		// Backslash: an ordinary filename on Unix, a separator on Windows.
		{"\\", false, true},
		{"\\\\", false, true},
		{"/\\", false, true},
		// Space and period: ordinary filename characters on Unix, but stripped
		// from a component by Win32 normalisation, so a component made only of
		// them vanishes and the path resolves to the volume root.
		{" ", false, true},
		{"  ", false, true},
		{" / ", false, true},
		{"...", false, true},
		{". .", false, true},
		// Never an alias anywhere.
		{"\t", false, false},
		{"\n", false, false},
		{"a", false, false},
		{"/a", false, false},
		{"a ", false, false},
		{" a", false, false},
		{"a.", false, false},
	} {
		if got := isVolumeRootAliasOn(tc.path, false); got != tc.unix {
			t.Errorf("isVolumeRootAliasOn(%q, unix) = %v, want %v", tc.path, got, tc.unix)
		}
		if got := isVolumeRootAliasOn(tc.path, true); got != tc.windowsWant {
			t.Errorf("isVolumeRootAliasOn(%q, windows) = %v, want %v", tc.path, got, tc.windowsWant)
		}
	}
}

// TestGuardAcceptsEveryLegalObjectName pins the invariant that actually matters
// for availability: if S3 accepts a name, the guards must accept it too.
//
// A guard that rejects a legal object name breaks writes on every remote drive
// simultaneously, which fails quorum - a worse outage than the vulnerability it
// defends against. This caught a real regression: isVolumeRootAlias originally
// treated whitespace as a separator, so a legal key of "  " was refused on the
// PutObject commit path.
func TestGuardAcceptsEveryLegalObjectName(t *testing.T) {
	names := []string{
		// Whitespace, in every position. All legal in S3.
		" ", "  ", "\t", "\n", "a b", " a", "a ", " a ", " / ", "/ ",
		// Dots that are not "." or ".." segments.
		"..foo", "foo..", ".hidden", "a/..b", "a/b..", "a.b/c..d",
		// "..." is a legal key on Unix and accepted; on Windows it is a volume-root
		// alias (Win32 strips trailing periods) and guardMayRefuse excuses it there.
		"part.1.meta", "...", "a/...",
		// Ordinary shapes.
		"a", "/a", "a/b/c", "obj/part.1", "__XLDIR__",
		"unicode/文件/名", "emoji/🙂", "pct%2e%2e/x",
		// Long-ish and punctuation-heavy.
		"a-b_c+d=e,f:g;h@i", "x!y'z(1)2*3",
		// Backslashes: ordinary filename characters on Unix.
		"\\", "\\\\", "/\\", "a\\b", "\\a", "a\\",
	}
	for _, name := range names {
		if !IsValidObjectName(name) {
			continue // S3 refuses it first; the guard is free to as well.
		}
		t.Run(name, func(t *testing.T) {
			if err := guardPaths(name); err != nil {
				t.Errorf("guardPaths(%q) = %v, but S3 accepts this object name", name, err)
			}
			if err := guardObjectPaths(name); err != nil {
				if guardMayRefuse(name) {
					t.Logf("allowed on this platform (%q): separator-only, addresses the volume root", name)
					return
				}
				t.Errorf("guardObjectPaths(%q) = %v, but S3 accepts this object name. "+
					"A guard that refuses a legal key fails writes on every drive at once.", name, err)
			}
		})
	}
}

// FuzzGuardAcceptsLegalObjectNames searches for more of the above. The property
// is one-directional on purpose: we assert the guards never refuse something S3
// allows, and say nothing about names S3 already refuses.
func FuzzGuardAcceptsLegalObjectNames(f *testing.F) {
	for _, seed := range []string{" ", "  ", "\t", "a b", "..foo", "a/..b", "/", "", "\\", "\\\\\\", "a/../b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if !IsValidObjectName(name) {
			return
		}
		if guardMayRefuse(name) {
			return
		}
		if err := guardPaths(name); err != nil {
			t.Fatalf("guardPaths(%q) = %v, but IsValidObjectName accepts it", name, err)
		}
		if err := guardObjectPaths(name); err != nil {
			t.Fatalf("guardObjectPaths(%q) = %v, but IsValidObjectName accepts it", name, err)
		}
	})
}

// FuzzGetVolDirAcceptsLegalBucketNames is the volume-axis twin of the object
// invariant above. G-A adds hasBadPathComponent to getVolDir, so any bucket
// name S3 accepts must survive it, or MakeBucket/HeadBucket/DeleteBucket start
// failing for legitimate buckets across the whole cluster.
func FuzzGetVolDirAcceptsLegalBucketNames(f *testing.F) {
	for _, seed := range []string{"bucket", "my-bucket", "a.b.c", "1234", "x--y", "..", "a..b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if s3utils.CheckValidBucketName(name) != nil {
			return // S3 refuses it first; getVolDir is free to as well.
		}
		if hasBadPathComponent(name) {
			t.Fatalf("getVolDir would reject %q, but s3utils.CheckValidBucketName accepts it", name)
		}
	})
}

// TestGetVolDirAcceptsReservedVolumes covers the volume names the server uses
// internally, which are not buckets and so are not covered by the fuzz above.
func TestGetVolDirAcceptsReservedVolumes(t *testing.T) {
	for _, vol := range []string{
		minioMetaBucket, minioMetaTmpBucket, minioMetaTmpDeletedBucket,
		minioMetaMultipartBucket, minioReservedBucket,
		pathJoin(minioMetaBucket, bucketMetaPrefix),
		pathJoin(minioMetaBucket, bucketMetaPrefix, deletedBucketsPrefix, "some-bucket"),
	} {
		if hasBadPathComponent(vol) {
			t.Errorf("getVolDir would reject the reserved volume %q", vol)
		}
	}
}

func TestGuardPathsAcceptsReservedNames(t *testing.T) {
	// Reserved volumes and directories contain dot-prefixed segments. Only an
	// exact "." or ".." segment is a traversal.
	for _, p := range []string{
		"", minioMetaBucket, minioMetaTmpBucket, minioMetaTmpDeletedBucket,
		minioMetaMultipartBucket, ".deleted", "obj/part.1.meta",
		"a.b/c..d", "__XLDIR__", "bucket/.metacache/x.s2",
	} {
		if err := guardPaths(p); err != nil {
			t.Errorf("guardPaths(%q) = %v, want nil", p, err)
		}
	}
	for _, p := range traversalPaths {
		if err := guardPaths(p); err == nil {
			t.Errorf("guardPaths(%q) = nil, want %v", p, errFileAccessDenied)
		}
	}
}
