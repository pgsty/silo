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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/minio/madmin-go/v3"
)

// TestObjectNamingEncodeDecode pins the on-disk naming transformation,
// including every example from the extended naming documentation.
func TestObjectNamingEncodeDecode(t *testing.T) {
	previous := globalObjectNamingExtended
	globalObjectNamingExtended = true
	defer func() { globalObjectNamingExtended = previous }()

	// v1 keeps the S3 key restrictions unchanged: "//" and leading "/" are
	// rejected at the API boundary before reaching the encoder, and a trailing
	// slash still uses the legacy __XLDIR__ representation. The escape
	// machinery exists to keep every legal key unambiguous on disk.
	encodeCases := []struct{ in, want string }{
		{"obj1", "obj1◊"},
		{"obj1/obj2", "obj1/obj2◊"},
		{"data◊file.txt", "data␣4file.txt◊"},
		{"a␣b", "a␣0b◊"},
		{"x⫽y", "x␣1y◊"},
		{"q◖r", "q␣2r◊"},
		{"q◗r", "q␣3r◊"},
		{"r◉s", "r␣5s◊"},
		{"r◈s", "r␣6s◊"},
		{"r◇s", "r␣7s◊"},
		{"r◆s", "r␣8s◊"},
		{"r⬡s", "r␣9s◊"},
	}
	for _, tc := range encodeCases {
		if got := encodeObjectName(tc.in); got != tc.want {
			t.Errorf("encodeObjectName(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got := decodeObjectName(tc.want); got != tc.in {
			t.Errorf("decodeObjectName(%q) = %q, want %q", tc.want, got, tc.in)
		}
	}

	// A trailing-slash key is a directory object: it keeps the legacy
	// __XLDIR__ form (the documented v1 choice) and round-trips.
	if got := encodeObjectName("myobject/"); got != "myobject__XLDIR__" {
		t.Errorf("directory object encoding = %q", got)
	}
	for _, name := range []string{"obj1/", "a␣b/", "x◊/"} {
		enc := encodeObjectName(name)
		if enc != escapeExtendedNaming(name[:len(name)-1])+globalDirSuffix {
			t.Fatalf("directory object %q encoded as %q", name, enc)
		}
		if got := decodeObjectName(enc); got != name {
			t.Errorf("decodeObjectName(%q) = %q, want %q", enc, got, name)
		}
	}

	// The pre-normalized directory-object form is accepted too (the scanner
	// passes it exactly as in safe mode).
	if got := encodeObjectName("obj1__XLDIR__"); got != "obj1__XLDIR__" {
		t.Errorf("encodeObjectName(pre-normalized dir object) = %q", got)
	}

	// Prefixes are escaped without a terminal marker.
	if got := encodeObjectPrefixName("a◊/b/"); got != "a␣4/b/" {
		t.Errorf("encodeObjectPrefixName = %q", got)
	}

	// Meta buckets are never transformed.
	if got := encodeObjectNameForBucket(minioMetaBucket, "config/x.json"); got != "config/x.json" {
		t.Errorf("meta bucket object was transformed: %q", got)
	}

	// Safe mode keeps the historical behavior.
	globalObjectNamingExtended = false
	if got := encodeObjectName("obj1"); got != "obj1" {
		t.Errorf("safe mode encodeObjectName = %q", got)
	}
	if got := encodeObjectName("obj1/"); got != "obj1__XLDIR__" {
		t.Errorf("safe mode directory object = %q", got)
	}
	if got := decodeObjectName("obj1__XLDIR__"); got != "obj1/" {
		t.Errorf("safe mode decodeObjectName = %q", got)
	}
}

// TestObjectNamingPrefixEscapeIsOrderPreserving verifies the per-character
// escape keeps the relative order of ordinary (non-reserved) characters, which
// the walk relies on for FilterPrefix and ForwardTo.
func TestObjectNamingPrefixEscapeIsOrderPreserving(t *testing.T) {
	previous := globalObjectNamingExtended
	globalObjectNamingExtended = true
	defer func() { globalObjectNamingExtended = previous }()

	samples := []string{
		"a", "ab", "a/b", "a/bc", "a0", "a b", "a-b", "a.b", "a~", "a中", "a z",
	}
	for i := range samples {
		for j := range samples {
			if samples[i] < samples[j] {
				if escapeExtendedNaming(samples[i]) >= escapeExtendedNaming(samples[j]) {
					t.Fatalf("escape reordered %q and %q", samples[i], samples[j])
				}
			}
			if samples[i] == samples[j] && escapeExtendedNaming(samples[i]) != escapeExtendedNaming(samples[j]) {
				t.Fatalf("escape not injective for %q", samples[i])
			}
		}
	}
}

// newExtendedNamingPool starts an erasure pool formatted with the extended
// object naming mode and returns it with a fresh bucket.
func newExtendedNamingPool(t *testing.T, nDisks int, bucketOpts MakeBucketOptions) (*erasureServerPools, []string, string) {
	t.Helper()

	previousMode := globalObjectNaming
	previousExtended := globalObjectNamingExtended
	globalObjectNaming = objectNamingExtended
	globalObjectNamingExtended = false
	t.Cleanup(func() {
		globalObjectNaming = previousMode
		globalObjectNamingExtended = previousExtended
	})

	ctx, cancel := context.WithCancel(t.Context())
	fsDirs, err := getRandomDisks(nDisks)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	obj, _, err := initObjectLayer(ctx, mustGetPoolEndpoints(0, fsDirs...))
	if err != nil {
		cancel()
		removeRoots(fsDirs)
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	t.Cleanup(func() {
		cancel()
		z.Shutdown(context.Background())
		removeRoots(fsDirs)
		setObjectLayer(previous)
	})
	if !globalObjectNamingExtended {
		t.Fatal("extended object naming was not enabled by the format")
	}

	bucket := getRandomBucketName()
	if err := z.MakeBucket(t.Context(), bucket, bucketOpts); err != nil {
		t.Fatal(err)
	}
	return z, fsDirs, bucket
}

func putTestObject(t *testing.T, z *erasureServerPools, bucket, name string) {
	t.Helper()
	body := []byte("body of " + name)
	if _, err := z.PutObject(t.Context(), bucket, name,
		mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), ObjectOptions{}); err != nil {
		t.Fatalf("PUT %q: %v", name, err)
	}
}

func readTestObject(t *testing.T, z *erasureServerPools, bucket, name string) string {
	t.Helper()
	gr, err := z.GetObjectNInfo(t.Context(), bucket, name, nil, nil, ObjectOptions{})
	if err != nil {
		t.Fatalf("GET %q: %v", name, err)
	}
	defer gr.Close()
	buf, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("read %q: %v", name, err)
	}
	return string(buf)
}

func listObjectNames(t *testing.T, z *erasureServerPools, bucket, prefix, delimiter string) (objs, prefixes []string) {
	t.Helper()
	loi, err := z.ListObjects(t.Context(), bucket, prefix, "", delimiter, 10000)
	if err != nil {
		t.Fatalf("LIST prefix=%q delimiter=%q: %v", prefix, delimiter, err)
	}
	for _, obj := range loi.Objects {
		objs = append(objs, obj.Name)
	}
	return objs, loi.Prefixes
}

// TestExtendedNamingConflictingObjects is the end-to-end matrix from the
// conflict analysis: an object and its own prefix must both be listed, read,
// and deleted independently.
func TestExtendedNamingConflictingObjects(t *testing.T) {
	z, fsDirs, bucket := newExtendedNamingPool(t, 16, MakeBucketOptions{})
	ctx := t.Context()

	putTestObject(t, z, bucket, "obj1")
	putTestObject(t, z, bucket, "obj1/obj2")

	// The disk layout must keep object and prefix directories apart.
	for _, want := range []string{
		filepath.Join(bucket, "obj1◊", xlStorageFormatFile),
		filepath.Join(bucket, "obj1", "obj2◊", xlStorageFormatFile),
	} {
		p := filepath.Join(fsDirs[0], want)
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("expected object directory %q: %v", p, err)
		}
	}

	// Both keys read normally.
	if got := readTestObject(t, z, bucket, "obj1"); got != "body of obj1" {
		t.Fatalf("GET obj1 = %q", got)
	}
	if got := readTestObject(t, z, bucket, "obj1/obj2"); got != "body of obj1/obj2" {
		t.Fatalf("GET obj1/obj2 = %q", got)
	}

	// Root, delimiter '/': object and prefix both appear.
	objs, prefixes := listObjectNames(t, z, bucket, "", "/")
	if len(objs) != 1 || objs[0] != "obj1" {
		t.Fatalf("root delimiter list objects = %v", objs)
	}
	if len(prefixes) != 1 || prefixes[0] != "obj1/" {
		t.Fatalf("root delimiter list prefixes = %v", prefixes)
	}

	// Recursive: both keys, in S3 order.
	objs, prefixes = listObjectNames(t, z, bucket, "", "")
	if len(prefixes) != 0 {
		t.Fatalf("recursive list returned prefixes: %v", prefixes)
	}
	if len(objs) != 2 || objs[0] != "obj1" || objs[1] != "obj1/obj2" {
		t.Fatalf("recursive list = %v", objs)
	}

	// Listing the prefix that is also an object name.
	objs, _ = listObjectNames(t, z, bucket, "obj1/", "")
	if len(objs) != 1 || objs[0] != "obj1/obj2" {
		t.Fatalf("prefix obj1/ list = %v", objs)
	}
	objs, _ = listObjectNames(t, z, bucket, "obj1/obj2", "")
	if len(objs) != 1 || objs[0] != "obj1/obj2" {
		t.Fatalf("exact key list = %v", objs)
	}

	// Resuming from a marker that is the prefix itself must not lose or repeat
	// the child.
	loi, err := z.ListObjects(ctx, bucket, "", "obj1/", "", 1000)
	if err != nil {
		t.Fatalf("LIST after prefix marker: %v", err)
	}
	if len(loi.Objects) != 1 || loi.Objects[0].Name != "obj1/obj2" {
		t.Fatalf("LIST after prefix marker = %v", loi.Objects)
	}

	// Pagination across the conflict point: one key per page, no duplicates,
	// no losses.
	var paged []string
	marker := ""
	for {
		loi, err := z.ListObjects(ctx, bucket, "", marker, "", 1)
		if err != nil {
			t.Fatalf("paged LIST: %v", err)
		}
		for _, obj := range loi.Objects {
			if len(paged) > 0 && paged[len(paged)-1] >= obj.Name {
				t.Fatalf("paged list out of order: %v then %q", paged, obj.Name)
			}
			paged = append(paged, obj.Name)
		}
		if !loi.IsTruncated {
			break
		}
		marker = loi.NextMarker
		if len(paged) > 10 {
			t.Fatal("paged list did not terminate")
		}
	}
	if len(paged) != 2 || paged[0] != "obj1" || paged[1] != "obj1/obj2" {
		t.Fatalf("paged list = %v", paged)
	}

	// Deleting the parent object must not touch the child.
	if _, err := z.DeleteObject(ctx, bucket, "obj1", ObjectOptions{}); err != nil {
		t.Fatalf("DELETE obj1: %v", err)
	}
	if _, err := z.GetObjectInfo(ctx, bucket, "obj1", ObjectOptions{}); !isErrObjectNotFound(err) {
		t.Fatalf("obj1 still readable after delete: %v", err)
	}
	if got := readTestObject(t, z, bucket, "obj1/obj2"); got != "body of obj1/obj2" {
		t.Fatalf("child damaged by parent delete: %q", got)
	}
	objs, prefixes = listObjectNames(t, z, bucket, "", "/")
	if len(objs) != 0 || len(prefixes) != 1 || prefixes[0] != "obj1/" {
		t.Fatalf("after parent delete: objects=%v prefixes=%v", objs, prefixes)
	}

	// Healing addresses both keys through the same transformation.
	if _, err := z.HealObject(ctx, bucket, "obj1/obj2", "", madmin.HealOpts{ScanMode: madmin.HealNormalScan}); err != nil {
		t.Fatalf("heal child: %v", err)
	}

	// Overwriting the parent again keeps the child intact.
	putTestObject(t, z, bucket, "obj1")
	if got := readTestObject(t, z, bucket, "obj1/obj2"); got != "body of obj1/obj2" {
		t.Fatalf("child damaged by parent overwrite: %q", got)
	}
	objs, _ = listObjectNames(t, z, bucket, "", "")
	if len(objs) != 2 || objs[0] != "obj1" || objs[1] != "obj1/obj2" {
		t.Fatalf("recursive list after overwrite = %v", objs)
	}
}

// TestExtendedNamingVersioned runs the same conflict through a versioned
// bucket, including delete markers and ListObjectVersions.
func TestExtendedNamingVersioned(t *testing.T) {
	z, _, bucket := newExtendedNamingPool(t, 16, MakeBucketOptions{VersioningEnabled: true})
	ctx := t.Context()

	putTestObject(t, z, bucket, "obj1")
	putTestObject(t, z, bucket, "obj1/obj2")

	loi, err := z.ListObjectVersions(ctx, bucket, "", "", "", "", 10000)
	if err != nil {
		t.Fatalf("ListObjectVersions: %v", err)
	}
	names := map[string]bool{}
	for _, obj := range loi.Objects {
		names[obj.Name] = true
	}
	if !names["obj1"] || !names["obj1/obj2"] {
		t.Fatalf("ListObjectVersions missing conflict keys: %v", loi.Objects)
	}

	// A delete marker on the parent hides only the parent.
	if _, err := z.DeleteObject(ctx, bucket, "obj1", ObjectOptions{}); err != nil {
		t.Fatalf("DELETE obj1: %v", err)
	}
	objs, _ := listObjectNames(t, z, bucket, "", "")
	if len(objs) != 1 || objs[0] != "obj1/obj2" {
		t.Fatalf("recursive list after marker = %v", objs)
	}
	if got := readTestObject(t, z, bucket, "obj1/obj2"); got != "body of obj1/obj2" {
		t.Fatalf("child unreadable after parent marker: %q", got)
	}
}

// TestExtendedNamingDirObjectCoexist covers an object, its directory-object
// twin and a child under the same prefix.
func TestExtendedNamingDirObjectCoexist(t *testing.T) {
	z, _, bucket := newExtendedNamingPool(t, 16, MakeBucketOptions{})

	putTestObject(t, z, bucket, "X")
	putTestObject(t, z, bucket, "X/")
	putTestObject(t, z, bucket, "X/child")

	objs, _ := listObjectNames(t, z, bucket, "", "")
	want := []string{"X", "X/", "X/child"}
	if len(objs) != len(want) {
		t.Fatalf("recursive list = %v, want %v", objs, want)
	}
	for i := range want {
		if objs[i] != want[i] {
			t.Fatalf("recursive list = %v, want %v", objs, want)
		}
	}

	if got := readTestObject(t, z, bucket, "X"); got != "body of X" {
		t.Fatalf("GET X = %q", got)
	}
	if got := readTestObject(t, z, bucket, "X/"); got != "body of X/" {
		t.Fatalf("GET X/ = %q", got)
	}
	if got := readTestObject(t, z, bucket, "X/child"); got != "body of X/child" {
		t.Fatalf("GET X/child = %q", got)
	}
}

// TestExtendedNamingEscapedKeyOrder lists keys that contain reserved
// characters and prefixes, checking the stream stays in user-key order.
func TestExtendedNamingEscapedKeyOrder(t *testing.T) {
	z, _, bucket := newExtendedNamingPool(t, 16, MakeBucketOptions{})

	keys := []string{"a", "a/b", "a0", "a◊b", "a␣c", "b"}
	for _, k := range keys {
		putTestObject(t, z, bucket, k)
	}
	// S3 orders keys by UTF-8 bytes: U+2423 (␣) sorts before U+25CA (◊).
	objs, _ := listObjectNames(t, z, bucket, "", "")
	want := []string{"a", "a/b", "a0", "a␣c", "a◊b", "b"}
	if len(objs) != len(want) {
		t.Fatalf("recursive list = %v, want %v", objs, want)
	}
	for i := range want {
		if objs[i] != want[i] {
			t.Fatalf("recursive list = %v, want %v", objs, want)
		}
	}
	// Every key reads back under its own name.
	for _, k := range keys {
		if got := readTestObject(t, z, bucket, k); got != "body of "+k {
			t.Fatalf("GET %q = %q", k, got)
		}
	}
}

// TestExtendedNamingMultipart completes a multipart upload onto a key that
// conflicts with a prefix in the same bucket.
func TestExtendedNamingMultipart(t *testing.T) {
	z, _, bucket := newExtendedNamingPool(t, 16, MakeBucketOptions{})
	ctx := t.Context()

	putTestObject(t, z, bucket, "obj1/obj2")

	res, err := z.NewMultipartUpload(ctx, bucket, "obj1", ObjectOptions{})
	if err != nil {
		t.Fatalf("NewMultipartUpload: %v", err)
	}
	data := bytes.Repeat([]byte("m"), 5<<20) // one part above the 5 MiB minimum
	part, err := z.PutObjectPart(ctx, bucket, "obj1", res.UploadID, 1,
		mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{})
	if err != nil {
		t.Fatalf("PutObjectPart: %v", err)
	}
	parts := []CompletePart{{ETag: part.ETag, PartNumber: part.PartNumber}}
	if _, err := z.CompleteMultipartUpload(ctx, bucket, "obj1", res.UploadID, parts, ObjectOptions{}); err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}

	gr, err := z.GetObjectNInfo(ctx, bucket, "obj1", nil, nil, ObjectOptions{})
	if err != nil {
		t.Fatalf("GET obj1: %v", err)
	}
	gr.Close()

	putTestObject(t, z, bucket, "obj1/tail")
	objs, _ := listObjectNames(t, z, bucket, "", "")
	want := []string{"obj1", "obj1/obj2", "obj1/tail"}
	if len(objs) != len(want) {
		t.Fatalf("recursive list = %v, want %v", objs, want)
	}
	for i := range want {
		if objs[i] != want[i] {
			t.Fatalf("recursive list = %v, want %v", objs, want)
		}
	}
}

// TestExtendedNamingFormatPersistence verifies the mode is recorded on every
// drive and that a conflicting request is rejected at startup.
func TestExtendedNamingFormatPersistence(t *testing.T) {
	z, fsDirs, _ := newExtendedNamingPool(t, 16, MakeBucketOptions{})
	_ = z

	data, err := os.ReadFile(filepath.Join(fsDirs[0], minioMetaBucket, formatConfigFile))
	if err != nil {
		t.Fatalf("read format.json: %v", err)
	}
	if !bytes.Contains(data, []byte(`"objectNaming":"extended"`)) {
		t.Fatalf("format.json does not record extended naming: %s", data)
	}

	// Re-opening the same drives while requesting safe mode must fail.
	globalObjectNaming = objectNamingSafe
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, _, err = initObjectLayer(ctx, mustGetPoolEndpoints(0, fsDirs...))
	if err == nil || !strings.Contains(err.Error(), "object naming") {
		t.Fatalf("expected object naming mismatch error, got %v", err)
	}
}

// TestSafeNamingConflictUnchanged locks in the documented behavior of the
// default mode: the conflicting subtree stays invisible to LIST.
func TestSafeNamingConflictUnchanged(t *testing.T) {
	// The formats are written at first start, so a fresh cluster is required.
	previousMode := globalObjectNaming
	previousExtended := globalObjectNamingExtended
	globalObjectNaming = ""
	globalObjectNamingExtended = false
	t.Cleanup(func() {
		globalObjectNaming = previousMode
		globalObjectNamingExtended = previousExtended
	})

	ctx, cancel := context.WithCancel(t.Context())
	fsDirs, err := getRandomDisks(16)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	obj, _, err := initObjectLayer(ctx, mustGetPoolEndpoints(0, fsDirs...))
	if err != nil {
		cancel()
		removeRoots(fsDirs)
		t.Fatal(err)
	}
	zs := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(zs)
	t.Cleanup(func() {
		cancel()
		zs.Shutdown(context.Background())
		removeRoots(fsDirs)
		setObjectLayer(previous)
	})
	safeBucket := getRandomBucketName()
	if err := zs.MakeBucket(ctx, safeBucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}

	putTestObject(t, zs, safeBucket, "obj1")
	putTestObject(t, zs, safeBucket, "obj1/obj2")

	objs, _ := listObjectNames(t, zs, safeBucket, "", "")
	if len(objs) != 1 || objs[0] != "obj1" {
		t.Fatalf("safe mode recursive list = %v, want [obj1]", objs)
	}
	objs, _ = listObjectNames(t, zs, safeBucket, "obj1/", "")
	if len(objs) != 0 {
		t.Fatalf("safe mode prefix obj1/ list = %v, want empty", objs)
	}
	// Exact-key reads still work in safe mode.
	if got := readTestObject(t, zs, safeBucket, "obj1/obj2"); got != "body of obj1/obj2" {
		t.Fatalf("safe mode GET obj1/obj2 = %q", got)
	}
}
