//go:build consistency_strict

// Preserved diagnostic for the deferred strict-read policy. This is not a
// maintenance release gate; failures record intentionally unresolved risks.

// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	xhttp "github.com/minio/minio/internal/http"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMutationReadPreservesAcknowledgedTags(t *testing.T) {
	z, bucket := mutationPools(t)
	const object = "tag-read"
	mutationPut(t, z, bucket, object, 0, "payload", time.Now())
	set := z.serverPools[0].getHashedSet(object)
	disks, swap := installListingDiskSwitch(set)
	defer swap(disks)
	partial := append([]StorageAPI(nil), disks...)
	partial[0] = nil
	swap(partial)
	const tags = "owner=acknowledged-B"
	if _, err := set.PutObjectTags(t.Context(), bucket, object, tags, ObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	swap(disks)
	before, err := disks[0].ReadVersion(t.Context(), "", bucket, object, "", ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	after, err := disks[1].ReadVersion(t.Context(), "", bucket, object, "", ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("old/new tags=%q/%q; equal tuple=%t", before.Metadata[xhttp.AmzObjectTagging], after.Metadata[xhttp.AmzObjectTagging], before.ModTime.Equal(after.ModTime) && before.DataDir == after.DataDir && before.Metadata["etag"] == after.Metadata["etag"])
	for _, fast := range []bool{false, true} {
		for _, version := range []string{"", nullVersionID} {
			oi, err := set.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{FastGetObjInfo: fast, VersionID: version})
			if err != nil {
				t.Fatal(err)
			}
			if oi.UserTags != tags {
				t.Fatalf("acknowledged tags replaced by stale metadata (fast=%t version=%q): %q", fast, version, oi.UserTags)
			}
		}
	}
}

func TestMutationVersionHistoryRead(t *testing.T) {
	z, bucket := mutationPools(t)
	const object = "history-read"
	set := z.serverPools[0].getHashedSet(object)
	var versions []string
	for i := range 12 {
		id := mustGetUUID()
		body := "version-" + strconv.Itoa(i)
		_, err := set.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader(body), int64(len(body)), "", ""), ObjectOptions{Versioned: true, VersionID: id})
		if err != nil {
			t.Fatal(err)
		}
		versions = append(versions, id)
	}
	disks, swap := installListingDiskSwitch(set)
	defer swap(disks)
	uniform := func() bool {
		raw := make([]RawFileInfo, len(disks))
		meta := make([]FileInfo, len(disks))
		errs := make([]error, len(disks))
		for i, disk := range disks {
			var err error
			raw[i], err = disk.ReadXL(t.Context(), bucket, object, false)
			if err != nil {
				t.Fatal(err)
			}
			meta[i], errs[i] = fileInfoFromRaw(raw[i], bucket, object, false, false)
		}
		return uniformLatestVersion(meta, errs)
	}
	if !uniform() {
		t.Fatal("healthy version history requires redundant full metadata decoding")
	}
	partial := append([]StorageAPI(nil), disks...)
	partial[0] = nil
	swap(partial)
	const tags = "owner=latest-acknowledged"
	if _, err := set.PutObjectTags(t.Context(), bucket, object, tags, ObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	swap(disks)
	if uniform() {
		t.Fatal("stale same-version metadata incorrectly accepted as uniform")
	}
	for _, fast := range []bool{false, true} {
		for _, version := range []string{"", versions[len(versions)-1]} {
			oi, err := set.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{FastGetObjInfo: fast, VersionID: version})
			if err != nil || oi.VersionID != versions[len(versions)-1] || oi.UserTags != tags {
				t.Fatalf("latest version/tags changed: version=%q tags=%q err=%v", oi.VersionID, oi.UserTags, err)
			}
		}
	}
	for i, id := range versions {
		r, err := set.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{VersionID: id})
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(r)
		r.Close()
		if err != nil || string(body) != "version-"+strconv.Itoa(i) {
			t.Fatalf("history version %d changed: %q err=%v", i, body, err)
		}
	}
}

func TestMutationCrossDiskOrderHasStableRead(t *testing.T) {
	z, bucket := mutationPools(t)
	const object = "cross-disk-order"
	base := time.Now().Add(-time.Hour)
	mutationPut(t, z, bucket, object, 0, "initial", base)
	set := z.serverPools[0].getHashedSet(object)
	disks, swap := installListingDiskSwitch(set)
	defer swap(disks)
	earlyDone, release := make(chan struct{}, 4), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	aDisks := append([]StorageAPI(nil), disks...)
	for i, d := range disks {
		aDisks[i] = orderedRenameDisk{d, i < 4, earlyDone, release}
	}
	swap(aDisks)
	put := func(body string, mtime time.Time) error {
		_, e := z.serverPools[0].PutObject(t.Context(), bucket, object,
			mustGetPutObjReader(t, strings.NewReader(body), int64(len(body)), "", ""),
			ObjectOptions{NoLock: true, MTime: mtime})
		return e
	}
	aDone := make(chan error, 1)
	go func() { aDone <- put("writer-A", base.Add(time.Minute)) }()
	for range 4 {
		select {
		case <-earlyDone:
		case <-time.After(5 * time.Second):
			t.Fatal("A did not reach first-half barrier")
		}
	}
	swap(disks)
	if err := put("writer-B", base.Add(2*time.Minute)); err != nil {
		t.Fatalf("B failed: %v", err)
	}
	unblock()
	select {
	case err := <-aDone:
		if err != nil {
			t.Fatalf("A failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("A did not finish")
	}
	t.Log("both PUTs succeeded; final per-disk order is A→B on four disks and B→A on four disks; no writer remains")
	swap(disks)
	for range 8 {
		for _, version := range []string{"", nullVersionID} {
			r, err := z.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{FastGetObjInfo: true, VersionID: version})
			if err != nil {
				t.Fatalf("quiescent successful writes became unreadable: %v", err)
			}
			body, err := io.ReadAll(r)
			r.Close()
			if err != nil || string(body) != "writer-B" {
				t.Fatalf("completed reads changed value: %q %v", body, err)
			}
		}
	}
}

func uniformLatestVersion(meta []FileInfo, errs []error) bool {
	if len(meta) == 0 {
		return false
	}
	first := meta[0]
	for i, fi := range meta {
		if errs[i] != nil || !fi.IsValid() || fi.XLV1 || fi.Deleted || !fi.IsLatest || fi.NumVersions < 1 ||
			!fi.ModTime.Equal(first.ModTime) || !sameFileInfoVersion(first, fi) ||
			fi.NumVersions != first.NumVersions || !fi.SuccessorModTime.Equal(first.SuccessorModTime) {
			return false
		}
	}
	return true
}

type orderedRenameDisk struct {
	StorageAPI
	early     bool
	earlyDone chan<- struct{}
	release   <-chan struct{}
}

func (d orderedRenameDisk) RenameData(ctx context.Context, sv, sp string, fi FileInfo, dv, dp string, opts RenameOptions) (RenameDataResp, error) {
	if !d.early {
		<-d.release
	}
	r, err := d.StorageAPI.RenameData(ctx, sv, sp, fi, dv, dp, opts)
	if d.early {
		d.earlyDone <- struct{}{}
		<-d.release
	}
	return r, err
}
