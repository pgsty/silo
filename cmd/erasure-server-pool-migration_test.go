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
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	xhttp "github.com/minio/minio/internal/http"
)

const migrationTagRevision = ReservedMetadataPrefixLower + TaggingTimestamp

var migrationTagStates = []struct {
	name, tags, revision string
	hasRevision          bool
}{
	{name: "initial", tags: "team=storage&path=a%2Fb"},
	{name: "empty-revision", tags: "team=storage", hasRevision: true},
	{name: "invalid-revision", tags: "team=storage", revision: "invalid", hasRevision: true},
	{name: "ordered", tags: "team=storage", revision: "2026-09-16T09:00:00Z", hasRevision: true},
	{name: "cleared", revision: "2026-09-16T09:00:00Z", hasRevision: true},
	{name: "never-tagged"},
	{name: "empty-empty-revision", hasRevision: true},
	{name: "empty-invalid-revision", revision: "invalid", hasRevision: true},
}

func TestMigrationObjectMetadata(t *testing.T) {
	for _, state := range migrationTagStates {
		for _, residual := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/residual=%t", state.name, residual), func(t *testing.T) {
				raw := map[string]string{
					xhttp.AmzObjectTagging:                    state.tags,
					"x-amz-meta-team":                         "storage",
					"x-amz-meta-empty":                        "",
					ReservedMetadataPrefix + "compression":    "opaque-compression-state",
					ReservedMetadataPrefix + "sealed-key":     "opaque-key-state",
					"x-amz-object-lock-retain-until-date":     "2030-01-01T00:00:00Z",
					"x-amz-object-lock-legal-hold":            "ON",
					"x-amz-tagging":                           "keep-noncanonical-metadata",
					ReservedMetadataPrefix + "actual-size":    "42",
					ReservedMetadataPrefix + "replica-status": "opaque-replication-state",
				}
				if state.hasRevision {
					raw[migrationTagRevision] = state.revision
				}
				oi := (FileInfo{Metadata: raw}).ToObjectInfo("bucket", "object", false)
				if residual {
					oi.UserDefined[xhttp.AmzObjectTagging] = "stale=raw"
				}
				before := maps.Clone(oi.UserDefined)
				got := migrationObjectMetadata(oi)
				if got == nil || !maps.Equal(before, oi.UserDefined) {
					t.Fatal("helper must return a new non-nil map without changing the read snapshot")
				}
				value, exists := got[xhttp.AmzObjectTagging]
				if value != state.tags || exists != (state.tags != "") {
					t.Fatalf("raw tags=(%q,%t), want (%q,%t)", value, exists, state.tags, state.tags != "")
				}
				stamp, present := got[migrationTagRevision]
				if stamp != state.revision || present != state.hasRevision {
					t.Fatalf("revision=(%q,%t), want (%q,%t)", stamp, present, state.revision, state.hasRevision)
				}
				for key, value := range before {
					if stored, exists := got[key]; key != xhttp.AmzObjectTagging && (!exists || stored != value) {
						t.Errorf("lost metadata %q", key)
					}
				}
				got["x-amz-meta-team"] = "changed"
				if !maps.Equal(before, oi.UserDefined) {
					t.Fatal("output aliases the read snapshot")
				}
			})
		}
	}
	for _, metadata := range []map[string]string{nil, {}} {
		got := migrationObjectMetadata(ObjectInfo{UserDefined: metadata})
		if got == nil || len(got) != 0 {
			t.Fatalf("empty input must yield a writable empty map: %#v", got)
		}
		got["new"] = "value"
		if len(metadata) != 0 {
			t.Fatal("empty map input was aliased")
		}
	}
}

// Allocation ignores the host's used-space percentage, as in the existing tag
// fixtures. All object data and metadata still use real erasure-storage disks.
func migrationTestPools(t *testing.T) (*erasureServerPools, string) {
	t.Helper()
	z, bucket := consistencyPools(t)
	for _, pool := range z.serverPools {
		pool.erasureDisksMu.Lock()
		previous := pool.erasureDisks
		wrapped := make([][]StorageAPI, len(previous))
		for i, disks := range previous {
			wrapped[i] = append([]StorageAPI(nil), disks...)
			for j := range wrapped[i] {
				wrapped[i][j] = tagTestCapacityDisk{StorageAPI: wrapped[i][j]}
			}
		}
		pool.erasureDisks = wrapped
		pool.erasureDisksMu.Unlock()
		t.Cleanup(func() { pool.erasureDisksMu.Lock(); pool.erasureDisks = previous; pool.erasureDisksMu.Unlock() })
	}
	return z, bucket
}

func migrationTestMover(t *testing.T, z *erasureServerPools, source int, kind string) func(context.Context, int, string, *GetObjectReader) error {
	t.Helper()
	if kind == "rebalance" {
		z.rebalMu.Lock()
		z.rebalMeta = &rebalanceMeta{PoolStats: make([]*rebalanceStats, len(z.serverPools))}
		for i := range z.rebalMeta.PoolStats {
			z.rebalMeta.PoolStats[i] = &rebalanceStats{}
		}
		z.rebalMeta.PoolStats[source] = &rebalanceStats{Participating: true, Info: rebalanceInfo{Status: rebalStarted}}
		z.rebalMu.Unlock()
		t.Cleanup(func() { z.rebalMu.Lock(); z.rebalMeta = nil; z.rebalMu.Unlock() })
		return z.rebalanceObject
	}
	z.poolMetaMutex.Lock()
	z.poolMeta.Pools[source].Decommission = &PoolDecommissionInfo{}
	z.poolMetaMutex.Unlock()
	t.Cleanup(func() { z.poolMetaMutex.Lock(); z.poolMeta.Pools[source].Decommission = nil; z.poolMetaMutex.Unlock() })
	return z.decommissionObject
}

func migrationTestObject(t *testing.T, z *erasureServerPools, bucket, object string, source int, multipart bool, parts []string, opts ObjectOptions) ObjectInfo {
	t.Helper()
	if !multipart {
		oi := putConsistencyObject(t, z, bucket, object, source, strings.Join(parts, ""), opts)
		return migrationTestPersistedInfo(t, z, source, oi)
	}
	mp, err := z.serverPools[source].NewMultipartUpload(t.Context(), bucket, object, opts)
	if err != nil {
		t.Fatal(err)
	}
	completed := make([]CompletePart, len(parts))
	for i, body := range parts {
		part, err := z.serverPools[source].PutObjectPart(t.Context(), bucket, object, mp.UploadID, i+1,
			mustGetPutObjReader(t, strings.NewReader(body), int64(len(body)), "", ""), ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		completed[i] = CompletePart{PartNumber: i + 1, ETag: part.ETag}
	}
	oi, err := z.serverPools[source].CompleteMultipartUpload(t.Context(), bucket, object, mp.UploadID, completed, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !oi.isMultipart() {
		t.Fatal("fixture did not create a multipart object")
	}
	return migrationTestPersistedInfo(t, z, source, oi)
}

func migrationTestPersistedInfo(t *testing.T, z *erasureServerPools, pool int, oi ObjectInfo) ObjectInfo {
	t.Helper()
	// PUT can return transient fields such as tier-free-versionID that are not
	// stored. Take the same persisted read representation used by the movers.
	got, err := z.serverPools[pool].GetObjectInfo(t.Context(), oi.Bucket, oi.Name, ObjectOptions{VersionID: migrationTestVersion(oi)})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func migrationTestVersion(oi ObjectInfo) string {
	if oi.VersionID == "" {
		return nullVersionID
	}
	return oi.VersionID
}

func migrationTestReader(t *testing.T, z *erasureServerPools, source int, oi ObjectInfo) *GetObjectReader {
	t.Helper()
	gr, err := z.serverPools[source].GetObjectNInfo(t.Context(), oi.Bucket, oi.Name, nil, nil,
		ObjectOptions{VersionID: migrationTestVersion(oi), NoLock: true, NoDecryption: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gr.Close() })
	return gr
}

func migrationTestStored(t *testing.T, z *erasureServerPools, pool int, original ObjectInfo, tags, revision string, hasRevision bool, body string) {
	t.Helper()
	version := migrationTestVersion(original)
	got, err := z.serverPools[pool].GetObjectInfo(t.Context(), original.Bucket, original.Name, ObjectOptions{VersionID: version})
	if err != nil {
		t.Fatal(err)
	}
	if got.UserTags != tags || got.ETag != original.ETag || !got.ModTime.Equal(original.ModTime) || got.VersionID != original.VersionID || got.Size != original.Size {
		t.Errorf("pool %d changed tags/object identity: tags=%q want=%q version=%q/%q etag=%q/%q size=%d/%d mtime=%v/%v", pool, got.UserTags, tags, got.VersionID, original.VersionID, got.ETag, original.ETag, got.Size, original.Size, got.ModTime, original.ModTime)
	}
	infos, errs := readAllFileInfo(t.Context(), z.serverPools[pool].getHashedSet(original.Name).getDisks(), "", original.Bucket, original.Name, version, false, false)
	for disk, fi := range infos {
		if errs[disk] != nil {
			t.Fatalf("pool %d disk %d: %v", pool, disk, errs[disk])
		}
		stamp, exists := fi.Metadata[migrationTagRevision]
		if fi.Metadata[xhttp.AmzObjectTagging] != tags || stamp != revision || exists != hasRevision {
			t.Errorf("pool %d disk %d: tags=%q revision=(%q,%t), want %q (%q,%t)", pool, disk, fi.Metadata[xhttp.AmzObjectTagging], stamp, exists, tags, revision, hasRevision)
		}
		for key, value := range original.UserDefined {
			if key != migrationTagRevision && fi.Metadata[key] != value {
				t.Errorf("pool %d disk %d lost metadata %q", pool, disk, key)
			}
		}
	}
	gr, err := z.serverPools[pool].GetObjectNInfo(t.Context(), original.Bucket, original.Name, nil, nil, ObjectOptions{VersionID: version})
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(gr)
	gr.Close()
	if err != nil || !bytes.Equal(data, []byte(body)) {
		t.Fatalf("pool %d content changed: bytes=%d err=%v", pool, len(data), err)
	}
}

func TestPoolsMigrationPreservesTagState(t *testing.T) {
	z, bucket := migrationTestPools(t)
	for _, kind := range []string{"rebalance", "decommission"} {
		for _, method := range []string{"put", "multipart"} {
			for source := range 2 {
				for _, state := range migrationTagStates {
					t.Run(fmt.Sprintf("%s/%s/source=%d/%s", kind, method, source, state.name), func(t *testing.T) {
						move := migrationTestMover(t, z, source, kind)
						meta := map[string]string{xhttp.AmzObjectTagging: state.tags, "x-amz-meta-owner": "retained"}
						if state.hasRevision {
							meta[migrationTagRevision] = state.revision
						}
						oi := migrationTestObject(t, z, bucket, t.Name(), source, method == "multipart", []string{"payload"}, ObjectOptions{Versioned: true, UserDefined: meta})
						migrationTestStored(t, z, source, oi, state.tags, state.revision, state.hasRevision, "payload")
						gr := migrationTestReader(t, z, source, oi)
						before := maps.Clone(gr.ObjInfo.UserDefined)
						if err := move(t.Context(), source, bucket, gr); err != nil {
							t.Fatal(err)
						}
						if !maps.Equal(before, gr.ObjInfo.UserDefined) {
							t.Error("migration modified its source snapshot")
						}
						migrationTestStored(t, z, 1-source, oi, state.tags, state.revision, state.hasRevision, "payload")
					})
				}
			}
		}
	}
}

type migrationTestGate struct {
	entered, resume chan struct{}
	once, release   sync.Once
}

func newMigrationTestGate() *migrationTestGate {
	return &migrationTestGate{entered: make(chan struct{}), resume: make(chan struct{})}
}

func (g *migrationTestGate) wait(ctx context.Context) error {
	g.once.Do(func() { close(g.entered) })
	select {
	case <-g.resume:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *migrationTestGate) unblock() { g.release.Do(func() { close(g.resume) }) }

type migrationTestGateReader struct {
	io.Reader
	ctx  context.Context
	gate *migrationTestGate
}

func (r migrationTestGateReader) Read(p []byte) (int, error) {
	if err := r.gate.wait(r.ctx); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func TestPoolsMigrationRechecksTags(t *testing.T) {
	z, bucket := migrationTestPools(t)
	const recent = "2026-09-16T10:00:00Z"
	for _, kind := range []string{"rebalance", "decommission"} {
		for _, method := range []string{"put", "multipart"} {
			for source := range 2 {
				for _, tags := range []string{"state=after", ""} {
					t.Run(fmt.Sprintf("%s/%s/source=%d/clear=%t", kind, method, source, tags == ""), func(t *testing.T) {
						move := migrationTestMover(t, z, source, kind)
						oi := migrationTestObject(t, z, bucket, t.Name(), source, method == "multipart", []string{"payload"}, ObjectOptions{
							Versioned: true, UserDefined: map[string]string{xhttp.AmzObjectTagging: "state=before"},
						})
						gr := migrationTestReader(t, z, source, oi)
						before := maps.Clone(gr.ObjInfo.UserDefined)
						ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
						defer cancel()
						gate := newMigrationTestGate()
						done, finished := make(chan error, 1), make(chan struct{})
						if method == "multipart" {
							// The first part read is after persisted upload initialization,
							// but before completion takes the object lock and reconciles.
							gr.Reader = migrationTestGateReader{Reader: gr.Reader, ctx: ctx, gate: gate}
							go func() { defer close(finished); done <- move(ctx, source, bucket, gr) }()
							defer func() { gate.unblock(); cancel(); <-finished }()
							select {
							case <-gate.entered:
							case err := <-done:
								t.Fatalf("migration finished before the part barrier: %v", err)
							case <-ctx.Done():
								t.Fatal(ctx.Err())
							}
							uploads, err := z.serverPools[1-source].listMultipartUploadsExact(ctx, bucket, oi.Name)
							if err != nil || len(uploads.Uploads) != 1 {
								t.Fatalf("upload not persisted at barrier: %+v, %v", uploads, err)
							}
							info, err := z.serverPools[1-source].GetMultipartInfo(ctx, bucket, oi.Name, uploads.Uploads[0].UploadID, ObjectOptions{})
							if err != nil || info.UserDefined[xhttp.AmzObjectTagging] != "state=before" {
								t.Fatalf("upload lost snapshot tags: %v, %v", info.UserDefined, err)
							}
						}
						// For ordinary PUT this must finish before calling the mover:
						// blocking its data Read would already hold the object lock.
						opts := ObjectOptions{VersionID: migrationTestVersion(oi), UserDefined: map[string]string{migrationTagRevision: recent}}
						var err error
						if tags == "" {
							_, err = z.DeleteObjectTags(ctx, bucket, oi.Name, opts)
						} else {
							_, err = z.PutObjectTags(ctx, bucket, oi.Name, tags, opts)
						}
						if err != nil {
							t.Fatal(err)
						}
						if gr.ObjInfo.UserTags != "state=before" || !maps.Equal(before, gr.ObjInfo.UserDefined) {
							t.Fatal("test must retain the old source snapshot")
						}
						migrationTestStored(t, z, source, oi, tags, recent, true, "payload")
						if method == "multipart" {
							gate.unblock()
							err = <-done
						} else {
							err = move(ctx, source, bucket, gr)
						}
						if err != nil {
							t.Fatal(err)
						}
						if !maps.Equal(before, gr.ObjInfo.UserDefined) {
							t.Error("reconciliation changed the reader's map")
						}
						migrationTestStored(t, z, 1-source, oi, tags, recent, true, "payload")
					})
				}
			}
		}
	}
}

type migrationTestMetadataGateDisk struct {
	StorageAPI
	bucket, object string
	gate           *migrationTestGate
}

func (d migrationTestMetadataGateDisk) UpdateMetadata(ctx context.Context, volume, path string, fi FileInfo, opts UpdateMetadataOpts) error {
	if volume == d.bucket && path == d.object {
		if err := d.gate.wait(ctx); err != nil {
			return err
		}
	}
	return d.StorageAPI.UpdateMetadata(ctx, volume, path, fi, opts)
}

func TestPoolsMigrationTagsDuringCleanup(t *testing.T) {
	z, bucket := migrationTestPools(t)
	const recent = "2026-09-16T10:00:00Z"
	for _, kind := range []string{"rebalance", "decommission"} {
		for source := range 2 {
			for _, tags := range []string{"state=after", ""} {
				for _, interrupt := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/source=%d/clear=%t/interrupt=%t", kind, source, tags == "", interrupt), func(t *testing.T) {
						move := migrationTestMover(t, z, source, kind)
						oi := migrationTestObject(t, z, bucket, t.Name(), source, false, []string{"payload"}, ObjectOptions{
							Versioned: true, UserDefined: map[string]string{xhttp.AmzObjectTagging: "state=before"},
						})
						if err := move(t.Context(), source, bucket, migrationTestReader(t, z, source, oi)); err != nil {
							t.Fatal(err)
						}
						migrationTestStored(t, z, 1-source, oi, "state=before", "", false, "payload")
						ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
						defer cancel()
						mutate := func() (ObjectInfo, error) {
							opts := ObjectOptions{VersionID: migrationTestVersion(oi), UserDefined: map[string]string{migrationTagRevision: recent}}
							if tags == "" {
								return z.DeleteObjectTags(ctx, bucket, oi.Name, opts)
							}
							return z.PutObjectTags(ctx, bucket, oi.Name, tags, opts)
						}
						set := z.serverPools[source].getHashedSet(oi.Name)
						cleanup := func() {
							// Use the same source prefix cleanup as both outer movers.
							if _, err := set.DeleteObject(ctx, bucket, oi.Name, ObjectOptions{DeletePrefix: true, DeletePrefixObject: true}); err != nil {
								t.Fatal(err)
							}
						}
						var updated ObjectInfo
						if !interrupt {
							var err error
							updated, err = mutate()
							if err != nil {
								t.Fatal(err)
							}
							cleanup()
						} else {
							gate := newMigrationTestGate()
							original := set.getDisks
							disks := append([]StorageAPI(nil), original()...)
							for i := range disks {
								disks[i] = migrationTestMetadataGateDisk{StorageAPI: disks[i], bucket: bucket, object: oi.Name, gate: gate}
							}
							set.getDisks = func() []StorageAPI { return disks }
							defer func() { set.getDisks = original }()
							done, finished := make(chan error, 1), make(chan struct{})
							go func() { defer close(finished); _, err := mutate(); done <- err }()
							defer func() { gate.unblock(); cancel(); <-finished }()
							select {
							case <-gate.entered:
							case err := <-done:
								t.Fatalf("metadata update missed the barrier: %v", err)
							case <-ctx.Done():
								t.Fatal(ctx.Err())
							}
							cleanup()
							gate.unblock()
							if err := <-done; err == nil {
								t.Fatal("update reported success after its source copy was removed")
							}
							<-finished
							set.getDisks = original
							var err error
							updated, err = mutate()
							if err != nil {
								t.Fatalf("metadata retry did not converge: %v", err)
							}
						}
						if _, err := z.serverPools[source].GetObjectInfo(ctx, bucket, oi.Name, ObjectOptions{VersionID: oi.VersionID}); !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
							t.Fatalf("source cleanup left a copy: %v", err)
						}
						migrationTestStored(t, z, 1-source, oi, tags, updated.UserDefined[migrationTagRevision], true, "payload")
					})
				}
			}
		}
	}
}

func TestPoolsMigrationVersionHistory(t *testing.T) {
	z, bucket := migrationTestPools(t)
	for _, kind := range []string{"rebalance", "decommission"} {
		for _, method := range []string{"put", "multipart"} {
			for _, versioning := range []string{"unversioned", "null", "history"} {
				t.Run(kind+"/"+method+"/"+versioning, func(t *testing.T) {
					move := migrationTestMover(t, z, 0, kind)
					opts := ObjectOptions{
						Versioned: versioning == "history", VersionSuspended: versioning == "null",
						MTime:       time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC),
						UserDefined: map[string]string{xhttp.AmzObjectTagging: "version=old"},
					}
					versions := []ObjectInfo{migrationTestObject(t, z, bucket, t.Name(), 0, method == "multipart", []string{"old"}, opts)}
					if versioning == "history" {
						opts.MTime = opts.MTime.Add(time.Minute)
						versions = append(versions, migrationTestObject(t, z, bucket, t.Name(), 0, method == "multipart", []string{"old"}, opts))
					}
					var newest ObjectInfo
					if versioning != "unversioned" {
						newest = migrationTestObject(t, z, bucket, t.Name(), 0, false, []string{"latest"}, ObjectOptions{
							Versioned: true, MTime: opts.MTime.Add(time.Minute),
							UserDefined: map[string]string{xhttp.AmzObjectTagging: "version=new"},
						})
					}
					for _, oi := range versions {
						if err := move(t.Context(), 0, bucket, migrationTestReader(t, z, 0, oi)); err != nil {
							t.Fatal(err)
						}
						migrationTestStored(t, z, 1, oi, "version=old", "", false, "old")
					}
					if versioning != "unversioned" {
						migrationTestStored(t, z, 0, newest, "version=new", "", false, "latest")
						if _, err := z.serverPools[1].GetObjectInfo(t.Context(), bucket, t.Name(), ObjectOptions{VersionID: newest.VersionID}); !isErrVersionNotFound(err) {
							t.Fatalf("moving an addressed version affected the newer version: %v", err)
						}
					}
				})
			}
		}
	}
}

func TestPoolsMigrationMultipartParts(t *testing.T) {
	z, bucket := migrationTestPools(t)
	parts := []string{strings.Repeat("a", 5<<20), "tail-with-tags"}
	body := strings.Join(parts, "")
	for _, kind := range []string{"rebalance", "decommission"} {
		for source := range 2 {
			t.Run(fmt.Sprintf("%s/source=%d", kind, source), func(t *testing.T) {
				move := migrationTestMover(t, z, source, kind)
				oi := migrationTestObject(t, z, bucket, t.Name(), source, true, parts, ObjectOptions{
					Versioned: true, UserDefined: map[string]string{xhttp.AmzObjectTagging: "multipart=kept"},
				})
				if err := move(t.Context(), source, bucket, migrationTestReader(t, z, source, oi)); err != nil {
					t.Fatal(err)
				}
				migrationTestStored(t, z, 1-source, oi, "multipart=kept", "", false, body)
				got, err := z.serverPools[1-source].GetObjectInfo(t.Context(), bucket, oi.Name, ObjectOptions{VersionID: oi.VersionID})
				if err != nil || len(got.Parts) != len(oi.Parts) {
					t.Fatalf("parts changed: %+v, %v", got.Parts, err)
				}
				for i, part := range got.Parts {
					old := oi.Parts[i]
					if part.Number != old.Number || part.Size != old.Size || part.ActualSize != old.ActualSize || part.ETag != old.ETag || !bytes.Equal(part.Index, old.Index) {
						t.Errorf("part %d changed: %+v / %+v", i, part, old)
					}
				}
				start := int64(len(parts[0]) - 3)
				gr, err := z.serverPools[1-source].GetObjectNInfo(t.Context(), bucket, oi.Name, &HTTPRangeSpec{Start: start, End: start + 7}, nil, ObjectOptions{VersionID: oi.VersionID})
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(gr)
				gr.Close()
				if err != nil || string(data) != body[start:start+8] {
					t.Fatalf("cross-part range changed: %q, %v", data, err)
				}
			})
		}
	}
}

func TestPoolsMigrationUnreadablePool(t *testing.T) {
	z, bucket := migrationTestPools(t)
	for _, kind := range []string{"rebalance", "decommission"} {
		for _, method := range []string{"put", "multipart"} {
			t.Run(kind+"/"+method, func(t *testing.T) {
				move := migrationTestMover(t, z, 0, kind)
				oi := migrationTestObject(t, z, bucket, t.Name(), 0, method == "multipart", []string{"payload"}, ObjectOptions{
					Versioned: true, UserDefined: map[string]string{xhttp.AmzObjectTagging: "keep=source"},
				})
				gr := migrationTestReader(t, z, 0, oi)
				set := z.serverPools[0].getHashedSet(oi.Name)
				original := set.getDisks
				disks := append([]StorageAPI(nil), original()...)
				for i := range disks {
					disks[i] = consistencyReadFaultDisk{StorageAPI: disks[i], bucket: bucket, object: oi.Name}
				}
				set.getDisks = func() []StorageAPI { return disks }
				defer func() { set.getDisks = original }()
				err := move(t.Context(), 0, bucket, gr)
				var quorum InsufficientReadQuorum
				if !errors.As(err, &quorum) {
					t.Fatalf("unreadable pool must fail migration with read quorum error: %v", err)
				}
				set.getDisks = original
				migrationTestStored(t, z, 0, oi, "keep=source", "", false, "payload")
				if _, err := z.serverPools[1].GetObjectInfo(t.Context(), bucket, oi.Name, ObjectOptions{VersionID: oi.VersionID}); !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
					t.Fatalf("failed migration committed a target version: %v", err)
				}
			})
		}
	}
}

// Three pools give a move two candidate destinations.
func migrationTestThreePools(t *testing.T) (*erasureServerPools, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	dirs, err := getRandomDisks(12)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var endpoints EndpointServerPools
	for i := range 3 {
		endpoints = append(endpoints, mustGetPoolEndpoints(i, dirs[4*i:4*i+4]...)...)
	}
	obj, _, err := initObjectLayer(ctx, endpoints)
	if err != nil {
		cancel()
		removeRoots(dirs)
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	t.Cleanup(func() { cancel(); z.Shutdown(context.Background()); removeRoots(dirs); setObjectLayer(previous) })
	bucket := "pool-migration"
	if err := z.MakeBucket(t.Context(), bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	return z, bucket
}

type migrationTestGetter func(context.Context, string, string, *HTTPRangeSpec, http.Header, ObjectOptions) (*GetObjectReader, error)

// migrationTestBody returns the content read for a version, or the read error.
func migrationTestBody(t *testing.T, get migrationTestGetter, bucket, object, versionID string) string {
	t.Helper()
	gr, err := get(t.Context(), bucket, object, nil, nil, ObjectOptions{VersionID: versionID})
	if err != nil {
		return fmt.Sprintf("<%v>", err)
	}
	defer gr.Close()
	data, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// migrationTestWalk runs one bucket of a decommission or rebalance of source,
// including the walker's accounting and source cleanup. It returns the number
// of versions decommission counted as failed.
func migrationTestWalk(t *testing.T, z *erasureServerPools, bucket string, source int, kind string) int64 {
	t.Helper()
	migrationTestMover(t, z, source, kind)
	if kind == "rebalance" {
		if err := z.rebalanceBucket(t.Context(), bucket, source); err != nil {
			t.Fatal(err)
		}
		return 0
	}
	z.poolMetaMutex.Lock()
	z.poolMeta.Pools[source].LastUpdate = UTCNow() // keep pool.bin and peers out of the walk
	z.poolMetaMutex.Unlock()
	if err := z.decommissionPool(t.Context(), source, z.serverPools[source], decomBucketInfo{Name: bucket}); err != nil {
		t.Fatal(err)
	}
	z.poolMetaMutex.RLock()
	defer z.poolMetaMutex.RUnlock()
	return z.poolMeta.Pools[source].Decommission.ItemsDecommissionFailed
}

// migrationTestTiered stores a null version whose data is in a remote tier, in
// the form decommission moves it.
func migrationTestTiered(t *testing.T, z *erasureServerPools, bucket, object string, pool int, mtime time.Time) ObjectInfo {
	t.Helper()
	oi := putConsistencyObject(t, z, bucket, object, pool, "old", ObjectOptions{MTime: mtime})
	infos, errs := readAllFileInfo(t.Context(), z.serverPools[pool].getHashedSet(oi.Name).getDisks(), "", bucket, oi.Name, nullVersionID, false, false)
	if errs[0] != nil {
		t.Fatal(errs[0])
	}
	fi := infos[0]
	fi.TransitionStatus, fi.TransitionTier, fi.TransitionedObjName = lifecycle.TransitionComplete, "WARM", "remote"
	if err := z.serverPools[pool].DecomTieredObject(t.Context(), bucket, oi.Name, fi, ObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	return oi
}

// A cross-pool overwrite can leave copies of one version in several pools.
// Reads return the newest copy, and moving an older one must not replace it.
// An equal ModTime marks the same write, as an interrupted move leaves it.
func TestPoolsMigrationKeepsCurrentCopy(t *testing.T) {
	z, bucket := migrationTestPools(t)
	base := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
	for _, kind := range []string{"rebalance", "decommission"} {
		for _, method := range []string{"put", "multipart"} {
			for _, versioned := range []bool{false, true} {
				for source := range 2 {
					for _, offset := range []time.Duration{-time.Minute, 0, time.Minute} {
						t.Run(fmt.Sprintf("%s/%s/versioned=%t/source=%d/offset=%s", kind, method, versioned, source, offset), func(t *testing.T) {
							move := migrationTestMover(t, z, source, kind)
							opts := ObjectOptions{Versioned: versioned, MTime: base.Add(offset)}
							if versioned {
								opts.VersionID = mustGetUUID()
							}
							oi := migrationTestObject(t, z, bucket, t.Name(), source, method == "multipart", []string{"source"}, opts)
							opts.MTime = base
							want, other := "source", "other"
							if offset == 0 {
								other = "source"
								opts.PreserveETag = oi.ETag // interrupted copies preserve the original multipart ETag
							} else if offset < 0 {
								want = "other"
							}
							putConsistencyObject(t, z, bucket, t.Name(), 1-source, other, opts)
							version := migrationTestVersion(oi)
							if got := migrationTestBody(t, z.GetObjectNInfo, bucket, t.Name(), version); got != want {
								t.Fatalf("fixture reads %q, want %q", got, want)
							}
							err := move(t.Context(), source, bucket, migrationTestReader(t, z, source, oi))
							if want == "other" && !isDataMovementSuperseded(err) || want == "source" && err != nil {
								t.Fatalf("move: %v", err)
							}
							if err != nil && strings.Contains(err.Error(), "CompleteMultipartUpload") {
								t.Error("copied the parts of a superseded version")
							}
							if got := migrationTestBody(t, z.serverPools[1-source].GetObjectNInfo, bucket, t.Name(), version); got != want {
								t.Errorf("destination holds %q, want %q", got, want)
							}
							if got := migrationTestBody(t, z.GetObjectNInfo, bucket, t.Name(), version); got != want {
								t.Errorf("move changed the read result to %q, want %q", got, want)
							}
						})
					}
				}
			}
		}
	}
}

// A client overwrite, or a replica of the same version, committed while a move
// copies the old version is newer than the moved copy. The move must yield to
// it, also at multipart completion.
func TestPoolsMigrationYieldsToNewerWrite(t *testing.T) {
	z, bucket := migrationTestPools(t)
	for _, kind := range []string{"rebalance", "decommission"} {
		for _, method := range []string{"put", "multipart"} {
			for _, versioned := range []bool{false, true} {
				for source := range 2 {
					t.Run(fmt.Sprintf("%s/%s/versioned=%t/source=%d", kind, method, versioned, source), func(t *testing.T) {
						migrationTestNewerWrite(t, z, bucket, kind, method, versioned, source)
					})
				}
			}
		}
	}
}

func migrationTestNewerWrite(t *testing.T, z *erasureServerPools, bucket, kind, method string, versioned bool, source int) {
	move := migrationTestMover(t, z, source, kind)
	oi := migrationTestObject(t, z, bucket, t.Name(), source, method == "multipart", []string{"moved"}, ObjectOptions{Versioned: versioned, MTime: UTCNow().Add(-time.Hour)})
	gr := migrationTestReader(t, z, source, oi)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	gate := newMigrationTestGate()
	done, finished := make(chan error, 1), make(chan struct{})
	if method == "multipart" {
		// Hold the move after its initial check, while it copies parts.
		gr.Reader = migrationTestGateReader{Reader: gr.Reader, ctx: ctx, gate: gate}
		go func() { defer close(finished); done <- move(ctx, source, bucket, gr) }()
		defer func() { gate.unblock(); cancel(); <-finished }()
		select {
		case <-gate.entered:
		case err := <-done:
			t.Fatalf("migration finished before the part barrier: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// An ordinary PUT copies under the object lock, so this write
	// lands between the mover's source read and its write.
	if versioned {
		putConsistencyObject(t, z, bucket, t.Name(), 1-source, "newer", ObjectOptions{Versioned: true, VersionID: oi.VersionID, MTime: UTCNow()})
	} else if _, err := z.PutObject(ctx, bucket, t.Name(), mustGetPutObjReader(t, strings.NewReader("newer"), 5, "", ""), ObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	var err error
	if method == "multipart" {
		gate.unblock()
		err = <-done
	} else {
		err = move(ctx, source, bucket, gr)
	}
	if !isDataMovementSuperseded(err) {
		t.Fatalf("move over a newer write: %v", err)
	}
	if got := migrationTestBody(t, z.GetObjectNInfo, bucket, t.Name(), migrationTestVersion(oi)); got != "newer" {
		t.Fatalf("newer write replaced by %q", got)
	}
}

// With two candidate destinations a superseded copy must neither replace the
// newer copy nor become a new duplicate in the third pool.
func TestPoolsMigrationThreePools(t *testing.T) {
	z, bucket := migrationTestThreePools(t)
	stale, recent := UTCNow().Add(-time.Hour), UTCNow().Add(-time.Minute)
	for _, kind := range []string{"rebalance", "decommission"} {
		for _, newest := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/newest=%d", kind, newest), func(t *testing.T) {
				move := migrationTestMover(t, z, 0, kind)
				mtime := func(pool int) time.Time {
					if pool == newest {
						return recent
					}
					return stale
				}
				oi := migrationTestObject(t, z, bucket, t.Name(), 0, false, []string{"pool-0"}, ObjectOptions{MTime: mtime(0)})
				putConsistencyObject(t, z, bucket, t.Name(), 1, "pool-1", ObjectOptions{MTime: mtime(1)})
				if newest == 0 {
					putConsistencyObject(t, z, bucket, t.Name(), 2, "pool-2", ObjectOptions{MTime: stale})
				}
				want := fmt.Sprintf("pool-%d", newest)
				err := move(t.Context(), 0, bucket, migrationTestReader(t, z, 0, oi))
				if newest == 1 && !isDataMovementSuperseded(err) || newest == 0 && err != nil {
					t.Fatalf("move: %v", err)
				}
				if got := migrationTestBody(t, z.GetObjectNInfo, bucket, t.Name(), ""); got != want {
					t.Errorf("reads return %q, want %q", got, want)
				}
				if newest == 1 {
					if _, err := z.serverPools[2].GetObjectInfo(t.Context(), bucket, t.Name(), ObjectOptions{}); !isErrObjectNotFound(err) {
						t.Errorf("superseded copy duplicated into pool 2: %v", err)
					}
				}
			})
		}
	}
}

// The walkers count a superseded version as moved, so its stale source copy is
// removed with the object and the source pool drains.
func TestPoolsMigrationRetiresSupersededCopy(t *testing.T) {
	for _, kind := range []string{"rebalance", "decommission"} {
		t.Run(kind, func(t *testing.T) {
			z, bucket := migrationTestPools(t)
			ctx := t.Context()
			stale, recent := UTCNow().Add(-time.Hour), UTCNow().Add(-time.Minute)
			put := func(object string, pool int, body string, multipart bool, opts ObjectOptions) ObjectInfo {
				return migrationTestObject(t, z, bucket, object, pool, multipart, []string{body}, opts)
			}
			put("stale", 0, "old", false, ObjectOptions{MTime: stale})
			put("stale", 1, "new", false, ObjectOptions{MTime: recent})
			put("stale-multipart", 0, "old", true, ObjectOptions{MTime: stale})
			put("stale-multipart", 1, "new", false, ObjectOptions{MTime: recent})
			put("newer", 0, "new", false, ObjectOptions{MTime: recent})
			put("newer", 1, "old", false, ObjectOptions{MTime: stale})
			oldest := put("history", 0, "old", false, ObjectOptions{Versioned: true, MTime: stale})
			put("history", 1, "new", false, ObjectOptions{Versioned: true, MTime: recent})
			// A suspended bucket's older null delete marker must not hide a newer
			// null version.
			hidden := put("stale-marker", 0, "old", false, ObjectOptions{Versioned: true, MTime: stale.Add(-time.Minute)})
			if _, err := z.serverPools[0].DeleteObject(ctx, bucket, "stale-marker", ObjectOptions{VersionSuspended: true, MTime: stale}); err != nil {
				t.Fatal(err)
			}
			put("stale-marker", 1, "new", false, ObjectOptions{VersionSuspended: true, MTime: recent})
			objects := []string{"stale", "stale-multipart", "newer", "history", "stale-marker"}
			if kind == "decommission" {
				// Rebalance leaves tiered versions in place; decommission moves
				// their metadata.
				migrationTestTiered(t, z, bucket, "stale-tiered", 0, stale)
				put("stale-tiered", 1, "new", false, ObjectOptions{MTime: recent})
				objects = append(objects, "stale-tiered")
			}
			want := map[string]string{}
			for _, object := range objects {
				want[object] = migrationTestBody(t, z.GetObjectNInfo, bucket, object, "")
			}
			if want["stale"] != "new" || want["stale-marker"] != "new" {
				t.Fatalf("fixture reads %v", want)
			}
			if failed := migrationTestWalk(t, z, bucket, 0, kind); failed != 0 {
				t.Fatalf("%d versions failed to move", failed)
			}
			for _, object := range objects {
				if got := migrationTestBody(t, z.GetObjectNInfo, bucket, object, ""); got != want[object] {
					t.Errorf("%s: reads %q after the move, want %q", object, got, want[object])
				}
			}
			var retained []string
			for _, set := range z.serverPools[0].sets {
				if err := set.listObjectsToDecommission(ctx, decomBucketInfo{Name: bucket}, func(entry metaCacheEntry) {
					retained = append(retained, entry.name)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if len(retained) > 0 {
				t.Errorf("source pool retained %v", retained)
			}
			for _, oi := range []ObjectInfo{oldest, hidden} {
				if got := migrationTestBody(t, z.GetObjectNInfo, bucket, oi.Name, oi.VersionID); got != "old" {
					t.Errorf("%s: lost version %s: %q", oi.Name, oi.VersionID, got)
				}
			}
		})
	}
}

func TestPoolsMigrationAfterCompleteRemoval(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	dirs, err := getRandomDisks(32)
	if err != nil {
		t.Fatal(err)
	}
	previousEndpoints := globalEndpoints
	endpoints := mustGetPoolEndpoints(0, dirs[:16]...)
	endpoints = append(endpoints, mustGetPoolEndpoints(1, dirs[16:]...)...)
	globalEndpoints = endpoints
	obj, _, err := initObjectLayer(ctx, endpoints)
	if err != nil {
		globalEndpoints = previousEndpoints
		removeRoots(dirs)
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	var reopened *erasureServerPools
	oldShutdown := false
	t.Cleanup(func() {
		if reopened != nil {
			_ = reopened.Shutdown(context.Background())
		}
		if !oldShutdown {
			_ = z.Shutdown(context.Background())
		}
		removeRoots(dirs)
		globalEndpoints = previousEndpoints
		setObjectLayer(previous)
	})

	bucket, _, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const object = "object"
	mtime := time.Now().UTC().Add(-time.Hour)
	oldBody := bytes.Repeat([]byte{'a'}, 64<<10)
	newBody := bytes.Repeat([]byte{'b'}, 256<<10)
	nullQuorumCrossParityOverwrite(t, z, 0, bucket, object, oldBody, newBody, mtime, ObjectOptions{})

	z.poolMetaMutex.Lock()
	z.poolMeta.Pools[0].Decommission = &PoolDecommissionInfo{}
	z.poolMetaMutex.Unlock()
	if err := z.decommissionPool(ctx, 0, z.serverPools[0], decomBucketInfo{Name: bucket}); err != nil {
		t.Fatal(err)
	}
	if err := z.CompleteDecommission(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := z.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldShutdown = true

	globalEndpoints = mustGetPoolEndpoints(0, dirs[16:]...)
	reopenedObj, _, err := initObjectLayer(t.Context(), globalEndpoints)
	if err != nil {
		t.Fatal(err)
	}
	reopened = reopenedObj.(*erasureServerPools)
	setObjectLayer(reopened)
	_, router, err := initAPIHandlerTest(t.Context(), reopened, nil, MakeBucketOptions{})
	if err != nil {
		t.Fatal(err)
	}

	get := nullQuorumRequest(t, router, http.MethodGet, getGetObjectURL("", bucket, object))
	if get.Code != http.StatusOK || !bytes.Equal(get.Body.Bytes(), newBody) {
		t.Fatalf("GET after pool removal: status=%d bytes=%d", get.Code, get.Body.Len())
	}
	if code, keys := nullQuorumListV2Keys(t, router, bucket); code != http.StatusOK || !slices.Equal(keys, []string{object}) {
		t.Fatalf("ListObjectsV2 after pool removal: status=%d keys=%v", code, keys)
	}
	if code, versions := nullQuorumListVersions(t, router, bucket); code != http.StatusOK || len(versions) != 1 || versions[0].Key != object || versions[0].VersionID != nullVersionID || versions[0].Size != int64(len(newBody)) {
		t.Fatalf("ListObjectVersions after pool removal: status=%d versions=%+v", code, versions)
	}
}

// A tiered move that fails, here because another pool cannot be read, must keep
// its source like any other failed version.
func TestPoolsMigrationTieredFailureKeepsSource(t *testing.T) {
	z, bucket := migrationTestPools(t)
	tiered := migrationTestTiered(t, z, bucket, t.Name(), 0, UTCNow().Add(-time.Hour))
	set := z.serverPools[1].getHashedSet(tiered.Name)
	original := set.getDisks
	disks := append([]StorageAPI(nil), original()...)
	for i := range disks {
		disks[i] = consistencyReadFaultDisk{StorageAPI: disks[i], bucket: bucket, object: tiered.Name}
	}
	set.getDisks = func() []StorageAPI { return disks }
	defer func() { set.getDisks = original }()
	if failed := migrationTestWalk(t, z, bucket, 0, "decommission"); failed != 1 {
		t.Fatalf("%d failed versions, want 1", failed)
	}
	if _, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, tiered.Name, ObjectOptions{VersionID: nullVersionID}); err != nil {
		t.Fatalf("failed move removed its source: %v", err)
	}
}
