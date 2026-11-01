//go:build consistency_strict

// Preserved diagnostic for the deferred strict-read policy. This is not a
// maintenance release gate; failures record intentionally unresolved risks.

// Copyright (c) 2026 Feng Ruohang
//
// This file is part of Silo Object Storage.
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
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	madmin "github.com/minio/madmin-go/v3"
)

// All metadata is valid and readable. Only the completed generations differ.
// No timing, missing files, synthetic read error or malformed metadata is needed.
func TestReadGenerationConflictIsNotAbsence(t *testing.T) {
	raw := make([]RawFileInfo, 8)
	for i := range raw {
		fi := newFileInfo("object", 4, 4)
		fi.Erasure.Index = i + 1
		fi.ModTime = time.Unix(100+int64(i%4), 0)
		fi.DataDir = mustGetUUID()
		fi.Metadata = map[string]string{"etag": fmt.Sprint(i % 4)}
		var meta xlMetaV2
		if err := meta.AddVersion(fi); err != nil {
			t.Fatal(err)
		}
		buf, err := meta.AppendTo(nil)
		if err != nil {
			t.Fatal(err)
		}
		raw[i] = RawFileInfo{Buf: buf}
	}
	_, errs := pickLatestQuorumFilesInfo(t.Context(), raw, make([]error, len(raw)), "bucket", "object", true, false)
	err := reduceReadQuorumErrs(t.Context(), errs, objectOpIgnoredErrs, 4)
	if api := toAPIError(t.Context(), toObjectErr(err, "bucket", "object")); api.HTTPStatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readable conflicting generations reported as absence: %v (%+v)", err, api)
	}
}

func TestPoolsReadGenerationConflictDoesNotExposeOldValue(t *testing.T) {
	z, bucket := consistencyPools(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	router := initTestAPIEndPoints(z, []string{"GetObject", "HeadObject"})
	for _, tc := range []struct {
		pool int
		mode string
	}{
		{0, "split"},
		{1, "split"},
		{0, "older-quorum"},
		{1, "older-quorum"},
		{0, "newer-quorum"},
		{1, "newer-quorum"},
	} {
		t.Run(fmt.Sprintf("%s/pool-%d", tc.mode, tc.pool), func(t *testing.T) {
			broken := tc.pool
			object := fmt.Sprintf("conflict-%s-%d", tc.mode, broken)
			base := UTCNow().Add(-time.Hour)
			putConsistencyObject(t, z, bucket, object, 1-broken, "old-acknowledged", ObjectOptions{MTime: base})
			set := z.serverPools[broken].getHashedSet(object)
			disks := set.getDisks()
			saved := make([][]byte, len(disks))
			savedParts := make([]map[string][]byte, len(disks))
			for generation := range 4 {
				putConsistencyObject(t, z, bucket, object, broken, fmt.Sprintf("newer-%d", generation),
					ObjectOptions{MTime: base.Add(time.Duration(generation+1) * time.Minute)})
				for i, disk := range disks {
					g := i % 4
					switch tc.mode {
					case "older-quorum":
						g = 0
						if i >= len(disks)-3 {
							g = i - (len(disks) - 3) + 1
						}
					case "newer-quorum":
						g = 3
						if i < 3 {
							g = i
						}
					}
					if g != generation {
						continue
					}
					buf, err := disk.ReadAll(ctx, bucket, pathJoin(object, xlStorageFormatFile))
					if err != nil {
						t.Fatal(err)
					}
					saved[i] = bytes.Clone(buf)
					savedParts[i] = readGenerationParts(t, disk, bucket, object, buf)
				}
			}
			for i, disk := range disks {
				for path, data := range savedParts[i] {
					if err := disk.WriteAll(ctx, bucket, path, data); err != nil {
						t.Fatal(err)
					}
				}
				if err := disk.WriteAll(ctx, bucket, pathJoin(object, xlStorageFormatFile), saved[i]); err != nil {
					t.Fatal(err)
				}
			}
			for _, version := range []string{"", nullVersionID} {
				for _, method := range []string{http.MethodHead, http.MethodGet} {
					rec := consistencyRequest(t, router, method, bucket, object, version)
					want := http.StatusServiceUnavailable
					if tc.mode == "newer-quorum" {
						want = http.StatusOK
					}
					if rec.Code != want {
						t.Errorf("%s version=%q: want status=%d, got=%d body=%q", method, version, want, rec.Code, rec.Body.String())
					}
					if want == http.StatusOK && method == http.MethodGet && rec.Body.String() != "newer-3" {
						t.Errorf("latest quorum did not return its payload: %q", rec.Body.String())
					}
				}
			}
			if tc.mode != "newer-quorum" {
				for _, version := range []string{"", nullVersionID} {
					_, err := set.CopyObject(ctx, bucket, object, bucket, object,
						ObjectInfo{metadataOnly: true, UserDefined: map[string]string{"copy-test": "conflicting-source"}},
						ObjectOptions{VersionID: version}, ObjectOptions{})
					if !isErrReadQuorum(err) {
						t.Errorf("COPY-to-self version=%q: want read-quorum error, got %v", version, err)
					}
					for _, scan := range []madmin.HealScanMode{madmin.HealNormalScan, madmin.HealDeepScan} {
						_, err := set.HealObject(ctx, bucket, object, version, madmin.HealOpts{ScanMode: scan, Remove: true})
						if !isErrReadQuorum(err) {
							t.Errorf("heal version=%q scan=%v: want read-quorum error, got %v", version, scan, err)
						}
					}
				}
			}
			for i, disk := range disks {
				buf, err := disk.ReadAll(ctx, bucket, pathJoin(object, xlStorageFormatFile))
				if err != nil || !bytes.Equal(buf, saved[i]) {
					t.Errorf("read or heal destroyed conflicting generation on disk %d: %v", i, err)
				}
				if tc.mode != "newer-quorum" {
					for path, data := range savedParts[i] {
						got, err := disk.ReadAll(ctx, bucket, path)
						if err != nil || !bytes.Equal(got, data) {
							t.Errorf("read or heal destroyed generation shard on disk %d: %s: %v", i, path, err)
						}
					}
				}
			}
		})
	}
}

func readGenerationParts(t *testing.T, disk StorageAPI, bucket, object string, metadata []byte) map[string][]byte {
	t.Helper()
	fi, err := fileInfoFromRaw(RawFileInfo{Buf: metadata}, bucket, object, false, false)
	if err != nil {
		t.Fatal(err)
	}
	parts := make(map[string][]byte)
	if fi.InlineData() || fi.Size == 0 {
		return parts
	}
	// Later PUTs remove the previous data directory. Save its real bitrot
	// shards too, so restoring metadata never fabricates missing-part damage.
	for _, part := range fi.Parts {
		path := pathJoin(object, fi.DataDir, fmt.Sprintf("part.%d", part.Number))
		data, err := disk.ReadAll(t.Context(), bucket, path)
		if err != nil {
			t.Fatal(err)
		}
		parts[path] = data
	}
	return parts
}

func TestPoolsReadUnavailablePoolDoesNotExposeOldValue(t *testing.T) {
	z, bucket := consistencyPools(t)
	for broken := range 2 {
		t.Run(fmt.Sprintf("broken-pool-%d", broken), func(t *testing.T) {
			object := fmt.Sprintf("unavailable-%d", broken)
			putConsistencyObject(t, z, bucket, object, 1-broken, "old-acknowledged", ObjectOptions{})
			set := z.serverPools[broken].getHashedSet(object)
			disks, switchDisks := installListingDiskSwitch(set)
			defer switchDisks(disks)
			faulty := append([]StorageAPI(nil), disks...)
			for i := range faulty {
				faulty[i] = consistencyReadFaultDisk{StorageAPI: faulty[i], bucket: bucket, object: object}
			}
			switchDisks(faulty)
			if _, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); err == nil || isErrObjectNotFound(err) {
				t.Errorf("unknown pool state allowed an old value: %v", err)
			}
		})
	}
}

type generationReadGateDisk struct {
	StorageAPI
	ready   chan<- struct{}
	release <-chan struct{}
}

func (d generationReadGateDisk) ReadXL(ctx context.Context, volume, path string, data bool) (RawFileInfo, error) {
	fi, err := d.StorageAPI.ReadXL(ctx, volume, path, data)
	d.ready <- struct{}{}
	if d.release != nil {
		<-d.release
	}
	return fi, err
}

func (d generationReadGateDisk) ReadVersion(ctx context.Context, orig, volume, path, version string, opts ReadOptions) (FileInfo, error) {
	fi, err := d.StorageAPI.ReadVersion(ctx, orig, volume, path, version, opts)
	d.ready <- struct{}{}
	if d.release != nil {
		<-d.release
	}
	return fi, err
}

func TestReadGenerationFastInfoWaitsForSlowDisk(t *testing.T) {
	for _, version := range []string{"", nullVersionID} {
		t.Run("version="+version, func(t *testing.T) {
			z, bucket := consistencyPools(t)
			const object = "slow-newer-generation"
			set := z.serverPools[0].getHashedSet(object)
			disks, switchDisks := installListingDiskSwitch(set)
			defer switchDisks(disks)
			base := UTCNow().Add(-time.Hour)
			putConsistencyObject(t, z, bucket, object, 0, "old", ObjectOptions{MTime: base})
			saved := make([][]byte, len(disks)-1)
			for i := range saved {
				saved[i] = mustReadNullQuorumMeta(t, disks[i], bucket, object)
			}
			putConsistencyObject(t, z, bucket, object, 0, "new", ObjectOptions{MTime: base.Add(time.Minute)})
			for i, meta := range saved {
				if err := disks[i].WriteAll(t.Context(), bucket, pathJoin(object, xlStorageFormatFile), meta); err != nil {
					t.Fatal(err)
				}
			}
			ready, release := make(chan struct{}, len(disks)), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			wrapped := append([]StorageAPI(nil), disks...)
			for i, disk := range disks {
				gate := generationReadGateDisk{StorageAPI: disk, ready: ready}
				if i == len(disks)-1 {
					gate.release = release
				}
				wrapped[i] = gate
			}
			switchDisks(wrapped)
			done := make(chan error, 1)
			go func() {
				_, _, _, err := set.getObjectFileInfo(t.Context(), bucket, object, ObjectOptions{FastGetObjInfo: true, VersionID: version}, false)
				done <- err
			}()
			for range disks {
				select {
				case <-ready:
				case <-time.After(5 * time.Second):
					t.Fatal("metadata reads did not reach the barrier")
				}
			}
			early := false
			select {
			case err := <-done:
				early = true
				t.Errorf("fast read returned before the newer disk: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			unblock()
			if !early {
				select {
				case err := <-done:
					if !isErrReadQuorum(err) {
						t.Fatalf("fast read exposed the old generation: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("fast read did not finish after the newer disk")
				}
			}
		})
	}
}
