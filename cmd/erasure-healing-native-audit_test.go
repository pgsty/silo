// Copyright (c) 2026 Jasper Bernhardt
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
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
)

// Unimplemented operations panic: the dry-run tests only allow reads and checks.
type nativeAuditDisk struct {
	StorageAPI
	info    FileInfo
	readErr error
	verify  func() (*CheckPartsResp, error)
	check   func() (*CheckPartsResp, error)
	deletes atomic.Int32
}

func (d *nativeAuditDisk) ReadVersion(context.Context, string, string, string, string, ReadOptions) (FileInfo, error) {
	return d.info, d.readErr
}

func (d *nativeAuditDisk) VerifyFile(context.Context, string, string, FileInfo) (*CheckPartsResp, error) {
	return d.verify()
}

func (d *nativeAuditDisk) CheckParts(context.Context, string, string, FileInfo) (*CheckPartsResp, error) {
	return d.check()
}

func (d *nativeAuditDisk) DeleteVersion(context.Context, string, string, FileInfo, bool, DeleteOptions) error {
	d.deletes.Add(1)
	return nil
}

func nativeAuditMetadata() []FileInfo {
	meta := make([]FileInfo, 4)
	for i := range meta {
		meta[i] = newFileInfo("object", 2, 2)
		meta[i].Volume, meta[i].Name = "bucket", "object"
		meta[i].DataDir = "data"
		meta[i].ModTime = time.Unix(123, 0).UTC()
		meta[i].Size = 1024
		meta[i].Erasure.Distribution = []int{1, 2, 3, 4}
		meta[i].Erasure.Index = i + 1
		meta[i].Parts = []ObjectPartInfo{{Number: 1, Size: 512}, {Number: 2, Size: 512}}
	}
	return meta
}

func nativeAuditEndpoints() []Endpoint {
	endpoints := make([]Endpoint, 4)
	for i := range endpoints {
		endpoints[i].URL = &url.URL{Path: fmt.Sprintf("/synthetic/disk%d", i)}
	}
	return endpoints
}

func TestNativeAuditDeepChecksOverlap(t *testing.T) {
	meta := nativeAuditMetadata()
	started, release := make(chan int, len(meta)), make(chan struct{})
	disks := make([]StorageAPI, len(meta))
	for i := range disks {
		disks[i] = &nativeAuditDisk{verify: func() (*CheckPartsResp, error) {
			started <- i
			<-release
			if i == 3 {
				return nil, errDiskNotFound
			}
			result := &CheckPartsResp{Results: []int{checkPartSuccess, checkPartSuccess}}
			if i == 2 {
				result.Results[1] = checkPartFileCorrupt
			}
			return result, nil
		}}
	}
	done := make(chan struct{})
	var byDisk, byPart map[int][]int
	go func() {
		byDisk, byPart = checkObjectWithAllParts(t.Context(), disks, meta, make([]error, 4), meta[0], false, "bucket", "object", madmin.HealDeepScan)
		close(done)
	}()
	// A serial implementation cannot reach all four calls before release.
	for range disks {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			<-done
			t.Fatal("deep drive verification did not overlap")
		}
	}
	close(release)
	<-done
	want := map[int][]int{0: {1, 1}, 1: {1, 1}, 2: {1, checkPartFileCorrupt}, 3: {checkPartDiskNotFound, checkPartDiskNotFound}}
	if !reflect.DeepEqual(byDisk, want) {
		t.Fatalf("per-drive results: got %v, want %v", byDisk, want)
	}
	if !reflect.DeepEqual(byPart[1], []int{1, 1, checkPartFileCorrupt, checkPartDiskNotFound}) {
		t.Fatalf("per-part transpose lost errors: %v", byPart)
	}
}

func TestNativeAuditNormalChecksStaySerial(t *testing.T) {
	meta := nativeAuditMetadata()
	var calls, active atomic.Int32
	disks := make([]StorageAPI, len(meta))
	for i := range disks {
		disks[i] = &nativeAuditDisk{check: func() (*CheckPartsResp, error) {
			if active.Add(1) != 1 {
				t.Error("normal checks overlapped")
			}
			defer active.Add(-1)
			calls.Add(1)
			return &CheckPartsResp{Results: []int{checkPartSuccess, checkPartSuccess}}, nil
		}}
	}
	checkObjectWithAllParts(t.Context(), disks, meta, make([]error, 4), meta[0], false, "bucket", "object", madmin.HealNormalScan)
	if calls.Load() != 4 {
		t.Fatalf("normal check calls: %d", calls.Load())
	}
}

func TestNativeAuditInlineStillUsesNativeBitrot(t *testing.T) {
	for _, mode := range []madmin.HealScanMode{madmin.HealNormalScan, madmin.HealDeepScan} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			meta := nativeAuditMetadata()
			disks := make([]StorageAPI, len(meta))
			for i := range disks {
				data := []byte("synthetic inline shard")
				sum := sha256.Sum256(data)
				meta[i].Data = append([]byte(nil), data...)
				meta[i].Parts = meta[i].Parts[:1]
				meta[i].SetInlineData()
				meta[i].Erasure.Checksums = []ChecksumInfo{{PartNumber: 1, Algorithm: SHA256, Hash: sum[:]}}
				disks[i] = &nativeAuditDisk{}
			}
			meta[2].Data[0] ^= 1
			results, _ := checkObjectWithAllParts(t.Context(), disks, meta, make([]error, 4), meta[0], false, "bucket", "object", mode)
			for i := range disks {
				want := checkPartSuccess
				if i == 2 {
					want = checkPartFileCorrupt
				}
				if results[i][0] != want {
					t.Fatalf("inline disk %d: got %v, want %d", i, results[i], want)
				}
			}
		})
	}
}

func TestNativeAuditDryRunPreservesFaults(t *testing.T) {
	for _, fault := range []string{"metadata-quorum", "corrupt-metadata", "missing-parts", "corrupt-parts", "inline-corrupt", "delete-marker-quorum"} {
		t.Run(fault, func(t *testing.T) {
			meta := nativeAuditMetadata()
			disks := make([]StorageAPI, len(meta))
			for i := range disks {
				disk := &nativeAuditDisk{info: meta[i], verify: func() (*CheckPartsResp, error) {
					return &CheckPartsResp{Results: []int{checkPartSuccess, checkPartSuccess}}, nil
				}}
				if i < 3 {
					switch fault {
					case "metadata-quorum", "delete-marker-quorum":
						disk.readErr = errFileVersionNotFound
					case "corrupt-metadata":
						disk.readErr = errFileCorrupt
					case "missing-parts":
						disk.verify = func() (*CheckPartsResp, error) { return nil, errFileNotFound }
					case "corrupt-parts":
						disk.verify = func() (*CheckPartsResp, error) { return nil, errFileCorrupt }
					}
				}
				if fault == "delete-marker-quorum" {
					disk.info.Deleted = true
					disk.info.Size = 0
				}
				if fault == "inline-corrupt" {
					disk.info.Data = []byte("corrupt")
					disk.info.Parts = disk.info.Parts[:1]
					disk.info.SetInlineData()
					disk.info.Erasure.Checksums = []ChecksumInfo{{PartNumber: 1, Algorithm: SHA256, Hash: make([]byte, sha256.Size)}}
				}
				disks[i] = disk
			}
			er := erasureObjects{
				setDriveCount: 4, defaultParityCount: 2,
				getDisks:     func() []StorageAPI { return disks },
				getEndpoints: nativeAuditEndpoints,
			}
			result, err := er.HealObject(t.Context(), "bucket", "object", "version", madmin.HealOpts{DryRun: true, NoLock: true, Remove: true, ScanMode: madmin.HealDeepScan})
			for _, disk := range disks {
				if got := disk.(*nativeAuditDisk).deletes.Load(); got != 0 {
					t.Fatalf("dry-run deleted data %d times", got)
				}
			}
			quorumFault := fault == "metadata-quorum" || fault == "corrupt-metadata" || fault == "delete-marker-quorum"
			if quorumFault && err == nil {
				t.Fatal("metadata quorum failure reported success")
			}
			if !quorumFault && err != nil {
				t.Fatal(err)
			}
			if len(result.Before.Drives) != len(disks) || !reflect.DeepEqual(result.Before, result.After) {
				t.Fatalf("dry-run states must preserve observed damage: %+v", result)
			}
			switch fault {
			case "metadata-quorum", "delete-marker-quorum":
				if !isErrVersionNotFound(err) {
					t.Fatalf("dry-run must return the reduced metadata error, got %v", err)
				}
			case "corrupt-metadata":
				if !errors.Is(err, errFileCorrupt) {
					t.Fatalf("dry-run must return the reduced metadata error, got %v", err)
				}
			}
			unhealthy := 0
			for _, drive := range result.Before.Drives {
				if drive.State != madmin.DriveStateOk {
					unhealthy++
				}
			}
			if unhealthy < 3 {
				t.Fatalf("faults were not reported: %+v", result.Before)
			}
		})
	}
}

// This control proves the missing-metadata fixture reaches dangling deletion.
func TestNativeAuditNonDryRunStillDeletesDangling(t *testing.T) {
	meta := nativeAuditMetadata()
	disks := make([]StorageAPI, len(meta))
	for i := range disks {
		disk := &nativeAuditDisk{info: meta[i]}
		if i < 3 {
			disk.readErr = errFileVersionNotFound
		}
		disks[i] = disk
	}
	er := erasureObjects{
		setDriveCount: 4, defaultParityCount: 2,
		getDisks:     func() []StorageAPI { return disks },
		getEndpoints: nativeAuditEndpoints,
	}
	_, err := er.HealObject(t.Context(), "bucket", "object", "version", madmin.HealOpts{NoLock: true, Remove: true, ScanMode: madmin.HealDeepScan})
	if err == nil {
		t.Fatal("dangling deletion must report the object removed")
	}
	for _, disk := range disks {
		if got := disk.(*nativeAuditDisk).deletes.Load(); got != 1 {
			t.Fatalf("control did not reach dangling deletion: %d", got)
		}
	}
}

func TestNativeAuditDryRunPreservesDanglingFiles(t *testing.T) {
	obj, roots, err := prepareErasure(t.Context(), 4)
	if err != nil {
		t.Fatal(err)
	}
	setObjectLayer(obj)
	defer removeRoots(roots)
	defer obj.Shutdown(t.Context())
	const bucket, object = "native-audit", "dangling-object"
	if err = obj.MakeBucket(t.Context(), bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("x"), 1024*1024)
	if _, err = obj.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, root := range roots[:3] {
		if err = os.Remove(filepath.Join(root, bucket, object, xlStorageFormatFile)); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func() map[string]string {
		files := make(map[string]string)
		for _, root := range roots {
			err := filepath.Walk(filepath.Join(root, bucket, object), func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				files[path] = fmt.Sprintf("%d/%d/%x", info.Size(), info.ModTime().UnixNano(), sha256.Sum256(data))
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		return files
	}
	before := snapshot()
	if len(before) < 2 {
		t.Fatal("fixture has no surviving metadata and payload files")
	}
	result, err := obj.HealObject(t.Context(), bucket, object, "", madmin.HealOpts{DryRun: true, Remove: true, ScanMode: madmin.HealDeepScan})
	if err == nil {
		t.Fatal("missing metadata quorum reported success")
	}
	if !reflect.DeepEqual(result.Before, result.After) {
		t.Fatalf("dry-run reported changes: %+v", result)
	}
	if after := snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("dry-run changed surviving object files: before=%v after=%v", before, after)
	}
}
