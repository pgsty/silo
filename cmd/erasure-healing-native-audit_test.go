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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
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
			if quorumFault && errors.Is(err, errFileNotFound) {
				t.Fatalf("dry-run must preserve quorum error, got %v", err)
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
			for _, disk := range disks {
				if got := disk.(*nativeAuditDisk).deletes.Load(); got != 0 {
					t.Fatalf("dry-run deleted data %d times", got)
				}
			}
		})
	}
}

func TestNativeAuditDryRunDoesNotReportFailedVerificationClean(t *testing.T) {
	for _, fault := range []struct {
		name string
		err  error
	}{
		{"disk", errDiskNotFound},
		{"volume", errVolumeNotFound},
		{"deadline", context.DeadlineExceeded},
		{"canceled", context.Canceled},
		{"permission", errFileAccessDenied},
	} {
		t.Run(fault.name, func(t *testing.T) {
			for _, mode := range []struct {
				name   string
				dryRun bool
				scan   madmin.HealScanMode
				want   string
			}{
				{"dry-deep", true, madmin.HealDeepScan, madmin.DriveStateUnknown},
				{"repair-deep-control", false, madmin.HealDeepScan, madmin.DriveStateOk},
				{"dry-normal-control", true, madmin.HealNormalScan, madmin.DriveStateOk},
			} {
				t.Run(mode.name, func(t *testing.T) {
					meta := nativeAuditMetadata()
					disks := make([]StorageAPI, len(meta))
					var verifies, checks atomic.Int32
					for i := range disks {
						disks[i] = &nativeAuditDisk{info: meta[i], verify: func() (*CheckPartsResp, error) {
							verifies.Add(1)
							if i == 0 {
								return nil, fault.err
							}
							return &CheckPartsResp{Results: []int{checkPartSuccess, checkPartSuccess}}, nil
						}, check: func() (*CheckPartsResp, error) {
							checks.Add(1)
							return &CheckPartsResp{Results: []int{checkPartSuccess, checkPartSuccess}}, nil
						}}
					}
					er := erasureObjects{
						setDriveCount: 4, defaultParityCount: 2,
						getDisks:     func() []StorageAPI { return disks },
						getEndpoints: nativeAuditEndpoints,
					}
					result, err := er.HealObject(t.Context(), "bucket", "object", "version", madmin.HealOpts{
						DryRun: mode.dryRun, NoLock: true, Remove: true, ScanMode: mode.scan,
					})
					if err != nil {
						t.Fatal(err)
					}
					if len(result.Before.Drives) != len(disks) || !reflect.DeepEqual(result.Before, result.After) {
						t.Fatalf("verification failure changed drive state: %+v", result)
					}
					for i, drive := range result.Before.Drives {
						want := madmin.DriveStateOk
						if i == 0 {
							want = mode.want
						}
						if drive.State != want {
							t.Fatalf("disk %d after successful metadata read and %v verification: got %s, want %s", i, fault.err, drive.State, want)
						}
						if disks[i].(*nativeAuditDisk).deletes.Load() != 0 {
							t.Fatal("verification failure unexpectedly deleted data")
						}
					}
					if mode.scan == madmin.HealDeepScan && (verifies.Load() != 4 || checks.Load() != 0) {
						t.Fatalf("deep verification calls: verifies=%d checks=%d", verifies.Load(), checks.Load())
					}
					if mode.scan == madmin.HealNormalScan && (verifies.Load() != 0 || checks.Load() != 4) {
						t.Fatalf("normal check control: verifies=%d checks=%d", verifies.Load(), checks.Load())
					}
				})
			}
		})
	}
}
