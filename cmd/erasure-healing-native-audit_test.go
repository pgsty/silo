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
	"io"
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

func TestNativeAuditCancellationWaitsForAllDriveChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	meta := nativeAuditMetadata()
	started, release := make(chan struct{}, len(meta)), make(chan struct{})
	finished := make(chan struct{}, len(meta)-1)
	disks := make([]StorageAPI, len(meta))
	for i := range disks {
		disks[i] = &nativeAuditDisk{verify: func() (*CheckPartsResp, error) {
			started <- struct{}{}
			<-ctx.Done()
			if i == 3 {
				<-release
			} else {
				finished <- struct{}{}
			}
			return nil, ctx.Err()
		}}
	}
	done := make(chan map[int][]int, 1)
	go func() {
		byDisk, _ := checkObjectWithAllParts(ctx, disks, meta, make([]error, 4), meta[0], false, "bucket", "object", madmin.HealDeepScan)
		done <- byDisk
	}()
	for range disks {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			cancel()
			close(release)
			t.Fatal("drive checks did not start")
		}
	}
	cancel()
	for range len(meta) - 1 {
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("canceled drive checks did not finish")
		}
	}
	select {
	case <-done:
		close(release)
		t.Fatal("cancellation published results while a drive check was still active")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case results := <-done:
		for _, parts := range results {
			for _, result := range parts {
				if result == checkPartSuccess {
					t.Fatal("canceled verification reported a healthy part")
				}
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled checks did not finish")
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

func TestNativeAuditSkippedPayloadsRemainHealthy(t *testing.T) {
	for _, kind := range []string{"deleted", "remote"} {
		t.Run(kind, func(t *testing.T) {
			meta := nativeAuditMetadata()
			disks := make([]StorageAPI, len(meta))
			for i := range disks {
				if kind == "deleted" {
					meta[i].Deleted, meta[i].Size = true, 0
				} else {
					meta[i].TransitionStatus = "complete"
				}
				// Keep Parts populated: these statuses are deliberately unchecked.
				// Unexpected VerifyFile/CheckParts calls panic through nil callbacks.
				disks[i] = &nativeAuditDisk{info: meta[i]}
			}
			er := erasureObjects{
				setDriveCount: 4, defaultParityCount: 2,
				getDisks:     func() []StorageAPI { return disks },
				getEndpoints: nativeAuditEndpoints,
			}
			result, err := er.HealObject(t.Context(), "bucket", "object", "version", madmin.HealOpts{
				DryRun: true, NoLock: true, Remove: true, ScanMode: madmin.HealDeepScan,
			})
			if err != nil || len(result.Before.Drives) != len(disks) || !reflect.DeepEqual(result.Before, result.After) {
				t.Fatalf("skipped payload dry-run changed results: %+v %v", result, err)
			}
			for i, drive := range result.Before.Drives {
				if drive.State != madmin.DriveStateOk || disks[i].(*nativeAuditDisk).deletes.Load() != 0 {
					t.Fatalf("skipped %s payload must stay healthy without mutations: %+v", kind, result)
				}
			}
		})
	}
}

func TestNativeAuditEmptyObjectRemainsHealthy(t *testing.T) {
	obj, roots, err := prepareErasure(t.Context(), 4)
	if err != nil {
		t.Fatal(err)
	}
	setObjectLayer(obj)
	defer removeRoots(roots)
	defer obj.Shutdown(t.Context())
	const bucket, object = "native-audit", "empty-object"
	if err = obj.MakeBucket(t.Context(), bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = obj.PutObject(t.Context(), bucket, object,
		mustGetPutObjReader(t, bytes.NewReader(nil), 0, "", ""), ObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	before := nativeAuditSnapshotBucket(t, roots, bucket)
	result, err := obj.HealObject(t.Context(), bucket, object, "", madmin.HealOpts{DryRun: true, Remove: true, ScanMode: madmin.HealDeepScan})
	if err != nil || !reflect.DeepEqual(result.Before, result.After) {
		t.Fatalf("empty-object dry-run changed results: %+v %v", result, err)
	}
	if len(result.Before.Drives) != 4 {
		t.Fatalf("empty-object dry-run lost drive observations: %+v", result)
	}
	for _, drive := range result.Before.Drives {
		if drive.State != madmin.DriveStateOk {
			t.Fatalf("empty payload was not healthy: %+v", result)
		}
	}
	if after := nativeAuditSnapshotBucket(t, roots, bucket); !reflect.DeepEqual(before, after) {
		t.Fatal("empty-object dry-run changed bucket files or directories")
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

// Include directories and unrelated objects so dry-run cannot hide removals,
// recreated metadata, or abandoned-part cleanup outside the damaged payload.
func nativeAuditSnapshotBucket(t *testing.T, roots []string, bucket string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	for _, root := range roots {
		err := filepath.Walk(filepath.Join(root, bucket), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			var sum [sha256.Size]byte
			if !info.IsDir() {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				sum = sha256.Sum256(data)
			}
			files[path] = fmt.Sprintf("%v/%d/%d/%x", info.Mode(), info.Size(), info.ModTime().UnixNano(), sum)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func nativeAuditTraverseBucket(t *testing.T, obj ObjectLayer, bucket string) []madmin.HealResultItem {
	t.Helper()
	previous := globalBackgroundHealRoutine
	routine := newHealRoutine()
	globalBackgroundHealRoutine = routine
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		routine.AddWorker(ctx, obj, nil)
	}()
	defer func() {
		cancel()
		<-done
		globalBackgroundHealRoutine = previous
	}()
	sequence := newHealSequence(ctx, bucket, "", "local-test", madmin.HealOpts{
		DryRun: true, Remove: true, Recursive: true, ScanMode: madmin.HealDeepScan,
	}, false)
	defer sequence.cancelCtx()
	if err := sequence.healBucket(obj, bucket, false); err != nil {
		t.Fatal(err)
	}
	if sequence.getScannedItemsCount() < 2 {
		t.Fatal("admin traversal did not scan the bucket and its objects")
	}
	return sequence.currentStatus.Items
}

func TestNativeAuditMultipartDryRunAndRepair(t *testing.T) {
	for _, unrecoverable := range []bool{false, true} {
		t.Run(fmt.Sprintf("unrecoverable=%v", unrecoverable), func(t *testing.T) {
			obj, roots, err := prepareErasure(t.Context(), 4)
			if err != nil {
				t.Fatal(err)
			}
			setObjectLayer(obj)
			defer removeRoots(roots)
			defer obj.Shutdown(t.Context())
			const bucket, object = "native-audit", "multipart-object"
			if err = obj.MakeBucket(t.Context(), bucket, MakeBucketOptions{}); err != nil {
				t.Fatal(err)
			}
			part := bytes.Repeat([]byte("native-audit-payload"), 300000)
			upload, err := obj.NewMultipartUpload(t.Context(), bucket, object, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			parts := make([]CompletePart, 2)
			for i := range parts {
				p, err := obj.PutObjectPart(t.Context(), bucket, object, upload.UploadID, i+1,
					mustGetPutObjReader(t, bytes.NewReader(part), int64(len(part)), "", ""), ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				parts[i] = CompletePart{PartNumber: p.PartNumber, ETag: p.ETag}
			}
			if _, err = obj.CompleteMultipartUpload(t.Context(), bucket, object, upload.UploadID, parts, ObjectOptions{}); err != nil {
				t.Fatal(err)
			}
			er := obj.(*erasureServerPools).serverPools[0].sets[0]
			disks := er.getDisks()
			fi, err := disks[0].ReadVersion(t.Context(), "", bucket, object, "", ReadOptions{Healing: true})
			if err != nil {
				t.Fatal(err)
			}
			shard := filepath.Join(roots[0], bucket, object, fi.DataDir, "part.1")
			original, err := os.ReadFile(shard)
			if err != nil {
				t.Fatal(err)
			}
			damaged := bytes.Clone(original)
			damaged[len(damaged)/2] ^= 1 // Keep size unchanged: only deep bitrot detects this.
			if err = os.WriteFile(shard, damaged, 0o600); err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(filepath.Join(roots[1], bucket, object, fi.DataDir, "part.2")); err != nil {
				t.Fatal(err)
			}
			if unrecoverable {
				for _, root := range roots[1:3] {
					if err = os.Remove(filepath.Join(root, bucket, object, fi.DataDir, "part.1")); err != nil {
						t.Fatal(err)
					}
				}
			}
			// These unreferenced parts must survive DryRun+Remove.
			for _, root := range roots {
				abandoned := filepath.Join(root, bucket, object, "00000000-0000-0000-0000-000000000001")
				if err = os.MkdirAll(abandoned, 0o700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(abandoned, "part.1"), []byte("keep during dry-run"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := nativeAuditSnapshotBucket(t, roots, bucket)
			result, err := obj.HealObject(t.Context(), bucket, object, "", madmin.HealOpts{DryRun: true, Remove: true, ScanMode: madmin.HealDeepScan})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result.Before, result.After) || result.Before.Drives[0].State == madmin.DriveStateOk {
				t.Fatalf("dry-run lost damage: %+v", result)
			}
			nativeAuditTraverseBucket(t, obj, bucket)
			if after := nativeAuditSnapshotBucket(t, roots, bucket); !reflect.DeepEqual(before, after) {
				t.Fatal("deep dry-run changed bucket files or directories")
			}
			if unrecoverable {
				return
			}
			if _, err = obj.HealObject(t.Context(), bucket, object, "", madmin.HealOpts{ScanMode: madmin.HealDeepScan}); err != nil {
				t.Fatal(err)
			}
			if repaired, err := os.ReadFile(shard); err != nil || !bytes.Equal(original, repaired) {
				t.Fatalf("corrupt shard was not restored byte for byte: %v", err)
			}
			reader, err := obj.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || !bytes.Equal(got, bytes.Repeat(part, 2)) {
				t.Fatalf("repaired multipart object differs from original: %v", err)
			}
			result, err = obj.HealObject(t.Context(), bucket, object, "", madmin.HealOpts{DryRun: true, ScanMode: madmin.HealDeepScan})
			if err != nil {
				t.Fatal(err)
			}
			for _, drive := range result.Before.Drives {
				if drive.State != madmin.DriveStateOk {
					t.Fatalf("repair left an unhealthy drive: %+v", result)
				}
			}
		})
	}
}

func TestNativeAuditVersionedInlineDryRunAndRepair(t *testing.T) {
	obj, roots, err := prepareErasure(t.Context(), 4)
	if err != nil {
		t.Fatal(err)
	}
	setObjectLayer(obj)
	defer removeRoots(roots)
	defer obj.Shutdown(t.Context())
	const bucket, object = "native-audit", "versioned-object"
	if err = obj.MakeBucket(t.Context(), bucket, MakeBucketOptions{VersioningEnabled: true}); err != nil {
		t.Fatal(err)
	}
	data := []byte("original inline version")
	newData := []byte("newer inline version")
	first, err := obj.PutObject(t.Context(), bucket, object,
		mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{Versioned: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := obj.PutObject(t.Context(), bucket, object,
		mustGetPutObjReader(t, bytes.NewReader(newData), int64(len(newData)), "", ""), ObjectOptions{Versioned: true})
	if err != nil {
		t.Fatal(err)
	}
	marker, err := obj.DeleteObject(t.Context(), bucket, object, ObjectOptions{Versioned: true})
	if err != nil {
		t.Fatal(err)
	}
	if first.VersionID == "" || first.VersionID == second.VersionID || !marker.DeleteMarker {
		t.Fatal("fixture did not create distinct versions and a delete marker")
	}
	disks := obj.(*erasureServerPools).serverPools[0].sets[0].getDisks()
	fi, err := disks[0].ReadVersion(t.Context(), "", bucket, object, first.VersionID, ReadOptions{ReadData: true, Healing: true})
	if err != nil {
		t.Fatal(err)
	}
	if !fi.InlineData() || len(fi.Data) == 0 {
		t.Fatal("fixture did not store inline data")
	}
	fi.Data = bytes.Clone(fi.Data)
	fi.Data[len(fi.Data)-1] ^= 1
	if err = disks[0].WriteMetadata(t.Context(), "", bucket, object, fi); err != nil {
		t.Fatal(err)
	}
	before := nativeAuditSnapshotBucket(t, roots, bucket)
	items := nativeAuditTraverseBucket(t, obj, bucket)
	if len(items) != 4 {
		t.Fatalf("admin traversal must report bucket plus all three versions, got %+v", items)
	}
	seen := make(map[string]bool)
	for _, item := range items {
		if !reflect.DeepEqual(item.Before, item.After) {
			t.Fatalf("admin traversal reported dry-run changes: %+v", item)
		}
		if item.Type == madmin.HealItemObject {
			seen[item.VersionID] = true
			if item.VersionID == first.VersionID && item.Before.Drives[0].State == madmin.DriveStateOk {
				t.Fatalf("admin traversal hid inline corruption: %+v", item)
			}
		}
	}
	if !seen[first.VersionID] || !seen[second.VersionID] || !seen[marker.VersionID] {
		t.Fatalf("admin traversal omitted a version: %v", seen)
	}
	if after := nativeAuditSnapshotBucket(t, roots, bucket); !reflect.DeepEqual(before, after) {
		t.Fatal("versioned inline dry-run changed files or directories")
	}
	result, err := obj.HealObject(t.Context(), bucket, object, first.VersionID, madmin.HealOpts{ScanMode: madmin.HealDeepScan})
	if err != nil {
		t.Fatal(err)
	}
	if result.Before.Drives[0].State == madmin.DriveStateOk || result.After.Drives[0].State != madmin.DriveStateOk {
		t.Fatalf("inline corruption was not detected and repaired: %+v", result)
	}
	for version, want := range map[string][]byte{first.VersionID: data, second.VersionID: newData} {
		reader, err := obj.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{VersionID: version})
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("version %s changed: %v", version, err)
		}
	}
	for _, disk := range disks {
		fi, err := disk.ReadVersion(t.Context(), "", bucket, object, marker.VersionID, ReadOptions{Healing: true})
		if err != nil || !fi.Deleted {
			t.Fatalf("delete marker changed during old-version repair: %v", err)
		}
	}
}

func TestNativeAuditBitrotAlgorithmsWithStorageInitialized(t *testing.T) {
	obj, roots, err := prepareErasure(t.Context(), 4)
	if err != nil {
		t.Fatal(err)
	}
	defer removeRoots(roots)
	defer obj.Shutdown(t.Context())
	// Streaming bitrot requires the byte pool initialized by the object layer.
	for algorithm := range bitrotAlgorithms {
		t.Run(fmt.Sprint(algorithm), func(t *testing.T) {
			testBitrotReaderWriterAlgo(t, algorithm)
		})
	}
}
