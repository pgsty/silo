//go:build consistency_strict

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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/minio/minio/internal/grid"
)

// Pause at the real disk health callback after staging xl.meta. Unlike a sleep,
// this fixes cancellation between staging and the final metadata rename.
type stagedRenameContext struct {
	context.Context
	meta             string
	entered, release chan struct{}
	once             sync.Once
	tracker          healthDiskCtxValue
}

func (c *stagedRenameContext) Value(key any) any {
	if _, ok := key.(healthDiskCtxKey); ok {
		if _, err := os.Stat(c.meta); err == nil {
			c.once.Do(func() {
				close(c.entered)
				<-c.release
			})
		}
		return &c.tracker
	}
	return c.Context.Value(key)
}

func TestRenameCancellationLocalWaitsForDisk(t *testing.T) {
	disk, root, err := newXLStorageTestSetup(t)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	if err := disk.MakeVol(t.Context(), "bucket"); err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var lastSuccess int64
		gate := &stagedRenameContext{
			Context: ctx, meta: filepath.Join(root, minioMetaTmpBucket, "staged", xlStorageFormatFile),
			entered: make(chan struct{}), release: make(chan struct{}),
			tracker: healthDiskCtxValue{lastSuccess: &lastSuccess},
		}
		fi := newFileInfo("object", 2, 2)
		fi.DataDir, fi.ModTime, fi.Erasure.Index = mustGetUUID(), UTCNow(), 1
		fi.Fresh = true
		done := make(chan error, 1)
		go func() {
			_, err := disk.RenameData(gate, minioMetaTmpBucket, "staged", fi, "bucket", "object", RenameOptions{})
			done <- err
		}()
		<-gate.entered
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			t.Errorf("RenameData returned %v while its disk worker was still running", err)
		default:
		}
		close(gate.release)
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("canceled staged write: %v", err)
			}
		default:
		}
		if _, err := os.Stat(filepath.Join(root, "bucket", "object", xlStorageFormatFile)); !os.IsNotExist(err) {
			t.Fatalf("canceled staged write committed metadata: %v", err)
		}
	})
}

func TestRenameCancellationRPCWaitsForDisk(t *testing.T) {
	for _, operation := range []string{"regular", "inline", "write-metadata", "update-metadata", "undo"} {
		t.Run(operation, func(t *testing.T) {
			tg, err := grid.SetupTestGrid(2)
			if err != nil {
				t.Fatal(err)
			}
			defer tg.Cleanup()
			entered, release := make(chan struct{}), make(chan struct{})
			var committed atomic.Bool
			handle := func(*RenameDataHandlerParams) (*RenameDataResp, *grid.RemoteErr) {
				close(entered)
				<-release
				committed.Store(true)
				return &RenameDataResp{OldDataDir: "previous-generation"}, nil
			}
			const route = "/cancel-commit"
			if err := storageRenameDataRPC.Register(tg.Managers[1], handle, route); err != nil {
				t.Fatal(err)
			}
			if err := storageRenameDataInlineRPC.Register(tg.Managers[1], func(p *RenameDataInlineHandlerParams) (*RenameDataResp, *grid.RemoteErr) {
				defer p.Recycle()
				return handle(&p.RenameDataHandlerParams)
			}, route); err != nil {
				t.Fatal(err)
			}
			meta := func(*MetadataHandlerParams) (grid.NoPayload, *grid.RemoteErr) {
				_, err := handle(nil)
				return grid.NewNoPayload(), err
			}
			if err := storageWriteMetadataRPC.Register(tg.Managers[1], meta, route); err != nil {
				t.Fatal(err)
			}
			if err := storageUpdateMetadataRPC.Register(tg.Managers[1], meta, route); err != nil {
				t.Fatal(err)
			}
			if err := storageDeleteVersionRPC.Register(tg.Managers[1], func(*DeleteVersionHandlerParams) (grid.NoPayload, *grid.RemoteErr) {
				return meta(nil)
			}, route); err != nil {
				t.Fatal(err)
			}
			client := &storageRESTClient{gridConn: tg.Managers[0].Connection(tg.Hosts[1]).Subroute(route)}
			client.diskID.Store(new(string))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fi := FileInfo{}
			if operation == "inline" {
				fi.Data = []byte("payload")
			}
			type result struct {
				resp RenameDataResp
				err  error
			}
			done := make(chan result, 1)
			go func() {
				var resp RenameDataResp
				var err error
				switch operation {
				case "write-metadata":
					err = client.WriteMetadata(ctx, "", "bucket", "object", fi)
				case "update-metadata":
					err = client.UpdateMetadata(ctx, "bucket", "object", fi, UpdateMetadataOpts{})
				case "undo":
					err = client.DeleteVersion(ctx, "bucket", "object", fi, false, DeleteOptions{UndoWrite: true})
				default:
					resp, err = client.RenameData(ctx, minioMetaTmpBucket, "staged", fi, "bucket", "object", RenameOptions{})
				}
				done <- result{resp, err}
			}()
			<-entered
			cancel()
			var early *result
			select {
			case r := <-done:
				early = &r
				t.Errorf("RPC returned %v before the remote disk completed", r.err)
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			if early == nil {
				select {
				case r := <-done:
					wantOld := ""
					if operation == "regular" || operation == "inline" {
						wantOld = "previous-generation"
					}
					if r.err != nil || r.resp.OldDataDir != wantOld || !committed.Load() {
						t.Errorf("lost completed result needed for rollback: %+v", r)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("RPC did not finish after disk completion")
				}
			}
		})
	}
}

func TestRenameCancellationAlreadyCanceledRPC(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// A canceled call must not access the connection or send a new mutation.
	client := &storageRESTClient{}
	client.diskID.Store(new(string))
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("canceled mutation reached the connection: %v", p)
		}
	}()
	_, err := client.RenameData(ctx, minioMetaTmpBucket, "staged", FileInfo{}, "bucket", "object", RenameOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled RenameData: %v", err)
	}
}

type gatedRenameDisk struct {
	StorageAPI
	client *storageRESTClient
}

func (d gatedRenameDisk) RenameData(ctx context.Context, sv, sp string, fi FileInfo, dv, dp string, opts RenameOptions) (RenameDataResp, error) {
	return d.client.RenameData(ctx, sv, sp, fi, dv, dp, opts)
}

func (d gatedRenameDisk) WriteMetadata(ctx context.Context, ov, volume, path string, fi FileInfo) error {
	return d.client.WriteMetadata(ctx, ov, volume, path, fi)
}

func (d gatedRenameDisk) DeleteVersion(ctx context.Context, volume, path string, fi FileInfo, force bool, opts DeleteOptions) error {
	return d.client.DeleteVersion(ctx, volume, path, fi, force, opts)
}

// Use real disk commits behind the real RPC client. The barrier fixes the
// order: every commit has started, then cancellation, then remote completion.
func TestRenameCancellationKeepsLockUntilRollback(t *testing.T) {
	for _, tc := range []struct {
		size      int
		versioned bool
		copy      bool
		shared    bool
	}{
		{32, false, false, false},
		{2 << 20, false, false, false},
		{32, true, false, false},
		{2 << 20, true, false, false},
		{32, false, true, false},
		{2 << 20, false, true, false},
		{32, false, false, true},
		{2 << 20, false, false, true},
	} {
		t.Run(fmt.Sprintf("bytes-%d/other-versions-%t/copy-%t/shared-%t", tc.size, tc.versioned, tc.copy, tc.shared), func(t *testing.T) {
			size := tc.size
			z, bucket := consistencyPools(t)
			object := "cancel-rollback"
			old := strings.Repeat("a", size)
			base := UTCNow().Add(-time.Hour)
			var sharedVersions [2]string
			for pool := range 2 {
				if tc.versioned {
					putConsistencyObject(t, z, bucket, object, pool, "retained-version", ObjectOptions{Versioned: true, MTime: base.Add(-time.Minute)})
				}
				putConsistencyObject(t, z, bucket, object, pool, old, ObjectOptions{MTime: base})
				if tc.shared {
					info, err := z.serverPools[pool].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{})
					if err != nil {
						t.Fatal(err)
					}
					info.metadataOnly, info.versionOnly = true, true
					copied, err := z.serverPools[pool].getHashedSet(object).CopyObject(t.Context(), bucket, object, bucket, object, info,
						ObjectOptions{}, ObjectOptions{Versioned: true, MTime: base.Add(time.Minute)})
					if err != nil {
						t.Fatal(err)
					}
					sharedVersions[pool] = copied.VersionID
				}
			}
			copyInfo, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			copyInfo.metadataOnly = true
			copyInfo.UserDefined["copy-test"] = "canceled"
			// Exercise the production rollback handler and wire options as
			// well as the client. A local DeleteVersion bypasses that boundary.
			globalLocalDrivesMu.Lock()
			previousSets, previousMap := globalLocalSetDrives, globalLocalDrivesMap
			globalLocalSetDrives = nil
			globalLocalDrivesMap = make(map[string]StorageAPI)
			for _, pool := range z.serverPools {
				for _, disk := range pool.getHashedSet(object).getDisks() {
					globalLocalDrivesMap[disk.Endpoint().String()] = disk
				}
			}
			globalLocalDrivesMu.Unlock()
			t.Cleanup(func() {
				globalLocalDrivesMu.Lock()
				globalLocalSetDrives, globalLocalDrivesMap = previousSets, previousMap
				globalLocalDrivesMu.Unlock()
			})
			tg, err := grid.SetupTestGrid(2)
			if err != nil {
				t.Fatal(err)
			}
			defer tg.Cleanup()
			entered := make(chan struct{}, 32)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			var completed atomic.Int32
			var injectCommitFailure atomic.Bool
			injectCommitFailure.Store(true)
			for pi, pool := range z.serverPools {
				set := pool.getHashedSet(object)
				disks, switchDisks := installListingDiskSwitch(set)
				defer switchDisks(disks)
				wrapped := append([]StorageAPI(nil), disks...)
				for i, disk := range disks {
					route := fmt.Sprintf("/cancel-rollback/%d/%d", pi, i)
					server := storageRESTServer{endpoint: disk.Endpoint()}
					if err := storageDeleteVersionRPC.Register(tg.Managers[1], server.DeleteVersionHandler, route); err != nil {
						t.Fatal(err)
					}
					handle := func(p *RenameDataHandlerParams) (*RenameDataResp, *grid.RemoteErr) {
						entered <- struct{}{}
						<-release
						// Cancellation alone must not undo a successful quorum.
						// This rollback fixture also fails half the disks, so its
						// original payload/lock assertions require a real failed commit.
						defer completed.Add(1)
						if i >= len(disks)/2 && injectCommitFailure.Load() {
							return nil, grid.NewRemoteErr(errDiskNotFound)
						}
						resp, err := disk.RenameData(context.Background(), p.SrcVolume, p.SrcPath, p.FI, p.DstVolume, p.DstPath, p.Opts)
						if err != nil {
							return nil, grid.NewRemoteErr(err)
						}
						return &resp, nil
					}
					if err := storageRenameDataRPC.Register(tg.Managers[1], handle, route); err != nil {
						t.Fatal(err)
					}
					if err := storageRenameDataInlineRPC.Register(tg.Managers[1], func(p *RenameDataInlineHandlerParams) (*RenameDataResp, *grid.RemoteErr) {
						defer p.Recycle()
						return handle(&p.RenameDataHandlerParams)
					}, route); err != nil {
						t.Fatal(err)
					}
					if err := storageWriteMetadataRPC.Register(tg.Managers[1], func(p *MetadataHandlerParams) (grid.NoPayload, *grid.RemoteErr) {
						if p.Volume == bucket && p.FilePath == object {
							entered <- struct{}{}
							<-release
							defer completed.Add(1)
						}
						err := disk.WriteMetadata(context.Background(), p.OrigVolume, p.Volume, p.FilePath, p.FI)
						return grid.NewNoPayload(), grid.NewRemoteErr(err)
					}, route); err != nil {
						t.Fatal(err)
					}
					client := &storageRESTClient{gridConn: tg.Managers[0].Connection(tg.Hosts[1]).Subroute(route)}
					client.diskID.Store(new(string))
					wrapped[i] = gatedRenameDisk{disk, client}
				}
				switchDisks(wrapped)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			pending := bytes.Repeat([]byte("b"), size)
			reader := mustGetPutObjReader(t, bytes.NewReader(pending), int64(size), "", "")
			done := make(chan error, 1)
			go func() {
				var err error
				if tc.copy {
					_, err = z.CopyObject(ctx, bucket, object, bucket, object, copyInfo, ObjectOptions{}, ObjectOptions{})
				} else {
					_, err = z.PutObject(ctx, bucket, object, reader, ObjectOptions{})
				}
				done <- err
			}()
			n := z.serverPools[0].getHashedSet(object).setDriveCount
			for range n {
				select {
				case <-entered:
				case err := <-done:
					t.Fatalf("write ended before commit barrier: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatal("write did not reach every disk")
				}
			}
			cancel()
			var early bool
			select {
			case err := <-done:
				early = true
				t.Errorf("mutation returned before remote commits completed: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			lock := z.NewNSLock(bucket, object)
			lockCtx, cancelLock := context.WithTimeout(t.Context(), 50*time.Millisecond)
			lc, lockErr := lock.GetLock(lockCtx, newDynamicTimeout(50*time.Millisecond, 50*time.Millisecond))
			cancelLock()
			if lockErr == nil {
				lock.Unlock(lc)
				t.Error("namespace lock released before remote commits and rollback")
			}
			unblock()
			if early {
				// Keep the old-code failure deterministic; don't race cleanup
				// against handlers intentionally still running at the barrier.
				deadline := time.Now().Add(5 * time.Second)
				for completed.Load() != int32(n) {
					if time.Now().After(deadline) {
						t.Fatal("remote handlers did not finish")
					}
					time.Sleep(time.Millisecond)
				}
				return
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled write unexpectedly acknowledged")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("canceled write did not finish rollback")
			}
			if completed.Load() != int32(n) {
				t.Fatal("returned without accounting for every remote commit")
			}
			injectCommitFailure.Store(false)
			for pi, pool := range z.serverPools {
				for _, version := range []string{"", nullVersionID} {
					r, err := pool.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{VersionID: version})
					if err != nil {
						t.Fatalf("pool %d lost its acknowledged copy (version %q): %v", pi, version, err)
					}
					body, err := io.ReadAll(r)
					r.Close()
					if err != nil || string(body) != old {
						t.Errorf("pool %d rollback lost acknowledged payload (version %q): bytes=%d err=%v", pi, version, len(body), err)
					}
				}
			}
			got, err := z.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(got)
			got.Close()
			if err != nil || string(body) != old {
				t.Fatalf("rollback lost acknowledged payload: bytes=%d err=%v", len(body), err)
			}
			newBody := bytes.Repeat([]byte("c"), size)
			if _, err := z.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, bytes.NewReader(newBody), int64(size), "", ""), ObjectOptions{}); err != nil {
				t.Fatal(err)
			}
			got, err = z.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(got)
			got.Close()
			if err != nil || !bytes.Equal(body, newBody) {
				t.Fatalf("late commit replaced subsequent successful PUT: bytes=%d err=%v", len(body), err)
			}
			if tc.shared {
				for pi, pool := range z.serverPools {
					r, err := pool.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{VersionID: sharedVersions[pi]})
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(r)
					r.Close()
					if err != nil || string(body) != old {
						t.Errorf("commit cleanup destroyed shared version on pool %d: bytes=%d err=%v", pi, len(body), err)
					}
				}
			}
		})
	}
}

func TestRenameCancellationStaleRollbackPreservesNewWrite(t *testing.T) {
	z, bucket := consistencyPools(t)
	const object = "stale-rollback"
	putConsistencyObject(t, z, bucket, object, 0, "canceled-generation", ObjectOptions{})
	disks := z.serverPools[0].getHashedSet(object).getDisks()
	stale := make([]FileInfo, len(disks))
	for i, disk := range disks {
		var err error
		stale[i], err = disk.ReadVersion(t.Context(), "", bucket, object, nullVersionID, ReadOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	putConsistencyObject(t, z, bucket, object, 0, "new-acknowledged-generation", ObjectOptions{})
	for i, disk := range disks {
		err := disk.DeleteVersion(t.Context(), bucket, object, stale[i], false, DeleteOptions{UndoWrite: true})
		if err != nil && !errors.Is(err, errFileVersionNotFound) {
			t.Fatal(err)
		}
	}
	got, err := z.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{})
	if err != nil {
		t.Fatalf("stale rollback removed the new acknowledged write: %v", err)
	}
	defer got.Close()
	body, err := io.ReadAll(got)
	if err != nil || string(body) != "new-acknowledged-generation" {
		t.Fatalf("stale rollback changed the new acknowledged payload: %q, %v", body, err)
	}
}
