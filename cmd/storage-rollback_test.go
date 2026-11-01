// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/minio/minio/internal/grid"
)

type cancelableRenameDisk struct {
	StorageAPI
	entered chan<- struct{}
	release <-chan struct{}
}

func (d cancelableRenameDisk) RenameData(ctx context.Context, _, _ string, _ FileInfo, _, _ string, _ RenameOptions) (RenameDataResp, error) {
	d.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return RenameDataResp{}, ctx.Err()
	case <-d.release:
		return RenameDataResp{}, errDiskNotFound
	}
}

func TestStorageTimeoutCoordinatorCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		entered, release := make(chan struct{}, 4), make(chan struct{})
		defer close(release)
		disks := make([]StorageAPI, 4)
		metadata := make([]FileInfo, 4)
		for i := range disks {
			disks[i] = cancelableRenameDisk{entered: entered, release: release}
			metadata[i] = FileInfo{Deleted: true}
		}
		done := make(chan error, 1)
		go func() {
			_, _, _, err := renameData(ctx, disks, minioMetaTmpBucket, "staged", metadata, "bucket", "object", 3)
			done <- err
		}()
		for range disks {
			<-entered
		}
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("canceled commit unexpectedly succeeded")
			}
		default:
			t.Fatal("coordinator did not propagate cancellation to disk calls")
		}
	})
}

type rollbackOptionsDisk struct {
	StorageAPI
	mu   sync.Mutex
	opts DeleteOptions
}

func (d *rollbackOptionsDisk) DeleteVersion(_ context.Context, _, _ string, _ FileInfo, _ bool, opts DeleteOptions) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.opts = opts
	return nil
}

func TestStorageRollbackRPCOptions(t *testing.T) {
	endpoint, err := NewEndpoint(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	disk := &rollbackOptionsDisk{}
	globalLocalDrivesMu.Lock()
	oldDrives, oldSets := globalLocalDrivesMap, globalLocalSetDrives
	globalLocalDrivesMap = map[string]StorageAPI{endpoint.String(): disk}
	globalLocalSetDrives = nil
	globalLocalDrivesMu.Unlock()
	defer func() {
		globalLocalDrivesMu.Lock()
		globalLocalDrivesMap, globalLocalSetDrives = oldDrives, oldSets
		globalLocalDrivesMu.Unlock()
	}()
	tg, err := grid.SetupTestGrid(2)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Cleanup()
	server := storageRESTServer{endpoint: endpoint}
	const route = "/rollback-options"
	if err := storageDeleteVersionRPC.Register(tg.Managers[1], server.DeleteVersionHandler, route); err != nil {
		t.Fatal(err)
	}
	client := &storageRESTClient{gridConn: tg.Managers[0].Connection(tg.Hosts[1]).Subroute(route)}
	client.diskID.Store(new(string))
	want := DeleteOptions{UndoWrite: true, OldDataDir: mustGetUUID()}
	if err := client.DeleteVersion(t.Context(), "bucket", "object", FileInfo{}, false, want); err != nil {
		t.Fatal(err)
	}
	disk.mu.Lock()
	defer disk.mu.Unlock()
	if disk.opts != want {
		t.Fatalf("remote handler lost rollback options: got %+v, want %+v", disk.opts, want)
	}
}

func TestStoragePrereleaseMetadataHidden(t *testing.T) {
	disk, _, err := newXLStorageTestSetup(t)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	if err := disk.MakeVol(t.Context(), "bucket"); err != nil {
		t.Fatal(err)
	}
	fi := newFileInfo("object", 2, 2)
	fi.DataDir, fi.ModTime, fi.Erasure.Index = mustGetUUID(), UTCNow(), 1
	fi.Metadata = map[string]string{rollbackIDKey: mustGetUUID(), "user-key": "value"}
	if err := disk.WriteMetadata(t.Context(), "", "bucket", "object", fi); err != nil {
		t.Fatal(err)
	}
	got, err := disk.ReadVersion(t.Context(), "", "bucket", "object", "", ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	public := cleanMetadata(got.Metadata)
	if _, ok := public[rollbackIDKey]; ok || public["user-key"] != "value" {
		t.Fatalf("pre-release metadata exposed or user metadata lost: %+v", public)
	}
}
