// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/minio/minio/internal/grid"
)

// TrackDiskHealth makes the first lookup. Pause the real disk worker at its
// next health callback, without requiring a broken drive or a wall-clock sleep.
type timeoutDiskContext struct {
	context.Context
	calls            atomic.Int32
	entered, release chan struct{}
	tracker          healthDiskCtxValue
	pauseDeadline    bool
	once             sync.Once
}

func (c *timeoutDiskContext) Deadline() (time.Time, bool) {
	if c.pauseDeadline {
		// Metadata operations create a nested deadline in their disk worker.
		c.once.Do(func() { close(c.entered); <-c.release })
	}
	return c.Context.Deadline()
}

func (c *timeoutDiskContext) Value(key any) any {
	if _, ok := key.(healthDiskCtxKey); ok {
		if !c.pauseDeadline && c.calls.Add(1) == 2 {
			close(c.entered)
			<-c.release
		}
		return &c.tracker
	}
	return c.Context.Value(key)
}

func TestStorageTimeoutLocal(t *testing.T) {
	for _, operation := range []string{"rename", "rename-cancel", "write-metadata", "update-metadata", "undo"} {
		t.Run(operation, func(t *testing.T) {
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
			fi.Metadata = map[string]string{"test": "original"}
			if err := disk.WriteMetadata(t.Context(), "", "bucket", "object", fi); err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var lastSuccess int64
				gate := &timeoutDiskContext{
					Context: ctx, entered: make(chan struct{}), release: make(chan struct{}),
					tracker:       healthDiskCtxValue{lastSuccess: &lastSuccess},
					pauseDeadline: operation != "rename" && operation != "rename-cancel",
				}
				unblock := sync.OnceFunc(func() { close(gate.release) })
				defer unblock()
				done := make(chan error, 1)
				go func() {
					var err error
					switch operation {
					case "rename", "rename-cancel":
						_, err = disk.RenameData(gate, minioMetaTmpBucket, "staged", fi, "bucket", "object", RenameOptions{})
					case "write-metadata":
						err = disk.WriteMetadata(gate, "", "bucket", "object", fi)
					case "update-metadata":
						err = disk.UpdateMetadata(gate, "bucket", "object", fi, UpdateMetadataOpts{})
					case "undo":
						err = disk.DeleteVersion(gate, "bucket", "object", fi, false, DeleteOptions{UndoWrite: true})
					}
					done <- err
				}()
				select {
				case <-gate.entered:
				case err := <-done:
					t.Fatalf("operation did not reach the disk worker: %v", err)
				}
				want := context.DeadlineExceeded
				if operation == "rename-cancel" {
					cancel()
					want = context.Canceled
				} else {
					time.Sleep(globalDriveConfig.GetMaxTimeout() + time.Second)
				}
				synctest.Wait()
				select {
				case err := <-done:
					if !errors.Is(err, want) {
						t.Fatalf("expected %v, got %v", want, err)
					}
				default:
					t.Fatal("operation still waits for the blocked worker after its deadline")
				}
				// A timed-out worker must not leave a new physical mutation lock
				// preventing subsequent work on this object.
				if err := disk.WriteMetadata(t.Context(), "", "bucket", "object", fi); err != nil {
					t.Fatalf("subsequent metadata write: %v", err)
				}
				unblock()
				// synctest waits for the released worker before disk teardown.
			})
		})
	}
}

func TestStorageTimeoutRPC(t *testing.T) {
	for _, operation := range []string{"rename", "inline", "write-metadata", "update-metadata", "undo"} {
		for _, deadline := range []bool{false, true} {
			mode := "cancel"
			if deadline {
				mode = "deadline"
			}
			t.Run(operation+"/"+mode, func(t *testing.T) {
				tg, err := grid.SetupTestGrid(2)
				if err != nil {
					t.Fatal(err)
				}
				defer tg.Cleanup()
				entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				handle := func() {
					close(entered)
					<-release
					close(finished)
				}
				const route = "/storage-timeout"
				if err := storageRenameDataRPC.Register(tg.Managers[1], func(*RenameDataHandlerParams) (*RenameDataResp, *grid.RemoteErr) {
					handle()
					return &RenameDataResp{}, nil
				}, route); err != nil {
					t.Fatal(err)
				}
				if err := storageRenameDataInlineRPC.Register(tg.Managers[1], func(p *RenameDataInlineHandlerParams) (*RenameDataResp, *grid.RemoteErr) {
					defer p.Recycle()
					handle()
					return &RenameDataResp{}, nil
				}, route); err != nil {
					t.Fatal(err)
				}
				meta := func(*MetadataHandlerParams) (grid.NoPayload, *grid.RemoteErr) {
					handle()
					return grid.NewNoPayload(), nil
				}
				if err := storageWriteMetadataRPC.Register(tg.Managers[1], meta, route); err != nil {
					t.Fatal(err)
				}
				if err := storageUpdateMetadataRPC.Register(tg.Managers[1], meta, route); err != nil {
					t.Fatal(err)
				}
				if err := storageDeleteVersionRPC.Register(tg.Managers[1], func(p *DeleteVersionHandlerParams) (grid.NoPayload, *grid.RemoteErr) {
					if !p.Opts.UndoWrite || p.Opts.OldDataDir != "previous" {
						t.Error("rollback options were lost on the wire")
					}
					return meta(nil)
				}, route); err != nil {
					t.Fatal(err)
				}
				client := &storageRESTClient{gridConn: tg.Managers[0].Connection(tg.Hosts[1]).Subroute(route)}
				client.diskID.Store(new(string))
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if deadline {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 500*time.Millisecond)
					defer stop()
				}
				done := make(chan error, 1)
				go func() {
					var err error
					fi := FileInfo{}
					switch operation {
					case "write-metadata":
						err = client.WriteMetadata(ctx, "", "bucket", "object", fi)
					case "update-metadata":
						err = client.UpdateMetadata(ctx, "bucket", "object", fi, UpdateMetadataOpts{})
					case "undo":
						err = client.DeleteVersion(ctx, "bucket", "object", fi, false, DeleteOptions{UndoWrite: true, OldDataDir: "previous"})
					default:
						if operation == "inline" {
							fi.Data = []byte("payload")
						}
						_, err = client.RenameData(ctx, minioMetaTmpBucket, "staged", fi, "bucket", "object", RenameOptions{})
					}
					done <- err
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("remote worker did not start")
				}
				want := context.DeadlineExceeded
				if !deadline {
					cancel()
					want = context.Canceled
				}
				select {
				case err := <-done:
					if !errors.Is(err, want) {
						t.Fatalf("expected %v, got %v", want, err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("RPC still waits for the remote worker")
				}
				unblock()
				<-finished
			})
		}
	}
}
