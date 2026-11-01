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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/dsync"
	"github.com/minio/minio/internal/grid"
)

type scopeLeaseLocker struct {
	*localLocker
	partition *atomic.Bool
	refresh   chan<- struct{}
}

func (l scopeLeaseLocker) Refresh(ctx context.Context, a dsync.LockArgs) (bool, error) {
	if l.partition.Load() {
		select {
		case l.refresh <- struct{}{}:
		default:
		}
		return false, errors.New("injected lock-plane partition")
	}
	return l.localLocker.Refresh(ctx, a)
}

func (l scopeLeaseLocker) ForceUnlock(ctx context.Context, a dsync.LockArgs) (bool, error) {
	if l.partition.Load() {
		return false, errors.New("partition")
	}
	return l.localLocker.ForceUnlock(ctx, a)
}

type scopeStagedContext struct {
	context.Context
	meta    string
	entered chan<- struct{}
	release <-chan struct{}
	once    sync.Once
	tracker healthDiskCtxValue
}

func (c *scopeStagedContext) Value(k any) any {
	if _, ok := k.(healthDiskCtxKey); ok {
		if _, e := os.Stat(c.meta); e == nil {
			c.once.Do(func() { c.entered <- struct{}{}; <-c.release })
		}
		return &c.tracker
	}
	return c.Context.Value(k)
}

type scopeRPCDisk struct {
	StorageAPI
	client *storageRESTClient
}

func (d scopeRPCDisk) RenameData(ctx context.Context, sv, sp string, fi FileInfo, dv, dp string, o RenameOptions) (RenameDataResp, error) {
	return d.client.RenameData(ctx, sv, sp, fi, dv, dp, o)
}

// Controlled fault schedule: real dsync lockers lose their expired lease,
// while a real disk RenameData is paused after reading and staging xl.meta.
// Only the clock age of lease records and the disk completion schedule are injected.
// No object data or metadata is rewritten by the test after the seed PUT.
func TestMutationLeaseLossAndPartition(t *testing.T) {
	for _, partitioned := range []bool{false, true} {
		t.Run(fmt.Sprintf("network-partition-%t", partitioned), func(t *testing.T) {
			size, _ := strconv.Atoi(os.Getenv("SILO_TEST_MUTATION_BYTES"))
			payload := func(s string) string {
				if size <= len(s) {
					return s
				}
				return s + strings.Repeat(".", size-len(s))
			}
			z, bucket := mutationPools(t)
			const object = "lease-key"
			base := time.Now().Add(-time.Hour)
			mutationPut(t, z, bucket, object, 0, payload("initial-0"), base)
			var partition atomic.Bool
			refreshed := make(chan struct{}, 16)
			locals := make([]*localLocker, 4)
			oldClients := make([]dsync.NetLocker, 4)
			newClients := make([]dsync.NetLocker, 4)
			for i := range locals {
				locals[i] = newLocker()
				oldClients[i] = scopeLeaseLocker{locals[i], &partition, refreshed}
				newClients[i] = locals[i]
			}
			mklock := func(clients []dsync.NetLocker) *distLockInstance {
				return &distLockInstance{rwMutex: dsync.NewDRWMutex(&dsync.Dsync{GetLockers: func() ([]dsync.NetLocker, string) { return clients, "scope-owner" }, Timeouts: dsync.DefaultTimeouts}, bucket+"/"+object), opsID: mustGetUUID()}
			}
			a := mklock(oldClients)
			requestCtx, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			alc, err := a.GetLock(requestCtx, newDynamicTimeout(time.Second, time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Unlock(alc)
			tg, err := grid.SetupTestGrid(2)
			if err != nil {
				t.Fatal(err)
			}
			defer tg.Cleanup()
			entered, release := make(chan struct{}, 8), make(chan struct{})
			physicalDone := make(chan error, 8)
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			set := z.serverPools[0].getHashedSet(object)
			disks, swap := installListingDiskSwitch(set)
			defer swap(disks)
			wrapped := append([]StorageAPI(nil), disks...)
			for i, disk := range disks {
				route := fmt.Sprintf("/lease/%d", i)
				handler := func(p *RenameDataHandlerParams) (*RenameDataResp, *grid.RemoteErr) {
					var success int64
					gate := &scopeStagedContext{Context: context.Background(), meta: filepath.Join(disk.Endpoint().Path, p.SrcVolume, p.SrcPath, xlStorageFormatFile), entered: entered, release: release, tracker: healthDiskCtxValue{lastSuccess: &success}}
					resp, e := disk.RenameData(gate, p.SrcVolume, p.SrcPath, p.FI, p.DstVolume, p.DstPath, p.Opts)
					physicalDone <- e
					return &resp, grid.NewRemoteErr(e)
				}
				if e := storageRenameDataRPC.Register(tg.Managers[1], handler, route); e != nil {
					t.Fatal(e)
				}
				if e := storageRenameDataInlineRPC.Register(tg.Managers[1], func(p *RenameDataInlineHandlerParams) (*RenameDataResp, *grid.RemoteErr) {
					defer p.Recycle()
					return handler(&p.RenameDataHandlerParams)
				}, route); e != nil {
					t.Fatal(e)
				}
				client := &storageRESTClient{gridConn: tg.Managers[0].Connection(tg.Hosts[1]).Subroute(route)}
				client.diskID.Store(new(string))
				wrapped[i] = scopeRPCDisk{disk, client}
			}
			swap(wrapped)
			done := make(chan error, 1)
			go func() {
				body := []byte(payload("pending-1000"))
				_, e := z.serverPools[0].PutObject(alc.Context(), bucket, object, mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), ObjectOptions{NoLock: true, MTime: base.Add(time.Minute)})
				done <- e
			}()
			for range disks {
				select {
				case <-entered:
				case e := <-done:
					t.Fatalf("A returned before disk barrier: %v", e)
				case <-time.After(5 * time.Second):
					t.Fatal("disk barrier timeout")
				}
			}
			t.Log("OBS A staged old metadata on all eight real disks; no final rename yet")
			partition.Store(partitioned)
			for _, l := range locals {
				l.mutex.Lock()
				for key, entries := range l.lockMap {
					for i := range entries {
						entries[i].TimeLastRefresh = time.Now().Add(-lockValidityDuration - time.Second).UnixNano()
					}
					l.lockMap[key] = entries
				}
				l.mutex.Unlock()
				l.expireOldLocks(lockValidityDuration)
			}
			if partitioned {
				select {
				case <-refreshed:
				case <-time.After(13 * time.Second):
					t.Fatal("refresh not attempted")
				}
				time.Sleep(20 * time.Millisecond)
				t.Logf("OBS after failed refresh old context error=%v", alc.Context().Err())
			} else {
				select {
				case <-alc.Context().Done():
				case <-time.After(13 * time.Second):
					t.Fatal("confirmed lost lock did not cancel")
				}
				t.Logf("OBS confirmed lease loss canceled old context: %v", alc.Context().Err())
			}
			b := mklock(newClients)
			blc, e := b.GetLock(context.Background(), newDynamicTimeout(time.Second, time.Second))
			if e != nil {
				t.Fatal(e)
			}
			swap(disks)
			bdone := make(chan error, 1)
			go func() {
				body := []byte(payload("ack-9999"))
				_, e := z.serverPools[0].PutObject(blc.Context(), bucket, object, mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), ObjectOptions{NoLock: true, MTime: base.Add(2 * time.Minute)})
				b.Unlock(blc)
				bdone <- e
			}()
			bearly := false
			select {
			case e := <-bdone:
				if e != nil {
					t.Fatal(e)
				}
				bearly = true
				t.Log("OBS B acquired the same lock and ACKed while A remained physically staged")
			case <-time.After(150 * time.Millisecond):
				t.Log("OBS B is waiting for the earlier disk transaction")
			}
			if partitioned {
				cancelRequest()
			}
			unblock()
			select {
			case e := <-done:
				t.Logf("OBS A finished: %v", e)
			case <-time.After(5 * time.Second):
				t.Fatal("A did not finish")
			}
			if !bearly {
				select {
				case e := <-bdone:
					if e != nil {
						t.Fatal(e)
					}
					t.Log("OBS B ACKed after disk serialization")
				case <-time.After(5 * time.Second):
					t.Fatal("B did not finish")
				}
			}

			for range disks {
				select {
				case e := <-physicalDone:
					t.Logf("OBS physical handler completed: %v", e)
				case <-time.After(5 * time.Second):
					t.Fatal("physical handler did not finish")
				}
			}
			for _, fast := range []bool{false, true} {
				r, e := z.GetObjectNInfo(context.Background(), bucket, object, nil, nil, ObjectOptions{FastGetObjInfo: fast})
				if e != nil {
					t.Errorf("OBS latest acknowledged payload unreadable fast=%t error=%v", fast, e)
					continue
				}
				data, e := io.ReadAll(r)
				r.Close()
				if e != nil {
					t.Fatal(e)
				}
				shown := string(data)
				if len(shown) > 32 {
					shown = shown[:32]
				}
				t.Logf("OBS final GET fast=%t bytes=%d prefix=%q", fast, len(data), shown)
				if string(data) != payload("ack-9999") && string(data) != payload("pending-1000") {
					t.Errorf("STRICT STALE VALUE: prefix %q is neither latest ACK nor pending write", shown)
				}
			}
		})
	}
}
