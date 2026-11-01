//go:build consistency_strict

// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type abandonedCleanupCommitDisk struct {
	StorageAPI
	entered chan<- struct{}
	release <-chan struct{}
}

func (d abandonedCleanupCommitDisk) RenameData(ctx context.Context, sv, sp string, fi FileInfo, dv, dp string, o RenameOptions) (RenameDataResp, error) {
	var success int64
	gate := &scopeStagedContext{
		Context: ctx, meta: filepath.Join(d.Endpoint().Path, dv, dp, fi.DataDir, "part.1"),
		entered: d.entered, release: d.release,
		tracker: healthDiskCtxValue{lastSuccess: &success},
	}
	return d.StorageAPI.RenameData(gate, sv, sp, fi, dv, dp, o)
}

// A lost namespace lease can admit cleanup while a disk transaction is between
// moving its external shards and replacing xl.meta. Those shards are live work,
// even though the old metadata does not refer to them yet. Cleanup must wait.
func TestMutationAbandonedCleanupWaitsForCommit(t *testing.T) {
	z, bucket := mutationPools(t)
	const object = "cleanup-during-commit"
	body := strings.Repeat("new payload", 200000)
	mutationPut(t, z, bucket, object, 0, strings.Repeat("old payload", 200000), time.Now().Add(-time.Minute))
	set := z.serverPools[0].getHashedSet(object)
	disks, swap := installListingDiskSwitch(set)
	defer swap(disks)
	entered, release := make(chan struct{}, len(disks)), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	wrapped := append([]StorageAPI(nil), disks...)
	for i, d := range disks {
		wrapped[i] = abandonedCleanupCommitDisk{d, entered, release}
	}
	swap(wrapped)
	committed := make(chan error, 1)
	go func() {
		_, err := z.serverPools[0].PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader(body), int64(len(body)), "", ""), ObjectOptions{NoLock: true})
		committed <- err
	}()
	for range disks {
		select {
		case <-entered:
		case err := <-committed:
			t.Fatalf("PUT returned before shard barrier: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("PUT did not move all external shards")
		}
	}
	t.Log("All eight new external shard directories exist; old xl.meta is still active")
	cleaned := make(chan error, len(disks))
	for _, d := range disks {
		go func(d StorageAPI) { cleaned <- d.CleanAbandonedData(context.Background(), bucket, object) }(d)
	}
	early := 0
	timer := time.NewTimer(150 * time.Millisecond)
wait:
	for {
		select {
		case err := <-cleaned:
			early++
			t.Errorf("abandoned-data cleanup overtook unfinished commit: %v", err)
			if early == len(disks) {
				break wait
			}
		case <-timer.C:
			break wait
		}
	}
	timer.Stop()
	unblock()
	select {
	case err := <-committed:
		if err != nil {
			t.Fatalf("PUT failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PUT did not finish")
	}
	for i := early; i < len(disks); i++ {
		select {
		case err := <-cleaned:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cleanup did not finish")
		}
	}
	swap(disks)
	r, err := z.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{})
	if err != nil {
		t.Fatalf("acknowledged PUT unreadable after abandoned-data cleanup: %v", err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil || string(data) != body {
		t.Fatalf("acknowledged external shards lost: bytes=%d err=%v", len(data), err)
	}
}

// Cleanup can also arrive after a disk has committed but before its delayed
// reply lets the coordinator decide to undo a failed quorum. The previous
// generation's backup is still owned by that unfinished transaction.
func TestMutationAbandonedCleanupPreservesUndoBackup(t *testing.T) {
	z, bucket := mutationPools(t)
	const object = "cleanup-before-undo"
	body := strings.Repeat("last acknowledged", 150000)
	base := time.Now().Add(-time.Minute)
	mutationPut(t, z, bucket, object, 0, body, base)
	set := z.serverPools[0].getHashedSet(object)
	disks, swap := installListingDiskSwitch(set)
	defer swap(disks)
	entered, release := make(chan struct{}, 4), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	wrapped := append([]StorageAPI(nil), disks...)
	for i, d := range disks {
		wrapped[i] = delayedRenameResult{d, i >= 4, entered, release}
	}
	swap(wrapped)
	committed := make(chan error, 1)
	go func() {
		next := strings.Repeat("failed update", 180000)
		_, err := z.serverPools[0].PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader(next), int64(len(next)), "", ""), ObjectOptions{NoLock: true, MTime: base.Add(time.Second)})
		committed <- err
	}()
	for range 4 {
		select {
		case <-entered:
		case err := <-committed:
			t.Fatalf("PUT returned before reply barrier: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("disk commit did not reach reply barrier")
		}
	}
	for _, d := range disks[:4] {
		if err := d.CleanAbandonedData(t.Context(), bucket, object); err != nil {
			t.Fatal(err)
		}
	}
	unblock()
	select {
	case err := <-committed:
		if err == nil {
			t.Fatal("four-of-eight commit unexpectedly reached write quorum")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failed PUT did not finish undo")
	}
	swap(disks)
	for i, d := range disks {
		fi, err := d.ReadVersion(t.Context(), "", bucket, object, "", ReadOptions{})
		if err != nil || !fi.ModTime.Equal(base) {
			t.Errorf("disk%d lost last acknowledged generation after failed PUT: mtime=%v err=%v", i, fi.ModTime, err)
		}
	}
	r, err := z.GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{})
	if err != nil {
		t.Fatalf("last acknowledged value unreadable after cleanup and undo: %v", err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil || string(data) != body {
		t.Fatalf("last acknowledged value lost after cleanup and undo: bytes=%d err=%v", len(data), err)
	}
}
