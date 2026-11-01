// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/minio/minio/internal/config/storageclass"
)

type compatibilityFailedOverwrite struct {
	StorageAPI
	commit bool
}

func (d compatibilityFailedOverwrite) RenameData(ctx context.Context, sv, sp string, fi FileInfo, dv, dp string, opts RenameOptions) (RenameDataResp, error) {
	if d.commit {
		if _, err := d.StorageAPI.RenameData(ctx, sv, sp, fi, dv, dp, opts); err != nil {
			return RenameDataResp{}, err
		}
	}
	return RenameDataResp{}, errDiskNotFound
}

// Maintenance compatibility requirement: after a failed overwrite with one residue, keep the previously acknowledged quorum readable.
// This tests a known history; it does not claim the resulting snapshot proves it.
func TestMaintenancePartialFailedOverwriteAvailability(t *testing.T) {
	// Lock RPC tests configure a single-drive backend (EC:0). Pin this
	// fixture to 12+4 so its fifteen old shards really have read quorum.
	previousStorageClass := globalStorageClass
	globalStorageClass.Update(storageclass.Config{Standard: storageclass.StorageClass{Parity: 4}})
	t.Cleanup(func() { globalStorageClass.Update(previousStorageClass) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dirs, err := getRandomDisks(16)
	if err != nil {
		t.Fatal(err)
	}
	obj, _, err := initObjectLayer(ctx, mustGetPoolEndpoints(0, dirs...))
	if err != nil {
		removeRoots(dirs)
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	defer func() { cancel(); z.Shutdown(context.Background()); removeRoots(dirs); setObjectLayer(previous) }()
	bucket := "maintenance-compatibility"
	key := "partial-overwrite"
	if err := z.MakeBucket(ctx, bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	oldBody := bytes.Repeat([]byte("old-A"), 65536)
	newBody := bytes.Repeat([]byte("new-B"), 65536)
	put := func(body []byte) error {
		_, err := z.PutObject(ctx, bucket, key, mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), ObjectOptions{})
		return err
	}
	if err := put(oldBody); err != nil {
		t.Fatal(err)
	}
	set := z.serverPools[0].getHashedSet(key)
	getDisks := set.getDisks
	disks := getDisks()
	fi, err := disks[0].ReadVersion(ctx, "", bucket, key, "", ReadOptions{})
	if err != nil || fi.Erasure.DataBlocks != 12 || fi.Erasure.ParityBlocks != 4 {
		t.Fatalf("compatibility fixture must have 12+4 erasure coding: %+v, %v", fi.Erasure, err)
	}
	wrapped := append([]StorageAPI(nil), disks...)
	for i, d := range disks {
		wrapped[i] = compatibilityFailedOverwrite{d, i == 0}
	}
	set.getDisks = func() []StorageAPI { return wrapped }
	err = put(newBody)
	set.getDisks = getDisks
	if err == nil {
		t.Fatal("partial overwrite must fail")
	}
	t.Logf("Overwrite completed with failure; one new residue, fifteen original shards: %v", err)
	r, err := z.GetObjectNInfo(ctx, bucket, key, nil, nil, ObjectOptions{})
	if err != nil {
		t.Fatalf("MAINTENANCE COMPATIBILITY: previously readable acknowledged value now refused: %v", err)
	}
	data, err := io.ReadAll(r)
	r.Close()
	if err != nil || !bytes.Equal(data, oldBody) {
		t.Fatalf("old acknowledged payload mismatch: bytes=%d err=%v", len(data), err)
	}
}
