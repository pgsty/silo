// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"bytes"
	"context"
	"testing"

	madmin "github.com/minio/madmin-go/v3"
)

func TestHealCRCWithoutQuorumPreservesMetadata(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "heal-crc-quorum", MakeBucketOptions{}, "")
	const key = "crc-quorum"
	p.put(0, key, "payload", daysAgo(2), ObjectOptions{})
	disks := z.serverPools[0].getHashedSet(key).getDisks()
	before := make([][]byte, len(disks))
	for i, disk := range disks {
		raw, err := disk.ReadAll(t.Context(), p.bucket, pathJoin(key, xlStorageFormatFile))
		if err != nil {
			t.Fatal(err)
		}
		if i <= len(disks)/2 {
			meta, _, err := isIndexedMetaV2(raw)
			if err != nil {
				t.Fatal(err)
			}
			meta[len(meta)-1] ^= 1
			if err := disk.WriteAll(t.Context(), p.bucket, pathJoin(key, xlStorageFormatFile), raw); err != nil {
				t.Fatal(err)
			}
		}
		before[i] = raw
	}
	for _, dry := range []bool{true, false} {
		if _, err := z.HealObject(t.Context(), p.bucket, key, nullVersionID, madmin.HealOpts{DryRun: dry, Remove: true, ScanMode: madmin.HealDeepScan}); err == nil {
			t.Fatal("healed without a metadata quorum")
		}
		for i, disk := range disks {
			after, err := disk.ReadAll(t.Context(), p.bucket, pathJoin(key, xlStorageFormatFile))
			if err != nil || !bytes.Equal(after, before[i]) {
				t.Fatalf("heal without quorum changed drive %d: %v", i, err)
			}
		}
	}
}

func TestHealListedVersionDeletedBeforeRepair(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "heal-delete-race", MakeBucketOptions{VersioningEnabled: true}, "")
	const key = "deleted-after-listing"
	listed := p.version(0, key, "old", 3)
	p.version(0, key, "latest", 2)
	// A healer has already listed this exact version. Its deletion commits
	// before the heal acquires the object's lock and re-reads the metadata.
	if _, err := z.DeleteObject(t.Context(), p.bucket, key, ObjectOptions{VersionID: listed.VersionID, Versioned: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := z.HealObject(t.Context(), p.bucket, key, listed.VersionID, madmin.HealOpts{ScanMode: madmin.HealDeepScan}); !isErrVersionNotFound(err) {
		t.Fatalf("heal of deleted listing: %v", err)
	}
	if got := p.get(key); got != "latest" {
		t.Fatalf("latest changed: %s", got)
	}
	for _, disk := range z.serverPools[0].getHashedSet(key).getDisks() {
		if _, err := disk.ReadVersion(t.Context(), "", p.bucket, key, listed.VersionID, ReadOptions{}); err == nil {
			t.Fatal("heal resurrected a deleted version")
		}
	}
}

func TestDecommissionCancellationSurvivesReload(t *testing.T) {
	z, _ := migrationTestPools(t)
	z.poolMeta.dontSave = false
	if err := z.StartDecommission(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	// Install the worker's cancel handle without racing an actual migration.
	_, cancel := context.WithCancel(t.Context())
	defer cancel()
	z.decommissionCancelers[0] = cancel
	if err := z.DecommissionCancel(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	// Late worker completion/failure must not overwrite the durable cancel.
	if err := z.DecommissionFailed(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	if err := z.CompleteDecommission(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	for _, pool := range z.serverPools {
		var loaded poolMeta
		if err := loaded.load(t.Context(), pool, z.serverPools); err != nil {
			t.Fatal(err)
		}
		state := loaded.Pools[0].Decommission
		if state == nil || !state.Canceled || state.Complete || state.Failed {
			t.Fatalf("persisted cancellation changed: %+v", state)
		}
		if got := loaded.returnResumablePools(); len(got) != 0 {
			t.Fatalf("canceled pool resumes after reload: %v", got)
		}
	}
}
