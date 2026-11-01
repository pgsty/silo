//go:build consistency_strict

// Preserved diagnostic for the deferred strict-read policy. This is not a
// maintenance release gate; failures record intentionally unresolved risks.

// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"testing"
	"time"
)

func TestStrictListFallbackRejectsSplitGenerations(t *testing.T) {
	z, bucket, _ := nullQuorumBackend(t)
	set := z.serverPools[0].sets[0]
	disks := set.getDisks()
	const object = "object"
	mtime := time.Now().UTC().Add(-time.Hour)
	var generations [3][][]byte
	for generation := range generations {
		body := bytes.Repeat([]byte{byte('a' + generation)}, 8192)
		nullQuorumPut(t, z, bucket, object, body, ObjectOptions{MTime: mtime.Add(time.Duration(generation) * time.Minute)})
		generations[generation] = make([][]byte, len(disks))
		for i, disk := range disks {
			generations[generation][i] = mustReadNullQuorumMeta(t, disk, bucket, object)
		}
	}
	// All sixteen drives are online, but the 7/5/4 split leaves no generation
	// with the eight matching snapshots required by the listing resolver.
	for i, disk := range disks {
		generation := 0
		if i >= 7 {
			generation = 1
		}
		if i >= 12 {
			generation = 2
		}
		if err := disk.WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, generations[generation][i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := set.getObjectFileInfo(t.Context(), bucket, object, ObjectOptions{}, false); !isErrReadQuorum(err) {
		t.Fatalf("split metadata must remain a read-quorum failure: %v", err)
	}
	entries := make(metaCacheEntries, len(disks))
	for i, disk := range disks {
		entries[i] = metaCacheEntry{name: object, metadata: mustReadNullQuorumMeta(t, disk, bucket, object)}
		if _, err := entries[i].xlmeta(); err != nil {
			t.Fatalf("drive %d no longer has valid metadata: %v", i, err)
		}
	}
	resolver := metadataResolutionParams{dirQuorum: 8, objQuorum: 8, bucket: bucket, requestedVersions: 1}
	entry, err := z.resolveListingGroup(t.Context(), bucket, []*metaCacheEntry{set.resolveListEntry(entries, nil, &resolver)})
	if entry != nil || !isErrReadQuorum(err) {
		t.Fatalf("split live metadata became absence: entry=%v err=%v", entry, err)
	}
}
