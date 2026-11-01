//go:build consistency_strict

// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"maps"
)

// Compare logical version state, excluding per-shard checksums/index, physical
// DataDir placement and properties of other versions in the same xl.meta.
// Different DataDir values remain readable for the existing rebalance recovery
// contract; rollback separately requires an exact DataDir match.
func sameFileInfoVersion(a, b FileInfo) bool {
	if a.VersionID != b.VersionID || a.Deleted != b.Deleted || a.XLV1 != b.XLV1 || a.Size != b.Size ||
		a.TransitionStatus != b.TransitionStatus || a.TransitionTier != b.TransitionTier ||
		a.TransitionedObjName != b.TransitionedObjName || a.TransitionVersionID != b.TransitionVersionID ||
		!sameVersionMetadata(a.Metadata, b.Metadata) || !bytes.Equal(a.Checksum, b.Checksum) || len(a.Parts) != len(b.Parts) {
		return false
	}
	if !a.Deleted && a.Size != 0 && !a.Erasure.Equal(b.Erasure) {
		return false
	}
	for i, p := range a.Parts {
		q := b.Parts[i]
		if p.Number != q.Number || p.Size != q.Size || p.ActualSize != q.ActualSize || p.ETag != q.ETag || !bytes.Equal(p.Index, q.Index) {
			return false
		}
	}
	return true
}

// The undo capability controls rollback ownership, not the logical contents.
// A partial no-op update can revoke it without changing a single public field.
func sameVersionMetadata(a, b map[string]string) bool {
	if a[rollbackIDKey] == b[rollbackIDKey] {
		return maps.Equal(a, b)
	}
	for k, v := range a {
		if k != rollbackIDKey {
			if other, ok := b[k]; !ok || other != v {
				return false
			}
		}
	}
	for k := range b {
		if k != rollbackIDKey {
			if _, ok := a[k]; !ok {
				return false
			}
		}
	}
	return true
}
