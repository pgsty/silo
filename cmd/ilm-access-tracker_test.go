// Copyright (c) 2015-2026 MinIO, Inc.

package cmd

import (
	"math"
	"testing"
	"time"

	"github.com/minio/minio/internal/config/ilm"
)

func TestAccessEntryRollAndHits(t *testing.T) {
	entry := accessEntry{Bins: []uint32{3, 2, 1}, HeadAt: 100, LastAt: 107}
	entry.rollTo(120, 10, 3)
	want := []uint32{0, 0, 3}
	for i := range want {
		if entry.Bins[i] != want[i] {
			t.Fatalf("bins = %v, want %v", entry.Bins, want)
		}
	}
	if entry.HeadAt != 120 || entry.LastAt != 107 {
		t.Fatalf("head/last = %d/%d", entry.HeadAt, entry.LastAt)
	}

	entry = accessEntry{Bins: []uint32{10, 20, 30}, HeadAt: 120}
	if got := entry.hits(20*time.Second, 10); got != 30 {
		t.Fatalf("20s hits = %d, want 30", got)
	}
	if got := entry.hits(21*time.Second, 10); got != 60 {
		t.Fatalf("21s hits = %d, want 60", got)
	}
	entry.rollTo(200, 10, 3)
	if got := entry.total(); got != 0 {
		t.Fatalf("expired total = %d, want 0", got)
	}
}

func TestAccessEntryMergeSaturates(t *testing.T) {
	entry := accessEntry{Bins: []uint32{math.MaxUint32 - 1}}
	entry.mergeFrom(accessEntry{Bins: []uint32{10}, LastAt: 50})
	if entry.Bins[0] != math.MaxUint32 || entry.LastAt != 50 {
		t.Fatalf("merged entry = %+v", entry)
	}
}

func TestAccessTrackerEvictsColdest(t *testing.T) {
	tracker := newAccessTracker()
	live := map[string]accessEntry{
		"a": {Bins: []uint32{1}, HeadAt: 100},
		"b": {Bins: []uint32{5}, HeadAt: 100},
		"c": {Bins: []uint32{3}, HeadAt: 100},
	}
	tracker.evict(live, 100, 10, ilm.Config{AccessBins: 1, AccessMaxTracked: 2})
	if len(live) != 2 {
		t.Fatalf("len = %d, want 2", len(live))
	}
	if _, ok := live["a"]; ok {
		t.Fatal("coldest entry was retained")
	}
}

func TestAccessKeyRoundTrip(t *testing.T) {
	key := accessKey("bucket", "a/b/c")
	bucket, object, ok := splitAccessKey(key)
	if !ok || bucket != "bucket" || object != "a/b/c" {
		t.Fatalf("split %q = %q/%q/%v", key, bucket, object, ok)
	}
}

func TestAccessShardFresh(t *testing.T) {
	const now = int64(1000)
	if !accessShardFresh(now, accessShard{UpdatedAt: 950}, 100) {
		t.Fatal("fresh shard rejected")
	}
	if accessShardFresh(now, accessShard{UpdatedAt: 899}, 100) {
		t.Fatal("stale shard accepted")
	}
	if accessShardFresh(now, accessShard{UpdatedAt: 1101}, 100) {
		t.Fatal("far-future shard accepted")
	}
	if accessShardFresh(now, accessShard{}, 100) {
		t.Fatal("zero timestamp accepted")
	}
}

func TestAccessTrackerRestoresDemoteCandidates(t *testing.T) {
	tracker := newAccessTracker()
	candidate := demoteCandidate{Bucket: "bucket", Object: "object", Pool: 1}
	tracker.restoreDemoteCandidates([]demoteCandidate{candidate})
	got := tracker.takeDemoteCandidates()
	if len(got) != 1 || got[0] != candidate {
		t.Fatalf("restored candidates = %+v, want %+v", got, candidate)
	}
}
