// Copyright (c) 2015-2026 MinIO, Inc.

package cmd

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/config/ilm"
	"github.com/tinylib/msgp/msgp"
)

func accessLifecycleForTest(t *testing.T) *lifecycle.Lifecycle {
	t.Helper()
	xml := "<LifecycleConfiguration>" +
		"<Rule><ID>access</ID><Status>Enabled</Status>" +
		"<AccessTransition><Window>10m</Window><PromoteAfterAccesses>100</PromoteAfterAccesses>" +
		"<DemoteAfterAccesses>5</DemoteAfterAccesses><DemoteAfterIdle>1h</DemoteAfterIdle></AccessTransition>" +
		"</Rule></LifecycleConfiguration>"
	lc, err := lifecycle.ParseLifecycleConfig(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	return lc
}

func TestAccessTierStampAndDemoteEligibility(t *testing.T) {
	oldTracker := globalAccessTracker
	globalAccessTracker = newAccessTracker()
	t.Cleanup(func() { globalAccessTracker = oldTracker })

	now := time.Now()
	cfg := ilm.Config{
		AccessTiering: true, AccessPools: []int{0, 1},
		AccessBinWidth: time.Minute, AccessBins: 12,
		AccessMinResidency: 30 * time.Minute,
	}
	oi := ObjectInfo{
		Bucket: "bucket", Name: "object", Size: 10, IsLatest: true,
		UserDefined: map[string]string{
			accessTierMetadataKey: "0:" + strconv.FormatInt(now.Add(-2*time.Hour).UnixNano(), 10),
		},
	}
	if !accessDemoteEligible(accessLifecycleForTest(t), oi, 0, cfg, now) {
		t.Fatal("cold, resident object should be demotion eligible")
	}
	oi.UserDefined[accessTierMetadataKey] = "0:" + strconv.FormatInt(now.Add(-time.Minute).UnixNano(), 10)
	if accessDemoteEligible(accessLifecycleForTest(t), oi, 0, cfg, now) {
		t.Fatal("object inside minimum residency was eligible")
	}
	oi.UserDefined[accessTierMetadataKey] = "broken"
	if accessDemoteEligible(accessLifecycleForTest(t), oi, 0, cfg, now) {
		t.Fatal("object with malformed marker was eligible")
	}
}

func TestAccessTierReservationsEnforceCaps(t *testing.T) {
	state := newAccessTierState(t.Context())
	state.usageReady = true
	state.baseUsage["a"] = 80
	state.baseTotal = 180

	cfg := ilm.Config{AccessMaxSize: 200}
	task := accessTierTask{ctx: t.Context(), bucket: "a", object: "one", bytes: 30}
	if reason, ok := state.reservePromotion(task, cfg, 0); ok || reason != "max-size" {
		t.Fatalf("max-size reserve = %q/%v", reason, ok)
	}

	cfg.AccessMaxSize = 0
	if reason, ok := state.reservePromotion(task, cfg, 100); ok || reason != "quota" {
		t.Fatalf("quota reserve = %q/%v", reason, ok)
	}

	task.bytes = 20
	if reason, ok := state.reservePromotion(task, cfg, 100); !ok || reason != "" {
		t.Fatalf("valid reserve = %q/%v", reason, ok)
	}
	if got := state.bucketUsageLocked("a"); got != 100 {
		t.Fatalf("reserved bucket usage = %d, want 100", got)
	}
	state.releasePending(task, true)
}

func TestDataMovementDestinationIsGated(t *testing.T) {
	dst := 0
	if got := dataMovementDstPool(ObjectOptions{DstPoolIdx: &dst}); got != nil {
		t.Fatal("destination honored without DataMovement")
	}
	if got := dataMovementDstPool(ObjectOptions{DataMovement: true, DstPoolIdx: &dst}); got == nil || *got != 0 {
		t.Fatalf("destination = %v", got)
	}
}

func TestForcedDestinationPoolSelection(t *testing.T) {
	z := &erasureServerPools{serverPools: make([]*erasureSets, 2)}
	dst := 1
	if got, err := z.getPoolIdx(context.Background(), "bucket", "object", 1, &dst); err != nil || got != dst {
		t.Fatalf("destination = %d, err = %v", got, err)
	}
	bad := 2
	if _, err := z.getPoolIdx(context.Background(), "bucket", "object", 1, &bad); !errors.Is(err, errInvalidArgument) {
		t.Fatalf("out-of-range error = %v", err)
	}
	z.poolMeta.Pools = make([]PoolStatus, 2)
	z.poolMeta.Pools[1].Decommission = &PoolDecommissionInfo{}
	if _, err := z.getPoolIdx(context.Background(), "bucket", "object", 1, &dst); err == nil {
		t.Fatal("suspended destination was accepted")
	}
}

func TestHotTierAccounting(t *testing.T) {
	entry := dataUsageEntry{}
	entry.addSizes(sizeSummary{totalSize: 100, hotTierSize: 60, versions: 1})
	entry.merge(dataUsageEntry{Size: 50, HotTierSize: 25})
	if entry.Size != 150 || entry.HotTierSize != 85 {
		t.Fatalf("usage = size:%d hot:%d", entry.Size, entry.HotTierSize)
	}
}

func TestScannerCyclesApart(t *testing.T) {
	tests := []struct {
		current, previous uint32
		want              uint32
	}{
		{current: 12, previous: 10, want: 2},
		{current: 0, previous: ^uint32(0), want: 1},
		// A cycle counter reset is not evidence that a complete pass covered
		// recent moves, so it must not release conservative deltas.
		{current: 1, previous: 100, want: 0},
	}
	for _, tt := range tests {
		if got := scannerCyclesApart(tt.current, tt.previous); got != tt.want {
			t.Fatalf("scannerCyclesApart(%d, %d) = %d, want %d", tt.current, tt.previous, got, tt.want)
		}
	}
}

func TestDataUsageCacheV8Migration(t *testing.T) {
	var encoded bytes.Buffer
	if err := encoded.WriteByte(dataUsageCacheVerV8); err != nil {
		t.Fatal(err)
	}
	zw, err := zstd.NewWriter(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	mw := msgp.NewWriter(zw)
	if err = mw.WriteMapHeader(2); err != nil {
		t.Fatal(err)
	}
	if err = mw.WriteString("Info"); err != nil {
		t.Fatal(err)
	}
	info := dataUsageCacheInfo{Name: dataUsageRoot, NextCycle: 17, LastUpdate: time.Now().UTC()}
	if err = info.EncodeMsg(mw); err != nil {
		t.Fatal(err)
	}
	if err = mw.WriteString("Cache"); err != nil {
		t.Fatal(err)
	}
	if err = mw.WriteMapHeader(1); err != nil {
		t.Fatal(err)
	}
	if err = mw.WriteString("entry"); err != nil {
		t.Fatal(err)
	}
	// A v8 entry has no hts field. Encoding only populated fields also
	// verifies that its map decoder retains normal msgpack compatibility.
	if err = mw.WriteMapHeader(2); err != nil {
		t.Fatal(err)
	}
	if err = mw.WriteString("sz"); err != nil {
		t.Fatal(err)
	}
	if err = mw.WriteInt64(123); err != nil {
		t.Fatal(err)
	}
	if err = mw.WriteString("os"); err != nil {
		t.Fatal(err)
	}
	if err = mw.WriteUint64(2); err != nil {
		t.Fatal(err)
	}
	if err = mw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}

	var migrated dataUsageCache
	if err = migrated.deserialize(bytes.NewReader(encoded.Bytes())); err != nil {
		t.Fatal(err)
	}
	entry := migrated.Cache["entry"]
	if entry.Size != 123 || entry.Objects != 2 || entry.HotTierSize != 0 {
		t.Fatalf("migrated entry = size:%d objects:%d hot:%d", entry.Size, entry.Objects, entry.HotTierSize)
	}
	if migrated.Info.NextCycle != 17 || !migrated.Info.LastUpdate.Equal(info.LastUpdate) {
		t.Fatalf("migrated cache info = %+v", migrated.Info)
	}
}

// The stamp written on every moved version and the stamp the rollback path
// matches against must agree, otherwise rollback silently skips its own work.
func TestAccessTierStampRoundTrip(t *testing.T) {
	movedAt := time.Now().UnixNano()
	stamp := accessTierStamp(3, movedAt)

	pool, at, ok := parseAccessTierStamp(map[string]string{accessTierMetadataKey: stamp})
	if !ok {
		t.Fatalf("stamp %q did not parse", stamp)
	}
	if pool != 3 {
		t.Fatalf("pool = %d, want 3", pool)
	}
	if at.UnixNano() != movedAt {
		t.Fatalf("movedAt = %d, want %d", at.UnixNano(), movedAt)
	}
	// A different move of the same object must not match, so a concurrent
	// client overwrite is never mistaken for our own copy.
	if stamp == accessTierStamp(3, movedAt+1) {
		t.Fatal("stamps from distinct moves collided")
	}
	if stamp == accessTierStamp(4, movedAt) {
		t.Fatal("stamps from distinct pools collided")
	}
}

func TestAccessHitsMightPromote(t *testing.T) {
	lc := accessLifecycleForTest(t)
	hot := accessEntry{Bins: []uint32{100}, HeadAt: 0}
	cold := accessEntry{Bins: []uint32{1}, HeadAt: 0}
	if !accessHitsMightPromote(lc, "object", hot, 60) {
		t.Fatal("object above promote threshold was rejected")
	}
	if accessHitsMightPromote(lc, "object", cold, 60) {
		t.Fatal("object below promote threshold was accepted")
	}

	xml := "<LifecycleConfiguration><Rule><ID>logs</ID><Status>Enabled</Status>" +
		"<Filter><Prefix>logs/</Prefix></Filter>" +
		"<AccessTransition><Window>10m</Window><PromoteAfterAccesses>100</PromoteAfterAccesses>" +
		"<DemoteAfterAccesses>5</DemoteAfterAccesses><DemoteAfterIdle>1h</DemoteAfterIdle></AccessTransition>" +
		"</Rule></LifecycleConfiguration>"
	prefixed, err := lifecycle.ParseLifecycleConfig(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if accessHitsMightPromote(prefixed, "data/object", hot, 60) {
		t.Fatal("object outside the rule prefix was accepted")
	}
	if !accessHitsMightPromote(prefixed, "logs/object", hot, 60) {
		t.Fatal("object inside the rule prefix was rejected")
	}
}
