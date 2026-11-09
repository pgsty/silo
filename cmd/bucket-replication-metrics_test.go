// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"testing"

	"github.com/minio/minio/internal/once"
	"github.com/rcrowley/go-metrics"
)

func TestReplicationWorkerMetricsWithoutPool(t *testing.T) {
	previous := globalReplicationPool
	t.Cleanup(func() { globalReplicationPool = previous })

	globalReplicationPool = once.NewSingleton[ReplicationPool]()
	globalReplicationPool.Set(&ReplicationPool{activeWorkers: 8})
	stat := newActiveWorkerStat(metrics.NewRegistry())
	stat.update()
	if got := stat.get(); got.Curr != 8 || got.Avg != 8 || got.Max != 8 {
		t.Fatalf("active pool metrics = %+v, want current/average/maximum 8", got)
	}

	// A collector may still run after replication has been disabled.
	globalReplicationPool = once.NewSingleton[ReplicationPool]()
	globalReplicationPool.Set(nil)
	stat.update()
	if got := stat.get(); got.Curr != 0 || got.Avg != 4 || got.Max != 8 {
		t.Fatalf("disabled pool metrics = %+v, want current 0, average 4, maximum 8", got)
	}
}
