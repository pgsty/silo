// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"sync"
	"testing"
)

// TestLoadCPUMetricsResourceMetricsRace runs the metrics-v3 CPU loader
// concurrently with resource metrics updates, mirroring a Prometheus scrape
// (MetricsGroup.Collect -> loadCPUMetrics) racing with the periodic resource
// collector (collectLocalResourceMetrics -> updateResourceMetrics).
//
// Regression test for https://github.com/pgsty/silo/issues/210:
// loadCPUMetrics must hold resourceMetricsMapMu.RLock() while reading
// resourceMetricsMap and its nested ResourceMetrics map, otherwise
// `go test -race` reports a concurrent map read/write.
func TestLoadCPUMetricsResourceMetricsRace(t *testing.T) {
	// Initialize resourceMetricsMap the same way startResourceMetricsCollection
	// does at server startup, then seed the cpu subsystem so readers always
	// find a populated nested map.
	resourceMetricsMapMu.Lock()
	resourceMetricsMap = map[MetricSubsystem]ResourceMetrics{}
	resourceMetricsMapMu.Unlock()
	updateResourceMetrics(cpuSubsystem, cpuIdle, 10.5, map[string]string{}, false)
	updateResourceMetrics(cpuSubsystem, cpuIOWait, 1.5, map[string]string{}, false)

	// Keep the descriptor set identical to the real /system/cpu group so that
	// every m.Set call in loadCPUMetrics resolves a descriptor.
	mg := NewMetricsGroup(systemCPUCollectorPath,
		[]MetricDescriptor{
			sysCPUAvgIdleMD,
			sysCPUAvgIOWaitMD,
			sysCPULoadMD,
			sysCPULoadPercMD,
			sysCPUNiceMD,
			sysCPUStealMD,
			sysCPUSystemMD,
			sysCPUUserMD,
		},
		loadCPUMetrics,
	)
	cache := newMetricsCache()

	const (
		readers    = 4
		writers    = 2
		iterations = 250
	)

	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				mv := newMetricValues(mg.descriptorMap)
				if err := loadCPUMetrics(context.Background(), mv, cache); err != nil {
					t.Errorf("loadCPUMetrics failed: %v", err)
					return
				}
			}
		}()
	}

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				updateResourceMetrics(cpuSubsystem, cpuIdle, float64(j%100)/4, map[string]string{}, false)
				updateResourceMetrics(cpuSubsystem, cpuIOWait, float64(j%100)/8, map[string]string{}, false)
			}
		}()
	}

	wg.Wait()
}
