// Copyright (c) 2024 MinIO, Inc.
//
// # This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
)

const (
	expiryPendingTasks             = "expiry_pending_tasks"
	transitionActiveTasks          = "transition_active_tasks"
	transitionPendingTasks         = "transition_pending_tasks"
	transitionMissedImmediateTasks = "transition_missed_immediate_tasks"
	accessTierActiveTasks          = "access_tier_active_tasks"
	accessTierPendingTasks         = "access_tier_pending_tasks"
	accessTierPromotionsTotal      = "access_tier_promotions_total"
	accessTierDemotionsTotal       = "access_tier_demotions_total"
	accessTierBytesMovedTotal      = "access_tier_bytes_moved_total"
	accessTierFailuresTotal        = "access_tier_failures_total"
	accessTierSkippedWatermark     = "access_tier_skipped_watermark_total"
	accessTierSkippedMaxSize       = "access_tier_skipped_max_size_total"
	accessTierSkippedQuota         = "access_tier_skipped_bucket_quota_total"
	accessTierHotBytes             = "access_tier_hot_bytes"
	accessTierSamplesDropped       = "access_tier_samples_dropped_total"
	versionsScanned                = "versions_scanned"
)

var (
	ilmExpiryPendingTasksMD             = NewGaugeMD(expiryPendingTasks, "Number of pending ILM expiry tasks in the queue")
	ilmTransitionActiveTasksMD          = NewGaugeMD(transitionActiveTasks, "Number of active ILM transition tasks")
	ilmTransitionPendingTasksMD         = NewGaugeMD(transitionPendingTasks, "Number of pending ILM transition tasks in the queue")
	ilmTransitionMissedImmediateTasksMD = NewCounterMD(transitionMissedImmediateTasks, "Number of missed immediate ILM transition tasks")
	ilmAccessTierActiveTasksMD          = NewGaugeMD(accessTierActiveTasks, "Number of active access-tier pool moves")
	ilmAccessTierPendingTasksMD         = NewGaugeMD(accessTierPendingTasks, "Number of pending access-tier pool moves")
	ilmAccessTierPromotionsTotalMD      = NewCounterMD(accessTierPromotionsTotal, "Total objects promoted by access-tier ILM")
	ilmAccessTierDemotionsTotalMD       = NewCounterMD(accessTierDemotionsTotal, "Total objects demoted by access-tier ILM")
	ilmAccessTierBytesMovedTotalMD      = NewCounterMD(accessTierBytesMovedTotal, "Total logical bytes moved by access-tier ILM")
	ilmAccessTierFailuresTotalMD        = NewCounterMD(accessTierFailuresTotal, "Total failed access-tier ILM moves")
	ilmAccessTierSkippedWatermarkMD     = NewCounterMD(accessTierSkippedWatermark, "Promotions skipped because the hot pool reached its watermark")
	ilmAccessTierSkippedMaxSizeMD       = NewCounterMD(accessTierSkippedMaxSize, "Promotions skipped because the cluster hot-tier size cap was reached")
	ilmAccessTierSkippedQuotaMD         = NewCounterMD(accessTierSkippedQuota, "Promotions skipped because the bucket hot-tier quota was reached")
	ilmAccessTierHotBytesMD             = NewGaugeMD(accessTierHotBytes, "Logical bytes currently accounted to the hot tier", "bucket")
	ilmAccessTierSamplesDroppedMD       = NewCounterMD(accessTierSamplesDropped, "GET samples dropped because the access tracker queue was full")
	ilmVersionsScannedMD                = NewCounterMD(versionsScanned, "Total number of object versions checked for ILM actions since server start")
)

// loadILMMetrics - `MetricsLoaderFn` for ILM metrics.
func loadILMMetrics(_ context.Context, m MetricValues, _ *metricsCache) error {
	if globalExpiryState != nil {
		m.Set(expiryPendingTasks, float64(globalExpiryState.PendingTasks()))
	}
	if globalTransitionState != nil {
		m.Set(transitionActiveTasks, float64(globalTransitionState.ActiveTasks()))
		m.Set(transitionPendingTasks, float64(globalTransitionState.PendingTasks()))
		m.Set(transitionMissedImmediateTasks, float64(globalTransitionState.MissedImmediateTasks()))
	}
	if globalAccessTierState != nil {
		m.Set(accessTierActiveTasks, float64(globalAccessTierState.ActiveTasks()))
		m.Set(accessTierPendingTasks, float64(globalAccessTierState.PendingTasks()))
		m.Set(accessTierPromotionsTotal, float64(globalAccessTierState.promotions.Load()))
		m.Set(accessTierDemotionsTotal, float64(globalAccessTierState.demotions.Load()))
		m.Set(accessTierBytesMovedTotal, float64(globalAccessTierState.bytesMoved.Load()))
		m.Set(accessTierFailuresTotal, float64(globalAccessTierState.failures.Load()))
		m.Set(accessTierSkippedWatermark, float64(globalAccessTierState.skippedWatermark.Load()))
		m.Set(accessTierSkippedMaxSize, float64(globalAccessTierState.skippedMaxSize.Load()))
		m.Set(accessTierSkippedQuota, float64(globalAccessTierState.skippedQuota.Load()))
		for bucket, bytes := range globalAccessTierState.hotUsageSnapshot() {
			m.Set(accessTierHotBytes, float64(bytes), "bucket", bucket)
		}
	}
	m.Set(accessTierSamplesDropped, float64(globalAccessTracker.dropped.Load()))
	m.Set(versionsScanned, float64(globalScannerMetrics.lifetime(scannerMetricILM)))

	return nil
}
