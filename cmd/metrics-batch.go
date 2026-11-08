package cmd

import (
	"maps"
	"time"

	"github.com/minio/madmin-go/v3"
)

type realtimeMetrics struct {
	madmin.RealtimeMetrics
	Aggregated realtimeMetricGroups            `json:"aggregated"`
	ByHost     map[string]realtimeMetricGroups `json:"by_host,omitempty"`
}

type realtimeMetricGroups struct {
	madmin.Metrics
	BatchJobs *batchJobMetricsReport `json:"batchJobs,omitempty"`
}

type batchJobMetricsReport struct {
	CollectedAt time.Time `json:"collected"`
	Jobs        map[string]batchJobStatusMetric
}

func (metrics *realtimeMetrics) Merge(other *realtimeMetrics) {
	if other == nil {
		return
	}
	metrics.RealtimeMetrics.Merge(&other.RealtimeMetrics)
	metrics.Aggregated.Merge(&other.Aggregated.Metrics)
	if other.Aggregated.BatchJobs != nil {
		if metrics.Aggregated.BatchJobs == nil {
			metrics.Aggregated.BatchJobs = &batchJobMetricsReport{Jobs: make(map[string]batchJobStatusMetric)}
		}
		jobs := metrics.Aggregated.BatchJobs
		if other.Aggregated.BatchJobs.CollectedAt.After(jobs.CollectedAt) {
			jobs.CollectedAt = other.Aggregated.BatchJobs.CollectedAt
		}
		for id, job := range other.Aggregated.BatchJobs.Jobs {
			if current, ok := jobs.Jobs[id]; !ok || !job.LastUpdate.Before(current.LastUpdate) {
				jobs.Jobs[id] = job
			}
		}
	}
	if len(other.ByHost) != 0 {
		if metrics.ByHost == nil {
			metrics.ByHost = make(map[string]realtimeMetricGroups, len(other.ByHost))
		}
		maps.Copy(metrics.ByHost, other.ByHost)
	}
}

func (metrics realtimeMetricGroups) legacy() madmin.Metrics {
	out := metrics.Metrics
	if metrics.BatchJobs != nil {
		out.BatchJobs = &madmin.BatchJobMetrics{
			CollectedAt: metrics.BatchJobs.CollectedAt,
			Jobs:        make(map[string]madmin.JobMetric, len(metrics.BatchJobs.Jobs)),
		}
		for id, job := range metrics.BatchJobs.Jobs {
			out.BatchJobs.Jobs[id] = job.JobMetric
		}
	}
	return out
}

func (metrics realtimeMetrics) legacy() madmin.RealtimeMetrics {
	out := metrics.RealtimeMetrics
	out.Aggregated = metrics.Aggregated.legacy()
	if metrics.ByHost != nil {
		out.ByHost = make(map[string]madmin.Metrics, len(metrics.ByHost))
		for host, groups := range metrics.ByHost {
			out.ByHost[host] = groups.legacy()
		}
	}
	return out
}
