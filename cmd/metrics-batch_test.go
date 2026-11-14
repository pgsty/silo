package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/grid"
)

func TestBatchMetricsStatusSnapshots(t *testing.T) {
	fixture := newBatchAuthzFixture(t)
	job := BatchJobRequest{
		ID: "expire-metrics-snapshot" + getKeySeparator() + "0", Started: UTCNow(),
		Submitter: batchRootSubmitter(t), Expire: &BatchJobExpire{},
	}
	for _, state := range []string{"skipped", "paused", "failed", "running"} {
		t.Run(state, func(t *testing.T) {
			report := &batchJobInfo{JobID: job.ID, JobType: string(job.Type()), StartTime: job.Started}
			switch state {
			case "skipped":
				report.Complete = true
				report.VersionsSkippedLocked, report.KeysRefused = 2, 1
			case "paused":
				report.PausedReason = "authorization plugin unavailable"
			case "failed":
				report.Failed = true
				report.FailureReason = "authorization denied"
			}
			mustIAM(t, report.updateAfter(fixture.ctx, fixture.obj, 0, job))
			globalBatchJobsMetrics.save(job.ID, report)
			saved := batchJobStatusJSON(t, job.ID)
			for _, field := range []string{"startTime", "lastUpdate"} {
				stamp, err := time.Parse(time.RFC3339Nano, saved[field].(string))
				mustIAM(t, err)
				saved[field] = stamp.UTC().Format(time.RFC3339Nano)
			}
			target := fmt.Sprintf("http://localhost/minio/admin/v3/metrics?types=%d&by-jobID=%s&n=1&by-host=true", madmin.MetricsBatchJobs, job.ID)
			request, err := newTestSignedRequestV4(http.MethodGet, target, 0, nil, globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
			mustIAM(t, err)
			mustIAM(t, request.ParseForm())
			response := httptest.NewRecorder()
			request = request.WithContext(newContext(request, response, "Metrics"))
			adminAPIHandlers{}.MetricsHandler(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("metrics returned %d: %s", response.Code, response.Body.String())
			}
			var wire struct {
				Aggregated struct {
					BatchJobs struct{ Jobs map[string]map[string]any }
				}
				ByHost map[string]struct {
					BatchJobs struct{ Jobs map[string]map[string]any }
				} `json:"by_host"`
			}
			mustIAM(t, json.Unmarshal(response.Body.Bytes(), &wire))
			if !reflect.DeepEqual(wire.Aggregated.BatchJobs.Jobs[job.ID], saved) {
				t.Fatalf("live snapshot differs from saved status: live=%v saved=%v", wire.Aggregated.BatchJobs.Jobs[job.ID], saved)
			}
			if len(wire.ByHost) != 1 {
				t.Fatalf("missing per-host snapshot: %s", response.Body.String())
			}
			for _, host := range wire.ByHost {
				if !reflect.DeepEqual(host.BatchJobs.Jobs[job.ID], saved) {
					t.Fatal("per-host metrics lost details")
				}
			}
			var legacy madmin.RealtimeMetrics
			mustIAM(t, json.Unmarshal(response.Body.Bytes(), &legacy))
			if legacy.Aggregated.BatchJobs.Jobs[job.ID].JobID != job.ID || legacy.Aggregated.BatchJobs.Jobs[job.ID].Complete != report.Complete {
				t.Fatal("additive details changed legacy metrics")
			}
		})
	}
}

func TestBatchMetricsPeerRoundTrip(t *testing.T) {
	report := &batchJobInfo{JobID: "remote-job", LastUpdate: UTCNow(), PausedReason: "IAM unavailable", VersionsSkippedLocked: 3, KeysRefused: 2}
	remote := realtimeMetrics{}
	remote.Hosts = []string{"peer"}
	remote.Aggregated.BatchJobs = &batchJobMetricsReport{
		CollectedAt: UTCNow(), Jobs: map[string]batchJobStatusMetric{report.JobID: report.statusMetric()},
	}
	remote.ByHost = map[string]realtimeMetricGroups{"peer": remote.Aggregated}
	encoded := madminRealtimeMetrics.NewJSONWith(&remote)
	data, err := encoded.MarshalMsg(nil)
	mustIAM(t, err)
	decoded := madminRealtimeMetrics.NewJSON()
	defer decoded.Recycle()
	_, err = decoded.UnmarshalMsg(data)
	mustIAM(t, err)
	var merged realtimeMetrics
	received := decoded.ValueOrZero()
	merged.Merge(&received)
	got := merged.Aggregated.BatchJobs.Jobs[report.JobID]
	if got.PausedReason != report.PausedReason || got.KeysRefused != 2 || got.VersionsSkippedLocked == nil || *got.VersionsSkippedLocked != 3 {
		t.Fatalf("peer aggregation lost details: %+v", got)
	}
	older := received
	older.Aggregated.BatchJobs = &batchJobMetricsReport{Jobs: map[string]batchJobStatusMetric{
		report.JobID: {JobMetric: madmin.JobMetric{JobID: report.JobID, LastUpdate: report.LastUpdate.Add(-time.Second), Complete: true}},
	}}
	merged.Merge(&older)
	if got := merged.Aggregated.BatchJobs.Jobs[report.JobID]; got.Complete || got.PausedReason != report.PausedReason {
		t.Fatal("older peer snapshot replaced current progress")
	}
	legacyPool := grid.NewJSONPool[madmin.RealtimeMetrics]()
	legacy := legacyPool.NewJSON()
	defer legacy.Recycle()
	_, err = legacy.UnmarshalMsg(data)
	mustIAM(t, err)
	if got := legacy.ValueOrZero().Aggregated.BatchJobs.Jobs[report.JobID]; got.JobID != report.JobID || !got.LastUpdate.Equal(report.LastUpdate) {
		t.Fatal("legacy peer could not read base metrics")
	}
	legacyData, err := legacy.MarshalMsg(nil)
	mustIAM(t, err)
	_, err = decoded.UnmarshalMsg(legacyData)
	mustIAM(t, err)
	received = decoded.ValueOrZero()
	if received.Aggregated.BatchJobs.Jobs[report.JobID].VersionsSkippedLocked != nil {
		t.Fatal("legacy peer falsely advertised complete status details")
	}
}

func TestBatchMetricsPreservesOtherMetrics(t *testing.T) {
	var legacy madmin.RealtimeMetrics
	var extended realtimeMetrics
	for _, host := range []string{"first", "second"} {
		groups := madmin.Metrics{
			Disk: &madmin.DiskMetric{CollectedAt: time.Unix(1, 0).UTC(), NDisks: 2, Offline: 1},
			CPU:  &madmin.CPUMetrics{CPUCount: 4},
		}
		sample := madmin.RealtimeMetrics{
			Hosts: []string{host}, Errors: []string{host + ": test"},
			Aggregated: groups, ByHost: map[string]madmin.Metrics{host: groups},
			ByDisk: map[string]madmin.DiskMetric{host: *groups.Disk},
		}
		data, err := json.Marshal(sample)
		mustIAM(t, err)
		var decoded realtimeMetrics
		mustIAM(t, json.Unmarshal(data, &decoded))
		extended.Merge(&decoded)
		legacy.Merge(&sample)
	}
	if got := extended.legacy(); !reflect.DeepEqual(got, legacy) {
		t.Fatalf("batch extension changed other metrics: got=%+v want=%+v", got, legacy)
	}
}
