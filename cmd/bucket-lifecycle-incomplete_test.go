// Copyright (c) 2026 PGSTY
//
// This file is part of Silo Object Storage stack
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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/logger"
	loghttp "github.com/minio/minio/internal/logger/target/http"
	"github.com/minio/minio/internal/pubsub"
	xnet "github.com/pgsty/silo-pkg/v3/net"
	"github.com/prometheus/client_golang/prometheus"
)

func TestILMExpiryNotDoneClassification(t *testing.T) {
	for _, tc := range []struct {
		err     error
		reason  string
		counted bool
	}{
		{nil, "", false},
		{ObjectNotFound{}, "", false},
		{VersionNotFound{}, "", false},
		{errLifecycleNotApplicable, ilmIncompleteNotApplicable, true},
		{fmt.Errorf("wrapped: %w", errLifecycleNotApplicable), ilmIncompleteNotApplicable, true},
		{ObjectLocked{}, ilmIncompleteLocked, true},
		{InsufficientWriteQuorum{}, ilmIncompleteHistoryUnavailable, true},
		{InsufficientReadQuorum{}, ilmIncompleteHistoryUnavailable, true},
		{errFaultyDisk, ilmIncompleteError, true},
	} {
		reason, counted := ilmExpiryNotDone(tc.err)
		if reason != tc.reason || counted != tc.counted {
			t.Errorf("%v: %q %v, want %q %v", tc.err, reason, counted, tc.reason, tc.counted)
		}
	}
}

// fixedDeleteResults is an object layer whose bulk deletes return errs.
type fixedDeleteResults struct {
	ObjectLayer
	errs []error
}

func (o fixedDeleteResults) DeleteObjects(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions) ([]DeletedObject, []error) {
	deleted := make([]DeletedObject, len(objects))
	for i, obj := range objects {
		deleted[i] = DeletedObject{ObjectName: obj.ObjectName, VersionID: obj.VersionID}
	}
	return deleted, slices.Clone(o.errs)
}

// ilmTestAudit captures the ILMExpiry audit entries of bucket.
func ilmTestAudit(t *testing.T, bucket string) <-chan map[string]any {
	t.Helper()
	if len(logger.AuditTargets()) != 0 {
		t.Fatal("unexpected pre-existing test audit targets")
	}
	entries := make(chan map[string]any, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var entry struct {
			Error string         `json:"error"`
			Tags  map[string]any `json:"tags"`
			API   struct {
				Name, Bucket string
				Objects      []struct {
					ObjectName string `json:"objectName"`
				} `json:"objects"`
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&entry); err == nil && entry.API.Name == "ILMExpiry" && entry.API.Bucket == bucket {
			tags := entry.Tags
			if tags == nil {
				tags = map[string]any{}
			}
			tags["error"] = entry.Error
			if len(entry.API.Objects) > 0 {
				tags["object"] = entry.API.Objects[0].ObjectName
			}
			entries <- tags
		}
		w.WriteHeader(http.StatusOK)
	}))
	endpoint, err := xnet.ParseHTTPURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if errs := logger.UpdateAuditWebhooks(ctx, map[string]loghttp.Config{"ilm": {Enabled: true, Name: "ilm", Endpoint: endpoint, BatchSize: 1, QueueSize: 128, MaxRetry: 1, RetryIntvl: time.Millisecond, HTTPTimeout: time.Second}}); len(errs) > 0 {
		t.Fatal(errs)
	}
	targets := logger.AuditTargets()
	t.Cleanup(func() {
		logger.UpdateAuditWebhooks(ctx, nil)
		for _, target := range targets {
			target.Cancel()
		}
		server.Close()
	})
	return entries
}

// A refused or failed noncurrent purge is counted and traced with its reason,
// a failure is audited, and only the version that was removed is announced.
func TestDeleteObjectVersionsReportsRefusalAndFailure(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	ctx := t.Context()
	audits := ilmTestAudit(t, s.bucket)
	done := make(chan struct{})
	defer close(done)
	events := make(chan event.Event, 8)
	if err := globalHTTPListen.Subscribe(pubsub.MaskFromMaskable(event.ObjectRemovedAll), events, done, nil); err != nil {
		t.Fatal(err)
	}
	traces := make(chan madmin.TraceInfo, 8)
	if err := globalTrace.Subscribe(madmin.TraceILM, traces, done, nil); err != nil {
		t.Fatal(err)
	}
	before := globalILMIncomplete.snapshot()

	layer := fixedDeleteResults{ObjectLayer: s.z, errs: []error{errLifecycleNotApplicable, InsufficientWriteQuorum{}, nil}}
	toDel := []ObjectToDelete{
		{ObjectV: ObjectV{ObjectName: "ncv-a", VersionID: "11111111-1111-1111-1111-111111111111"}},
		{ObjectV: ObjectV{ObjectName: "ncv-b", VersionID: "22222222-2222-2222-2222-222222222222"}},
		{ObjectV: ObjectV{ObjectName: "ncv-c", VersionID: "33333333-3333-3333-3333-333333333333"}},
	}
	evs := []lifecycle.Event{{Action: lifecycle.DeleteVersionAction}, {Action: lifecycle.DeleteVersionAction}, {Action: lifecycle.DeleteVersionAction}}
	deleteObjectVersions(ctx, layer, s.bucket, toDel, evs)

	after := globalILMIncomplete.snapshot()
	if d := after[ilmIncompleteNotApplicable] - before[ilmIncompleteNotApplicable]; d != 1 {
		t.Errorf("not_applicable moved by %d, want 1", d)
	}
	if d := after[ilmIncompleteHistoryUnavailable] - before[ilmIncompleteHistoryUnavailable]; d != 1 {
		t.Errorf("history_unavailable moved by %d, want 1", d)
	}
	var removed []string
	results := map[string]string{}
	for drained := false; !drained; {
		select {
		case ev := <-events:
			removed = append(removed, ev.S3.Object.Key)
		case tr := <-traces:
			if r := tr.Custom["result"]; r != "" {
				results[tr.Custom["version-id"]] = r
				if tr.Error == "" {
					t.Errorf("%s expiry of %s traced without its error", r, tr.Custom["version-id"])
				}
			}
		default:
			drained = true
		}
	}
	if !slices.Equal(removed, []string{"ncv-c"}) {
		t.Errorf("removal events for %v, want only ncv-c", removed)
	}
	if results[toDel[0].VersionID] != "refused" || results[toDel[1].VersionID] != "failed" {
		t.Errorf("traces %v, want refused and failed", results)
	}
	// Drain every audit entry of the bucket: until the removal of ncv-c,
	// audited after the refusal and the failure were reported, has arrived,
	// and then while the target empties its queue.
	var got []map[string]any
	deadline := time.After(10 * time.Second)
	for removal := false; !removal; {
		select {
		case tags := <-audits:
			got = append(got, tags)
			removal = removal || tags["object"] == "ncv-c"
		case <-deadline:
			t.Fatalf("audits %v: the removal of ncv-c was not audited", got)
		}
	}
	for idle := time.After(time.Second); idle != nil; {
		select {
		case tags := <-audits:
			got = append(got, tags)
		case <-idle:
			idle = nil
		}
	}
	perObject := map[any][]map[string]any{}
	for _, tags := range got {
		perObject[tags["object"]] = append(perObject[tags["object"]], tags)
	}
	if a := perObject["ncv-a"]; len(a) != 0 {
		t.Errorf("the refusal was audited: %v", a)
	}
	if b := perObject["ncv-b"]; len(b) != 1 || b[0]["ilm-incomplete-reason"] != ilmIncompleteHistoryUnavailable || b[0]["error"] == "" {
		t.Errorf("audits of the failure: %v, want one with its reason and error", b)
	}
	if c := perObject["ncv-c"]; len(c) != 1 || c[0]["ilm-incomplete-reason"] != nil {
		t.Errorf("audits of the removal: %v, want one", c)
	}
}

// expiryEvent returns the removal events sent while run runs.
func expiryEvents(t *testing.T, run func()) []event.Event {
	t.Helper()
	done := make(chan struct{})
	defer close(done)
	events := make(chan event.Event, 8)
	if err := globalHTTPListen.Subscribe(pubsub.MaskFromMaskable(event.ObjectRemovedAll), events, done, nil); err != nil {
		t.Fatal(err)
	}
	run()
	var got []event.Event
	for {
		select {
		case ev := <-events:
			got = append(got, ev)
		default:
			return got
		}
	}
}

// The notification of a completed expiry names what its delete did: the
// delete marker it created, or the version it removed.
func TestExpiryEventsNameTheResult(t *testing.T) {
	type expiry struct {
		name      string
		status    versioning.State
		key       string
		versions  []splitVersion
		expire    string // label of the version expired
		action    lifecycle.Action
		wantEvent event.Name
		wantID    func(s *splitILM, key string) []string // acceptable version IDs
	}
	marker := func(s *splitILM, key string) []string {
		oi, err := s.z.GetObjectInfo(s.t.Context(), s.bucket, key, ObjectOptions{})
		if !oi.DeleteMarker {
			s.t.Fatalf("latest of %s is not a marker: %+v %v", key, oi, err)
		}
		return []string{oi.VersionID}
	}
	label := func(l string) func(s *splitILM, key string) []string {
		return func(s *splitILM, key string) []string { return []string{s.ids[key+" "+l]} }
	}
	null := func(*splitILM, string) []string { return []string{"", nullVersionID} }
	cases := []expiry{
		{"latest-versioned", versioning.Enabled, "exp-ev-latest", []splitVersion{splitAt("v1", 5, 0)}, "v1", lifecycle.DeleteAction, event.ObjectRemovedDeleteMarkerCreated, marker},
		{"noncurrent", versioning.Enabled, "ncv-ev-noncurrent", []splitVersion{splitAt("v1", 5, 0), splitAt("v2", 3, 0)}, "v1", lifecycle.DeleteVersionAction, event.ObjectRemovedDelete, label("v1")},
		{"expired-marker", versioning.Enabled, "edm-ev-marker", []splitVersion{splitMarker("dm", 5, 0)}, "dm", lifecycle.DeleteVersionAction, event.ObjectRemovedDelete, label("dm")},
		{"latest-suspended-null", versioning.Suspended, "exp-ev-null", []splitVersion{splitNull("v1", 5, 0)}, "v1", lifecycle.DeleteAction, event.ObjectRemovedDeleteMarkerCreated, null},
		{"tiered-latest-versioned", versioning.Enabled, "exp-ev-tiered", []splitVersion{splitTiered("v1", 5, 0)}, "v1", lifecycle.DeleteAction, event.ObjectRemovedDeleteMarkerCreated, marker},
		{"tiered-noncurrent", versioning.Enabled, "ncv-ev-tiered", []splitVersion{splitTiered("v1", 5, 0), splitAt("v2", 3, 0)}, "v1", lifecycle.DeleteVersionAction, event.ObjectRemovedDelete, label("v1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSplitILM(t, tc.status, splitILMRules)
			installExpiryTestTier(t, map[string][]byte{"remote-v1": []byte("v1")})
			for _, v := range tc.versions {
				s.write(tc.key, v)
			}
			vid := s.ids[tc.key+" "+tc.expire]
			if vid == "" {
				vid = nullVersionID
			}
			oi, err := s.z.GetObjectInfo(t.Context(), s.bucket, tc.key, ObjectOptions{VersionID: vid})
			if err != nil && !isErrMethodNotAllowed(err) {
				t.Fatal(err)
			}
			oi.Bucket, oi.Name = s.bucket, tc.key
			lcEvent := lifecycle.Event{Action: tc.action}
			got := expiryEvents(t, func() {
				if oi.TransitionedObject.Status != "" {
					if !applyExpiryOnTransitionedObject(t.Context(), s.z, oi, lcEvent, lcEventSrc_Scanner) {
						t.Fatal("transitioned expiry did not apply")
					}
					return
				}
				if !applyExpiryOnNonTransitionedObjects(t.Context(), s.z, oi, lcEvent, lcEventSrc_Scanner) {
					t.Fatal("expiry did not apply")
				}
			})
			if len(got) != 1 {
				t.Fatalf("events %+v, want one", got)
			}
			if got[0].EventName != tc.wantEvent {
				t.Errorf("event %s, want %s", got[0].EventName, tc.wantEvent)
			}
			if want := tc.wantID(s, tc.key); !slices.Contains(want, got[0].S3.Object.VersionID) {
				t.Errorf("event names version %q, want one of %v", got[0].S3.Object.VersionID, want)
			}
		})
	}
}

// expiry_incomplete_total is exported as a counter with a reason label by
// both metrics versions.
func TestILMExpiryIncompleteMetrics(t *testing.T) {
	// Metrics v3 exports a counter once it is above zero.
	for _, r := range ilmIncompleteReasons {
		globalILMIncomplete.add(r)
	}
	// v3, through the collector the metrics handler registers.
	families, err := newMetricGroups(prometheus.NewRegistry()).mgGatherers[ilmCollectorPath].Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := ilmCollectorPath.metricPrefix() + "_" + string(expiryIncompleteTotal)
	reasons := map[string]bool{}
	for _, family := range families {
		if family.GetName() != want {
			continue
		}
		for _, m := range family.Metric {
			if m.Counter == nil || m.GetCounter().GetValue() <= 0 {
				t.Errorf("v3 %s: %v, want a counter above zero", want, m)
			}
			for _, l := range m.Label {
				if l.GetName() == "reason" {
					reasons[l.GetValue()] = true
				}
			}
		}
	}
	for _, r := range ilmIncompleteReasons {
		if !reasons[r] {
			t.Errorf("v3: %s{reason=%q} not exported", want, r)
		}
	}
	reasons = map[string]bool{}
	for _, mv := range getILMNodeMetrics().Get() {
		if mv.Description.Name == expiryIncompleteTotal {
			if mv.Description.Type != counterMetric {
				t.Errorf("v2 type %v", mv.Description.Type)
			}
			reasons[mv.VariableLabels["reason"]] = true
		}
	}
	for _, r := range ilmIncompleteReasons {
		if !reasons[r] {
			t.Errorf("v2: reason %q not exported", r)
		}
	}
}
