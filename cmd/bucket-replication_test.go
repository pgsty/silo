// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	"github.com/minio/minio/internal/bucket/replication"
	xhttp "github.com/minio/minio/internal/http"
)

var configs = []replication.Config{
	{ // Config0 - Replication config has no filters, existing object replication enabled
		Rules: []replication.Rule{
			{
				Status:                    replication.Enabled,
				Priority:                  1,
				DeleteMarkerReplication:   replication.DeleteMarkerReplication{Status: replication.Enabled},
				DeleteReplication:         replication.DeleteReplication{Status: replication.Enabled},
				Filter:                    replication.Filter{},
				ExistingObjectReplication: replication.ExistingObjectReplication{Status: replication.Enabled},
				SourceSelectionCriteria: replication.SourceSelectionCriteria{
					ReplicaModifications: replication.ReplicaModifications{Status: replication.Enabled},
				},
			},
		},
	},
}

var replicationConfigTests = []struct {
	info         ObjectInfo
	name         string
	rcfg         replicationConfig
	dsc          ReplicateDecision
	tgtStatuses  map[string]replication.StatusType
	expectedSync bool
}{
	{ // 1. no replication config
		name:         "no replication config",
		info:         ObjectInfo{Size: 100},
		rcfg:         replicationConfig{Config: nil},
		expectedSync: false,
	},
	{ // 2. existing object replication config enabled, no versioning
		name:         "existing object replication config enabled, no versioning",
		info:         ObjectInfo{Size: 100},
		rcfg:         replicationConfig{Config: &configs[0]},
		expectedSync: false,
	},
	{ // 3. existing object replication config enabled, versioning suspended
		name:         "existing object replication config enabled, versioning suspended",
		info:         ObjectInfo{Size: 100, VersionID: nullVersionID},
		rcfg:         replicationConfig{Config: &configs[0]},
		expectedSync: false,
	},
	{ // 4. existing object replication enabled, versioning enabled; no reset in progress
		name: "existing object replication enabled, versioning enabled; no reset in progress",
		info: ObjectInfo{
			Size:              100,
			ReplicationStatus: replication.Completed,
			VersionID:         "a3348c34-c352-4498-82f0-1098e8b34df9",
		},
		rcfg:         replicationConfig{Config: &configs[0]},
		expectedSync: false,
	},
}

func TestReplicationResync(t *testing.T) {
	ctx := t.Context()
	for i, test := range replicationConfigTests {
		if sync := test.rcfg.Resync(ctx, test.info, test.dsc, test.tgtStatuses); sync.mustResync() != test.expectedSync {
			t.Errorf("Test%d (%s): Resync  got %t , want %t", i+1, test.name, sync.mustResync(), test.expectedSync)
		}
	}
}

var (
	start                   = UTCNow().AddDate(0, 0, -1)
	replicationConfigTests2 = []struct {
		info         ObjectInfo
		name         string
		rcfg         replicationConfig
		dsc          ReplicateDecision
		tgtStatuses  map[string]replication.StatusType
		expectedSync bool
	}{
		{ // Cases 1-4: existing object replication enabled, versioning enabled, no reset - replication status varies
			// 1: Pending replication
			name: "existing object replication on object in Pending replication status",
			info: ObjectInfo{
				Size:                      100,
				ReplicationStatusInternal: "arn1:PENDING;",
				ReplicationStatus:         replication.Pending,
				VersionID:                 "a3348c34-c352-4498-82f0-1098e8b34df9",
			},
			rcfg: replicationConfig{remotes: &madmin.BucketTargets{Targets: []madmin.BucketTarget{{
				Arn: "arn1",
			}}}},
			dsc:          ReplicateDecision{targetsMap: map[string]replicateTargetDecision{"arn1": newReplicateTargetDecision("arn1", true, false)}},
			expectedSync: true,
		},

		{ // 2. replication status Failed
			name: "existing object replication on object in Failed replication status",
			info: ObjectInfo{
				Size:                      100,
				ReplicationStatusInternal: "arn1:FAILED",
				ReplicationStatus:         replication.Failed,
				VersionID:                 "a3348c34-c352-4498-82f0-1098e8b34df9",
			},
			dsc: ReplicateDecision{targetsMap: map[string]replicateTargetDecision{"arn1": newReplicateTargetDecision("arn1", true, false)}},
			rcfg: replicationConfig{remotes: &madmin.BucketTargets{Targets: []madmin.BucketTarget{{
				Arn: "arn1",
			}}}},
			expectedSync: true,
		},
		{ // 3. replication status unset
			name: "existing object replication on pre-existing unreplicated object",
			info: ObjectInfo{
				Size:              100,
				ReplicationStatus: replication.StatusType(""),
				VersionID:         "a3348c34-c352-4498-82f0-1098e8b34df9",
			},
			rcfg: replicationConfig{remotes: &madmin.BucketTargets{Targets: []madmin.BucketTarget{{
				Arn: "arn1",
			}}}},
			dsc:          ReplicateDecision{targetsMap: map[string]replicateTargetDecision{"arn1": newReplicateTargetDecision("arn1", true, false)}},
			expectedSync: true,
		},
		{ // 4. replication status Complete
			name: "existing object replication on object in Completed replication status",
			info: ObjectInfo{
				Size:                      100,
				ReplicationStatusInternal: "arn1:COMPLETED",
				ReplicationStatus:         replication.Completed,
				VersionID:                 "a3348c34-c352-4498-82f0-1098e8b34df9",
			},
			dsc: ReplicateDecision{targetsMap: map[string]replicateTargetDecision{"arn1": newReplicateTargetDecision("arn1", false, false)}},
			rcfg: replicationConfig{remotes: &madmin.BucketTargets{Targets: []madmin.BucketTarget{{
				Arn: "arn1",
			}}}},
			expectedSync: false,
		},
		{ // 5. existing object replication enabled, versioning enabled, replication status Pending & reset ID present
			name: "existing object replication with reset in progress and object in Pending status",
			info: ObjectInfo{
				Size:                      100,
				ReplicationStatusInternal: "arn1:PENDING;",
				ReplicationStatus:         replication.Pending,
				VersionID:                 "a3348c34-c352-4498-82f0-1098e8b34df9",
				UserDefined:               map[string]string{xhttp.MinIOReplicationResetStatus: fmt.Sprintf("%s;abc", UTCNow().AddDate(0, -1, 0).String())},
			},
			expectedSync: true,
			dsc:          ReplicateDecision{targetsMap: map[string]replicateTargetDecision{"arn1": newReplicateTargetDecision("arn1", true, false)}},
			rcfg: replicationConfig{
				remotes: &madmin.BucketTargets{Targets: []madmin.BucketTarget{{
					Arn:             "arn1",
					ResetID:         "xyz",
					ResetBeforeDate: UTCNow(),
				}}},
			},
		},
		{ // 6. existing object replication enabled, versioning enabled, replication status Failed & reset ID present
			name: "existing object replication with reset in progress and object in Failed status",
			info: ObjectInfo{
				Size:                      100,
				ReplicationStatusInternal: "arn1:FAILED;",
				ReplicationStatus:         replication.Failed,
				VersionID:                 "a3348c34-c352-4498-82f0-1098e8b34df9",
				UserDefined:               map[string]string{xhttp.MinIOReplicationResetStatus: fmt.Sprintf("%s;abc", UTCNow().AddDate(0, -1, 0).String())},
			},
			dsc: ReplicateDecision{targetsMap: map[string]replicateTargetDecision{"arn1": newReplicateTargetDecision("arn1", true, false)}},
			rcfg: replicationConfig{
				remotes: &madmin.BucketTargets{Targets: []madmin.BucketTarget{{
					Arn:             "arn1",
					ResetID:         "xyz",
					ResetBeforeDate: UTCNow(),
				}}},
			},
			expectedSync: true,
		},
		{ // 7. existing object replication enabled, versioning enabled, replication status unset & reset ID present
			name: "existing object replication with reset in progress and object never replicated before",
			info: ObjectInfo{
				Size:              100,
				ReplicationStatus: replication.StatusType(""),
				VersionID:         "a3348c34-c352-4498-82f0-1098e8b34df9",
				UserDefined:       map[string]string{xhttp.MinIOReplicationResetStatus: fmt.Sprintf("%s;abc", UTCNow().AddDate(0, -1, 0).String())},
			},
			dsc: ReplicateDecision{targetsMap: map[string]replicateTargetDecision{"arn1": newReplicateTargetDecision("arn1", true, false)}},
			rcfg: replicationConfig{
				remotes: &madmin.BucketTargets{Targets: []madmin.BucketTarget{{
					Arn:             "arn1",
					ResetID:         "xyz",
					ResetBeforeDate: UTCNow(),
				}}},
			},

			expectedSync: true,
		},

		{ // 8. existing object replication enabled, versioning enabled, replication status Complete & reset ID present
			name: "existing object replication enabled - reset in progress for an object in Completed status",
			info: ObjectInfo{
				Size:                      100,
				ReplicationStatusInternal: "arn1:COMPLETED;",
				ReplicationStatus:         replication.Completed,
				VersionID:                 "a3348c34-c352-4498-82f0-1098e8b34df8",
				UserDefined:               map[string]string{xhttp.MinIOReplicationResetStatus: fmt.Sprintf("%s;abc", UTCNow().AddDate(0, -1, 0).String())},
			},
			expectedSync: true,
			dsc:          ReplicateDecision{targetsMap: map[string]replicateTargetDecision{"arn1": newReplicateTargetDecision("arn1", true, false)}},
			rcfg: replicationConfig{
				remotes: &madmin.BucketTargets{Targets: []madmin.BucketTarget{{
					Arn:             "arn1",
					ResetID:         "xyz",
					ResetBeforeDate: UTCNow(),
				}}},
			},
		},
		{ // 9. existing object replication enabled, versioning enabled, replication status Pending & reset ID different
			name: "existing object replication enabled, newer reset in progress on object in Pending replication status",
			info: ObjectInfo{
				Size:                      100,
				ReplicationStatusInternal: "arn1:PENDING;",

				ReplicationStatus: replication.Pending,
				VersionID:         "a3348c34-c352-4498-82f0-1098e8b34df9",
				UserDefined:       map[string]string{xhttp.MinIOReplicationResetStatus: fmt.Sprintf("%s;%s", UTCNow().AddDate(0, 0, -1).Format(http.TimeFormat), "abc")},
				ModTime:           UTCNow().AddDate(0, 0, -2),
			},
			expectedSync: true,
			dsc:          ReplicateDecision{targetsMap: map[string]replicateTargetDecision{"arn1": newReplicateTargetDecision("arn1", true, false)}},
			rcfg: replicationConfig{
				remotes: &madmin.BucketTargets{Targets: []madmin.BucketTarget{{
					Arn:             "arn1",
					ResetID:         "xyz",
					ResetBeforeDate: UTCNow(),
				}}},
			},
		},
		{ // 10. existing object replication enabled, versioning enabled, replication status Complete & reset done
			name: "reset done on object in Completed Status - ineligbile for re-replication",
			info: ObjectInfo{
				Size:                      100,
				ReplicationStatusInternal: "arn1:COMPLETED;",
				ReplicationStatus:         replication.Completed,
				VersionID:                 "a3348c34-c352-4498-82f0-1098e8b34df9",
				UserDefined:               map[string]string{xhttp.MinIOReplicationResetStatus: fmt.Sprintf("%s;%s", start.Format(http.TimeFormat), "xyz")},
			},
			expectedSync: false,
			dsc:          ReplicateDecision{targetsMap: map[string]replicateTargetDecision{"arn1": newReplicateTargetDecision("arn1", true, false)}},
			rcfg: replicationConfig{
				remotes: &madmin.BucketTargets{Targets: []madmin.BucketTarget{{
					Arn:             "arn1",
					ResetID:         "xyz",
					ResetBeforeDate: start,
				}}},
			},
		},
	}
)

func TestReplicationResyncwrapper(t *testing.T) {
	for i, test := range replicationConfigTests2 {
		if sync := test.rcfg.resync(test.info, test.dsc, test.tgtStatuses); sync.mustResync() != test.expectedSync {
			t.Errorf("%s (%s): Replicationresync  got %t , want %t", fmt.Sprintf("Test%d - %s", i+1, time.Now().Format(http.TimeFormat)), test.name, sync.mustResync(), test.expectedSync)
		}
	}
}

func TestReplicationValidationObjectUsesRulePrefix(t *testing.T) {
	tests := []struct {
		name string
		rule replication.Rule
		want string
	}{
		{name: "empty prefix", rule: replication.Rule{}, want: path.Join(minioReservedBucket, globalLocalNodeNameHex, "deleteme")},
		{name: "filter prefix", rule: replication.Rule{Filter: replication.Filter{Prefix: "data/"}}, want: path.Join("data", minioReservedBucket, globalLocalNodeNameHex, "deleteme")},
		{name: "and prefix", rule: replication.Rule{Filter: replication.Filter{And: replication.And{Prefix: "archive/"}}}, want: path.Join("archive", minioReservedBucket, globalLocalNodeNameHex, "deleteme")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := replicationValidationObject(test.rule); got != test.want {
				t.Fatalf("replicationValidationObject() = %q, want %q", got, test.want)
			}
		})
	}
}

// newMatchingReplicationPair returns a source/target pair that getReplicationAction must
// classify as replicateNone: same ETag, version id, size, modification time and content
// type. Any action other than replicateNone is therefore attributable to the object lock
// entries a caller adds on top.
func newMatchingReplicationPair() (ObjectInfo, minio.ObjectInfo) {
	mtime := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	size := int64(7)
	src := ObjectInfo{
		Bucket:      "bucket",
		Name:        "object",
		ETag:        "d41d8cd98f00b204e9800998ecf8427e",
		VersionID:   "b0ff1d6e-0000-4000-8000-000000000001",
		Size:        size,
		ActualSize:  &size,
		ModTime:     mtime,
		ContentType: "application/octet-stream",
		UserDefined: map[string]string{"content-type": "application/octet-stream"},
	}
	tgt := minio.ObjectInfo{
		ETag:         src.ETag,
		VersionID:    src.VersionID,
		Size:         size,
		LastModified: mtime,
		ContentType:  src.ContentType,
		Metadata:     http.Header{},
	}
	return src, tgt
}

// TestGetReplicationActionEmptyObjectLockValues covers the comparison of object lock entries
// whose value is empty. Removing retention from a version stores the mode and retain-until-date
// keys with empty values, while the target's HEAD response omits them entirely, so the two must
// compare equal or the version can never be reported as in sync. Cases 3 and 4 are synthetic
// comparison inputs, since a SILO target cannot return empty lock headers; cases 7 and 8 guard
// against over-normalizing.
func TestGetReplicationActionEmptyObjectLockValues(t *testing.T) {
	var (
		modeKey = strings.ToLower(xhttp.AmzObjectLockMode)
		dateKey = strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)
		until   = "2026-10-05T10:00:00.000Z"
	)
	emptyRetention := map[string]string{modeKey: "", dateKey: ""}
	realRetention := map[string]string{modeKey: "GOVERNANCE", dateKey: until}

	tests := []struct {
		name    string
		srcMeta map[string]string
		tgtHdr  map[string]string
		want    replicationAction
	}{
		{"1-both-clean-never-had-retention", nil, nil, replicateNone},
		{"2-source-present-empty-target-absent", emptyRetention, nil, replicateNone},
		{"3-source-absent-target-present-empty", nil, emptyRetention, replicateNone},
		{"4-both-present-empty", emptyRetention, emptyRetention, replicateNone},
		{"5-both-governance-equal", realRetention, realRetention, replicateNone},
		{"6-source-governance-target-absent", realRetention, nil, replicateMetadata},
		{"7-source-empty-target-real-retention", emptyRetention, realRetention, replicateMetadata},
		{"8-empty-user-metadata-is-not-normalized", map[string]string{"x-amz-meta-foo": ""}, nil, replicateMetadata},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src, tgt := newMatchingReplicationPair()
			for k, v := range test.srcMeta {
				src.UserDefined[k] = v
			}
			for k, v := range test.tgtHdr {
				tgt.Metadata.Set(k, v)
			}
			if got := getReplicationAction(src, tgt, replication.HealReplicationType); got != test.want {
				t.Fatalf("getReplicationAction() = %q, want %q (source %v, target %v)", got, test.want, src.UserDefined, tgt.Metadata)
			}
		})
	}
}

// TestEmptyRetentionValuesAreOmittedFromObjectResponseHeaders records why the target half of the
// comparison in getReplicationAction can never report an empty object lock entry:
// FilterObjectLockMetadata drops both keys because an empty mode is not a valid retention mode,
// and setObjectHeaders skips them when writing response headers. Neither filter reaches the
// replication wire: the empty entries are still carried by getCopyObjMetadata and sent by the
// metadata CopyObject, which is why the sender's comparison is what has to tolerate them.
// FilterObjectLockMetadata is also applied by CopyObject (cmd/object-handlers.go:1708), where it
// strips the source's lock metadata before the destination re-derives it from the request.
func TestEmptyRetentionValuesAreOmittedFromObjectResponseHeaders(t *testing.T) {
	modeKey := strings.ToLower(xhttp.AmzObjectLockMode)
	dateKey := strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)
	meta := map[string]string{
		modeKey:        "",
		dateKey:        "",
		"content-type": "application/octet-stream",
	}

	filtered := objectlock.FilterObjectLockMetadata(meta, false, false)
	if _, ok := filtered[modeKey]; ok {
		t.Errorf("FilterObjectLockMetadata() kept the empty lock mode key: %v", filtered)
	}
	if _, ok := filtered[dateKey]; ok {
		t.Errorf("FilterObjectLockMetadata() kept the empty retain-until-date key: %v", filtered)
	}

	rec := httptest.NewRecorder()
	if err := setObjectHeaders(t.Context(), rec, ObjectInfo{UserDefined: meta, ModTime: time.Now(), Size: 7}, nil, ObjectOptions{}); err != nil {
		t.Fatalf("setObjectHeaders() = %v", err)
	}
	if v, ok := rec.Header()[http.CanonicalHeaderKey(xhttp.AmzObjectLockMode)]; ok {
		t.Errorf("setObjectHeaders() emitted an empty lock mode header: %v", v)
	}
	if v, ok := rec.Header()[http.CanonicalHeaderKey(xhttp.AmzObjectLockRetainUntilDate)]; ok {
		t.Errorf("setObjectHeaders() emitted an empty retain-until-date header: %v", v)
	}
}

// fakeRetentionGetter answers GetObjectRetention with a fixed result and counts its calls.
type fakeRetentionGetter struct {
	mode  *minio.RetentionMode
	err   error
	calls int
}

func (f *fakeRetentionGetter) GetObjectRetention(_ context.Context, _, _, _ string) (*minio.RetentionMode, *time.Time, error) {
	f.calls++
	return f.mode, nil, f.err
}

func TestRetentionRemovedAtSource(t *testing.T) {
	modeKey := strings.ToLower(xhttp.AmzObjectLockMode)
	dateKey := strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)
	tests := []struct {
		name string
		meta map[string]string
		want bool
	}{
		{"no lock keys", map[string]string{"content-type": "text/plain"}, false},
		{"empty pair", map[string]string{modeKey: "", dateKey: ""}, true},
		{"empty mode only", map[string]string{modeKey: ""}, true},
		{"empty date only", map[string]string{dateKey: ""}, true},
		{"real retention", map[string]string{modeKey: "GOVERNANCE", dateKey: "2026-10-05T10:00:00.000Z"}, false},
		{"canonical case", map[string]string{xhttp.AmzObjectLockMode: ""}, true},
		{"empty user metadata", map[string]string{"x-amz-meta-foo": ""}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := retentionRemovedAtSource(ObjectInfo{UserDefined: test.meta}); got != test.want {
				t.Fatalf("retentionRemovedAtSource() = %v, want %v", got, test.want)
			}
		})
	}
}

// TestTargetRetentionConfirmedAbsent pins the rule that only an explicit answer from the
// destination clears a removed retention. A denied or unreachable destination must read as still
// holding retention, because HEAD hides a real retention from a credential without
// s3:GetObjectRetention exactly as it hides one that does not exist.
func TestTargetRetentionConfirmedAbsent(t *testing.T) {
	governance := minio.Governance
	var emptyMode minio.RetentionMode
	unknownMode := minio.RetentionMode("ARCHIVE")
	tests := []struct {
		name string
		mode *minio.RetentionMode
		err  error
		want bool
	}{
		{"version holds governance retention", &governance, nil, false},
		{"no retention on the version", nil, minio.ErrorResponse{Code: "NoSuchObjectLockConfiguration"}, true},
		{
			// The destination also answers this when its own read of the bucket's Object Lock
			// configuration fails, so it does not establish that Object Lock is disabled.
			"invalid request naming a missing object lock configuration",
			nil,
			minio.ErrorResponse{Code: "InvalidRequest", Message: "Bucket is missing ObjectLockConfiguration"},
			false,
		},
		{
			"unrelated invalid request",
			nil,
			minio.ErrorResponse{Code: "InvalidRequest", Message: "Object is WORM protected and cannot be overwritten"},
			false,
		},
		{"retention read denied", nil, minio.ErrorResponse{Code: "AccessDenied"}, false},
		{"destination unreachable", nil, errors.New("dial tcp: connection refused"), false},
		{"empty mode returned", &emptyMode, nil, true},
		{"unknown non-empty mode returned", &unknownMode, nil, false},
		{"nil mode returned", nil, nil, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tgt := &fakeRetentionGetter{mode: test.mode, err: test.err}
			if got := targetRetentionConfirmedAbsent(t.Context(), tgt, "bucket", "object", "v1"); got != test.want {
				t.Fatalf("targetRetentionConfirmedAbsent() = %v, want %v", got, test.want)
			}
			if tgt.calls != 1 {
				t.Fatalf("GetObjectRetention called %d times, want 1", tgt.calls)
			}
		})
	}
}

// TestReplicationActionForTargetRetentionRemoval covers the decision the replication worker makes
// for a version whose retention was removed. The destination's HEAD never reports the empty keys,
// so the comparison alone reads every one of these as in sync; only the confirmation separates a
// destination that really dropped the retention from one that is hiding it.
func TestReplicationActionForTargetRetentionRemoval(t *testing.T) {
	modeKey := strings.ToLower(xhttp.AmzObjectLockMode)
	dateKey := strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)
	governance := minio.Governance

	tests := []struct {
		name      string
		srcMeta   map[string]string
		mode      *minio.RetentionMode
		err       error
		want      replicationAction
		wantCalls int
	}{
		{
			name:      "removal confirmed by destination",
			srcMeta:   map[string]string{modeKey: "", dateKey: ""},
			err:       minio.ErrorResponse{Code: "NoSuchObjectLockConfiguration"},
			want:      replicateNone,
			wantCalls: 1,
		},
		{
			name:      "destination still holds the retention hidden from HEAD",
			srcMeta:   map[string]string{modeKey: "", dateKey: ""},
			mode:      &governance,
			want:      replicateMetadata,
			wantCalls: 1,
		},
		{
			name:      "retention hidden from HEAD by permissions",
			srcMeta:   map[string]string{modeKey: "", dateKey: ""},
			err:       minio.ErrorResponse{Code: "AccessDenied"},
			want:      replicateMetadata,
			wantCalls: 1,
		},
		{
			// A destination that names a missing Object Lock configuration answers the same way
			// when its own read of that configuration failed, so it confirms nothing.
			name:      "destination reports no object lock configuration",
			srcMeta:   map[string]string{modeKey: "", dateKey: ""},
			err:       minio.ErrorResponse{Code: "InvalidRequest", Message: "Bucket is missing ObjectLockConfiguration"},
			want:      replicateMetadata,
			wantCalls: 1,
		},
		{
			name:      "version never had retention is not confirmed",
			srcMeta:   nil,
			want:      replicateNone,
			wantCalls: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src, tgtInfo := newMatchingReplicationPair()
			for k, v := range test.srcMeta {
				src.UserDefined[k] = v
			}
			tgt := &fakeRetentionGetter{mode: test.mode, err: test.err}
			got := replicationActionForTarget(t.Context(), src, tgtInfo, replication.HealReplicationType, tgt, "bucket", "object")
			if got != test.want {
				t.Fatalf("replicationActionForTarget() = %q, want %q", got, test.want)
			}
			if tgt.calls != test.wantCalls {
				t.Fatalf("GetObjectRetention called %d times, want %d", tgt.calls, test.wantCalls)
			}
		})
	}
}

// TestReplicationActionForTargetNullVersionResync pins that the confirmation does not reopen the
// null-version exclusion at the head of getReplicationAction. An existing object resync returns
// replicateNone for a null version whose source modification time is later than the target's,
// before comparing anything, and that must stand even when the source carries a removed retention
// and the destination would report retention or refuse to answer.
func TestReplicationActionForTargetNullVersionResync(t *testing.T) {
	modeKey := strings.ToLower(xhttp.AmzObjectLockMode)
	dateKey := strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)
	governance := minio.Governance

	tests := []struct {
		name string
		mode *minio.RetentionMode
		err  error
	}{
		{"destination holds retention", &governance, nil},
		{"retention read denied", nil, minio.ErrorResponse{Code: "AccessDenied"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src, tgtInfo := newMatchingReplicationPair()
			// A null version whose source modification time is later, and whose content differs,
			// so only the exclusion can hold the action at replicateNone.
			src.VersionID = nullVersionID
			src.ModTime = tgtInfo.LastModified.Add(time.Hour)
			src.ETag = "5d41402abc4b2a76b9719d911017c592"
			src.UserDefined[modeKey] = ""
			src.UserDefined[dateKey] = ""
			tgtInfo.VersionID = nullVersionID

			tgt := &fakeRetentionGetter{mode: test.mode, err: test.err}
			got := replicationActionForTarget(t.Context(), src, tgtInfo, replication.ExistingObjectReplicationType, tgt, "bucket", "object")
			if got != replicateNone {
				t.Fatalf("replicationActionForTarget() = %q, want %q", got, replicateNone)
			}
			if tgt.calls != 0 {
				t.Fatalf("GetObjectRetention called %d times, want 0", tgt.calls)
			}
		})
	}
}
