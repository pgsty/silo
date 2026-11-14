// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
)

func TestPeerBucketMetadataSourceTimeAndDeletion(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testPeerBucketMetadataSourceTimeAndDeletion})
}

func testPeerBucketMetadataSourceTimeAndDeletion(obj ObjectLayer, backend, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
	ctx := t.Context()
	created := UTCNow().Add(-time.Hour)
	putAt := created.Add(10 * time.Minute)
	delAt := putAt.Add(time.Minute)
	enc := func(s string) *string { v := base64.StdEncoding.EncodeToString([]byte(s)); return &v }
	base := newBucketMetadata(bucket)
	base.SetCreatedAt(created)
	base.defaultTimestamps()
	quotaJSON, err := json.Marshal(madmin.BucketQuota{Quota: 1024, Type: madmin.HardQuota})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, file string
		put        madmin.SRBucketMeta
		value      func(BucketMetadata) []byte
		stamp      func(BucketMetadata) time.Time
		deletable  bool
	}{
		{"policy", bucketPolicyConfig, madmin.SRBucketMeta{Type: madmin.SRBucketMetaTypePolicy, Policy: []byte(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}`, bucket))}, func(m BucketMetadata) []byte { return m.PolicyConfigJSON }, func(m BucketMetadata) time.Time { return m.PolicyConfigUpdatedAt }, true},
		{"tags", bucketTaggingConfig, madmin.SRBucketMeta{Type: madmin.SRBucketMetaTypeTags, Tags: enc(`<Tagging><TagSet><Tag><Key>key</Key><Value>old</Value></Tag></TagSet></Tagging>`)}, func(m BucketMetadata) []byte { return m.TaggingConfigXML }, func(m BucketMetadata) time.Time { return m.TaggingConfigUpdatedAt }, true},
		{"sse", bucketSSEConfig, madmin.SRBucketMeta{Type: madmin.SRBucketMetaTypeSSEConfig, SSEConfig: enc(`<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)}, func(m BucketMetadata) []byte { return m.EncryptionConfigXML }, func(m BucketMetadata) time.Time { return m.EncryptionConfigUpdatedAt }, true},
		{"quota", bucketQuotaConfigFile, madmin.SRBucketMeta{Type: madmin.SRBucketMetaTypeQuotaConfig, Quota: quotaJSON}, func(m BucketMetadata) []byte { return m.QuotaConfigJSON }, func(m BucketMetadata) time.Time { return m.QuotaConfigUpdatedAt }, true},
		{"versioning", bucketVersioningConfig, madmin.SRBucketMeta{Type: madmin.SRBucketMetaTypeVersionConfig, Versioning: enc(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)}, func(m BucketMetadata) []byte { return m.VersioningConfigXML }, func(m BucketMetadata) time.Time { return m.VersioningConfigUpdatedAt }, false},
		{"objectlock", objectLockConfig, newSRBucketObjectLockMeta(bucket, enc(`<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>`), putAt), func(m BucketMetadata) []byte { return m.ObjectLockConfigXML }, func(m BucketMetadata) time.Time { return m.ObjectLockConfigUpdatedAt }, false},
	}
	for _, tc := range cases {
		t.Run(backend+"/"+tc.name, func(t *testing.T) {
			if err := globalBucketMetadataSys.save(ctx, base); err != nil {
				t.Fatal(err)
			}
			item := tc.put
			item.Bucket, item.UpdatedAt = bucket, putAt
			apply := func(item madmin.SRBucketMeta) {
				t.Helper()
				rec := applySRBucketMetaViaAdmin(t, cred, item)
				if rec.Code != http.StatusOK {
					t.Fatalf("admin apply returned %d: %s", rec.Code, rec.Body.String())
				}
			}
			read := func() BucketMetadata {
				t.Helper()
				m, err := loadBucketMetadata(ctx, obj, bucket)
				if err != nil {
					t.Fatal(err)
				}
				return m
			}
			apply(item)
			put := read()
			if len(tc.value(put)) == 0 {
				t.Fatal("PUT did not establish live config")
			}
			if !tc.stamp(put).Equal(putAt) {
				t.Errorf("SOURCE_TIME: persisted %s, want source %s", tc.stamp(put), putAt)
			}
			apply(madmin.SRBucketMeta{Type: item.Type, Bucket: bucket, UpdatedAt: delAt})
			after := read()
			if !tc.deletable {
				if !bytes.Equal(tc.value(put), tc.value(after)) || !tc.stamp(put).Equal(tc.stamp(after)) {
					t.Error("NIL_NOOP: update-only config changed")
				}
				t.Log("nil payload is correctly a no-op")
				return
			}
			if len(tc.value(after)) != 0 {
				t.Error("NEWER_DELETE: HTTP 200, but live config remained after newer source DELETE")
			}
			if _, err := globalBucketMetadataSys.Delete(ctx, bucket, tc.file); err != nil {
				t.Fatal(err)
			}
			tombstone := read()
			if len(tc.value(tombstone)) != 0 {
				t.Fatal("local DELETE failed to establish tombstone")
			}
			apply(item)
			after = read()
			if len(tc.value(after)) != 0 {
				t.Error("STALE_RESURRECTION: older source PUT resurrected a locally deleted config")
			} else {
				t.Log("older source PUT did not resurrect config")
			}
		})
	}
}

func TestPeerBucketMetadataBulkOrdering(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, backend, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			meta, err := loadBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			newAt := meta.Created.Add(time.Hour)
			newXML := `<Tagging><TagSet><Tag><Key>key</Key><Value>new</Value></Tag></TagSet></Tagging>`
			meta.TaggingConfigXML, meta.TaggingConfigUpdatedAt = []byte(newXML), newAt
			if err := globalBucketMetadataSys.save(ctx, meta); err != nil {
				t.Fatal(err)
			}
			oldXML := base64.StdEncoding.EncodeToString([]byte(`<Tagging><TagSet><Tag><Key>key</Key><Value>old</Value></Tag></TagSet></Tagging>`))
			item := madmin.SRBucketMeta{Bucket: bucket, Tags: &oldXML, UpdatedAt: newAt.Add(-time.Minute)}
			rec := applySRBucketMetaViaAdmin(t, cred, item)
			if rec.Code != http.StatusOK {
				t.Fatalf("bulk apply returned %d: %s", rec.Code, rec.Body.String())
			}
			after, err := loadBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after.TaggingConfigXML, []byte(newXML)) || !after.TaggingConfigUpdatedAt.Equal(newAt) {
				t.Errorf("BULK_STALE_OVERWRITE: older bulk event overwrote newer config, value=%q time=%s", after.TaggingConfigXML, after.TaggingConfigUpdatedAt)
			}
		})
	}})
}

func TestPeerBucketMetadataOrderingUnderLock(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, backend, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			meta, err := loadBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			oldAt, newAt := meta.Created.Add(time.Hour), meta.Created.Add(2*time.Hour)
			oldXML := base64.StdEncoding.EncodeToString([]byte(`<Tagging><TagSet><Tag><Key>key</Key><Value>older</Value></Tag></TagSet></Tagging>`))
			newXML := []byte(`<Tagging><TagSet><Tag><Key>key</Key><Value>newest</Value></Tag></TagSet></Tagging>`)
			lockCtx, unlock, err := lockBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			locked := true
			defer func() {
				if locked {
					unlock()
				}
			}()
			ready := make(chan struct{}, 1)
			hook := func(name string) {
				if name == bucket {
					select {
					case ready <- struct{}{}:
					default:
					}
				}
			}
			lockBucketMetadataAcquireHook.Store(&hook)
			defer lockBucketMetadataAcquireHook.Store(nil)
			done := make(chan error, 1)
			go func() { done <- globalSiteReplicationSys.PeerBucketTaggingHandler(ctx, bucket, &oldXML, oldAt) }()
			select {
			case <-ready:
			case <-time.After(5 * time.Second):
				t.Fatal("older event never reached metadata lock")
			}
			// A newer writer commits while holding the existing metadata lock.
			// The old peer event has already checked the pre-commit cache.
			meta.TaggingConfigXML, meta.TaggingConfigUpdatedAt = newXML, newAt
			if err := globalBucketMetadataSys.saveMetadata(lockCtx, obj, &meta); err != nil {
				t.Fatal(err)
			}
			unlock()
			locked = false
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("older event did not finish")
			}
			after, err := loadBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			if string(after.TaggingConfigXML) != string(newXML) {
				t.Errorf("CHECK_OUTSIDE_LOCK: queued older event replaced newer committed tags with %q", after.TaggingConfigXML)
			}
		})
	}})
}

// Count actual metadata persistence, including writes that would be invisible
// in a value-only assertion after a duplicate or rejected event.
type bucketConfigWriteCounter struct {
	ObjectLayer
	writes atomic.Int64
}

func (o *bucketConfigWriteCounter) PutObject(ctx context.Context, bucket, object string, data *PutObjReader, opts ObjectOptions) (ObjectInfo, error) {
	if bucket == minioMetaBucket && path.Base(object) == bucketMetadataFile {
		o.writes.Add(1)
	}
	return o.ObjectLayer.PutObject(ctx, bucket, object, data, opts)
}

func TestBucketConfigStateOrdering(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	live := []byte(`<Tagging><TagSet><Tag><Key>k</Key><Value>a</Value></Tag></TagSet></Tagging>`)
	other := bytes.ReplaceAll(live, []byte("<Value>a"), []byte("<Value>b"))
	state := func(data []byte, at, birth time.Time) bucketConfigState {
		t.Helper()
		s, err := newBucketConfigState("bucket", bucketTaggingConfig, data, at, birth, false)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	baseline := state(nil, created, created)
	baselineLive := state(live, created, created)
	put := state(live, created.Add(time.Second), created)
	deleted := state(nil, put.at, created)
	lateBaseline := state(other, created.Add(time.Hour), created.Add(time.Hour))
	tests := []struct {
		name          string
		lower, higher bucketConfigState
	}{
		{"baseline initialization", baseline, baselineLive},
		{"real before later baseline", lateBaseline, put},
		{"delete wins tie", put, deleted},
		{"live key tie", put, state(other, put.at, created)},
		{"new PUT after deletion", deleted, state(live, put.at.Add(time.Second), created)},
		{"baseline key ignores creation time", state(live, created.Add(time.Hour), created.Add(time.Hour)), state(other, created, created)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if compareBucketConfigStates(tc.lower, tc.higher) >= 0 || compareBucketConfigStates(tc.higher, tc.lower) <= 0 {
				t.Fatal("ordering is not antisymmetric or chose the wrong winner")
			}
		})
	}
	for _, s := range []bucketConfigState{baseline, state(live, created.Add(-time.Second), created), state(live, created, time.Time{})} {
		if s.candidate() {
			t.Fatal("default, pre-creation, or unknown-generation state became a source")
		}
	}
	for _, file := range []string{bucketVersioningConfig, objectLockConfig} {
		s, err := newBucketConfigState("bucket", file, nil, put.at, created, false)
		if err != nil || s.candidate() {
			t.Fatalf("empty update-only candidate: %+v %v", s, err)
		}
	}
}

func TestBucketPolicyReplicationKey(t *testing.T) {
	// Permute independent set arrays and parse separately, as two sites would.
	a := []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"one","Effect":"Allow","Principal":{"AWS":["b","a"]},"Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::bucket/b*","arn:aws:s3:::bucket/a*"],"Condition":{"StringLike":{"s3:prefix":["b*","a*"]}}},{"Sid":"two","Effect":"Deny","Principal":"*","NotAction":["s3:GetObject","s3:PutObject"],"NotResource":["arn:aws:s3:::bucket/d*","arn:aws:s3:::bucket/c*"]}]}`)
	// Use a condition valid for object actions.
	a = bytes.ReplaceAll(a, []byte("s3:prefix"), []byte("aws:UserAgent"))
	b := []byte(`{"Statement":[{"NotResource":["arn:aws:s3:::bucket/c*","arn:aws:s3:::bucket/d*"],"NotAction":["s3:PutObject","s3:GetObject"],"Principal":"*","Effect":"Deny","Sid":"two"},{"Condition":{"StringLike":{"aws:UserAgent":["a*","b*"]}},"Resource":["arn:aws:s3:::bucket/a*","arn:aws:s3:::bucket/b*"],"Action":["s3:PutObject","s3:GetObject"],"Principal":{"AWS":["a","b"]},"Effect":"Allow","Sid":"one"}],"Version":"2012-10-17"}`)
	_, key, err := bucketConfigPayload("bucket", bucketPolicyConfig, a, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 30 {
		_, next, err := bucketConfigPayload("bucket", bucketPolicyConfig, b, false)
		if err != nil || !bytes.Equal(key, next) {
			t.Fatalf("independent parse %d: %s != %s (%v)", i, key, next, err)
		}
	}
	_, sid, err := bucketConfigPayload("bucket", bucketPolicyConfig, bytes.ReplaceAll(a, []byte(`"one"`), []byte(`"other"`)), false)
	if err != nil || bytes.Equal(key, sid) {
		t.Fatalf("Sid difference lost: %v", err)
	}
	n, err := canonicalBucketPolicyJSON([]byte(`{"n":[9007199254740993,9007199254740992]}`))
	if err != nil || string(n) != `{"n":[9007199254740992,9007199254740993]}` {
		t.Fatalf("integer precision lost: %s %v", n, err)
	}
}

func TestBucketPolicyReplicationStatusLegacyOrder(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, backend, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			// Statement order here is the reverse of the canonical encoder's,
			// which is what an upgraded peer stores: the permutation must not
			// be reported as a permanent mismatch.
			legacy := []byte(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"allow","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"},{"Sid":"deny","Effect":"Deny","Principal":"*","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::%s/*"}]}`, bucket, bucket))
			source, err := policy.ParseBucketPolicyConfig(bytes.NewReader(legacy), bucket)
			if err != nil {
				t.Fatal(err)
			}
			meta := newBucketMetadata(bucket)
			meta.Created = UTCNow().Add(-time.Hour)
			meta.PolicyConfigJSON = legacy
			meta.PolicyConfigUpdatedAt = meta.Created.Add(time.Minute)
			event, send, err := initialBucketConfigReplicationEvent(meta, bucketPolicyConfig)
			if err != nil || !send {
				t.Fatalf("legacy initial event: %v send=%v", err, send)
			}
			target := newBucketMetadata(bucket)
			target.Created = meta.Created
			if err := globalBucketMetadataSys.save(ctx, target); err != nil {
				t.Fatal(err)
			}
			if rec := applySRBucketMetaViaAdmin(t, cred, event); rec.Code != http.StatusOK {
				t.Fatalf("peer apply: %d %s", rec.Code, rec.Body.String())
			}
			received, _, err := globalBucketMetadataSys.GetPolicyConfig(bucket)
			if err != nil {
				t.Fatal(err)
			}
			if !isBktPolicyReplicated(2, []*policy.BucketPolicy{source, received}) {
				t.Fatal("equivalent legacy and received policy reported as permanently mismatched")
			}
			changed, err := policy.ParseBucketPolicyConfig(bytes.NewReader(legacy), bucket)
			if err != nil {
				t.Fatal(err)
			}
			changed.Statements[0].SID = "different"
			if isBktPolicyReplicated(2, []*policy.BucketPolicy{source, changed}) {
				t.Fatal("distinct policy state reported as replicated")
			}
			if isBktPolicyReplicated(2, []*policy.BucketPolicy{source, nil}) || !isBktPolicyReplicated(2, []*policy.BucketPolicy{nil, nil}) {
				t.Fatal("per-site presence accounting changed")
			}
		})
	}})
}

func TestPeerBucketMetadataWireAtomicity(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, backend, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			meta, err := loadBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			stamp := meta.Created.Add(time.Hour)
			policyData := []byte(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}`, bucket))
			meta.PolicyConfigJSON, meta.PolicyConfigUpdatedAt = policyData, stamp
			meta.QuotaConfigJSON, meta.QuotaConfigUpdatedAt = []byte(`{"quota":1024,"quotatype":"hard"}`), stamp
			meta.TaggingConfigXML, meta.TaggingConfigUpdatedAt = []byte(`<Tagging><TagSet><Tag><Key>k</Key><Value>a</Value></Tag></TagSet></Tagging>`), stamp
			if err = globalBucketMetadataSys.save(ctx, meta); err != nil {
				t.Fatal(err)
			}
			counter := &bucketConfigWriteCounter{ObjectLayer: obj}
			setObjectLayer(counter)
			defer setObjectLayer(obj)
			read := func() BucketMetadata {
				t.Helper()
				m, err := loadBucketMetadata(ctx, obj, bucket)
				if err != nil {
					t.Fatal(err)
				}
				return m
			}
			apply := func(fragment string, at time.Time, ok bool) {
				t.Helper()
				raw := fmt.Sprintf(`{"bucket":%q,"updatedAt":%q,%s}`, bucket, at.Format(time.RFC3339Nano), fragment)
				var item madmin.SRBucketMeta
				if err := json.Unmarshal([]byte(raw), &item); err != nil {
					t.Fatal(err)
				}
				rec := applySRBucketMetaViaAdmin(t, cred, item)
				if (rec.Code == http.StatusOK) != ok {
					t.Fatalf("%s: %d %s", raw, rec.Code, rec.Body.String())
				}
			}
			// Omitted/null *string and empty update-only payloads are all no-ops.
			apply(`"policy":null,"quota":null,"tags":null,"versioningConfig":"","objectLockConfig":""`, stamp.Add(time.Minute), true)
			current := read()
			if len(current.PolicyConfigJSON) != 0 || len(current.QuotaConfigJSON) == 0 {
				t.Fatal("explicit null semantics lost")
			}
			if q, _, err := globalBucketMetadataSys.GetQuotaConfig(ctx, bucket); err != nil || q.Quota != 0 {
				t.Fatalf("zero quota cache: %+v %v", q, err)
			}
			before := counter.writes.Load()
			apply(`"tags":null,"versioningConfig":"","objectLockConfig":""`, stamp.Add(2*time.Minute), true)
			if counter.writes.Load() != before {
				t.Fatal("omitted fields or empty update-only wrote metadata")
			}
			// An invalid second field cannot persist the valid deletion in this bulk.
			apply(`"tags":"","quota":{"quota":1,"quotatype":"invalid"}`, stamp.Add(2*time.Minute), false)
			if counter.writes.Load() != before || len(read().TaggingConfigXML) == 0 {
				t.Fatal("invalid bulk partially committed")
			}
			apply(`"tags":""`, stamp.Add(2*time.Minute), true)
			before = counter.writes.Load()
			apply(`"tags":""`, stamp.Add(2*time.Minute), true)
			apply(`"tags":""`, stamp.Add(time.Minute), true)
			if counter.writes.Load() != before {
				t.Fatal("duplicate or old event wrote metadata")
			}
			localAt, err := globalBucketMetadataSys.Update(ctx, bucket, bucketQuotaConfigFile, []byte(`{}`))
			if err != nil || !localAt.After(current.QuotaConfigUpdatedAt) {
				t.Fatalf("local future monotonic time: %v %v", localAt, err)
			}
			deletedAt, err := globalBucketMetadataSys.Delete(ctx, bucket, bucketQuotaConfigFile)
			if err != nil || !deletedAt.After(localAt) {
				t.Fatalf("adjacent local time: %v %v", deletedAt, err)
			}
			if q, _, err := globalBucketMetadataSys.GetQuotaConfig(ctx, bucket); err != nil || q.Quota != 0 {
				t.Fatalf("deleted quota cache: %+v %v", q, err)
			}
		})
	}})
}

func TestPeerBucketAdoptionRebasesOnlyDefaults(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, backend, bucket string, _ http.Handler, _ auth.Credentials, t *testing.T) {
		for _, shift := range []time.Duration{-time.Hour, 0, time.Hour, 3 * time.Hour} {
			t.Run(fmt.Sprintf("%s/%s", backend, shift), func(t *testing.T) {
				created := UTCNow().Add(-3 * time.Hour)
				meta := newBucketMetadata(bucket)
				meta.Created = created
				meta.defaultTimestamps()
				meta.QuotaConfigUpdatedAt = time.Time{}
				meta.TaggingConfigUpdatedAt = created.Add(2 * time.Hour) // real deletion
				meta.EncryptionConfigXML = []byte(`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)
				meta.EncryptionConfigUpdatedAt = created.Add(2 * time.Hour)
				if err := globalBucketMetadataSys.save(t.Context(), meta); err != nil {
					t.Fatal(err)
				}
				if err := globalSiteReplicationSys.PeerBucketMakeWithVersioningHandler(t.Context(), bucket, MakeBucketOptions{CreatedAt: created.Add(shift)}); err != nil {
					t.Fatal(err)
				}
				got, err := readBucketMetadata(t.Context(), obj, bucket)
				if err != nil {
					t.Fatal(err)
				}
				if !got.PolicyConfigUpdatedAt.Equal(got.Created) || !got.QuotaConfigUpdatedAt.Equal(got.Created) {
					t.Fatal("default turned into tombstone or invalid source")
				}
				if !got.TaggingConfigUpdatedAt.Equal(meta.TaggingConfigUpdatedAt) || !got.EncryptionConfigUpdatedAt.Equal(meta.EncryptionConfigUpdatedAt) || !bytes.Equal(got.EncryptionConfigXML, meta.EncryptionConfigXML) {
					t.Fatal("actual state changed during adoption")
				}
				if shift > 2*time.Hour {
					// Preserve history, but do not promote state from an earlier
					// bucket generation to a new valid source by retimestamping it.
					for _, file := range []string{bucketTaggingConfig, bucketSSEConfig} {
						data, at := replicatedBucketConfig(&got, file)
						state, err := newBucketConfigState(bucket, file, *data, *at, got.Created, false)
						if err != nil || state.candidate() {
							t.Fatalf("pre-generation history became a source: %s %v", file, err)
						}
						// As a target, that invalid history must yield to a valid
						// state from the adopted generation, including a live tag
						// replacing the preserved earlier-generation deletion.
						incoming := bucketConfigTestData(bucket)[file]
						incomingAt := got.Created.Add(time.Minute)
						changed, err := applyBucketConfig(&got, file, incoming, incomingAt)
						if err != nil || !changed || !at.Equal(incomingAt) || !bytes.Equal(*data, incoming) {
							t.Fatalf("adopted generation did not replace invalid target: %s %v", file, err)
						}
					}
				}
			})
		}
	}})
}

func recordBucketConfigPeer(t *testing.T, cred auth.Credentials) func() []madmin.SRBucketMeta {
	t.Helper()
	var mu sync.Mutex
	var events []madmin.SRBucketMeta
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event madmin.SRBucketMeta
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(remote.Close)
	serviceCred, err := auth.CreateCredentials("metadata-source-time-svc", "metadata-source-time-service-secret")
	if err != nil {
		t.Fatal(err)
	}
	serviceCred.ParentUser = cred.AccessKey
	globalSiteReplicatorCred.Set(serviceCred.SecretKey)
	t.Cleanup(func() { globalSiteReplicatorCred.Set("") })
	if _, err = globalIAMSys.store.AddServiceAccount(t.Context(), serviceCred); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { globalIAMSys.DeleteServiceAccount(context.Background(), serviceCred.AccessKey, false) })
	globalSiteReplicationSys.Lock()
	oldEnabled, oldState := globalSiteReplicationSys.enabled, globalSiteReplicationSys.state
	globalSiteReplicationSys.enabled = true
	globalSiteReplicationSys.state = srState{Name: "metadata-source-test", ServiceAccountAccessKey: serviceCred.AccessKey, Peers: map[string]madmin.PeerInfo{
		globalDeploymentID(): {Name: "local", DeploymentID: globalDeploymentID()},
		"metadata-peer":      {Name: "remote", DeploymentID: "metadata-peer", Endpoint: remote.URL},
	}}
	globalSiteReplicationSys.Unlock()
	t.Cleanup(func() {
		globalSiteReplicationSys.Lock()
		globalSiteReplicationSys.enabled, globalSiteReplicationSys.state = oldEnabled, oldState
		globalSiteReplicationSys.Unlock()
	})
	return func() []madmin.SRBucketMeta {
		mu.Lock()
		defer mu.Unlock()
		return append([]madmin.SRBucketMeta(nil), events...)
	}
}

// The final metadata lock is taken after reading the ZIP. Commit another
// writer immediately before that acquisition, using the existing lock wrapper.
type importInterleavingObjectLayer struct {
	ObjectLayer
	once  atomic.Bool
	write func()
}

func (o *importInterleavingObjectLayer) NewNSLock(bucket string, objects ...string) RWLocker {
	lock := o.ObjectLayer.NewNSLock(bucket, objects...)
	if bucket != minioMetaBucket || len(objects) != 1 || path.Base(objects[0]) != "metadata.lock" {
		return lock
	}
	return metadataObservedRWLocker{RWLocker: lock, onLock: func(context.Context) {
		if o.once.CompareAndSwap(false, true) {
			o.write()
		}
	}}
}

func TestLocalBucketMetadataCommittedEvents(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, endpoints: []string{"PutBucketPolicy", "GetBucketPolicy", "PutBucketVersioning"}, objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			events := recordBucketConfigPeer(t, cred)
			putPolicy := func(data []byte) {
				t.Helper()
				req, err := newTestSignedRequestV4(http.MethodPut, getPutPolicyURL("", bucket), int64(len(data)), bytes.NewReader(data), cred.AccessKey, cred.SecretKey, nil)
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusNoContent {
					t.Fatalf("empty policy PUT: %d %s", rec.Code, rec.Body.String())
				}
			}
			putPolicy([]byte(`{"Version":"2012-10-17","Statement":[]}`))
			meta, err := loadBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			got := events()
			if len(got) != 1 || got[0].Type != madmin.SRBucketMetaTypePolicy || len(got[0].Policy) != 0 || len(meta.PolicyConfigJSON) != 0 || !meta.PolicyConfigUpdatedAt.Equal(got[0].UpdatedAt) {
				t.Fatalf("empty policy event/disk mismatch: %+v", got)
			}
			req, err := newTestSignedRequestV4(http.MethodGet, getGetPolicyURL("", bucket), 0, nil, cred.AccessKey, cred.SecretKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("empty policy GET: %d %s", rec.Code, rec.Body.String())
			}
			// Supported negative sets must survive the same serializer on PUT,
			// peer apply, GET and export instead of failing on empty Action.
			putPolicy([]byte(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","NotAction":["s3:DeleteObject"],"NotResource":["arn:aws:s3:::%s/private/*"]}]}`, bucket)))
			req, err = newTestSignedRequestV4(http.MethodGet, getGetPolicyURL("", bucket), 0, nil, cred.AccessKey, cred.SecretKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"NotAction"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"NotResource"`)) {
				t.Fatalf("negative policy set GET: %d %s", rec.Code, rec.Body.String())
			}

			corsAdminRequest(t, cred, http.MethodPut, "/set-bucket-quota?bucket="+bucket, []byte(`{}`))
			meta, err = loadBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			got = events()
			last := got[len(got)-1]
			if last.Type != madmin.SRBucketMetaTypeQuotaConfig || len(last.Quota) == 0 || !last.UpdatedAt.Equal(meta.QuotaConfigUpdatedAt) {
				t.Fatalf("zero quota event: %+v", last)
			}

			// Replicated buckets must reject prefix exclusions without changing
			// the stored versioning document or announcing a successful update.
			beforeRejected := len(events())
			rec = corsAdminRequest(t, cred, http.MethodPut, "/import-bucket-metadata", corsZip(t, map[string][]byte{
				bucket + "/" + bucketVersioningConfig: []byte(`<VersioningConfiguration><Status>Enabled</Status><ExcludeFolders>true</ExcludeFolders></VersioningConfiguration>`),
			}))
			if report := corsImportReport(t, rec).Buckets[bucket]; report.Versioning.Err == "" {
				t.Fatal("replicated bucket accepted excluded prefixes")
			}
			afterRejected, err := loadBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(afterRejected.VersioningConfigXML, meta.VersioningConfigXML) || !afterRejected.VersioningConfigUpdatedAt.Equal(meta.VersioningConfigUpdatedAt) || len(events()) != beforeRejected {
				t.Fatal("rejected versioning import changed metadata or emitted an event")
			}

			injectedAt := UTCNow().Add(2 * time.Hour)
			interleaving := &importInterleavingObjectLayer{ObjectLayer: obj, write: func() {
				data := []byte(`{"quota":2048,"quotatype":"hard"}`)
				_, err := globalBucketMetadataSys.updateAndParseMetadata(ctx, bucket, bucketQuotaConfigFile, data, false, false, &injectedAt)
				if err != nil {
					t.Error(err)
				}
			}}
			setObjectLayer(interleaving)
			defer setObjectLayer(obj)
			before := len(events())
			rec = corsAdminRequest(t, cred, http.MethodPut, "/import-bucket-metadata", corsZip(t, map[string][]byte{
				bucket + "/" + bucketPolicyConfig:     []byte(`{"Version":"2012-10-17","Statement":[]}`),
				bucket + "/quota.json":                []byte(`{}`),
				bucket + "/" + bucketTaggingConfig:    []byte(`<Tagging><TagSet><Tag><Key>imported</Key><Value>yes</Value></Tag></TagSet></Tagging>`),
				bucket + "/" + objectLockConfig:       enabledBucketObjectLockConfig,
				bucket + "/" + bucketVersioningConfig: enabledBucketVersioningConfig,
			}))
			report := corsImportReport(t, rec).Buckets[bucket]
			if report.Err != "" || report.Policy.Err != "" || report.Quota.Err != "" || report.Tagging.Err != "" || report.Versioning.Err != "" {
				t.Fatalf("import: %+v", report)
			}
			meta, err = loadBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			if !meta.QuotaConfigUpdatedAt.After(injectedAt) || !meta.TaggingConfigUpdatedAt.Equal(meta.QuotaConfigUpdatedAt) || !meta.PolicyConfigUpdatedAt.Equal(meta.QuotaConfigUpdatedAt) {
				t.Fatalf("import time %v must exceed intervening %v; policy=%v tags=%v", meta.QuotaConfigUpdatedAt, injectedAt, meta.PolicyConfigUpdatedAt, meta.TaggingConfigUpdatedAt)
			}
			if !bytes.Equal(meta.VersioningConfigXML, enabledBucketVersioningConfig) || !meta.VersioningConfigUpdatedAt.Equal(meta.QuotaConfigUpdatedAt) || !meta.ObjectLockConfigUpdatedAt.Equal(meta.QuotaConfigUpdatedAt) {
				t.Fatal("import normalization or common source time lost")
			}
			got = events()[before:]
			if len(got) != 2 {
				t.Fatalf("import events: %+v", got)
			}
			for _, event := range got {
				if !event.UpdatedAt.Equal(meta.QuotaConfigUpdatedAt) {
					t.Fatal("import hook used ZIP start time")
				}
				if event.Type == madmin.SRBucketMetaTypePolicy {
					if len(event.Policy) != 0 {
						t.Fatal("empty policy import is not deletion")
					}
				} else if event.Tags == nil || len(event.Quota) == 0 {
					t.Fatalf("bulk omitted imported state: %+v", event)
				}
				if event.Type == "" {
					if event.Versioning == nil || event.ObjectLockConfig == nil {
						t.Fatal("normalized import fields omitted")
					}
					payload, err := base64.StdEncoding.DecodeString(*event.Versioning)
					if err != nil || !bytes.Equal(payload, enabledBucketVersioningConfig) {
						t.Fatal("import sent pre-normalization versioning")
					}
				}
			}
			beforeMeta, beforeEvents := meta, len(events())
			rec = corsAdminRequest(t, cred, http.MethodPut, "/import-bucket-metadata", corsZip(t, map[string][]byte{
				bucket + "/" + bucketTaggingConfig: []byte(`<Tagging><TagSet><Tag><Key>only</Key><Value>tags</Value></Tag></TagSet></Tagging>`),
			}))
			if status := corsImportReport(t, rec).Buckets[bucket]; status.Err != "" || status.Tagging.Err != "" {
				t.Fatalf("tags-only import: %+v", status)
			}
			meta, err = loadBucketMetadata(ctx, obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(meta.PolicyConfigJSON, beforeMeta.PolicyConfigJSON) || !meta.PolicyConfigUpdatedAt.Equal(beforeMeta.PolicyConfigUpdatedAt) || !bytes.Equal(meta.QuotaConfigJSON, beforeMeta.QuotaConfigJSON) || !meta.QuotaConfigUpdatedAt.Equal(beforeMeta.QuotaConfigUpdatedAt) {
				t.Fatal("tags-only import changed Policy or Quota")
			}
			got = events()[beforeEvents:]
			if len(got) != 1 || got[0].Tags == nil || got[0].Policy != nil || got[0].Quota != nil || got[0].Versioning != nil || got[0].ObjectLockConfig != nil || !got[0].UpdatedAt.Equal(meta.TaggingConfigUpdatedAt) {
				t.Fatalf("tags-only import hook leaked unspecified fields: %+v", got)
			}
		})
	}})
}

func TestPeerBucketMetadataNormalizesBeforeComparison(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, backend, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
		t.Run(backend, func(t *testing.T) {
			meta, err := loadBucketMetadata(t.Context(), obj, bucket)
			if err != nil {
				t.Fatal(err)
			}
			versioning := base64.StdEncoding.EncodeToString([]byte(`<VersioningConfiguration><Status>Enabled</Status><ExcludedPrefixes><Prefix>skip/</Prefix></ExcludedPrefixes><ExcludeFolders>true</ExcludeFolders></VersioningConfiguration>`))
			lock := base64.StdEncoding.EncodeToString(enabledBucketObjectLockConfig)
			item := madmin.SRBucketMeta{Bucket: bucket, ObjectLockConfig: &lock, Versioning: &versioning, UpdatedAt: meta.Created.Add(time.Hour)}
			counter := &bucketConfigWriteCounter{ObjectLayer: obj}
			setObjectLayer(counter)
			defer setObjectLayer(obj)
			for range 2 {
				rec := applySRBucketMetaViaAdmin(t, cred, item)
				if rec.Code != http.StatusOK {
					t.Fatalf("bulk: %d %s", rec.Code, rec.Body.String())
				}
			}
			if counter.writes.Load() != 1 {
				t.Fatalf("normalized duplicate persisted %d times", counter.writes.Load())
			}
			meta, err = loadBucketMetadata(t.Context(), obj, bucket)
			if err != nil || !bytes.Equal(meta.VersioningConfigXML, enabledBucketVersioningConfig) || !meta.VersioningConfigUpdatedAt.Equal(item.UpdatedAt) {
				t.Fatalf("normalization: %s %v", meta.VersioningConfigXML, err)
			}
			// Ordinary local updates use the identical effective document in their
			// commit result, even if Object Lock changed since the handler's precheck.
			data, _ := base64.StdEncoding.DecodeString(versioning)
			result, err := globalBucketMetadataSys.updateAndParseMetadata(t.Context(), bucket, bucketVersioningConfig, data, false, false, nil)
			if err != nil || !bytes.Equal(result.meta.VersioningConfigXML, enabledBucketVersioningConfig) {
				t.Fatalf("local commit snapshot: %s %v", result.meta.VersioningConfigXML, err)
			}
		})
	}})
}

func TestPeerBucketMetadataEqualTimeArrivalOrders(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, backend, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
		t.Run(backend, func(t *testing.T) {
			created := UTCNow().Add(-time.Hour)
			a := []byte(`<Tagging><TagSet><Tag><Key>key</Key><Value>a</Value></Tag></TagSet></Tagging>`)
			b := bytes.ReplaceAll(a, []byte("<Value>a"), []byte("<Value>b"))
			for _, pair := range [][2][]byte{{a, b}, {b, a}, {a, nil}, {nil, a}} {
				meta := newBucketMetadata(bucket)
				meta.Created = created
				meta.defaultTimestamps()
				if err := globalBucketMetadataSys.save(t.Context(), meta); err != nil {
					t.Fatal(err)
				}
				for _, data := range pair {
					var payload *string
					if data != nil {
						encoded := base64.StdEncoding.EncodeToString(data)
						payload = &encoded
					}
					rec := applySRBucketMetaViaAdmin(t, cred, madmin.SRBucketMeta{Bucket: bucket, Type: madmin.SRBucketMetaTypeTags, Tags: payload, UpdatedAt: created.Add(time.Minute)})
					if rec.Code != http.StatusOK {
						t.Fatalf("equal time apply: %d %s", rec.Code, rec.Body.String())
					}
				}
				got, err := readBucketMetadata(t.Context(), obj, bucket)
				if err != nil {
					t.Fatal(err)
				}
				want := b
				if pair[0] == nil || pair[1] == nil {
					want = nil
				}
				if !bytes.Equal(got.TaggingConfigXML, want) || !got.TaggingConfigUpdatedAt.Equal(created.Add(time.Minute)) {
					t.Fatalf("arrival order changed winner: %q at %v", got.TaggingConfigXML, got.TaggingConfigUpdatedAt)
				}
			}
		})
	}})
}
