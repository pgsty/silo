// Copyright (c) 2026 Feng Ruohang
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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
)

func TestPoolLockReductionOrderIndependent(t *testing.T) {
	const old = objectLockTestStamp0900
	const recent = objectLockTestStamp1000
	const newest = objectLockTestStamp1100
	compliance := objectLockState{mode: "COMPLIANCE", retainUntil: "2035-01-01T00:00:00Z", retentionTimestamp: old}
	for _, tc := range []struct {
		name   string
		states [3]objectLockState
		want   objectLockState
	}{
		{"compliance-before-newer-removal", [3]objectLockState{compliance, {retentionTimestamp: recent}, {mode: "GOVERNANCE", retainUntil: "2036-01-01T00:00:00Z", retentionTimestamp: newest}}, compliance},
		{"longer-compliance-before-newer-shortening", [3]objectLockState{compliance, {mode: "COMPLIANCE", retainUntil: "2034-01-01T00:00:00Z", retentionTimestamp: newest}, {retentionTimestamp: recent}}, compliance},
		{"unordered-compliance", [3]objectLockState{{mode: "COMPLIANCE", retainUntil: compliance.retainUntil, retentionTimestamp: "invalid"}, {retentionTimestamp: newest}, {}}, objectLockState{mode: "COMPLIANCE", retainUntil: compliance.retainUntil, retentionTimestamp: "invalid"}},
		{"expired-compliance-can-release", [3]objectLockState{{mode: "COMPLIANCE", retainUntil: "2000-01-01T00:00:00Z", retentionTimestamp: old}, {retentionTimestamp: newest}, {retentionTimestamp: recent}}, objectLockState{retentionTimestamp: newest}},
		{"governance-can-release", [3]objectLockState{{mode: "GOVERNANCE", retainUntil: compliance.retainUntil, retentionTimestamp: old}, {retentionTimestamp: newest}, {}}, objectLockState{retentionTimestamp: newest}},
		{"unordered-hold-conflict", [3]objectLockState{{legalHold: "OFF"}, {legalHold: "ON"}, {}}, objectLockState{legalHold: "ON"}},
		{"newer-hold-release", [3]objectLockState{{legalHold: "ON", legalHoldTimestamp: old}, {legalHold: "OFF", legalHoldTimestamp: newest}, {legalHold: "ON", legalHoldTimestamp: "invalid"}}, objectLockState{legalHold: "OFF", legalHoldTimestamp: newest}},
		{"independent-fields", [3]objectLockState{compliance, {retentionTimestamp: newest, legalHold: "ON", legalHoldTimestamp: recent}, {legalHold: "OFF", legalHoldTimestamp: old}}, objectLockState{mode: compliance.mode, retainUntil: compliance.retainUntil, retentionTimestamp: old, legalHold: "ON", legalHoldTimestamp: recent}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
				var copies []PoolObjInfo
				for _, i := range order {
					meta := make(map[string]string)
					tc.states[i].restoreRetention(meta)
					tc.states[i].restoreLegalHold(meta)
					copies = append(copies, PoolObjInfo{Index: i, ObjInfo: ObjectInfo{UserDefined: meta}})
				}
				for name, reduce := range map[string]func([]PoolObjInfo) objectLockState{"merge": mergePoolLockState, "lifecycle": newestLockState} {
					if got := reduce(copies); got != tc.want {
						t.Errorf("%s order=%v: got %+v want %+v", name, order, got, tc.want)
					}
				}
			}
		})
	}
}

// All requests copy the same bytes. Revisions belong to the addressed
// destination, even if the source is the latest version of the same key.
func TestAPICopyReplicaDestinationState(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, makeBucketOptions: MakeBucketOptions{LockEnabled: true},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			for _, sameKey := range []bool{true, false} {
				for _, missing := range []bool{false, true} {
					for _, directive := range []string{copyDirective, replaceDirective} {
						name := fmt.Sprintf("copy-destination/%t/%t/%s", sameKey, missing, directive)
						source := name
						if !sameKey {
							source += "-source"
						}
						targetMeta := poolLockMetadata("GOVERNANCE", "ON", objectLockTestStamp1000, objectLockTestStamp1000)
						targetMeta[xhttp.AmzObjectTagging] = "state=destination"
						targetMeta[r5TagStamp] = objectLockTestStamp1000
						targetID := mustGetUUID()
						if !missing {
							targetID = putObjectLockVersion(t, obj, bucket, name, targetMeta)
						}
						sourceMeta := poolLockMetadata("", "OFF", objectLockTestStamp1100, objectLockTestStamp1100)
						sourceMeta[xhttp.AmzObjectTagging] = "state=source"
						sourceMeta[r5TagStamp] = objectLockTestStamp1100
						sourceID := putObjectLockVersion(t, obj, bucket, source, sourceMeta)
						headers := map[string]string{
							xhttp.AmzCopySource:        "/" + bucket + "/" + source + "?versionId=" + sourceID,
							xhttp.AmzMetadataDirective: directive, xhttp.AmzTagDirective: replaceDirective,
							xhttp.MinIOSourceReplicationRequest: "true", xhttp.AmzBucketReplicationStatus: "REPLICA",
						}
						// No source revision means no change, including no
						// inheritance from a different source for a first write.
						rec := r5Request(t, router, cred, http.MethodPut, "/"+bucket+"/"+name+"?versionId="+targetID, "", headers)
						if rec.Code != http.StatusOK {
							t.Fatalf("%s %s: %d %s", backend, name, rec.Code, rec.Body.String())
						}
						want := storedObjectLockState(targetMeta)
						wantTags, wantStamp := "state=destination", objectLockTestStamp1000
						if missing {
							want = objectLockState{}
							wantTags = ""
							wantStamp = ""
						}
						got := r5Stored(t, obj, bucket, name, targetID, wantTags, wantStamp)
						if state := storedObjectLockState(got.UserDefined); state != want {
							t.Fatalf("%s absent revision: got %+v want %+v", name, state, want)
						}
						// The incoming update is older than the source but may
						// still win at a new destination. A source lookup loses it.
						headers[xhttp.MinIOSourceObjectRetentionTimestamp] = objectLockTestStamp0930
						headers[xhttp.MinIOSourceObjectLegalHoldTimestamp] = objectLockTestStamp0930
						headers[xhttp.AmzObjectLockMode] = "GOVERNANCE"
						headers[xhttp.AmzObjectLockRetainUntilDate] = objectLockTestRetainUntil
						headers[xhttp.AmzObjectLockLegalHold] = "ON"
						headers[xhttp.MinIOSourceTaggingTimestamp] = objectLockTestStamp0930
						headers[xhttp.AmzObjectTagging] = "state=incoming"
						rec = r5Request(t, router, cred, http.MethodPut, "/"+bucket+"/"+name+"?versionId="+targetID, "", headers)
						if rec.Code != http.StatusOK {
							t.Fatalf("incoming %s: %d %s", name, rec.Code, rec.Body.String())
						}
						if missing {
							want = objectLockState{mode: "GOVERNANCE", retainUntil: "2030-01-01T00:00:00.000Z", retentionTimestamp: objectLockTestStamp0930, legalHold: "ON", legalHoldTimestamp: objectLockTestStamp0930}
							wantTags = "state=incoming"
							wantStamp = objectLockTestStamp0930
						}
						got = r5Stored(t, obj, bucket, name, targetID, wantTags, wantStamp)
						if state := storedObjectLockState(got.UserDefined); state != want {
							t.Fatalf("%s stale revision: got %+v want %+v", name, state, want)
						}
						// Authorized same-content release needs no governance
						// bypass header; it must not be rejected by the data guard.
						delete(headers, xhttp.AmzObjectLockMode)
						delete(headers, xhttp.AmzObjectLockRetainUntilDate)
						headers[xhttp.MinIOSourceObjectRetentionTimestamp] = "2026-09-03T10:30:00Z"
						headers[xhttp.MinIOSourceObjectLegalHoldTimestamp] = "2026-09-03T10:30:00Z"
						headers[xhttp.AmzObjectLockLegalHold] = "OFF"
						rec = r5Request(t, router, cred, http.MethodPut, "/"+bucket+"/"+name+"?versionId="+targetID, "", headers)
						if rec.Code != http.StatusOK {
							t.Fatalf("release %s: %d %s", name, rec.Code, rec.Body.String())
						}
						got = r5Stored(t, obj, bucket, name, targetID, wantTags, wantStamp)
						want = objectLockState{retentionTimestamp: "2026-09-03T10:30:00Z", legalHold: "OFF", legalHoldTimestamp: "2026-09-03T10:30:00Z"}
						if state := storedObjectLockState(got.UserDefined); state != want {
							t.Fatalf("%s release: got %+v want %+v", name, state, want)
						}
					}
				}
			}
		},
	})
}

func TestReplicaReferenceCopyDestinationState(t *testing.T) {
	z, bucket := consistencyPools(t)
	for _, missing := range []bool{false, true} {
		key := fmt.Sprintf("reference-copy-%t", missing)
		id := mustGetUUID()
		targetMeta := poolLockMetadata("GOVERNANCE", "ON", objectLockTestStamp1000, objectLockTestStamp1000)
		targetMeta[xhttp.AmzObjectTagging] = "state=destination"
		targetMeta[r5TagStamp] = objectLockTestStamp1000
		if !missing {
			putConsistencyObject(t, z, bucket, key, 0, "data", ObjectOptions{Versioned: true, VersionID: id, UserDefined: targetMeta})
		}
		sourceMeta := poolLockMetadata("", "OFF", objectLockTestStamp1100, objectLockTestStamp1100)
		sourceMeta[xhttp.AmzObjectTagging] = "state=source"
		sourceMeta[r5TagStamp] = objectLockTestStamp1100
		src := putConsistencyObject(t, z, bucket, key, 0, "data", ObjectOptions{Versioned: true, UserDefined: sourceMeta})
		src.metadataOnly = true
		src.UserDefined = make(map[string]string)
		_, err := z.CopyObject(t.Context(), bucket, key, bucket, key, src, ObjectOptions{VersionID: src.VersionID}, ObjectOptions{Versioned: true, VersionID: id, ReplicaLockReconcile: true, ReplicationRequest: true})
		if err != nil {
			t.Fatal(err)
		}
		want := storedObjectLockState(targetMeta)
		wantTags, wantStamp := "state=destination", objectLockTestStamp1000
		if missing {
			want = objectLockState{}
			wantTags = ""
			wantStamp = ""
		}
		got := r5Stored(t, z, bucket, key, id, wantTags, wantStamp)
		if state := storedObjectLockState(got.UserDefined); state != want {
			t.Fatalf("missing=%t: got %+v want %+v", missing, state, want)
		}
	}
}

// The set must not undo the all-pools decision with a newer weak revision
// from its own copy before the protected competing copy is retired.
func TestPoolsReplicaComplianceMetadataCopyOrder(t *testing.T) {
	z, bucket := consistencyPools(t)
	for _, protectedPool := range []int{0, 1} {
		key := fmt.Sprintf("compliance-copy-%d", protectedPool)
		id := mustGetUUID()
		stamp := UTCNow().Add(-time.Hour)
		var source ObjectInfo
		for pool := range 2 {
			meta := poolLockMetadata("", "OFF", objectLockTestStamp1100, objectLockTestStamp1000)
			if pool == protectedPool {
				meta = poolLockMetadata("COMPLIANCE", "OFF", objectLockTestStamp0900, objectLockTestStamp1000)
			}
			oi := putConsistencyObject(t, z, bucket, key, pool, "data", ObjectOptions{Versioned: true, VersionID: id, MTime: stamp, UserDefined: meta})
			if pool == 0 {
				source = oi
			}
		}
		source.metadataOnly = true
		source.UserDefined = map[string]string{}
		_, err := z.CopyObject(t.Context(), bucket, key, bucket, key, source, ObjectOptions{VersionID: id}, ObjectOptions{VersionID: id, Versioned: true, ReplicaLockReconcile: true, ReplicationRequest: true})
		if err != nil {
			t.Fatal(err)
		}
		got := readObjectLockFields(t, z, bucket, key, id)
		if got.mode != "COMPLIANCE" || got.retainUntil != "2030-01-01T00:00:00Z" {
			t.Fatalf("protected pool %d lost COMPLIANCE: %+v", protectedPool, got)
		}
	}
}

func TestAPIReplicaRetentionTimestampAuthorization(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, makeBucketOptions: MakeBucketOptions{LockEnabled: true},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
			basic := `"s3:GetObject","s3:PutObject","s3:ReplicateObject"`
			noRetention := newObjectAttributesAuthzUser(t, backend, bucket, basic)
			withRetention := newObjectAttributesAuthzUser(t, backend, bucket, basic+`,"s3:PutObjectRetention"`)
			for _, operation := range []string{"put", "copy", "multipart"} {
				for _, authorized := range []bool{false, true} {
					for _, timestamp := range []bool{false, true} {
						key := fmt.Sprintf("replica-permission/%s/%t/%t", operation, authorized, timestamp)
						meta := poolLockMetadata("GOVERNANCE", "", objectLockTestStamp0900, "")
						id := putObjectLockVersion(t, obj, bucket, key, meta)
						headers := map[string]string{xhttp.MinIOSourceReplicationRequest: "true", xhttp.AmzBucketReplicationStatus: "REPLICA"}
						if timestamp {
							headers[xhttp.MinIOSourceObjectRetentionTimestamp] = objectLockTestStamp1000
						}
						method, path, body := http.MethodPut, "/"+bucket+"/"+key+"?versionId="+id, "data"
						switch operation {
						case "copy":
							headers[xhttp.AmzCopySource] = "/" + bucket + "/" + key + "?versionId=" + id
							headers[xhttp.AmzMetadataDirective] = replaceDirective
							body = ""
						case "multipart":
							method = http.MethodPost
							path += "&uploads"
							body = ""
						}
						cred := noRetention
						if authorized {
							cred = withRetention
						}
						rec := r5Request(t, router, cred, method, path, body, headers)
						want := http.StatusOK
						if timestamp && !authorized {
							want = http.StatusForbidden
						}
						if rec.Code != want {
							t.Fatalf("%s: %d want %d: %s", key, rec.Code, want, rec.Body.String())
						}
						if want == http.StatusForbidden || !timestamp {
							got := readObjectLockFields(t, obj, bucket, key, id)
							if got.mode != "GOVERNANCE" || got.retentionStamp != objectLockTestStamp0900 {
								t.Fatalf("unrequested/denied retention changed: %+v", got)
							}
						}
					}
				}
			}
		},
	})
}

func TestAPILocalObjectLockTimestampsAdvance(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, makeBucketOptions: MakeBucketOptions{LockEnabled: true},
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			future := UTCNow().Add(48 * time.Hour)
			meta := poolLockMetadata("GOVERNANCE", "ON", future.Format(time.RFC3339Nano), future.Format(time.RFC3339Nano))
			id := putObjectLockVersion(t, obj, bucket, "local-lock", meta)
			for n := 1; n <= 2; n++ {
				if status := putRetention(t, router, cred, bucket, "local-lock", id, "GOVERNANCE", time.Date(2035, 1, n, 0, 0, 0, 0, time.UTC), false); status != http.StatusOK {
					t.Fatalf("%s retention: %d", backend, status)
				}
				body := []byte(`<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>OFF</Status></LegalHold>`)
				sum := md5.Sum(body)
				rec := retentionAuthzRequest(t, router, cred, http.MethodPut, makeTestTargetURL("", bucket, "local-lock", url.Values{"legal-hold": {""}, "versionId": {id}}), body, map[string]string{xhttp.ContentMD5: base64.StdEncoding.EncodeToString(sum[:])})
				if rec.Code != http.StatusOK {
					t.Fatalf("%s hold: %d %s", backend, rec.Code, rec.Body.String())
				}
				got := readObjectLockFields(t, obj, bucket, "local-lock", id)
				want := future.Add(time.Duration(n) * time.Nanosecond).Format(time.RFC3339Nano)
				if got.retentionStamp != want || got.legalHoldStamp != want {
					t.Fatalf("local mutation %d regressed: %+v want %s", n, got, want)
				}
			}
		},
	})
}

type lockBoundaryReadFailure struct {
	ObjectLayer
	bucket, key, version string
	metadataError        error
	destinationError     error
	deleteCalls          int
}

func (f *lockBoundaryReadFailure) GetObjectNInfo(ctx context.Context, bucket, key string, rs *HTTPRangeSpec, h http.Header, opts ObjectOptions) (*GetObjectReader, error) {
	if f.metadataError != nil && bucket == minioMetaBucket && strings.HasPrefix(key, pathJoin(bucketMetaPrefix, f.bucket)+"/") {
		return nil, f.metadataError
	}
	return f.ObjectLayer.GetObjectNInfo(ctx, bucket, key, rs, h, opts)
}
func (f *lockBoundaryReadFailure) GetObjectInfo(ctx context.Context, bucket, key string, opts ObjectOptions) (ObjectInfo, error) {
	if f.destinationError != nil && bucket == f.bucket && key == f.key && opts.VersionID == f.version {
		return ObjectInfo{}, f.destinationError
	}
	return f.ObjectLayer.GetObjectInfo(ctx, bucket, key, opts)
}
func (f *lockBoundaryReadFailure) DeleteObject(ctx context.Context, bucket, key string, opts ObjectOptions) (ObjectInfo, error) {
	f.deleteCalls++
	return f.ObjectLayer.DeleteObject(ctx, bucket, key, opts)
}

func TestAPICopyReplicaDestinationReadFailure(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, makeBucketOptions: MakeBucketOptions{LockEnabled: true}, objAPITest: func(obj ObjectLayer, backend, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
		id := putObjectLockVersion(t, obj, bucket, "destination", poolLockMetadata("GOVERNANCE", "ON", objectLockTestStamp1000, objectLockTestStamp1000))
		source := putObjectLockVersion(t, obj, bucket, "source", nil)
		f := &lockBoundaryReadFailure{ObjectLayer: obj, bucket: bucket, key: "destination", version: id, destinationError: errErasureReadQuorum}
		router := initTestAPIEndPoints(f, []string{"CopyObject"})
		headers := map[string]string{xhttp.AmzCopySource: "/" + bucket + "/source?versionId=" + source, xhttp.MinIOSourceReplicationRequest: "true", xhttp.AmzBucketReplicationStatus: "REPLICA"}
		rec := r5Request(t, router, cred, http.MethodPut, "/"+bucket+"/destination?versionId="+id, "", headers)
		if rec.Code < 500 {
			t.Fatalf("%s read failure allowed copy: %d %s", backend, rec.Code, rec.Body.String())
		}
		if got := readObjectLockFields(t, obj, bucket, "destination", id); got.legalHold != "ON" || got.mode != "GOVERNANCE" {
			t.Fatalf("failed read changed state: %+v", got)
		}
	}})
}

func TestAPIForceDeleteLockConfigFailure(t *testing.T) {
	for _, locked := range []bool{false, true} {
		t.Run(fmt.Sprintf("locked=%t", locked), func(t *testing.T) {
			ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, makeBucketOptions: MakeBucketOptions{LockEnabled: locked}, objAPITest: func(obj ObjectLayer, backend, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
				saved, err := globalBucketMetadataSys.Get(bucket)
				if err != nil {
					t.Fatal(err)
				}
				restoreInit := markBucketMetadataInitialized(t)
				defer restoreInit()
				previous := newObjectLayerFn()
				defer setObjectLayer(previous)
				defer globalBucketMetadataSys.Set(bucket, saved)
				for _, failure := range []string{"quorum", "unavailable", "cache-miss"} {
					key := "force-" + failure + "/data"
					putObjectLockVersion(t, obj, bucket, key, nil)
					f := &lockBoundaryReadFailure{ObjectLayer: obj, bucket: bucket}
					globalBucketMetadataSys.Remove(bucket)
					switch failure {
					case "quorum":
						f.metadataError = errErasureReadQuorum
					case "unavailable":
						f.metadataError = errServerNotInitialized
					}
					router := initTestAPIEndPoints(f, []string{"DeleteObject"})
					rec := r5Request(t, router, cred, http.MethodDelete, "/"+bucket+"/force-"+failure, "", map[string]string{xhttp.MinIOForceDelete: "true"})
					setObjectLayer(previous)
					globalBucketMetadataSys.Set(bucket, saved)
					allowed := failure == "cache-miss" && !locked
					if allowed {
						if rec.Code != http.StatusNoContent || f.deleteCalls != 1 {
							t.Fatalf("%s missing unlocked cache: %d calls=%d %s", backend, rec.Code, f.deleteCalls, rec.Body.String())
						}
					} else {
						if rec.Code < 400 || f.deleteCalls != 0 {
							t.Fatalf("%s %s: force-delete proceeded: %d calls=%d %s", backend, failure, rec.Code, f.deleteCalls, rec.Body.String())
						}
						if _, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{}); err != nil {
							t.Fatalf("rejected force-delete lost data: %v", err)
						}
					}
				}
			}})
		})
	}
}

func TestAPILocalCopyTagTimestampAdvances(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
		stamp := UTCNow().Add(48 * time.Hour)
		meta := map[string]string{r5TagStamp: stamp.Format(time.RFC3339Nano), xhttp.AmzObjectTagging: "key=old"}
		_, err := obj.PutObject(t.Context(), bucket, "local-copy", mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{UserDefined: maps.Clone(meta)})
		if err != nil {
			t.Fatal(err)
		}
		rec := r5Request(t, router, cred, http.MethodPut, "/"+bucket+"/local-copy", "", map[string]string{xhttp.AmzCopySource: "/" + bucket + "/local-copy", xhttp.AmzMetadataDirective: replaceDirective, xhttp.AmzTagDirective: replaceDirective})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s copy: %d %s", backend, rec.Code, rec.Body.String())
		}
		r5Stored(t, obj, bucket, "local-copy", "", "", stamp.Add(time.Nanosecond).Format(time.RFC3339Nano))
	}})
}
