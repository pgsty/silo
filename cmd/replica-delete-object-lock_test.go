// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/amztime"
	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
)

// replicaDeleteRequest sends DELETE ?versionId= as site replication does.
func replicaDeleteRequest(t *testing.T, router http.Handler, cred auth.Credentials, bucket, key, versionID string, marker bool) *httptest.ResponseRecorder {
	t.Helper()
	target := getDeleteObjectURL("", bucket, key) + "?" + url.Values{xhttp.VersionID: {versionID}}.Encode()
	req, err := newTestSignedRequestV4(http.MethodDelete, target, 0, nil, cred.AccessKey, cred.SecretKey, map[string]string{
		xhttp.MinIOSourceReplicationRequest: "true",
		xhttp.AmzBucketReplicationStatus:    "REPLICA",
		xhttp.MinIOSourceDeleteMarker:       strconv.FormatBool(marker),
		xhttp.MinIOSourceMTime:              UTCNow().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func replicaDeleteMarkerExists(t *testing.T, obj ObjectLayer, bucket, key, versionID string) bool {
	t.Helper()
	oi, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: versionID})
	return oi.DeleteMarker && (err == nil || isErrMethodNotAllowed(err))
}

// A replicated delete leaves a destination version under Object Lock as it
// is, whether it purges that version or names it in a delete marker. The
// replication credential is not a retention bypass on the destination.
func TestReplicaDeleteObjectLock(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, endpoints: []string{"DeleteObject"},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			enableBucketObjectLock(t, bucket)
			for _, kind := range batchLockKinds {
				for _, marker := range []bool{false, true} {
					key := "locked/" + kind + "/marker=" + strconv.FormatBool(marker)
					before := batchPutVersion(t, obj, bucket, key, batchLockMeta(kind))
					rec := replicaDeleteRequest(t, router, cred, bucket, key, before.VersionID, marker)
					if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "WORM") {
						t.Errorf("%s: %s: status %d, want 400 WORM: %s", instance, key, rec.Code, rec.Body.String())
					}
					after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: before.VersionID})
					if err != nil || after.DeleteMarker || after.ETag != before.ETag {
						t.Errorf("%s: %s: locked version was removed or replaced: %v", instance, key, err)
					}
				}
			}

			// Controls: replication still purges unprotected versions and
			// writes new delete markers, also beside a locked version.
			expired := batchLockMeta("GOVERNANCE")
			expired[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = amztime.ISO8601Format(UTCNow().Add(-time.Hour))
			for name, meta := range map[string]map[string]string{"unlocked": nil, "expired": expired} {
				key := "purge/" + name
				v := batchPutVersion(t, obj, bucket, key, meta)
				if rec := replicaDeleteRequest(t, router, cred, bucket, key, v.VersionID, false); rec.Code != http.StatusNoContent {
					t.Errorf("%s: %s: status %d, want 204: %s", instance, key, rec.Code, rec.Body.String())
				}
				if batchVersionExists(t, obj, bucket, key, v.VersionID) {
					t.Errorf("%s: %s: version survived the replicated purge", instance, key)
				}
			}

			const key = "marker/new"
			locked := batchPutVersion(t, obj, bucket, key, batchLockMeta("COMPLIANCE"))
			marker := mustGetUUID()
			if rec := replicaDeleteRequest(t, router, cred, bucket, key, marker, true); rec.Code != http.StatusNoContent {
				t.Errorf("%s: new marker: status %d, want 204: %s", instance, rec.Code, rec.Body.String())
			}
			if !replicaDeleteMarkerExists(t, obj, bucket, key, marker) {
				t.Errorf("%s: the replicated delete marker was not written", instance)
			}
			if !batchVersionExists(t, obj, bucket, key, locked.VersionID) {
				t.Errorf("%s: a new marker removed a locked version", instance)
			}
		},
	})
}

// With more than one pool, the protected version may be in a pool other than
// the one that holds the latest version and takes the delete marker.
func TestPoolsReplicaDeleteObjectLock(t *testing.T) {
	z, _ := consistencyPools(t)
	bucket, router, err := initAPIHandlerTest(t.Context(), z, nil, MakeBucketOptions{VersioningEnabled: true, LockEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for pool := range z.serverPools {
		for _, marker := range []bool{false, true} {
			key := "pool-" + strconv.Itoa(pool) + "/marker=" + strconv.FormatBool(marker)
			before := putConsistencyObject(t, z, bucket, key, pool, "locked",
				ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour), UserDefined: batchLockMeta("COMPLIANCE")})
			putConsistencyObject(t, z, bucket, key, 1-pool, "newer", ObjectOptions{Versioned: true, MTime: UTCNow()})
			rec := replicaDeleteRequest(t, router, globalActiveCred, bucket, key, before.VersionID, marker)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status %d, want 400: %s", key, rec.Code, rec.Body.String())
			}
			// The logical lookup also finds a marker written with this ID in
			// the other pool, which would shadow the protected version.
			after, gerr := z.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: before.VersionID})
			if gerr != nil || after.DeleteMarker || after.ETag != before.ETag {
				t.Errorf("%s: locked version was removed, replaced or shadowed: %v", key, gerr)
			}
		}
	}
}
