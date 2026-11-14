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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

// TestAPICopyObjectReplicaTaggingTimestampUnderKMS covers signed replica COPY
// requests through encryption, metadata replacement and disk persistence. Both
// the single-disk and 16-disk fixtures are single-pool backends.
func TestAPICopyObjectReplicaTaggingTimestampUnderKMS(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t, objAPITest: testAPICopyObjectReplicaTaggingTimestampUnderKMS,
		// Ignore host free-space percentage while retaining real disk I/O.
		// Install once before IAM starts and keep the disks until shutdown.
		wrapDisk: func(disk StorageAPI) StorageAPI { return tagTestCapacityDisk{StorageAPI: disk} },
	})
}

func testAPICopyObjectReplicaTaggingTimestampUnderKMS(obj ObjectLayer, instance, bucket string, router http.Handler, creds auth.Credentials, t *testing.T) {
	oldKMS, oldAuto := GlobalKMS, globalAutoEncryption
	GlobalKMS = kms.NewStub("replica-tags-key")
	globalAutoEncryption = false
	defer func() { GlobalKMS, globalAutoEncryption = oldKMS, oldAuto }()
	if _, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig); err != nil {
		t.Fatal(err)
	}
	const tsKey = ReservedMetadataPrefixLower + TaggingTimestamp
	stamp := time.Date(2026, 9, 15, 1, 0, 0, 123456789, time.UTC)
	for _, mode := range []string{"none", "explicit-sse-s3", "explicit-kms", "auto-kms", "bucket-kms"} {
		t.Run(instance+"/"+mode, func(t *testing.T) {
			globalAutoEncryption = mode == "auto-kms"
			if mode == "bucket-kms" {
				sseXML := []byte(`<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>replica-tags-key</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)
				if _, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketSSEConfig, sseXML); err != nil {
					t.Fatal(err)
				}
			}
			const data = "encrypted replica copy remains readable"
			oi, err := obj.PutObject(t.Context(), bucket, mode, mustGetPutObjReader(t, bytes.NewReader([]byte(data)), int64(len(data)), "", ""), ObjectOptions{
				Versioned: true, UserDefined: map[string]string{xhttp.AmzObjectTagging: "key=old", tsKey: stamp.Format(time.RFC3339Nano)},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range []struct {
				name, tags, wantTags string
				delta, wantDelta     time.Duration
				missingTimestamp     bool
			}{
				{"newer", "key=new", "key=new", 2, 2, false},
				{"stale", "key=stale", "key=new", 1, 2, false},
				{"duplicate", "key=new", "key=new", 2, 2, false},
				{"newer-again", "key=latest", "key=latest", 3, 3, false},
				{"missing-timestamp", "key=unordered", "key=latest", 0, 3, true},
			} {
				headers := map[string]string{
					xhttp.AmzCopySource:        "/" + bucket + "/" + mode + "?versionId=" + oi.VersionID,
					xhttp.AmzMetadataDirective: "REPLACE", xhttp.AmzTagDirective: "REPLACE",
					xhttp.AmzObjectTagging: event.tags, xhttp.MinIOSourceReplicationRequest: "true",
					xhttp.AmzBucketReplicationStatus: "REPLICA", xhttp.MinIOSourceTaggingTimestamp: stamp.Add(event.delta).Format(time.RFC3339Nano),
					xhttp.MinIOSourceMTime: oi.ModTime.Format(time.RFC3339Nano), xhttp.MinIOSourceETag: oi.ETag,
				}
				if event.missingTimestamp {
					delete(headers, xhttp.MinIOSourceTaggingTimestamp)
				}
				if mode == "explicit-sse-s3" {
					headers[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionAES
				}
				if mode == "explicit-kms" {
					headers[xhttp.AmzServerSideEncryption] = "aws:kms"
					headers[xhttp.AmzServerSideEncryptionKmsID] = "replica-tags-key"
				}
				req, err := newTestSignedRequestV4(http.MethodPut, "/"+bucket+"/"+mode+"?versionId="+oi.VersionID, 0, nil, creds.AccessKey, creds.SecretKey, headers)
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("%s: COPY %d %s", event.name, w.Code, w.Body.String())
				}
				got, err := obj.GetObjectInfo(t.Context(), bucket, mode, ObjectOptions{VersionID: oi.VersionID})
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%s: tags=%q timestamp=%q kms=%v", event.name, got.UserTags, got.UserDefined[tsKey], crypto.S3KMS.IsEncrypted(got.UserDefined))
				if got.UserTags != event.wantTags || got.UserDefined[tsKey] != stamp.Add(event.wantDelta).Format(time.RFC3339Nano) {
					t.Errorf("%s: incorrect persisted tags/timestamp", event.name)
				}
				wantKMS := mode == "explicit-kms" || mode == "auto-kms" || mode == "bucket-kms"
				if crypto.S3KMS.IsEncrypted(got.UserDefined) != wantKMS || crypto.S3.IsEncrypted(got.UserDefined) != (mode == "explicit-sse-s3") {
					t.Errorf("%s: unexpected destination encryption", event.name)
				}
				if got.VersionID != oi.VersionID {
					t.Errorf("%s: version=%q, want %q", event.name, got.VersionID, oi.VersionID)
				}
				req, err = newTestSignedRequestV4(http.MethodGet, "/"+bucket+"/"+mode+"?versionId="+oi.VersionID, 0, nil, creds.AccessKey, creds.SecretKey, nil)
				if err != nil {
					t.Fatal(err)
				}
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != http.StatusOK || w.Body.String() != data {
					t.Fatalf("%s: GET %d %q", event.name, w.Code, w.Body.String())
				}
			}
		})
	}
}
