// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

// A suspended destination does not keep a source version ID. Authorization
// must therefore describe the null destination version that the write really
// replaces, and must not let a source ID escape that model.
func TestBatchReviewPullSuspendedVersionBinding(t *testing.T) {
	f := newBatchAuthzFixture(t)
	_, err := globalBucketMetadataSys.Update(f.ctx, f.bucket, bucketVersioningConfig, []byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Suspended</Status></VersioningConfiguration>`))
	mustIAM(t, err)

	sourceVersion := mustGetUUID()
	batchAuthzPolicy(f.ctx, t, f.sys, "pull-source-version-deny", batchAuthzFullAccess+fmt.Sprintf(`,
{"Effect":"Deny","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"StringEquals":{"s3:versionid":"%s"}}}`, sourceVersion))
	cred := iamAdminUser(f.ctx, t, f.sys, "pull-source-version-user", "pull-source-version-deny")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	job := BatchJobReplicateV1{
		Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: "remote"},
		Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: f.bucket},
	}
	err = job.ReplicateFromSource(f.ctx, f.obj, batchLockRemote(t, "replacement"), ObjectInfo{
		Name: "pull/suspended-version", VersionID: sourceVersion, ModTime: UTCNow(), ETag: "batchetag",
		UserDefined: map[string]string{},
	}, false, sub)
	if !isBatchJobAuthzError(err) {
		t.Fatalf("a source version ID must not evade the destination deny: %v", err)
	}
	if _, gerr := f.obj.GetObjectInfo(f.ctx, f.bucket, "pull/suspended-version", ObjectOptions{VersionID: sourceVersion}); gerr == nil {
		t.Fatal("a denied suspended-destination write created the source version")
	}
}

// A failed source open in a non-skipping snowball must be reported to the
// batch rather than silently omitted from a successful archive.
type batchReviewOpenFailure struct {
	ObjectLayer
	name string
}

func (a batchReviewOpenFailure) GetObjectNInfo(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, opts ObjectOptions) (*GetObjectReader, error) {
	if object == a.name {
		return nil, fmt.Errorf("test: source open failed")
	}
	return a.ObjectLayer.GetObjectNInfo(ctx, bucket, object, rs, h, opts)
}

func TestBatchReviewSnowballSourceOpenFailure(t *testing.T) {
	f := newBatchAuthzFixture(t)
	name := "archive/open-failure"
	entry := batchPutVersion(t, f.obj, f.bucket, name, nil)
	remote, err := minio.New("archive.invalid", &minio.Options{
		Region: "us-east-1", Creds: credentials.NewStaticV4("test-access", "test-secret", ""),
		Transport: batchLockTransport(func(r *http.Request) (*http.Response, error) {
			if r.Body != nil {
				_, _ = io.Copy(io.Discard, r.Body)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}),
	})
	mustIAM(t, err)
	r := BatchJobReplicateV1{
		Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: f.bucket},
		Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: "remote"},
	}
	r.Source.Snowball.InMemory = ptr(true)
	r.Source.Snowball.Compress = ptr(false)
	r.Source.Snowball.SkipErrs = ptr(false)
	api := batchReviewOpenFailure{ObjectLayer: f.obj, name: name}
	if err := r.writeAsArchive(t.Context(), api, remote, []ObjectInfo{entry}, "", batchRootSubmitter(t)); err == nil {
		t.Fatal("a source open failure must not be reported as a successful archive")
	}
}

// Rotation must apply tag conditions to the logical version, including
// a more recent tag update stored in a pool other than the selected copy.
func TestBatchReviewRotationAuthoritativeTags(t *testing.T) {
	z, bucket := consistencyPools(t)
	f := newBatchAuthzFixture(t)
	previousKMS := GlobalKMS
	GlobalKMS = kms.NewStub("batch-round5-rotation-key")
	t.Cleanup(func() { GlobalKMS = previousKMS })
	batchAuthzPolicy(f.ctx, t, f.sys, "round5-rotation-tags", fmt.Sprintf(`
{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:PutObject"],"Resource":["arn:aws:s3:::%s/*"]},
{"Effect":"Deny","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::%s/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/classification":"private"}}}`, bucket, bucket))
	cred := iamAdminUser(f.ctx, t, f.sys, "round5-rotation-user", "round5-rotation-tags")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	for _, classification := range []string{"private", "public"} {
		t.Run(classification, func(t *testing.T) {
			name := "rotation/authoritative-" + classification
			first := make(map[string]string)
			key, err := newEncryptMetadata(f.ctx, crypto.S3, "", nil, bucket, name, first, nil)
			mustIAM(t, err)
			first[xhttp.AmzObjectTagging] = "classification=public"
			first[ReservedMetadataPrefixLower+TaggingTimestamp] = UTCNow().Add(-time.Hour).Format(time.RFC3339Nano)
			second := maps.Clone(first)
			second[xhttp.AmzObjectTagging] = "classification=" + classification
			second[ReservedMetadataPrefixLower+TaggingTimestamp] = UTCNow().Format(time.RFC3339Nano)
			ciphertext, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader("test encrypted payload"), key))
			mustIAM(t, err)
			before := putConsistencyObject(t, z, bucket, name, 0, string(ciphertext), ObjectOptions{Versioned: true, UserDefined: first})
			putConsistencyObject(t, z, bucket, name, 1, string(ciphertext), ObjectOptions{Versioned: true, VersionID: before.VersionID, MTime: before.ModTime, UserDefined: second})
			logical, err := z.replicaObjectInfo(f.ctx, bucket, name, ObjectOptions{VersionID: before.VersionID})
			mustIAM(t, err)
			if logical.UserTags != "classification="+classification {
				t.Fatal("control: the second pool must govern the logical tags")
			}
			job := BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: sses3}}
			err = job.KeyRotate(f.ctx, z, before, sub)
			after, readErr := z.serverPools[0].GetObjectInfo(f.ctx, bucket, name, ObjectOptions{VersionID: before.VersionID})
			mustIAM(t, readErr)
			changed := after.UserDefined[crypto.MetaSealedKeyS3] != before.UserDefined[crypto.MetaSealedKeyS3]
			if classification == "private" {
				if !isBatchJobAuthzError(err) || changed {
					t.Fatalf("authoritative tag deny must prevent rewrapping: err=%v changed=%v", err, changed)
				}
			} else if err != nil || !changed {
				t.Fatalf("authorized unlocked version must rotate: err=%v changed=%v", err, changed)
			}
		})
	}
}
