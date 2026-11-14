// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

// Rotation and listing cases found in review.

// Rotation rewrites the copy GetObjectInfo returns, which can carry another
// tag revision than the merged version of all pools: both are authorized.
func TestBatchReviewRotationAuthorizesWrittenCopy(t *testing.T) {
	z, bucket := consistencyPools(t)
	f := newBatchAuthzFixture(t)
	previousKMS := GlobalKMS
	GlobalKMS = kms.NewStub("review6-rotation-copy-key")
	t.Cleanup(func() { GlobalKMS = previousKMS })
	batchAuthzPolicy(f.ctx, t, f.sys, "review6-rotation-copy-deny", fmt.Sprintf(`
{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:PutObject"],"Resource":["arn:aws:s3:::%s/*"]},
{"Effect":"Deny","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::%s/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/classification":"private"}}}`, bucket, bucket))
	cred := iamAdminUser(f.ctx, t, f.sys, "review6-rotation-copy-user", "review6-rotation-copy-deny")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	const name = "rotation/written-copy"
	first := make(map[string]string)
	key, err := newEncryptMetadata(f.ctx, crypto.S3, "", nil, bucket, name, first, nil)
	mustIAM(t, err)
	first[xhttp.AmzObjectTagging] = "classification=private"
	first[ReservedMetadataPrefixLower+TaggingTimestamp] = UTCNow().Add(-time.Hour).Format(time.RFC3339Nano)
	second := maps.Clone(first)
	second[xhttp.AmzObjectTagging] = "classification=public"
	second[ReservedMetadataPrefixLower+TaggingTimestamp] = UTCNow().Format(time.RFC3339Nano)
	ciphertext, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader("review6 rotation payload"), key))
	mustIAM(t, err)
	before := putConsistencyObject(t, z, bucket, name, 0, string(ciphertext), ObjectOptions{Versioned: true, UserDefined: first})
	putConsistencyObject(t, z, bucket, name, 1, string(ciphertext), ObjectOptions{Versioned: true, VersionID: before.VersionID, MTime: before.ModTime, UserDefined: second})
	logical, err := z.replicaObjectInfo(f.ctx, bucket, name, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, err)
	if logical.UserTags != "classification=public" {
		t.Fatalf("control: merged tags=%q, want public", logical.UserTags)
	}
	job := BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: sses3}}
	if err = job.KeyRotate(f.ctx, z, before, sub); !isBatchJobAuthzError(err) {
		t.Fatalf("rotation of a copy the submitter may not read returned %v", err)
	}
	after, err := z.serverPools[0].GetObjectInfo(f.ctx, bucket, name, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, err)
	if after.UserDefined[crypto.MetaSealedKeyS3] != before.UserDefined[crypto.MetaSealedKeyS3] {
		t.Fatal("a refused rotation rewrote the copy")
	}
}

// batchWalkError fails every listing before it returns a result.
type batchWalkError struct {
	ObjectLayer
	err error
}

func (w batchWalkError) Walk(context.Context, string, string, chan<- itemOrErr[ObjectInfo], WalkOptions) error {
	return w.err
}

// A listing outage pauses the run, as a streamed listing error does.
func TestBatchReviewExpireWalkErrorPausesRun(t *testing.T) {
	f := newBatchAuthzFixture(t)
	rec, job := f.submit(t, globalActiveCred, f.expireYAML("data/"))
	if job == nil {
		t.Fatalf("submission status %d: %s", rec.Code, rec.Body.String())
	}
	listErr := errors.New("review6: listing failed")
	if err := job.Expire.Start(f.ctx, batchWalkError{ObjectLayer: f.obj, err: listErr}, *job); !errors.Is(err, listErr) {
		t.Fatalf("start returned %v, want %v", err, listErr)
	}
	if ri := f.jobInfo(t, job); ri.Failed || ri.Complete || ri.PausedReason == "" {
		t.Fatalf("failed listing: complete=%v failed=%v", ri.Complete, ri.Failed)
	}
}

// Two pools hold different writes of the null version, and a newer version
// of the key is in the second one. Rotation rewrites the copy it read and
// authorized, in the first pool, not the copy the latest version of the key
// would route a write to; the other write keeps its key and stays readable.
func TestBatchReviewRotationRewritesTheCopyItRead(t *testing.T) {
	for _, otherLatest := range []bool{false, true} {
		name := "addressed-version-is-latest"
		if otherLatest {
			name = "another-version-is-latest"
		}
		t.Run(name, func(t *testing.T) {
			resetTestGlobals()
			t.Cleanup(resetTestGlobals)
			z, _ := consistencyPools(t)
			globalIAMSys.initStore(z, nil)
			mustIAM(t, globalIAMSys.Load(t.Context(), true))
			const bucket = "review7-rotation-copies"
			mustIAM(t, z.MakeBucket(t.Context(), bucket, MakeBucketOptions{VersioningEnabled: true}))
			_, versionErr := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
			mustIAM(t, versionErr)
			oldKMS := GlobalKMS
			GlobalKMS = kms.NewStub("review7-rotation-key")
			t.Cleanup(func() { GlobalKMS = oldKMS })
			const object = "rotation/null-copy"
			const payload = "rotation must preserve this data"
			readCopy := func(pool int) ([]byte, error) {
				gr, err := z.serverPools[pool].GetObjectNInfo(t.Context(), bucket, object, nil, nil, ObjectOptions{VersionID: nullVersionID})
				if err != nil {
					return nil, err
				}
				defer gr.Close()
				return io.ReadAll(gr)
			}
			var before [2]ObjectInfo
			var keys [2]crypto.ObjectKey
			kinds := []crypto.Type{crypto.S3, crypto.S3KMS}
			for pool, kind := range kinds {
				meta := make(map[string]string)
				key, err := newEncryptMetadata(t.Context(), kind, "review7-rotation-key", nil, bucket, object, meta, nil)
				mustIAM(t, err)
				keys[pool] = key
				meta[xhttp.AmzObjectTagging] = "classification=public"
				if pool == 1 {
					meta[xhttp.AmzObjectTagging] = "classification=private"
				}
				meta[ReservedMetadataPrefixLower+TaggingTimestamp] = UTCNow().Add(-time.Duration(pool+2) * time.Hour).Format(time.RFC3339Nano)
				body, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader(payload), key))
				mustIAM(t, err)
				putConsistencyObject(t, z, bucket, object, pool, string(body), ObjectOptions{
					Versioned: true, VersionID: nullVersionID, UserDefined: meta,
					MTime: UTCNow().Add(-time.Duration(pool+2) * time.Hour),
				})
				// As a read returns it, without the write's internal fields.
				before[pool], err = z.serverPools[pool].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: nullVersionID})
				mustIAM(t, err)
				data, err := readCopy(pool)
				if err != nil || string(data) != payload {
					t.Fatalf("control: pool %d was not readable before rotation: %v", pool, err)
				}
			}
			if otherLatest {
				putConsistencyObject(t, z, bucket, object, 1, "later version", ObjectOptions{Versioned: true, MTime: UTCNow().Add(-time.Hour)})
			}
			selected, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: nullVersionID, Versioned: true})
			mustIAM(t, err)
			if selected.VersionID != nullVersionID || !selected.ModTime.Equal(before[0].ModTime) || !crypto.S3.IsEncrypted(selected.UserDefined) {
				t.Fatal("control: the addressed null version must select the SSE-S3 write in pool zero")
			}
			logical, err := batchAuthoritativeVersion(t.Context(), z, bucket, object, selected)
			mustIAM(t, err)
			if logical.UserTags != "classification=public" || selected.UserTags != logical.UserTags {
				t.Fatal("control: both current authorization inputs must have public tags")
			}
			r := BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: ssekms, Key: "review7-rotation-key"}}
			sub := batchRootSubmitter(t)
			if otherLatest {
				batchAuthzPolicy(t.Context(), t, globalIAMSys, "review7-rotate-public", fmt.Sprintf(`
{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:PutObject"],"Resource":["arn:aws:s3:::%s/*"]},
{"Effect":"Deny","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::%s/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/classification":"private"}}}`, bucket, bucket))
				cred := iamAdminUser(t.Context(), t, globalIAMSys, "review7-rotate-user", "review7-rotate-public")
				sub, err = newBatchJobSubmitter(cred)
				mustIAM(t, err)
				if err := sub.authorize(t.Context(), r.rotateAuthzRequests(before[1])...); !isBatchJobAuthzError(err) {
					t.Fatal("control: the older write in pool one must be denied")
				}
			}
			err = r.KeyRotate(t.Context(), z, selected, sub)
			if err != nil {
				t.Logf("rotation refused: %v", err)
			}
			for pool, want := range keys {
				after, readErr := z.serverPools[pool].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: nullVersionID})
				mustIAM(t, readErr)
				if otherLatest && pool == 1 && (!maps.Equal(after.UserDefined, before[pool].UserDefined) || !after.ModTime.Equal(before[pool].ModTime) || after.UserTags != before[pool].UserTags) {
					t.Error("rotation rewrote a copy denied by the submitter's tag-conditioned policy")
				}
				kind, _ := crypto.IsEncrypted(after.UserDefined)
				var got crypto.ObjectKey
				switch kind {
				case crypto.S3:
					got, readErr = crypto.S3.UnsealObjectKey(GlobalKMS, after.UserDefined, bucket, object)
				case crypto.S3KMS:
					got, readErr = crypto.S3KMS.UnsealObjectKey(GlobalKMS, after.UserDefined, bucket, object)
				default:
					t.Fatalf("pool %d: rotation lost encryption metadata", pool)
				}
				mustIAM(t, readErr)
				if got != want {
					t.Errorf("pool %d: rotation changed the data key without reencrypting its ciphertext (rotation error: %v)", pool, err)
				}
				data, readErr := readCopy(pool)
				if readErr != nil || string(data) != payload {
					t.Errorf("pool %d: rotation left unreadable ciphertext: %v", pool, readErr)
				}
			}
		})
	}
}

// A version in a pool that a decommission or a rebalance is moving is not
// rewritten there: only the source holds it, so the rotation is left to a
// later run.
func TestBatchReviewRotationLeavesMovingSource(t *testing.T) {
	resetTestGlobals()
	t.Cleanup(resetTestGlobals)
	z, _ := consistencyPools(t)
	globalIAMSys.initStore(z, nil)
	mustIAM(t, globalIAMSys.Load(t.Context(), true))
	const bucket = "review8-rotation-draining"
	mustIAM(t, z.MakeBucket(t.Context(), bucket, MakeBucketOptions{VersioningEnabled: true}))
	_, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
	mustIAM(t, err)
	oldKMS := GlobalKMS
	GlobalKMS = kms.NewStub("review8-rotation-key")
	t.Cleanup(func() { GlobalKMS = oldKMS })
	const object = "rotation/draining"
	meta := make(map[string]string)
	key, err := newEncryptMetadata(t.Context(), crypto.S3, "review8-rotation-key", nil, bucket, object, meta, nil)
	mustIAM(t, err)
	body, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader("draining rotation"), key))
	mustIAM(t, err)
	before := putConsistencyObject(t, z, bucket, object, 0, string(body), ObjectOptions{Versioned: true, UserDefined: meta, MTime: UTCNow().Add(-time.Hour)})
	beforeInfo, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, err)

	z.poolMetaMutex.Lock()
	z.poolMeta.Pools[0].Decommission = &PoolDecommissionInfo{}
	z.poolMetaMutex.Unlock()

	r := BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: ssekms, Key: "review8-rotation-key"}}
	err = r.KeyRotate(t.Context(), z, beforeInfo, batchRootSubmitter(t))
	if !errors.Is(err, errBatchRotateMoving) {
		t.Errorf("rotation of a version only a draining pool holds returned %v", err)
	}
	after, readErr := z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, readErr)
	if after.UserDefined[crypto.MetaSealedKeyS3] != beforeInfo.UserDefined[crypto.MetaSealedKeyS3] {
		t.Fatal("rotation rewrote a draining pool")
	}
	// The job pauses and resumes in-process once the selected pool stops moving.
	job := BatchJobRequest{ID: "rotation-moving-resume", Started: UTCNow(), Submitter: batchRootSubmitter(t), KeyRotate: &r}
	batchTestJobPool(t.Context(), t, z)
	if err := r.Start(t.Context(), z, job); !isBatchJobUnavailable(err) {
		t.Fatalf("moving job did not pause: %v", err)
	}
	ri := &batchJobInfo{}
	mustIAM(t, ri.load(t.Context(), z, job))
	if ri.PausedReason == "" || ri.Failed || ri.Complete || ri.Object != "" || ri.ObjectsFailed != 0 {
		t.Fatalf("moving job report: %+v", ri)
	}
	z.poolMetaMutex.Lock()
	z.poolMeta.Pools[0].Decommission = nil
	z.poolMetaMutex.Unlock()
	mustIAM(t, r.Start(t.Context(), z, job))
	mustIAM(t, ri.load(t.Context(), z, job))
	if !ri.Complete || ri.Failed || ri.PausedReason != "" || ri.Objects != 1 {
		t.Fatalf("resumed rotation: %+v", ri)
	}
}

// Once a move copied a version, the rotation leaves it to a later run, so the
// source stays as the move's cleanup expects it.
func TestBatchReviewRotationKeepsMigrationCleanup(t *testing.T) {
	for _, tc := range []struct {
		kind   string
		rotate bool
	}{{"decommission", false}, {"decommission", true}, {"rebalance", false}, {"rebalance", true}} {
		name := tc.kind + "/without-rotation"
		if tc.rotate {
			name = tc.kind + "/with-rotation"
		}
		t.Run(name, func(t *testing.T) {
			resetTestGlobals()
			t.Cleanup(resetTestGlobals)
			z, _ := migrationTestPools(t)
			globalIAMSys.initStore(z, nil)
			mustIAM(t, globalIAMSys.Load(t.Context(), true))
			const bucket = "review8-rotation-migration"
			mustIAM(t, z.MakeBucket(t.Context(), bucket, MakeBucketOptions{VersioningEnabled: true}))
			_, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
			mustIAM(t, err)
			oldKMS := GlobalKMS
			GlobalKMS = kms.NewStub("review8-rotation-key")
			t.Cleanup(func() { GlobalKMS = oldKMS })
			const object = "rotation/migration"
			meta := make(map[string]string)
			key, err := newEncryptMetadata(t.Context(), crypto.S3, "", nil, bucket, object, meta, nil)
			mustIAM(t, err)
			body, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader("rotation and migration"), key))
			mustIAM(t, err)
			before := putConsistencyObject(t, z, bucket, object, 0, string(body), ObjectOptions{Versioned: true, UserDefined: meta, MTime: UTCNow().Add(-time.Hour)})
			beforeInfo, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
			mustIAM(t, err)
			move := migrationTestMover(t, z, 0, tc.kind)
			mustIAM(t, move(t.Context(), 0, bucket, migrationTestReader(t, z, 0, beforeInfo)))
			if _, err := z.serverPools[1].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID}); err != nil {
				t.Fatalf("control: migration did not copy the version: %v", err)
			}
			r := BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: ssekms, Key: "review8-rotation-key"}}
			var rotationErr error
			if tc.rotate {
				moved, err := z.serverPools[1].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
				mustIAM(t, err)
				rotationErr = r.KeyRotate(t.Context(), z, beforeInfo, batchRootSubmitter(t))
				if !errors.Is(rotationErr, errBatchRotateMoving) {
					t.Errorf("rotation during a move returned %v", rotationErr)
				}
				after, err := z.serverPools[1].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
				mustIAM(t, err)
				if !maps.Equal(after.UserDefined, moved.UserDefined) || after.UserTags != moved.UserTags {
					t.Error("rotation during a move rewrote the moved copy")
				}
			}
			after, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
			mustIAM(t, err)
			if !after.ModTime.Equal(beforeInfo.ModTime) || !maps.Equal(after.UserDefined, beforeInfo.UserDefined) {
				t.Errorf("rotation changed a draining source after its version was copied (rotation error: %v)", rotationErr)
			}
			snapshot := []FileInfo{{VersionID: before.VersionID, ModTime: beforeInfo.ModTime}}
			if _, err := z.removeMovedVersions(t.Context(), bucket, object, 0, snapshot, nil); err != nil {
				t.Fatalf("rotation prevented migration cleanup: %v", err)
			}
			if _, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID}); !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
				t.Fatalf("migration left a source version behind: %v", err)
			}
		})
	}
}

// The rewrite keeps the tags and the expiry of the version, which a read
// returns apart from its metadata.
func TestBatchReviewRotationKeepsTagsAndExpiry(t *testing.T) {
	for _, mode := range []string{"single-pool", "multiple-pools"} {
		t.Run(mode, func(t *testing.T) {
			resetTestGlobals()
			t.Cleanup(resetTestGlobals)
			var z *erasureServerPools
			if mode == "single-pool" {
				z = purgeSinglePool(t, 4)
			} else {
				z, _ = consistencyPools(t)
			}
			globalIAMSys.initStore(z, nil)
			mustIAM(t, globalIAMSys.Load(t.Context(), true))
			const bucket = "review8-rotation-metadata"
			mustIAM(t, z.MakeBucket(t.Context(), bucket, MakeBucketOptions{VersioningEnabled: true}))
			_, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
			mustIAM(t, err)
			oldKMS := GlobalKMS
			GlobalKMS = kms.NewStub("review8-rotation-metadata-key")
			t.Cleanup(func() { GlobalKMS = oldKMS })
			const object = "rotation/tagged"
			meta := make(map[string]string)
			key, err := newEncryptMetadata(t.Context(), crypto.S3, "", nil, bucket, object, meta, nil)
			mustIAM(t, err)
			meta[xhttp.AmzObjectTagging] = "classification=private"
			meta[ReservedMetadataPrefixLower+TaggingTimestamp] = UTCNow().Add(-time.Minute).Format(time.RFC3339Nano)
			meta["expires"] = UTCNow().Add(time.Hour).Format(http.TimeFormat)
			body, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader("metadata preservation"), key))
			mustIAM(t, err)
			written := putConsistencyObject(t, z, bucket, object, 0, string(body), ObjectOptions{Versioned: true, UserDefined: meta})
			before, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: written.VersionID})
			mustIAM(t, err)
			if before.UserTags == "" || before.Expires.IsZero() {
				t.Fatal("control: stored version is missing the metadata to preserve")
			}
			r := BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: sses3}}
			mustIAM(t, r.KeyRotate(t.Context(), z, before, batchRootSubmitter(t)))
			after, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
			mustIAM(t, err)
			if after.UserDefined[crypto.MetaSealedKeyS3] == before.UserDefined[crypto.MetaSealedKeyS3] {
				t.Error("control: rotation did not rewrap the key")
			}
			if after.UserTags != before.UserTags {
				t.Errorf("rotation changed stored tags: got %q, want %q", after.UserTags, before.UserTags)
			}
			if !after.Expires.Equal(before.Expires) {
				t.Errorf("rotation changed Expires: got %v, want %v", after.Expires, before.Expires)
			}
		})
	}
}

// Two pools hold the same write with different tags, with or without
// tagging timestamps. A rotation, also during a move, leaves the tags that
// the merged version has.
func TestBatchReviewRotationKeepsMergedTags(t *testing.T) {
	for _, tc := range []struct {
		ordered, moving bool
	}{{false, false}, {false, true}, {true, false}, {true, true}} {
		t.Run(fmt.Sprintf("timestamp=%t/moving=%t", tc.ordered, tc.moving), func(t *testing.T) {
			resetTestGlobals()
			t.Cleanup(resetTestGlobals)
			z, _ := consistencyPools(t)
			globalIAMSys.initStore(z, nil)
			mustIAM(t, globalIAMSys.Load(t.Context(), true))
			const bucket = "review9-rotation-tag-tie"
			const object = "rotation/tag-tie"
			mustIAM(t, z.MakeBucket(t.Context(), bucket, MakeBucketOptions{VersioningEnabled: true}))
			_, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
			mustIAM(t, err)
			previousKMS := GlobalKMS
			GlobalKMS = kms.NewStub("review9-tag-tie-key")
			t.Cleanup(func() { GlobalKMS = previousKMS })
			meta := make(map[string]string)
			key, err := newEncryptMetadata(t.Context(), crypto.S3, "", nil, bucket, object, meta, nil)
			mustIAM(t, err)
			meta[xhttp.AmzObjectTagging] = "classification=private"
			if tc.ordered {
				meta[ReservedMetadataPrefixLower+TaggingTimestamp] = UTCNow().Add(-time.Minute).Format(time.RFC3339Nano)
			}
			other := maps.Clone(meta)
			other[xhttp.AmzObjectTagging] = "classification=public"
			body, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader("same write"), key))
			mustIAM(t, err)
			before := putConsistencyObject(t, z, bucket, object, 0, string(body), ObjectOptions{Versioned: true, UserDefined: meta, MTime: UTCNow().Add(-time.Hour)})
			putConsistencyObject(t, z, bucket, object, 1, string(body), ObjectOptions{Versioned: true, VersionID: before.VersionID, MTime: before.ModTime, UserDefined: other})
			prior, err := z.replicaObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
			mustIAM(t, err)
			if prior.UserTags != "classification=private" {
				t.Fatalf("control: logical tags=%q", prior.UserTags)
			}
			if tc.moving {
				migrationTestMover(t, z, 0, "decommission")
			}
			r := BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: sses3}}
			rotationErr := r.KeyRotate(t.Context(), z, before, batchRootSubmitter(t))
			after, err := z.replicaObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
			mustIAM(t, err)
			if after.UserTags != prior.UserTags {
				t.Fatalf("rotation changed logical tags from %q to %q (rotation error: %v)", prior.UserTags, after.UserTags, rotationErr)
			}
		})
	}
}

// batchRotateFlipDisk starts a decommission of pool 0 at the flipAt-th
// version read, after the rotation's first read of the version.
type batchRotateFlipDisk struct {
	StorageAPI
	z       *erasureServerPools
	reads   *atomic.Int32
	flipAt  int32
	flipped *atomic.Bool
}

func (d batchRotateFlipDisk) ReadVersion(ctx context.Context, origvolume, volume, path, versionID string, opts ReadOptions) (FileInfo, error) {
	n := d.reads.Add(1)
	if n == d.flipAt && d.flipped.CompareAndSwap(false, true) {
		d.z.poolMetaMutex.Lock()
		d.z.poolMeta.Pools[0].Decommission = &PoolDecommissionInfo{}
		d.z.poolMetaMutex.Unlock()
	}
	return d.StorageAPI.ReadVersion(ctx, origvolume, volume, path, versionID, opts)
}

// A move that starts while the rotation authorizes and rewraps the version
// defers it: the state is checked again right before the write, where the
// pools layer checks it.
func TestBatchReviewRotationRechecksPoolBeforeWrite(t *testing.T) {
	resetTestGlobals()
	t.Cleanup(resetTestGlobals)
	z, _ := consistencyPools(t)
	globalIAMSys.initStore(z, nil)
	mustIAM(t, globalIAMSys.Load(t.Context(), true))
	const bucket = "review11-rotation-window"
	const object = "rotation/window"
	mustIAM(t, z.MakeBucket(t.Context(), bucket, MakeBucketOptions{VersioningEnabled: true}))
	_, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
	mustIAM(t, err)
	oldKMS := GlobalKMS
	GlobalKMS = kms.NewStub("review11-rotation-key")
	t.Cleanup(func() { GlobalKMS = oldKMS })

	meta := make(map[string]string)
	key, err := newEncryptMetadata(t.Context(), crypto.S3, "", nil, bucket, object, meta, nil)
	mustIAM(t, err)
	body, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader("rotation window"), key))
	mustIAM(t, err)
	before := putConsistencyObject(t, z, bucket, object, 0, string(body), ObjectOptions{
		Versioned:   true,
		UserDefined: meta,
		MTime:       UTCNow().Add(-time.Hour),
	})
	beforeInfo, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, err)

	var reads atomic.Int32
	var flipped atomic.Bool
	firstPass := int32(0)
	for _, pool := range z.serverPools {
		firstPass += int32(pool.SetDriveCount())
	}
	var restore []func()
	for _, pool := range z.serverPools {
		restore = append(restore, conditionalPutSwapDisks(pool, object, func(d StorageAPI) StorageAPI {
			return batchRotateFlipDisk{
				StorageAPI: d,
				z:          z,
				reads:      &reads,
				flipAt:     firstPass + 1,
				flipped:    &flipped,
			}
		}))
	}
	t.Cleanup(func() {
		for _, fn := range restore {
			fn()
		}
	})

	r := BatchJobKeyRotateV1{Bucket: bucket, Encryption: BatchJobKeyRotateEncryption{Type: sses3}}
	gotErr := r.KeyRotate(t.Context(), z, beforeInfo, batchRootSubmitter(t))
	if !flipped.Load() {
		t.Fatal("fault injection did not occur after the initial rotation read")
	}
	if !errors.Is(gotErr, errBatchRotateMoving) {
		t.Errorf("rotation did not defer after the pool became moving during pre-work: %v", gotErr)
	}
	after, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: before.VersionID})
	mustIAM(t, err)
	if after.UserDefined[crypto.MetaSealedKeyS3] != beforeInfo.UserDefined[crypto.MetaSealedKeyS3] {
		t.Error("rotation rewrote the pool after it became moving during pre-work")
	}
}
