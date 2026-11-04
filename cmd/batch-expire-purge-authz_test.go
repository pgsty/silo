// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// A batch expiration that keeps no versions purges each key it matched under
// the purge's lock. What it authorizes for the submitter, and checks for
// Object Lock, are the versions the purge deletes then, not the versions the
// walk saw before.

// batchPurgeHook runs change once, after the walk of a job and before its
// first purge of all versions.
type batchPurgeHook struct {
	ObjectLayer
	once   sync.Once
	change func()
}

func (h *batchPurgeHook) DeleteObject(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	if opts.DeleteAllVersions {
		h.once.Do(h.change)
	}
	return h.ObjectLayer.DeleteObject(ctx, bucket, object, opts)
}

func (f *batchAuthzFixture) purgeYAML(prefix string) string {
	return fmt.Sprintf(`expire:
  apiVersion: v1
  bucket: %s
  prefix: %q
  rules:
    - type: object
      purge:
        retainVersions: 0
`, f.bucket, prefix)
}

// runChanged submits a purge of prefix as cred and runs it, with change made
// between its walk and its purge, and returns the job's final state.
func (f *batchAuthzFixture) runChanged(t *testing.T, cred auth.Credentials, prefix string, change func()) *batchJobInfo {
	t.Helper()
	rec, job := f.submit(t, cred, f.purgeYAML(prefix))
	if job == nil {
		t.Fatalf("submission status %d: %s", rec.Code, rec.Body.String())
	}
	hook := &batchPurgeHook{ObjectLayer: f.obj, change: change}
	if err := job.Expire.Start(f.ctx, hook, *job); err != nil {
		t.Logf("start: %v", err)
	}
	return f.jobInfo(t, job)
}

// putOlder writes a version of key older than every version it has, as a
// replicated or pulled version can be, with metadata meta.
func (f *batchAuthzFixture) putOlder(t *testing.T, key, versionID string, meta map[string]string) {
	t.Helper()
	data := []byte("older " + key)
	_, err := f.obj.PutObject(f.ctx, f.bucket, key, mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""),
		ObjectOptions{Versioned: true, VersionID: versionID, MTime: UTCNow().Add(-time.Hour), UserDefined: meta})
	mustIAM(t, err)
}

func batchPurgeVersionIDs(t *testing.T, f *batchAuthzFixture, key string) []string {
	t.Helper()
	var ids []string
	marker, vmarker := "", ""
	for {
		res, err := f.obj.ListObjectVersions(f.ctx, f.bucket, key, marker, vmarker, "", 1000)
		mustIAM(t, err)
		for _, o := range res.Objects {
			if o.Name == key {
				ids = append(ids, o.VersionID)
			}
		}
		if !res.IsTruncated {
			return ids
		}
		marker, vmarker = res.NextMarker, res.NextVersionIDMarker
	}
}

// A version that the submitter may not expire, because of its tags or its
// version ID, is refused although the walk did not see it so: the job fails
// and the key keeps all its versions.
func TestBatchExpirePurgeAuthorizesCurrentVersions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string // the action a conditional Deny denies
		deny   string // its condition
		// change returns the version IDs that change made.
		change func(t *testing.T, f *batchAuthzFixture, key, older string) []string
	}{
		{
			name:   "tagged-after-walk",
			action: "s3:GetObjectVersion",
			deny:   `{"StringEquals":{"s3:ExistingObjectTag/keep":["yes"]}}`,
			change: func(t *testing.T, f *batchAuthzFixture, key, older string) []string {
				_, err := f.obj.PutObjectTags(f.ctx, f.bucket, key, "keep=yes", ObjectOptions{VersionID: older})
				mustIAM(t, err)
				return nil
			},
		},
		{
			name:   "version-after-walk",
			action: "s3:DeleteObjectVersion",
			deny:   `{"StringEquals":{"s3:versionid":["%s"]}}`,
			change: func(t *testing.T, f *batchAuthzFixture, key, older string) []string {
				f.putOlder(t, key, batchPurgeDeniedVersion, nil)
				return []string{batchPurgeDeniedVersion}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			deny := tc.deny
			if strings.Contains(deny, "%s") {
				deny = fmt.Sprintf(deny, batchPurgeDeniedVersion)
			}
			batchAuthzPolicy(f.ctx, t, f.sys, "batch-purge", batchAuthzFullAccess+`,
{"Effect":"Deny","Action":["`+tc.action+`"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":`+deny+`}`)
			cred := iamAdminUser(f.ctx, t, f.sys, "batch-purge-user", "batch-purge")
			const key = "purge/key"
			older := f.putVersions(t, key)
			want := batchPurgeVersionIDs(t, f, key)
			ri := f.runChanged(t, cred, "purge/", func() {
				want = append(want, tc.change(t, f, key, older)...)
			})
			for _, id := range want {
				if !f.versionExists(t, key, id) {
					t.Errorf("version %s was purged although the submitter may not delete it", id)
				}
			}
			if !ri.Failed || ri.Complete || ri.FailureReason == "" {
				t.Errorf("job complete=%v failed=%v reason=%q, want a refused job", ri.Complete, ri.Failed, ri.FailureReason)
			}
			if ri.Objects != 0 || ri.KeysRefused != 0 {
				t.Errorf("job counts objects=%d refused=%d", ri.Objects, ri.KeysRefused)
			}
		})
	}
}

const batchPurgeDeniedVersion = "6c4b2f8e-1d3a-4e5b-9c7d-0a1b2c3d4e5f"

// A version that Object Lock protects refuses the whole key, also when it
// was added after the walk. The job completes with the key counted as
// refused, not failed.
func TestBatchExpirePurgeRefusesLockedAfterWalk(t *testing.T) {
	for _, kind := range batchLockKinds {
		t.Run(kind, func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			enableBucketObjectLock(t, f.bucket)
			batchAuthzPolicy(f.ctx, t, f.sys, "batch-full", batchAuthzFullAccess)
			cred := iamAdminUser(f.ctx, t, f.sys, "batch-user", "batch-full")
			const key = "purge/locked"
			f.putVersions(t, key)
			want := batchPurgeVersionIDs(t, f, key)
			locked := mustGetUUID()
			ri := f.runChanged(t, cred, "purge/", func() {
				f.putOlder(t, key, locked, batchLockMeta(kind))
				want = append(want, locked)
			})
			for _, id := range want {
				if !f.versionExists(t, key, id) {
					t.Errorf("version %s of a key with a locked version was purged", id)
				}
			}
			if !ri.Complete || ri.Failed || ri.KeysRefused != 1 || ri.ObjectsFailed != 0 || ri.Objects != 0 {
				t.Errorf("job complete=%v failed=%v refused=%d failed objects=%d objects=%d, want complete with 1 refused key",
					ri.Complete, ri.Failed, ri.KeysRefused, ri.ObjectsFailed, ri.Objects)
			}
		})
	}
}

// Controls: a purge by root and by an authorized user removes every version,
// including one added after the walk.
func TestBatchExpirePurgeAuthorizedControls(t *testing.T) {
	for _, root := range []bool{true, false} {
		t.Run(fmt.Sprintf("root=%v", root), func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			cred := globalActiveCred
			if !root {
				batchAuthzPolicy(f.ctx, t, f.sys, "batch-full", batchAuthzFullAccess)
				cred = iamAdminUser(f.ctx, t, f.sys, "batch-user", "batch-full")
			}
			const key = "purge/key"
			f.putVersions(t, key)
			added := mustGetUUID()
			ri := f.runChanged(t, cred, "purge/", func() {
				f.putOlder(t, key, added, map[string]string{xhttp.AmzObjectTagging: "keep=yes"})
			})
			if ids := batchPurgeVersionIDs(t, f, key); len(ids) != 0 {
				t.Errorf("an authorized purge kept %v", ids)
			}
			if !ri.Complete || ri.Failed || ri.Objects != 3 || ri.KeysRefused != 0 {
				t.Errorf("job complete=%v failed=%v objects=%d refused=%d, want complete with 3 objects",
					ri.Complete, ri.Failed, ri.Objects, ri.KeysRefused)
			}
		})
	}
}

// Cases found in the sixth review round.

// batchPurgeBudgetChange runs change once the first purge stopped at its
// budget after removing versions.
type batchPurgeBudgetChange struct {
	ObjectLayer
	change func()
	calls  int
}

func (h *batchPurgeBudgetChange) DeleteObject(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	oi, err := h.ObjectLayer.DeleteObject(ctx, bucket, object, opts)
	if opts.DeleteAllVersions {
		h.calls++
		if h.calls == 1 && errors.Is(err, errDeleteAllBudget) && opts.DeleteAllResult.Removed > 0 {
			h.change()
		}
	}
	return oi, err
}

// A purge that continues after its budget authorizes the versions again, as
// they are then; the refusal and the versions already removed persist
// across another start.
func TestBatchExpirePurgeBudgetReauthorizes(t *testing.T) {
	f := newBatchAuthzFixture(t)
	const key = "purge/budget"
	oldest := batchPutVersion(t, f.obj, f.bucket, key, nil)
	middle := batchPutVersion(t, f.obj, f.bucket, key, nil)
	latest := batchPutVersion(t, f.obj, f.bucket, key, nil)
	batchAuthzPolicy(f.ctx, t, f.sys, "review6-budget-deny", batchAuthzFullAccess+`,
{"Effect":"Deny","Action":["s3:GetObjectVersion"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/keep":"yes"}}}`)
	cred := iamAdminUser(f.ctx, t, f.sys, "review6-budget-user", "review6-budget-deny")
	rec, job := f.submit(t, cred, f.purgeYAML("purge/"))
	if job == nil {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
	}
	oldBudget := deleteAllBudget
	deleteAllBudget.versions = 1
	t.Cleanup(func() { deleteAllBudget = oldBudget })
	hook := &batchPurgeBudgetChange{ObjectLayer: f.obj, change: func() {
		_, err := f.obj.PutObjectTags(f.ctx, f.bucket, key, "keep=yes", ObjectOptions{VersionID: middle.VersionID})
		mustIAM(t, err)
	}}
	mustIAM(t, job.Expire.Start(f.ctx, hook, *job))
	ri := f.jobInfo(t, job)
	if hook.calls != 2 || !ri.Failed || ri.Complete || ri.FailureReason == "" || ri.Objects != 1 || ri.KeysRefused != 0 {
		t.Fatalf("continuation: calls=%d complete=%v failed=%v reason=%q objects=%d refused=%d", hook.calls, ri.Complete, ri.Failed, ri.FailureReason, ri.Objects, ri.KeysRefused)
	}
	if f.versionExists(t, key, oldest.VersionID) || !f.versionExists(t, key, middle.VersionID) || !f.versionExists(t, key, latest.VersionID) {
		t.Fatal("only the first authorized version may be removed")
	}
	_, err := f.obj.DeleteObjectTags(f.ctx, f.bucket, key, ObjectOptions{VersionID: middle.VersionID})
	mustIAM(t, err)
	mustIAM(t, job.Expire.Start(f.ctx, hook, *job))
	after := f.jobInfo(t, job)
	if hook.calls != 2 || after.FailureReason != ri.FailureReason || after.Objects != 1 || after.Complete {
		t.Fatal("persisted refusal must prevent a fresh purge after the tags change")
	}
}

// The purge's lock excludes tag writers from its authorization through its
// last delete, for a directory key in a lock domain of its own on one pool
// and for a key in a second pool.
func TestBatchExpirePurgeExcludesTagWriter(t *testing.T) {
	for _, mode := range []string{ldDsync, "two-pools"} {
		t.Run(mode, func(t *testing.T) {
			var z *erasureServerPools
			var bucket string
			pool, key := 0, "purge/tags/"
			if mode == "two-pools" {
				z, bucket = consistencyPools(t)
				pool = 1
			} else {
				z, bucket = ldPool(t, mode)
				for i := 0; ; i++ {
					key = fmt.Sprintf("purge/tags-%d/", i)
					if z.serverPools[0].getHashedSetIndex(encodeDirObject(key)) == 1 {
						break
					}
				}
			}
			before := putConsistencyObject(t, z, bucket, encodeDirObject(key), pool, "", ObjectOptions{Versioned: true})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			var released atomic.Bool
			unblock := func() {
				if released.CompareAndSwap(false, true) {
					close(release)
				}
			}
			defer unblock()
			purged := make(chan error, 1)
			go func() {
				_, err := z.DeleteObject(ctx, bucket, key, ObjectOptions{
					DeleteAllVersions: true,
					DeleteAllLatest:   &deleteAllMatch{VersionID: before.VersionID, ModTime: before.ModTime},
					deleteAllAuthorize: func(versions []ObjectInfo) error {
						close(entered)
						select {
						case <-release:
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					},
				})
				purged <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("purge never reached authorization")
			}
			written := make(chan error, 1)
			go func() {
				_, err := z.PutObjectTags(ctx, bucket, key, "keep=yes", ObjectOptions{VersionID: before.VersionID})
				written <- err
			}()
			select {
			case err := <-written:
				t.Errorf("tag writer crossed the purge's authorization lock: %v", err)
			case <-time.After(ldWait):
				unblock()
				err := <-written
				if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
					t.Errorf("writer must observe the completed purge: %v", err)
				}
			}
			unblock()
			mustIAM(t, <-purged)
		})
	}
}

// batchTagWriteFault fails metadata updates of one key, so that a tag write
// reaches only the drives it does not wrap.
type batchTagWriteFault struct {
	StorageAPI
	bucket, object string
}

func (d batchTagWriteFault) UpdateMetadata(ctx context.Context, bucket, object string, fi FileInfo, opts UpdateMetadataOpts) error {
	if bucket == d.bucket && object == d.object {
		return errDiskNotFound
	}
	return d.StorageAPI.UpdateMetadata(ctx, bucket, object, fi, opts)
}

// A failed tag write can leave a revision that the submitter may not expire
// on a minority of drives. The purge removes it with the version, so it is
// authorized too.
func TestBatchExpirePurgeAuthorizesDriveRevisions(t *testing.T) {
	resetTestGlobals()
	t.Cleanup(resetTestGlobals)
	z := purgeSinglePool(t, 16)
	globalIAMSys.initStore(z, nil)
	mustIAM(t, globalIAMSys.Load(t.Context(), true))
	f := &batchAuthzFixture{ctx: t.Context(), sys: globalIAMSys, obj: z, bucket: "review6-batch-authz"}
	mustIAM(t, z.MakeBucket(f.ctx, f.bucket, MakeBucketOptions{VersioningEnabled: true}))
	batchTestJobPool(f.ctx, t, z)
	const key = "purge/minority-tags"
	older := f.putVersions(t, key)
	batchAuthzPolicy(f.ctx, t, f.sys, "review6-minority-deny", strings.ReplaceAll(batchAuthzFullAccess+`,
{"Effect":"Deny","Action":["s3:GetObjectVersion"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/keep":"yes"}}}`, "batch-authz", f.bucket))
	cred := iamAdminUser(f.ctx, t, f.sys, "review6-minority-user", "review6-minority-deny")
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	if err := sub.authorize(f.ctx, batchAuthzRequest{action: policy.GetObjectVersionAction, bucket: f.bucket, object: key, versionID: older, tags: "keep=yes"}); !isBatchJobAuthzError(err) {
		t.Fatal("control: this tag revision must deny the read needed for expiration")
	}
	set := z.serverPools[0].getHashedSet(key)
	original := set.getDisks
	disks := append([]StorageAPI(nil), original()...)
	wrapped := append([]StorageAPI(nil), disks...)
	for i := 1; i < len(wrapped); i++ {
		wrapped[i] = batchTagWriteFault{StorageAPI: wrapped[i], bucket: f.bucket, object: key}
	}
	set.getDisks = func() []StorageAPI { return wrapped }
	_, err = f.obj.PutObjectTags(f.ctx, f.bucket, key, "keep=yes", ObjectOptions{VersionID: older, UserDefined: map[string]string{
		ReservedMetadataPrefixLower + TaggingTimestamp: UTCNow().Format(time.RFC3339Nano),
	}})
	set.getDisks = original
	if err == nil {
		t.Fatal("control: the tag write must fail its quorum")
	}
	fi, err := disks[0].ReadVersion(f.ctx, "", f.bucket, key, older, ReadOptions{})
	mustIAM(t, err)
	if fi.Metadata[xhttp.AmzObjectTagging] != "keep=yes" {
		t.Fatal("control: the successful drive must hold the denied tag revision")
	}
	history, err := z.deleteAllHistory(f.ctx, f.bucket, key)
	mustIAM(t, err)
	for _, v := range history {
		for _, c := range v.copies {
			if c.fi.Metadata[xhttp.AmzObjectTagging] != "" {
				t.Fatal("control: the quorum history must still have the original tags")
			}
		}
	}
	ri := f.runChanged(t, cred, "purge/", func() {})
	if !ri.Failed || ri.Complete || !strings.Contains(ri.FailureReason, "is not allowed") {
		t.Errorf("denied physical revision must refuse the job: complete=%v failed=%v reason=%q", ri.Complete, ri.Failed, ri.FailureReason)
	}
	if _, err := disks[0].ReadVersion(f.ctx, "", f.bucket, key, older, ReadOptions{}); err != nil {
		t.Errorf("denied physical revision was removed: %v", err)
	}
	if got := batchPurgeVersionIDs(t, f, key); len(got) != 2 {
		t.Errorf("denial must keep the whole key; remaining versions=%v", got)
	}
}

// Cases found in the seventh review round.

// The time the authorization takes counts against the purge's budget: a
// late allow and a deny both delete nothing.
func TestBatchExpirePurgeBudgetIncludesAuthorization(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "review7-purge-auth-time", MakeBucketOptions{VersioningEnabled: true}, "")
	const key = "purge/key"
	p.version(0, key, "older", 2)
	p.version(0, key, "latest", 1)
	exp := p.matched(key)
	oldBudget := deleteAllBudget
	deleteAllBudget.duration = 10 * time.Millisecond
	t.Cleanup(func() { deleteAllBudget = oldBudget })
	denied := errors.New("review7: revision denied")
	for _, decision := range []error{nil, denied} {
		called := false
		var res deleteAllResult
		_, err := z.DeleteObject(t.Context(), p.bucket, key, ObjectOptions{
			DeleteAllVersions: true,
			DeleteAllLatest:   &deleteAllMatch{VersionID: exp.VersionID, ModTime: exp.ModTime},
			DeleteAllResult:   &res,
			deleteAllAuthorize: func(versions []ObjectInfo) error {
				called = true
				if len(versions) < 2 {
					t.Error("authorization did not receive both approved versions")
				}
				time.Sleep(20 * time.Millisecond)
				return decision
			},
		})
		want := decision
		if want == nil {
			want = errDeleteAllBudget
		}
		if !called || !errors.Is(err, want) || res.Started || res.Complete || res.Removed != 0 {
			t.Errorf("late authorization: called=%v err=%v result=%+v", called, err, res)
		}
		if got := p.held(0, key); len(got) != 2 {
			t.Fatalf("purge removed versions after late authorization: %v", got)
		}
	}
}
