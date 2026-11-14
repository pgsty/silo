// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
	"github.com/puzpuzpuz/xsync/v3"
)

// batchBlockedIAMStore holds the lazy load of one user's policy mapping, or
// of one policy document, until released or until the load's context ends.
type batchBlockedIAMStore struct {
	IAMStorageAPI
	mapping string // access key whose mapping load blocks
	doc     string // policy whose document load blocks
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *batchBlockedIAMStore) block(ctx context.Context) error {
	s.once.Do(func() { close(s.started) })
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *batchBlockedIAMStore) loadMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, m *xsync.MapOf[string, MappedPolicy]) error {
	if name == s.mapping && !isGroup {
		if err := s.block(ctx); err != nil {
			return err
		}
	}
	return s.IAMStorageAPI.loadMappedPolicy(ctx, name, userType, isGroup, m)
}

func (s *batchBlockedIAMStore) loadPolicyDoc(ctx context.Context, name string, out map[string]PolicyDoc) error {
	if name == s.doc {
		if err := s.block(ctx); err != nil {
			return err
		}
	}
	return s.IAMStorageAPI.loadPolicyDoc(ctx, name, out)
}

// The batch path and the request path share one IAM cache. A lazy load that
// batch authorization needs, of a mapping that is never cached (a user whose
// policies come from a group) or of an evicted policy document, must not
// hold request authentication and cached authorization while storage is
// slow, and must end at the deadline of the job's context.
func TestBatchAuthorizeSlowLoadKeepsCachedAuthorizationAvailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		// submitter returns the submitter whose authorization lazily loads,
		// and arranges for blocked to hold that load.
		submitter func(t *testing.T, f *batchAuthzFixture, blocked *batchBlockedIAMStore) *batchJobSubmitter
	}{
		{"mapping", func(t *testing.T, f *batchAuthzFixture, blocked *batchBlockedIAMStore) *batchJobSubmitter {
			// No mapping of the user itself is stored, so every lookup of
			// its policies reads storage before it falls back to the group.
			cred := iamAdminUser(f.ctx, t, f.sys, "snapshot-group-user", "")
			_, err := f.sys.AddUsersToGroup(f.ctx, "snapshot-group", []string{cred.AccessKey})
			mustIAM(t, err)
			_, err = f.sys.PolicyDBSet(f.ctx, "snapshot-group", "snapshot-full", regUser, true)
			mustIAM(t, err)
			blocked.mapping = cred.AccessKey
			sub, err := newBatchJobSubmitter(cred)
			mustIAM(t, err)
			return sub
		}},
		{"document", func(t *testing.T, f *batchAuthzFixture, blocked *batchBlockedIAMStore) *batchJobSubmitter {
			batchAuthzPolicy(f.ctx, t, f.sys, "snapshot-evicted", batchAuthzFullAccess)
			cred := iamAdminUser(f.ctx, t, f.sys, "snapshot-doc-user", "snapshot-evicted")
			cache := f.sys.store.lock()
			delete(cache.iamPolicyDocsMap, "snapshot-evicted")
			f.sys.store.unlock()
			blocked.doc = "snapshot-evicted"
			sub, err := newBatchJobSubmitter(cred)
			mustIAM(t, err)
			return sub
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			batchAuthzPolicy(f.ctx, t, f.sys, "snapshot-full", batchAuthzFullAccess)
			cached := iamAdminUser(f.ctx, t, f.sys, "snapshot-cached-user", "snapshot-full")
			store := f.sys.store
			original := store.IAMStorageAPI
			blocked := &batchBlockedIAMStore{IAMStorageAPI: original, started: make(chan struct{}), release: make(chan struct{})}
			sub := tc.submitter(t, f, blocked)
			req := batchAuthzRequest{action: policy.GetObjectAction, bucket: f.bucket, object: "key", versionID: mustGetUUID()}
			if err := sub.authorize(f.ctx, req); err != nil {
				t.Fatalf("control: %v", err)
			}
			store.IAMStorageAPI = blocked
			var wg sync.WaitGroup
			var once sync.Once
			unblock := func() { once.Do(func() { close(blocked.release) }) }
			t.Cleanup(func() { unblock(); wg.Wait(); store.IAMStorageAPI = original })

			slowDone := make(chan error, 1)
			wg.Go(func() { slowDone <- sub.authorize(f.ctx, req) })
			select {
			case <-blocked.started:
			case <-time.After(5 * time.Second):
				t.Fatal("the lazy load did not start")
			}
			cachedDone := make(chan bool, 2)
			wg.Go(func() {
				_, ok := f.sys.GetUser(f.ctx, cached.AccessKey)
				cachedDone <- ok
			})
			wg.Go(func() {
				cachedDone <- f.sys.IsAllowed(policy.Args{AccountName: cached.AccessKey, Action: policy.GetObjectAction, BucketName: f.bucket, ObjectName: "key"})
			})
			for range 2 {
				select {
				case ok := <-cachedDone:
					if !ok {
						t.Fatal("cached authentication or authorization was rejected")
					}
				case <-time.After(time.Second):
					t.Fatal("a slow IAM load during batch authorization blocked cached authentication")
				}
			}
			unblock()
			if err := <-slowDone; err != nil {
				t.Fatalf("authorization after the load completed: %v", err)
			}

			// A load that does not return ends with the job's context, as an
			// unavailable dependency, not with the storage layer's patience.
			blocked.release = make(chan struct{})
			once = sync.Once{}
			unblock = func() { once.Do(func() { close(blocked.release) }) }
			ctx, cancel := context.WithTimeout(f.ctx, 200*time.Millisecond)
			defer cancel()
			deadlineDone := make(chan error, 1)
			wg.Go(func() { deadlineDone <- sub.authorize(ctx, req) })
			select {
			case err := <-deadlineDone:
				if !isBatchJobUnavailable(err) {
					t.Fatalf("a load that ended with the job's context: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("a lazy load outlived the job's context")
			}
		})
	}
}

// A policy that a mapping still names after it was deleted takes no part in
// the decision, for a batch job as for a request: the remaining mapped
// policies decide. An STS parent user's mapping can name a deleted policy,
// because deleting a policy checks only user and group mappings for use.
func TestBatchAuthorizeSkipsDeletedMappedPolicy(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "mapped-full", batchAuthzFullAccess)
	batchAuthzPolicy(f.ctx, t, f.sys, "mapped-deleted", `{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/*"]}`)
	parent := iamAdminUser(f.ctx, t, f.sys, "mapped-parent", "")
	_, err := f.sys.PolicyDBSet(f.ctx, parent.AccessKey, "mapped-full,mapped-deleted", stsUser, false)
	mustIAM(t, err)
	cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{parentClaim: parent.AccessKey, "exp": UTCNow().Add(time.Hour).Unix()}, globalActiveCred.SecretKey)
	mustIAM(t, err)
	cred.ParentUser = parent.AccessKey
	_, err = f.sys.SetTempUser(f.ctx, cred.AccessKey, cred, "")
	mustIAM(t, err)
	sub, err := newBatchJobSubmitter(cred)
	mustIAM(t, err)
	req := batchAuthzRequest{action: policy.GetObjectAction, bucket: f.bucket, object: "key", versionID: mustGetUUID()}
	if err := sub.authorize(f.ctx, req); err != nil {
		t.Fatalf("control: %v", err)
	}
	p, err := sub.principal(f.ctx)
	mustIAM(t, err)
	args := policy.Args{AccountName: cred.AccessKey, Action: req.action, BucketName: req.bucket, ObjectName: req.object, Claims: p.claims, ConditionValues: p.conditionValues(req)}

	mustIAM(t, f.sys.DeletePolicy(f.ctx, "mapped-deleted", true))
	if !f.sys.IsAllowed(args) {
		t.Fatal("the request path denied the remaining mapped policy")
	}
	if err := sub.authorize(f.ctx, req); err != nil {
		t.Fatalf("batch authorization diverged from the request after a mapped policy was deleted: %v", err)
	}

	// With every mapped policy deleted, both deny; the job is refused, not
	// paused, as nothing is unavailable.
	mustIAM(t, f.sys.DeletePolicy(f.ctx, "mapped-full", true))
	if f.sys.IsAllowed(args) {
		t.Fatal("the request path allowed without any mapped policy")
	}
	if err := sub.authorize(f.ctx, req); !isBatchJobAuthzError(err) {
		t.Fatalf("batch authorization without any mapped policy: %v", err)
	}
}
