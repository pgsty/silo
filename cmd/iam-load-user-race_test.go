// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pgsty/silo-pkg/v3/policy"
)

// Hold a lazy user load after it has read storage. This makes the ordering
// between an in-flight read and a completed credential edit deterministic.
type iamLoadUserBlocker struct {
	IAMStorageAPI
	key          string
	waiting      chan struct{}
	release      chan struct{}
	once         sync.Once
	loads        atomic.Int32
	retryWaiting chan struct{}
	retryRelease chan struct{}
	retryErr     error
}

func (s *iamLoadUserBlocker) loadUser(ctx context.Context, key string, userType IAMUserType, out map[string]UserIdentity) error {
	if key == s.key && userType == regUser && s.loads.Add(1) == 2 {
		if s.retryWaiting != nil {
			close(s.retryWaiting)
			select {
			case <-s.retryRelease:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if s.retryErr != nil {
			return s.retryErr
		}
	}
	err := s.IAMStorageAPI.loadUser(ctx, key, userType, out)
	if err == nil && key == s.key && userType == regUser {
		s.once.Do(func() { close(s.waiting) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func TestIAMLoadUserConcurrentUpdates(t *testing.T) {
	for _, change := range []string{"unrelated-edit", "unrelated-load", "delete", "mapping", "policy"} {
		t.Run(change, func(t *testing.T) {
			ctx, sys, _ := prepareIAMRevisionFixture(t)
			const policyName = "lazy-policy"
			batchAuthzPolicy(ctx, t, sys, policyName, `{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::bucket/*"]}`)
			cold := iamAdminUser(ctx, t, sys, "lazy-cold", policyName)
			other := iamAdminUser(ctx, t, sys, "lazy-other", "readwrite")
			cache := sys.store.lock()
			delete(cache.iamUsersMap, cold.AccessKey)
			sys.store.unlock()
			original := sys.store.IAMStorageAPI
			blocker := &iamLoadUserBlocker{
				IAMStorageAPI: original, key: cold.AccessKey,
				waiting: make(chan struct{}), release: make(chan struct{}),
			}
			sys.store.IAMStorageAPI = blocker
			unblock := sync.OnceFunc(func() { close(blocker.release) })
			done := make(chan struct{})
			t.Cleanup(func() {
				unblock()
				<-done
				sys.store.IAMStorageAPI = original
			})
			var valid bool
			var loadErr error
			go func() {
				defer close(done)
				_, valid, loadErr = sys.CheckKey(ctx, cold.AccessKey)
			}()
			select {
			case <-blocker.waiting:
			case <-time.After(5 * time.Second):
				t.Fatal("cold load did not read the identity")
			}
			switch change {
			case "unrelated-edit":
				mustIAM(t, sys.SetUserSecretKey(ctx, other.AccessKey, "unrelated-rotated-secret"))
			case "unrelated-load":
				mustIAM(t, sys.store.LoadUser(ctx, other.AccessKey))
			case "delete":
				mustIAM(t, sys.DeleteUser(ctx, cold.AccessKey, false))
			case "mapping":
				_, err := sys.PolicyDBSet(ctx, cold.AccessKey, "readonly", regUser, false)
				mustIAM(t, err)
			case "policy":
				batchAuthzPolicy(ctx, t, sys, policyName, `{"Effect":"Deny","Action":["s3:*"],"Resource":["arn:aws:s3:::bucket/*"]}`)
			}
			unblock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("cold load did not finish")
			}
			if loadErr != nil || valid != (change != "delete") {
				t.Fatalf("valid=%v err=%v after %s", valid, loadErr, change)
			}
			if blocker.loads.Load() != 2 {
				t.Fatalf("conflicting load read the identity %d times, want 2", blocker.loads.Load())
			}
			if change == "mapping" {
				names, err := sys.store.PolicyDBGet(cold.AccessKey)
				mustIAM(t, err)
				if !slices.Equal(names, []string{"readonly"}) {
					t.Fatalf("restored stale mapping: %v", names)
				}
			}
			if change == "policy" {
				current, err := sys.store.GetPolicy(policyName)
				mustIAM(t, err)
				if current.IsAllowed(policy.Args{Action: policy.PutObjectAction, BucketName: "bucket", ObjectName: "object"}) {
					t.Fatal("restored stale policy")
				}
			}
		})
	}
}

func TestIAMLoadUserRetryKeepsCachedReadsAvailable(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "loaded", true: "unavailable"}[unavailable], func(t *testing.T) {
			ctx, sys, _ := prepareIAMRevisionFixture(t)
			cold := iamAdminUser(ctx, t, sys, "retry-cold", "readwrite")
			other := iamAdminUser(ctx, t, sys, "retry-cached", "readwrite")
			cache := sys.store.lock()
			delete(cache.iamUsersMap, cold.AccessKey)
			sys.store.unlock()
			original := sys.store.IAMStorageAPI
			blocker := &iamLoadUserBlocker{
				IAMStorageAPI: original, key: cold.AccessKey,
				waiting: make(chan struct{}), release: make(chan struct{}),
				retryWaiting: make(chan struct{}), retryRelease: make(chan struct{}),
			}
			if unavailable {
				blocker.retryErr = errErasureReadQuorum
			}
			sys.store.IAMStorageAPI = blocker
			unblock := sync.OnceFunc(func() { close(blocker.release) })
			unblockRetry := sync.OnceFunc(func() { close(blocker.retryRelease) })
			done := make(chan struct{})
			t.Cleanup(func() {
				unblock()
				unblockRetry()
				<-done
				sys.store.IAMStorageAPI = original
			})
			var valid bool
			var loadErr error
			go func() {
				defer close(done)
				_, valid, loadErr = sys.CheckKey(ctx, cold.AccessKey)
			}()
			awaitIAMPolicyReload(t, blocker.waiting)
			mustIAM(t, sys.SetUserSecretKey(ctx, other.AccessKey, "retry-rotated-secret"))
			unblock()
			awaitIAMPolicyReload(t, blocker.retryWaiting)
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				user, ok, err := sys.CheckKey(ctx, other.AccessKey)
				if err != nil || !ok || user.Credentials.SecretKey != "retry-rotated-secret" {
					t.Errorf("cached read failed: valid=%v err=%v", ok, err)
				}
			}()
			select {
			case <-readDone:
			case <-time.After(time.Second):
				unblockRetry()
				<-readDone
				t.Fatal("cold-load retry blocked cached authentication")
			}
			unblockRetry()
			<-done
			if unavailable {
				if valid || !errors.Is(loadErr, errIAMNotInitialized) {
					t.Fatalf("retry outage was not retryable: valid=%v err=%v", valid, loadErr)
				}
			} else if !valid || loadErr != nil {
				t.Fatalf("retry lost the cold identity: valid=%v err=%v", valid, loadErr)
			}
		})
	}
}

func TestIAMLoadUserRefreshesAssociatedRecords(t *testing.T) {
	t.Setenv("_MINIO_IAM_GROUP_REFRESH", "on")
	for _, change := range []string{"policy", "mapping", "group", "parent"} {
		t.Run(change, func(t *testing.T) {
			ctx, sys, obj := prepareIAMRevisionFixture(t)
			const policyName = "associated-policy"
			const groupName = "associated-group"
			batchAuthzPolicy(ctx, t, sys, policyName, `{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::bucket/*"]}`)
			parent := iamAdminUser(ctx, t, sys, "associated-parent", policyName)
			_, err := sys.AddUsersToGroup(ctx, groupName, []string{parent.AccessKey})
			mustIAM(t, err)
			key := parent.AccessKey
			if change == "parent" {
				key = iamAdminServiceAccount(ctx, t, sys, parent.AccessKey, "associated-service", "").AccessKey
			}
			gate := &iamPolicyRefreshReadGate{
				ObjectLayer: obj, userPath: getGroupInfoPath(groupName),
				refreshEntered: make(chan struct{}), refreshRelease: make(chan struct{}),
			}
			sys.store.IAMStorageAPI.(*IAMObjectStore).objAPI = gate
			unblock := sync.OnceFunc(func() { close(gate.refreshRelease) })
			done := make(chan struct{})
			var loadErr error
			t.Cleanup(func() {
				unblock()
				<-done
			})
			go func() {
				defer close(done)
				loadErr = sys.store.LoadUser(context.WithValue(ctx, iamPolicyRefreshContext{}, "refresh"), key)
			}()
			awaitIAMPolicyReload(t, gate.refreshEntered)
			switch change {
			case "policy":
				batchAuthzPolicy(ctx, t, sys, policyName, `{"Effect":"Deny","Action":["s3:*"],"Resource":["arn:aws:s3:::bucket/*"]}`)
			case "mapping":
				_, err = sys.PolicyDBSet(ctx, parent.AccessKey, "readonly", regUser, false)
				mustIAM(t, err)
			case "group":
				_, err = sys.RemoveUsersFromGroup(ctx, groupName, []string{parent.AccessKey})
				mustIAM(t, err)
			case "parent":
				mustIAM(t, sys.SetUserSecretKey(ctx, parent.AccessKey, "associated-rotated-secret"))
			}
			unblock()
			select {
			case <-done:
				mustIAM(t, loadErr)
			case <-time.After(5 * time.Second):
				t.Fatal("associated-record reload did not finish")
			}
			switch change {
			case "policy":
				current, err := sys.store.GetPolicy(policyName)
				mustIAM(t, err)
				if current.IsAllowed(policy.Args{Action: policy.PutObjectAction, BucketName: "bucket", ObjectName: "object"}) {
					t.Fatal("partial snapshot restored old policy")
				}
			case "mapping":
				mapping, ok := sys.store.GetMappedPolicy(parent.AccessKey, false)
				if !ok || mapping.Policies != "readonly" {
					t.Fatalf("partial snapshot restored old mapping: %+v", mapping)
				}
			case "group":
				cache := sys.store.rlock()
				member := cache.iamUserGroupMemberships[parent.AccessKey].Contains(groupName)
				sys.store.runlock()
				if member {
					t.Fatal("partial snapshot restored old group membership")
				}
			case "parent":
				current, valid, err := sys.CheckKey(ctx, parent.AccessKey)
				if err != nil || !valid || current.Credentials.SecretKey != "associated-rotated-secret" {
					t.Fatal("child reload restored old parent credential")
				}
			}
		})
	}
}

func TestIAMLoadUserDoesNotRestoreRotatedCredential(t *testing.T) {
	ctx, sys, _ := prepareIAMRevisionFixture(t)
	user := iamAdminUser(ctx, t, sys, "load-user-race", "readwrite")
	original := sys.store.IAMStorageAPI
	blocker := &iamLoadUserBlocker{
		IAMStorageAPI: original,
		key:           user.AccessKey,
		waiting:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	sys.store.IAMStorageAPI = blocker
	t.Cleanup(func() { sys.store.IAMStorageAPI = original })

	loadDone := make(chan error, 1)
	go func() { loadDone <- sys.store.LoadUser(ctx, user.AccessKey) }()
	select {
	case <-blocker.waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("LoadUser did not reach the controlled read barrier")
	}

	const rotatedSecret = "load-user-rotated-secret"
	if err := sys.SetUserSecretKey(ctx, user.AccessKey, rotatedSecret); err != nil {
		t.Fatal(err)
	}
	current, valid, err := sys.CheckKey(ctx, user.AccessKey)
	if err != nil || !valid || current.Credentials.SecretKey != rotatedSecret {
		t.Fatalf("rotation did not update the serving cache: valid=%v secret=%q err=%v", valid, current.Credentials.SecretKey, err)
	}

	close(blocker.release)
	select {
	case err := <-loadDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LoadUser did not finish after the read barrier was released")
	}
	loaded, valid, err := sys.CheckKey(ctx, user.AccessKey)
	if err != nil || !valid || loaded.Credentials.SecretKey != rotatedSecret {
		t.Fatalf("an in-flight LoadUser restored the old credential: valid=%v secret=%q err=%v", valid, loaded.Credentials.SecretKey, err)
	}
}
