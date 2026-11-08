// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Hold a lazy user load after it has read storage. This makes the ordering
// between an in-flight read and a completed credential edit deterministic.
type iamLoadUserBlocker struct {
	IAMStorageAPI
	key     string
	waiting chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *iamLoadUserBlocker) loadUser(ctx context.Context, key string, userType IAMUserType, out map[string]UserIdentity) error {
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
