// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"errors"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
)

func TestIAMCredentialRetention(t *testing.T) {
	for _, backend := range []string{"object", "etcd"} {
		t.Run(backend, func(t *testing.T) {
			ctx, sys, _ := prepareIAMRevisionFixture(t, backend)
			secret, err := getTokenSigningKey()
			mustIAM(t, err)
			parent := "external-idp-parent"
			credential := func(exp time.Time) auth.Credentials {
				cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{"exp": exp.Unix(), parentClaim: parent}, secret)
				mustIAM(t, err)
				cred.ParentUser = parent
				return cred
			}
			// Disablement of an external identity must include cached STS,
			// which are kept separately from regular and service accounts.
			cred := credential(UTCNow().Add(time.Hour))
			_, err = sys.SetTempUser(ctx, cred.AccessKey, cred, "")
			mustIAM(t, err)
			mustIAM(t, sys.store.DeleteUsers(ctx, []string{parent}))
			r, err := loadIAMRevision(ctx, sys.store, getUserIdentityPath(cred.AccessKey, stsUser))
			mustIAM(t, err)
			if !r.Deleted || !r.ExpiresAt.Equal(cred.Expiration.Add(globalMaxSkewTime)) || r.Credentials.SessionToken != "" || r.Credentials.SecretKey != "" {
				t.Fatal("early STS revocation lost its retention boundary or retained a secret")
			}
			if _, ok := sys.store.GetUser(cred.AccessKey); ok {
				t.Fatal("external disablement left the STS cache live")
			}
			_, err = sys.SetTempUser(withIAMReplicationTime(ctx, UTCNow().Add(time.Minute)), cred.AccessKey, cred, "")
			if !errors.Is(err, errIAMStaleUpdate) {
				t.Fatalf("same revoked token was reissued by replay: %v", err)
			}
			var mp MappedPolicy
			err = sys.store.loadIAMConfig(ctx, &mp, getMappedPolicyPath(cred.AccessKey, stsUser, false))
			if !errors.Is(err, errConfigNotFound) {
				t.Fatalf("random STS key produced a permanent mapping: %v", err)
			}

			// Seed genuinely expired immutable tokens, as an ordinary startup
			// loader sees them. Natural expiry leaves no permanent tombstone.
			expired := credential(UTCNow().Add(-time.Hour))
			path := getUserIdentityPath(expired.AccessKey, stsUser)
			mustIAM(t, sys.store.saveIAMConfig(ctx, &UserIdentity{Version: 1, Credentials: expired, UpdatedAt: UTCNow().Add(-2 * time.Hour)}, path))
			_ = sys.store.loadUser(ctx, expired.AccessKey, stsUser, make(map[string]UserIdentity))
			var u UserIdentity
			if err := sys.store.loadIAMConfig(ctx, &u, path); !errors.Is(err, errConfigNotFound) {
				t.Fatalf("natural expiration retained a random key: %v", err)
			}
			// A retained early-revocation record is collectable only after the
			// immutable token's expiration plus the skew allowance.
			tomb := UserIdentity{Version: 1, Deleted: true, UpdatedAt: UTCNow().Add(-2 * time.Hour), ExpiresAt: expired.Expiration.Add(globalMaxSkewTime)}
			mustIAM(t, sys.store.saveIAMConfig(ctx, &tomb, path))
			_ = sys.store.loadUser(ctx, expired.AccessKey, stsUser, make(map[string]UserIdentity))
			if err := sys.store.loadIAMConfig(ctx, &u, path); !errors.Is(err, errConfigNotFound) {
				t.Fatalf("expired STS revocation not collected: %v", err)
			}
			if _, ok := sys.store.revisionIndex().snapshot()[path]; ok {
				t.Fatal("expired STS retained an index entry")
			}
		})
	}
}

func TestIAMPolicyDeletionRemainsExplicit(t *testing.T) {
	for _, backend := range []string{"object", "etcd"} {
		t.Run(backend, func(t *testing.T) {
			ctx, sys, _ := prepareIAMRevisionFixture(t, backend)
			mustIAM(t, sys.DeletePolicy(ctx, "misspelled-policy", true))
			r, err := loadIAMRevision(ctx, sys.store, getPolicyDocPath("misspelled-policy"))
			mustIAM(t, err)
			if r.Deleted {
				t.Fatal("local nonexistent policy created a tombstone")
			}
			p, err := sys.store.GetPolicy("readwrite")
			mustIAM(t, err)
			native, err := sys.InfoPolicy("readwrite")
			mustIAM(t, err)
			if err := sys.DeletePolicy(ctx, "readwrite", true); err == nil {
				t.Fatal("local pristine builtin policy became deletable")
			}
			_, err = sys.SetPolicy(ctx, "readwrite", p)
			mustIAM(t, err)
			mustIAM(t, sys.DeletePolicy(ctx, "readwrite", true))
			assertIAMPolicyResetInfo(t, sys, "readwrite", native)
			mustIAM(t, sys.store.LoadIAMCache(ctx, false))
			assertIAMPolicyResetInfo(t, sys, "readwrite", native)
			r, err = loadIAMRevision(ctx, sys.store, getPolicyDocPath("readwrite"))
			mustIAM(t, err)
			if !r.Deleted {
				t.Fatal("native policy restoration removed the override tombstone")
			}
			_, err = sys.SetPolicy(ctx, "readwrite", p)
			mustIAM(t, err)
			if _, err := sys.store.GetPolicy("readwrite"); err != nil {
				t.Fatal("explicit policy recreation failed", err)
			}
			mustIAM(t, globalSiteReplicationSys.PeerAddPolicyHandler(ctx, "remote-unknown-policy", nil, UTCNow()))
			r, err = loadIAMRevision(ctx, sys.store, getPolicyDocPath("remote-unknown-policy"))
			mustIAM(t, err)
			if !r.Deleted {
				t.Fatal("replicated unknown deletion lost its version")
			}
		})
	}
}
