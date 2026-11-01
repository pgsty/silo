// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
)

type iamPolicyRefreshContext struct{}

// Keep IAMStorageAPI as *IAMObjectStore so LoadIAMCache exercises the actual
// 32-worker object loader. Capture bytes and release the physical read lock
// before pausing; concurrent writes can commit against real object storage.
type iamPolicyRefreshReadGate struct {
	ObjectLayer
	policyPath, userPath                                     string
	listEntered, listRelease, refreshEntered, refreshRelease chan struct{}
	listOnce, refreshOnce                                    sync.Once
}

func (g *iamPolicyRefreshReadGate) GetObjectNInfo(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, opts ObjectOptions) (*GetObjectReader, error) {
	r, err := g.ObjectLayer.GetObjectNInfo(ctx, bucket, object, rs, h, opts)
	if err != nil {
		return nil, err
	}
	mode, _ := ctx.Value(iamPolicyRefreshContext{}).(string)
	var release <-chan struct{}
	if bucket == minioMetaBucket && mode == "list" && object == g.policyPath {
		release = g.listRelease
	}
	if bucket == minioMetaBucket && mode == "refresh" && object == g.userPath {
		release = g.refreshRelease
	}
	if release == nil {
		return r, nil
	}
	data, err := io.ReadAll(r)
	info := r.ObjInfo
	r.Close()
	if err != nil {
		return nil, err
	}
	if mode == "list" {
		g.listOnce.Do(func() { close(g.listEntered) })
	} else {
		g.refreshOnce.Do(func() { close(g.refreshEntered) })
	}
	select {
	case <-release:
		return NewGetObjectReaderFromReader(bytes.NewReader(data), info, opts)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestIAMPolicyReloadActualObjectRefresh(t *testing.T) {
	for _, docs := range []bool{false, true} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("docs=%t/cancel=%t", docs, canceled), func(t *testing.T) {
				ctx, sys, obj := prepareIAMRevisionFixture(t)
				store := sys.store
				rw, err := store.GetPolicy("readwrite")
				mustIAM(t, err)
				ro, err := store.GetPolicy("readonly")
				mustIAM(t, err)
				for _, name := range []string{"review-edit", "review-delete"} {
					_, err = store.SetPolicy(ctx, name, rw)
					mustIAM(t, err)
				}
				const parent = "review-parent"
				_, err = sys.CreateUser(ctx, parent, madmin.AddOrUpdateUserReq{SecretKey: "synthetic-review-password", Status: madmin.AccountEnabled})
				mustIAM(t, err)
				secret, err := getTokenSigningKey()
				mustIAM(t, err)
				issue := func(typ string) auth.Credentials {
					c, err := auth.GetNewCredentialsWithMetadata(map[string]any{"exp": UTCNow().Add(time.Hour).Unix(), parentClaim: parent, tokenRevokeTypeClaim: typ}, secret)
					mustIAM(t, err)
					c.ParentUser = parent
					_, err = store.SetTempUser(ctx, c.AccessKey, c, "")
					mustIAM(t, err)
					return c
				}
				revoked, retained := issue("selected"), issue("other")
				gate := &iamPolicyRefreshReadGate{ObjectLayer: obj, policyPath: getPolicyDocPath("review-edit"), userPath: getUserIdentityPath(parent, regUser), listEntered: make(chan struct{}), listRelease: make(chan struct{}), refreshEntered: make(chan struct{}), refreshRelease: make(chan struct{})}
				store.IAMStorageAPI.(*IAMObjectStore).objAPI = gate
				freeList := sync.OnceFunc(func() { close(gate.listRelease) })
				freeRefresh := sync.OnceFunc(func() { close(gate.refreshRelease) })
				var wg sync.WaitGroup
				t.Cleanup(func() { freeList(); freeRefresh(); wg.Wait() })
				start := func(fn func() error) <-chan error {
					done := make(chan error, 1)
					wg.Go(func() { done <- fn() })
					return done
				}
				refreshDone := start(func() error {
					return store.LoadIAMCache(context.WithValue(ctx, iamPolicyRefreshContext{}, "refresh"), false)
				})
				awaitIAMPolicyReload(t, gate.refreshEntered)
				listCtx, cancel := context.WithCancel(context.WithValue(ctx, iamPolicyRefreshContext{}, "list"))
				defer cancel()
				listDone := start(func() error { return iamPolicyReloadCall(listCtx, store, docs) })
				awaitIAMPolicyReload(t, gate.listEntered)
				read := start(func() error {
					if _, ok := store.GetUser(parent); !ok {
						return errors.New("cached user lost")
					}
					_, err := store.GetPolicy("review-edit")
					return err
				})
				select {
				case err := <-read:
					mustIAM(t, err)
				case <-time.After(time.Second):
					t.Fatal("actual object reload blocked cached reads")
				}
				writes := []<-chan error{
					start(func() error { _, err := store.SetPolicy(ctx, "review-edit", ro); return err }),
					start(func() error { return store.DeletePolicy(ctx, "review-delete", false) }),
					start(func() error { _, err := store.RevokeTokens(ctx, parent, "selected"); return err }),
				}
				if canceled {
					cancel()
				} else {
					freeList()
				}
				err = <-listDone
				if canceled {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancel error: %v", err)
					}
				} else {
					mustIAM(t, err)
				}
				for _, done := range writes {
					mustIAM(t, <-done)
				}
				freeRefresh()
				mustIAM(t, <-refreshDone)
				p, err := store.GetPolicy("review-edit")
				mustIAM(t, err)
				if p.IsAllowed(policy.Args{Action: policy.PutObjectAction, BucketName: "bucket", ObjectName: "object"}) || !p.IsAllowed(policy.Args{Action: policy.GetObjectAction, BucketName: "bucket", ObjectName: "object"}) {
					t.Fatal("actual object refresh restored stale policy")
				}
				if _, err := store.GetPolicy("review-delete"); !errors.Is(err, errNoSuchPolicy) {
					t.Fatal("deleted policy restored")
				}
				if _, ok := store.GetUser(revoked.AccessKey); ok {
					t.Fatal("revoked STS token restored")
				}
				if _, ok := store.GetUser(retained.AccessKey); !ok {
					t.Fatal("unrelated token lost")
				}
			})
		}
	}
}
