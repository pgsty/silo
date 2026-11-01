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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/kms"
	"github.com/puzpuzpuz/xsync/v3"
	etcd "go.etcd.io/etcd/client/v3"
)

type iamPolicyBudgetGetObserver struct {
	etcd.KV
	elapsed time.Duration
	budget  time.Duration
	block   bool
}

func (k *iamPolicyBudgetGetObserver) Get(ctx context.Context, key string, opts ...etcd.OpOption) (*etcd.GetResponse, error) {
	start := time.Now()
	if d, ok := ctx.Deadline(); ok {
		k.budget = time.Until(d)
	}
	defer func() { k.elapsed = time.Since(start) }()
	if k.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return k.KV.Get(ctx, key, opts...)
}

func iamPolicyBudgetCall(ctx context.Context, store *IAMStoreSys, operation string) (int, error) {
	switch operation {
	case "policies":
		m, err := store.ListPolicies(ctx, "")
		return len(m), err
	case "docs":
		m, err := store.ListPolicyDocs(ctx, "")
		return len(m), err
	default:
		m := xsync.NewMapOf[string, MappedPolicy]()
		err := store.IAMStorageAPI.(*IAMEtcdStore).loadMappedPolicies(ctx, regUser, false, m)
		return m.Size(), err
	}
}

func prepareIAMPolicyBudgetFixture(t *testing.T, operation string) (*IAMStoreSys, *iamPolicyBudgetGetObserver, *atomic.Int32) {
	t.Helper()
	ctx, sys, _ := prepareIAMRevisionFixture(t, "etcd")
	backend := sys.store.IAMStorageAPI.(*IAMEtcdStore)
	builtin, err := kms.NewBuiltin("cancellation-key", bytes.Repeat([]byte{43}, 32))
	mustIAM(t, err)
	var doc any
	path := getPolicyDocPath("budget-slow")
	if operation == "mappings" {
		path = getMappedPolicyPath("budget-slow", regUser, false)
		doc = newMappedPolicy("readonly")
	} else {
		p, err := sys.store.GetPolicy("readonly")
		mustIAM(t, err)
		doc = newPolicyDoc(p)
	}
	plain, err := json.Marshal(doc)
	mustIAM(t, err)
	encrypted, err := config.EncryptBytes(builtin, plain, kms.Context{minioMetaBucket: minioMetaBucket + "/" + path})
	mustIAM(t, err)
	_, err = backend.client.Put(ctx, path, string(encrypted))
	mustIAM(t, err)
	calls := &atomic.Int32{}
	priorKMS := GlobalKMS
	GlobalKMS = connectCancellationKES(t, cancellationDecryptHandler(t, builtin, func(r *http.Request) {
		calls.Add(1)
		select {
		case <-time.After(450 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { GlobalKMS = priorKMS })
	priorTimeout := defaultContextTimeout
	defaultContextTimeout = 200 * time.Millisecond
	t.Cleanup(func() { defaultContextTimeout = priorTimeout })
	observer := &iamPolicyBudgetGetObserver{KV: backend.client.KV}
	backend.client.KV = observer
	t.Cleanup(func() { backend.client.KV = observer.KV })
	return sys.store, observer, calls
}

// A fast etcd Get followed by slow KES decryption must retain the caller's
// budget, even when decryption lasts longer than the etcd read timeout.
func TestIAMPolicyEtcdDecodeBudget(t *testing.T) {
	for _, operation := range []string{"policies", "docs", "mappings"} {
		t.Run(operation, func(t *testing.T) {
			store, observer, calls := prepareIAMPolicyBudgetFixture(t, operation)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			start := time.Now()
			n, err := iamPolicyBudgetCall(ctx, store, operation)
			t.Logf("operation=%s total_ms=%.3f get_ms=%.3f get_budget_ms=%.3f decrypts=%d count=%d error=%v caller_error=%v", operation, float64(time.Since(start).Microseconds())/1000, float64(observer.elapsed.Microseconds())/1000, float64(observer.budget.Microseconds())/1000, calls.Load(), n, err, ctx.Err())
			if err != nil {
				t.Fatalf("valid caller budget was shortened after etcd Get completed: %v", err)
			}
			if observer.elapsed >= 200*time.Millisecond || observer.budget <= 0 || observer.budget > 210*time.Millisecond {
				t.Fatalf("etcd read budget invalid: %+v", observer)
			}
			if n == 0 || calls.Load() != 1 || ctx.Err() != nil {
				t.Fatal("successful result was incomplete")
			}
		})
	}
}

// The correction must retain bounded etcd RPCs and caller cancellation. A
// failed list cannot publish its private map or advance the cache timestamp.
func TestIAMPolicyEtcdBudgetGuards(t *testing.T) {
	for _, operation := range []string{"policies", "docs", "mappings"} {
		for _, mode := range []string{"read_timeout", "caller_deadline", "caller_cancel"} {
			t.Run(fmt.Sprintf("%s/%s", operation, mode), func(t *testing.T) {
				store, observer, calls := prepareIAMPolicyBudgetFixture(t, operation)
				cache := store.rlock()
				before, count := cache.updatedAt, len(cache.iamPolicyDocsMap)
				store.runlock()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				want := context.DeadlineExceeded
				if mode == "read_timeout" {
					observer.block = true
				}
				if mode == "caller_deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 80*time.Millisecond)
					defer cancel()
				}
				var timer *time.Timer
				if mode == "caller_cancel" {
					timer = time.AfterFunc(80*time.Millisecond, cancel)
					defer timer.Stop()
					want = context.Canceled
				}
				start := time.Now()
				_, err := iamPolicyBudgetCall(ctx, store, operation)
				t.Logf("operation=%s mode=%s elapsed_ms=%.3f decrypts=%d error=%v", operation, mode, float64(time.Since(start).Microseconds())/1000, calls.Load(), err)
				if !errors.Is(err, want) {
					t.Fatalf("expected %v, got %v", want, err)
				}
				if mode == "read_timeout" && (calls.Load() != 0 || ctx.Err() != nil) {
					t.Fatal("read timeout did not remain local to the etcd RPC")
				}
				cache = store.rlock()
				unchanged := cache.updatedAt.Equal(before) && len(cache.iamPolicyDocsMap) == count
				store.runlock()
				if !unchanged {
					t.Fatal("failed list published a cache replacement")
				}
			})
		}
	}
}
