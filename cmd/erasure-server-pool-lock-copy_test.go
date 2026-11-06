// Copyright (c) 2026 PGSTY
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
	"context"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	xhttp "github.com/minio/minio/internal/http"
)

// ldCopyAPI returns an API router for mode, or for two pools.
func ldCopyAPI(t *testing.T, mode string) (*erasureServerPools, string, http.Handler) {
	t.Helper()
	if mode != "pools" {
		return ldAPI(t, mode)
	}
	z, bucket := bulkDeletePools(t, 2)
	if err := newTestConfig(globalMinioDefaultRegion, z); err != nil {
		t.Fatal(err)
	}
	return z, bucket, initTestAPIEndPoints(z, nil)
}

// A lock is taken on the cleaned name, so an invalid name that aliases
// another one locks the same resource. A copy whose source or destination is
// such an alias is refused before it locks anything, as the release refused
// it when it read the source.
func TestLockDomainCopyRejectsAliasNames(t *testing.T) {
	for _, mode := range append(slices.Clone(ldModes), "pools") {
		t.Run(mode, func(t *testing.T) {
			z, bucket, router := ldCopyAPI(t, mode)
			prev := globalOperationTimeout
			globalOperationTimeout = newDynamicTimeout(5*time.Second, 5*time.Second)
			t.Cleanup(func() { globalOperationTimeout = prev })
			ldMustPut(t, z, bucket, "alias/x", "victim")

			for _, tc := range []struct{ src, dst string }{
				{"alias//x", "alias/x"},
				{"alias/./x", "alias/x"},
				{"alias/x", "alias//x"},
			} {
				t.Run(fmt.Sprintf("%s->%s", tc.src, tc.dst), func(t *testing.T) {
					start := time.Now()
					rec := ldCopyRequest(t.Context(), t, router, bucket, tc.src, tc.dst, nil)
					if took := time.Since(start); took > time.Second {
						t.Errorf("refused after %v", took)
					}
					if rec.Code != http.StatusBadRequest {
						t.Errorf("status %d, want 400: %s", rec.Code, rec.Body.String())
					}
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()
					if err := ldPut(ctx, z, bucket, "alias/x", "victim"); err != nil {
						t.Errorf("a PUT of alias/x after the copy: %v", err)
					}
					if body, _ := ldBody(t, z, bucket, "alias/x"); body != "victim" {
						t.Errorf("alias/x = %q", body)
					}
				})
			}
		})
	}
}

// An invalid destination does not change which error a copy reports first:
// a missing source and a failed source precondition still answer as in the
// release.
func TestLockDomainCopyErrorPrecedence(t *testing.T) {
	for _, mode := range append(slices.Clone(ldModes), "pools") {
		t.Run(mode, func(t *testing.T) {
			z, bucket, router := ldCopyAPI(t, mode)
			ldMustPut(t, z, bucket, "prec/src", "source")
			rec := ldCopyRequest(t.Context(), t, router, bucket, "prec/missing", "prec//dst", nil)
			if rec.Code != http.StatusNotFound {
				t.Errorf("missing source: status %d, want 404: %s", rec.Code, rec.Body.String())
			}
			rec = ldCopyRequest(t.Context(), t, router, bucket, "prec/src", "prec//dst", map[string]string{
				xhttp.AmzCopySourceIfMatch: `"00000000000000000000000000000000"`,
			})
			if rec.Code != http.StatusPreconditionFailed {
				t.Errorf("failed precondition: status %d, want 412: %s", rec.Code, rec.Body.String())
			}
			rec = ldCopyRequest(t.Context(), t, router, bucket, "prec/src", "prec//dst", nil)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("invalid destination: status %d, want 400: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// lockObjects merges the requests of one resource in one lock table, also for
// names that differ before cleaning; the same resource in two distributed
// lock domains stays two locks.
func TestLockObjectsMergesByResource(t *testing.T) {
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket := ldPool(t, mode)
			pool := z.serverPools[0]
			prev := globalOperationTimeout
			globalOperationTimeout = newDynamicTimeout(3*time.Second, 3*time.Second)
			t.Cleanup(func() { globalOperationTimeout = prev })
			for i := range 16 {
				clean := fmt.Sprintf("merge-%d/x", i)
				alias := fmt.Sprintf("merge-%d//x", i)
				start := time.Now()
				_, unlock, err := z.lockObjects(t.Context(),
					objectLockRequest{bucket: bucket, object: alias},
					objectLockRequest{bucket: bucket, object: clean, write: true})
				if err != nil {
					t.Fatalf("%s + %s: %v after %v", alias, clean, err, time.Since(start))
				}
				if took := time.Since(start); took > time.Second {
					t.Errorf("%s + %s took %v", alias, clean, took)
				}
				sameTable := pool.sharesLocalNSLock() || pool.getHashedSetIndex(alias) == pool.getHashedSetIndex(clean)
				// The resource is write locked in the clean name's table.
				if ldTry(t, pool.getHashedSet(clean).NewNSLock(bucket, clean), false) {
					t.Errorf("%s: not write locked", clean)
				}
				if !sameTable && !ldTry(t, pool.getHashedSet(alias).NewNSLock(bucket, clean), false) {
					// The alias holds only a read lock in its own domain.
					t.Errorf("%s: alias domain write locked", alias)
				}
				unlock()
			}
		})
	}
}
