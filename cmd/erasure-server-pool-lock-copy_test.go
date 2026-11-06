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
// it when it read the source: the refusal comes at once while another writer
// holds the cleaned name.
func TestLockDomainCopyRejectsAliasNames(t *testing.T) {
	for _, mode := range append(slices.Clone(ldModes), "pools") {
		t.Run(mode, func(t *testing.T) {
			z, bucket, router := ldCopyAPI(t, mode)
			ldMustPut(t, z, bucket, "alias/x", "victim")
			ldMustPut(t, z, bucket, "alias/src", "source")

			for _, tc := range []struct{ src, dst string }{
				{"alias//x", "alias/x"},
				{"alias/./x", "alias/x"},
				{"alias/src", "alias//x"},
				{"alias/src", "alias/./x"},
			} {
				t.Run(fmt.Sprintf("%s->%s", tc.src, tc.dst), func(t *testing.T) {
					// Another writer holds the cleaned name of the alias.
					release := ldHoldLock(t, z.NewObjectNSLock(bucket, "alias/x"))
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					start := time.Now()
					rec := ldCopyRequest(ctx, t, router, bucket, tc.src, tc.dst, nil)
					took := time.Since(start)
					cancel()
					release()
					if took > time.Second {
						t.Errorf("refused after %v", took)
					}
					if rec.Code != http.StatusBadRequest {
						t.Errorf("status %d, want 400: %s", rec.Code, rec.Body.String())
					}
					if body, _ := ldBody(t, z, bucket, "alias/x"); body != "victim" {
						t.Errorf("alias/x = %q", body)
					}
					if body, _ := ldBody(t, z, bucket, "alias/src"); body != "source" {
						t.Errorf("alias/src = %q", body)
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
// names that differ before cleaning, into one lock that is a write lock when
// either asks for one. The same resource in two distributed lock domains
// stays two locks: a read lock in the alias's domain and a write lock in the
// clean name's.
func TestLockObjectsMergesByResource(t *testing.T) {
	for _, mode := range ldModes {
		t.Run(mode, func(t *testing.T) {
			z, bucket := ldPool(t, mode)
			pool := z.serverPools[0]
			split := !pool.sharesLocalNSLock()
			// Names whose alias hashes to the clean name's set, and, where the
			// sets have their own lockers, names whose alias does not.
			pick := func(sameSet bool) (string, string) {
				for i := range 1000 {
					clean, alias := fmt.Sprintf("merge-%d/x", i), fmt.Sprintf("merge-%d//x", i)
					if (pool.getHashedSetIndex(alias) == pool.getHashedSetIndex(clean)) == sameSet {
						return clean, alias
					}
				}
				t.Fatalf("no names with sameSet=%v", sameSet)
				return "", ""
			}
			cases := []bool{true}
			if split {
				cases = append(cases, false)
			}
			for _, sameSet := range cases {
				clean, alias := pick(sameSet)
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				start := time.Now()
				_, unlock, err := z.lockObjects(ctx,
					objectLockRequest{bucket: bucket, object: alias},
					objectLockRequest{bucket: bucket, object: clean, write: true})
				cancel()
				if err != nil {
					t.Fatalf("%s + %s: %v after %v", alias, clean, err, time.Since(start))
				}
				if took := time.Since(start); took > time.Second {
					t.Errorf("%s + %s took %v", alias, clean, took)
				}
				// The clean name's table holds a write lock.
				if ldTry(t, pool.getHashedSet(clean).NewNSLock(bucket, clean), false) {
					t.Errorf("%s: readers admitted in its own table", clean)
				}
				if split && !sameSet {
					// The alias's table holds the alias's read lock.
					aliasSet := pool.getHashedSet(alias)
					if !ldTry(t, aliasSet.NewNSLock(bucket, alias), false) {
						t.Errorf("%s: readers excluded in its own table", alias)
					}
					if ldTry(t, aliasSet.NewNSLock(bucket, alias), true) {
						t.Errorf("%s: writers admitted in its own table, the alias lock is missing", alias)
					}
				}
				unlock()
			}
		})
	}
}
