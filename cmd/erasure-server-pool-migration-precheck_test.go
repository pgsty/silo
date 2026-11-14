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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/versioning"
)

// The walk of a decommission or a rebalance prechecks every due version of a
// key with the versions of the key in all pools. It reads that history once
// per key, not once per version.
func TestPoolsMigrationExpiryPrecheckReadsHistoryOnce(t *testing.T) {
	for _, kind := range []string{"decommission", "rebalance"} {
		t.Run(kind, func(t *testing.T) {
			m := newMigrationILM(t, versioning.Enabled, false,
				migrationILMRule("<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration>"))
			const key, versions = "obj-many", 64
			for i := range versions {
				m.put(key, fmt.Sprintf("v%02d", i), ObjectOptions{Versioned: true, MTime: UTCNow().AddDate(0, 0, -10).Add(-time.Duration(versions-i) * time.Minute)})
			}
			var mu sync.Mutex
			loads := map[string]int{}
			migrationHistoryLoaded = func(object string) {
				mu.Lock()
				loads[object]++
				mu.Unlock()
			}
			t.Cleanup(func() { migrationHistoryLoaded = nil })

			m.migrate(kind)

			mu.Lock()
			n := loads[key]
			mu.Unlock()
			if n != 1 {
				t.Errorf("the walk read the history of %s %d times for %d due versions, want once", key, n, versions-1)
			}
			m.check(map[string][]string{key: {fmt.Sprintf("v%02d", versions-1)}})
		})
	}
}
