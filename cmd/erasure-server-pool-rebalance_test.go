// Copyright (c) 2026 Denis Babchuk
//
// This file is part of Silo Object Storage stack
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
	"errors"
	"testing"
)

// Without rebalance.bin and without in-memory metadata no rebalance has run,
// so there is nothing to update: saving must report that instead of
// dereferencing the missing metadata, and must not create rebalance.bin.
func TestSaveRebalanceStatsWithoutMeta(t *testing.T) {
	z, _ := consistencyPools(t)
	for _, opts := range []rebalSaveOpts{rebalSaveStoppedAt, rebalSaveStats} {
		if err := z.saveRebalanceStats(t.Context(), 0, opts); !errors.Is(err, errRebalanceNotStarted) {
			t.Fatalf("opts %d: got %v, want %v", opts, err, errRebalanceNotStarted)
		}
		if z.rebalMeta != nil {
			t.Fatalf("opts %d: in-memory rebalance metadata was set", opts)
		}
		r := &rebalanceMeta{}
		if err := r.load(t.Context(), z.serverPools[0]); !errors.Is(err, errConfigNotFound) {
			t.Fatalf("opts %d: rebalance.bin after save: %v, want %v", opts, err, errConfigNotFound)
		}
	}
}
