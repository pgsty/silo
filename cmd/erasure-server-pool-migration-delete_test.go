// Copyright (c) 2026 Feng Ruohang
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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"fmt"
	"testing"
	"time"
)

// Both walkers must preserve markers even when all older versions reside in
// another pool. Local version counts cannot prove that a marker is redundant.
func TestPoolsMigrationDeleteMarkers(t *testing.T) {
	for _, kind := range []string{"rebalance", "decommission"} {
		for _, pools := range []int{2, 3} {
			for _, null := range []bool{false, true} {
				for _, history := range []string{"none", "source", "destination"} {
					t.Run(fmt.Sprintf("%s/pools=%d/null=%t/history=%s", kind, pools, null, history), func(t *testing.T) {
						var z *erasureServerPools
						var bucket string
						if pools == 2 {
							z, bucket = migrationTestPools(t)
						} else {
							z, bucket = migrationTestThreePools(t)
						}
						const object = "deleted"
						old, stamp := UTCNow().Add(-time.Hour), UTCNow().Add(-time.Minute)
						var prior ObjectInfo
						if history != "none" {
							pool := 0
							if history == "destination" {
								pool = 1
							}
							prior = putConsistencyObject(t, z, bucket, object, pool, "history", ObjectOptions{Versioned: true, MTime: old})
						}
						// A stale null copy is a normal consequence of cross-pool overwrites.
						putConsistencyObject(t, z, bucket, object, 1, "stale", ObjectOptions{MTime: old})
						vid := mustGetUUID()
						if null {
							vid = nullVersionID
						}
						opts := ObjectOptions{Versioned: true, VersionID: vid, DeleteMarker: true, MTime: stamp}
						marker, err := z.serverPools[0].DeleteObject(t.Context(), bucket, object, opts)
						mustIAM(t, err)
						if !marker.DeleteMarker {
							t.Fatal("fixture did not create marker")
						}
						if oi, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); !isErrObjectNotFound(err) || !oi.DeleteMarker {
							t.Fatalf("fixture visible: %+v %v", oi, err)
						}
						if failed := migrationTestWalk(t, z, bucket, 0, kind); failed != 0 {
							t.Fatalf("failed moves: %d", failed)
						}
						for attempt := 0; attempt < 2; attempt++ {
							if oi, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); !isErrObjectNotFound(err) || !oi.DeleteMarker || !oi.ModTime.Equal(stamp) {
								t.Fatalf("marker lost: %+v %v", oi, err)
							}
							if _, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: migrationTestVersion(marker)}); !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
								t.Fatalf("source marker retained: %v", err)
							}
							if prior.VersionID != "" && migrationTestBody(t, z.GetObjectNInfo, bucket, object, prior.VersionID) != "history" {
								t.Fatal("lost historical version")
							}
							// Repeating a completed walk must preserve the same state.
							migrationTestWalk(t, z, bucket, 0, kind)
						}
					})
				}
			}
		}
	}
}

// A reader opened before a public purge must not recreate the purged version.
func TestPoolsMigrationDoesNotResurrectPurgedSource(t *testing.T) {
	for _, kind := range []string{"rebalance", "decommission"} {
		for _, multipart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/multipart=%t", kind, multipart), func(t *testing.T) {
				z, bucket := migrationTestPools(t)
				move := migrationTestMover(t, z, 0, kind)
				oi := migrationTestObject(t, z, bucket, "purged", 0, multipart, []string{"payload"}, ObjectOptions{Versioned: true})
				gr := migrationTestReader(t, z, 0, oi)
				_, err := z.DeleteObject(t.Context(), bucket, oi.Name, ObjectOptions{VersionID: oi.VersionID, Versioned: true})
				mustIAM(t, err)
				err = move(t.Context(), 0, bucket, gr)
				if err == nil {
					t.Error("move accepted a purged source")
				}
				if oi, err := z.GetObjectInfo(t.Context(), bucket, oi.Name, ObjectOptions{}); !isErrObjectNotFound(err) {
					t.Fatalf("purged version resurrected: %+v %v", oi, err)
				}
			})
		}
	}
}

// Cleanup must not erase a marker created after the data was copied. It must
// also fail closed if the destination becomes unreadable before source removal.
func TestPoolsMigrationCleanupRechecksSource(t *testing.T) {
	for _, change := range []string{"delete-null", "delete-uuid", "unreadable-destination", "missing-destination"} {
		t.Run(change, func(t *testing.T) {
			z, bucket := migrationTestPools(t)
			move := migrationTestMover(t, z, 0, "decommission")
			oi := migrationTestObject(t, z, bucket, "cleanup", 0, false, []string{"payload"}, ObjectOptions{})
			snapshot := []FileInfo{{VersionID: oi.VersionID, ModTime: oi.ModTime}}
			mustIAM(t, move(t.Context(), 0, bucket, migrationTestReader(t, z, 0, oi)))
			switch change {
			case "delete-null", "delete-uuid":
				_, err := z.DeleteObject(t.Context(), bucket, oi.Name, ObjectOptions{VersionSuspended: change == "delete-null", Versioned: change == "delete-uuid"})
				mustIAM(t, err)
			case "unreadable-destination":
				restore := conditionalPutSwapDisks(z.serverPools[1], oi.Name, func(d StorageAPI) StorageAPI {
					return consistencyReadFaultDisk{StorageAPI: d, bucket: bucket, object: oi.Name}
				})
				defer restore()
			case "missing-destination":
				_, err := z.serverPools[1].DeleteObject(t.Context(), bucket, oi.Name, ObjectOptions{VersionID: nullVersionID})
				mustIAM(t, err)
			}
			err := z.removeMovedVersions(t.Context(), bucket, oi.Name, 0, snapshot)
			if change != "delete-uuid" && err == nil {
				t.Fatal("cleanup accepted changed or uncertain state")
			}
			if change == "delete-null" || change == "delete-uuid" {
				if got, err := z.GetObjectInfo(t.Context(), bucket, oi.Name, ObjectOptions{}); !isErrObjectNotFound(err) || !got.DeleteMarker {
					t.Fatalf("cleanup resurrected data: %v", err)
				}
			} else if _, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, oi.Name, ObjectOptions{}); err != nil {
				t.Fatalf("cleanup lost source: %v", err)
			}
		})
	}
}

func TestPoolsMigrationConflictingTimestampTie(t *testing.T) {
	for _, kind := range []string{"rebalance", "decommission"} {
		for source := range 2 {
			t.Run(fmt.Sprintf("%s/source=%d", kind, source), func(t *testing.T) {
				z, bucket := migrationTestPools(t)
				stamp := UTCNow().Add(-time.Minute)
				for i := range 2 {
					putConsistencyObject(t, z, bucket, "tie", i, fmt.Sprintf("pool-%d", i), ObjectOptions{MTime: stamp})
				}
				if got := migrationTestBody(t, z.GetObjectNInfo, bucket, "tie", ""); got != "pool-0" {
					t.Fatalf("fixture winner: %s", got)
				}
				migrationTestWalk(t, z, bucket, source, kind)
				if got := migrationTestBody(t, z.GetObjectNInfo, bucket, "tie", ""); got != "pool-0" {
					t.Fatalf("changed tie winner: %s", got)
				}
			})
		}
	}
}
