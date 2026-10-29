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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"
)

func crossParityNullVersion(t *testing.T, generation int64, data, parity int) xlMetaV2ShallowVersion {
	t.Helper()
	fi := newFileInfo("bucket/object", data, parity)
	fi.Erasure.Index = 1
	fi.DataDir = "11111111-1111-1111-1111-111111111111"
	fi.ModTime = time.Unix(generation, 0).UTC()
	fi.Size = 1024
	fi.Parts = []ObjectPartInfo{{Number: 1, Size: fi.Size, ActualSize: fi.Size}}
	fi.Metadata = map[string]string{"etag": fmt.Sprintf("%032d", generation)}
	var xl xlMetaV2
	if err := xl.AddVersion(fi); err != nil {
		t.Fatal(err)
	}
	return xl.versions[0]
}

// A restarted node can retain four 12+4 shards while a successful degraded
// write leaves twelve newer 8+8 shards. Neither disk order nor the minority's
// EC must hide the independently sufficient newer group.
func TestMergeXLV2LatestNullCrossParity(t *testing.T) {
	versions := []xlMetaV2ShallowVersion{
		crossParityNullVersion(t, 100, 12, 4),
		crossParityNullVersion(t, 200, 8, 8),
		crossParityNullVersion(t, 300, 10, 6),
	}
	for _, tt := range []struct {
		name   string
		counts [3]int
		empty  int
		quorum int
		want   int
	}{
		{"new-twelve-old-four", [3]int{4, 12}, 0, 8, 1},
		{"old-twelve-new-four", [3]int{12, 4}, 0, 8, 0},
		{"new-nine-old-seven", [3]int{7, 9}, 0, 8, 1},
		{"eight-meets-eight", [3]int{4, 8}, 4, 8, 1},
		{"eight-does-not-meet-nine", [3]int{8, 8}, 0, 9, -1},
		{"three-subquorums", [3]int{7, 5, 4}, 0, 8, -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var input [][]xlMetaV2ShallowVersion
			for group, count := range tt.counts {
				for range count {
					input = append(input, []xlMetaV2ShallowVersion{versions[group]})
				}
			}
			input = append(input, make([][]xlMetaV2ShallowVersion, tt.empty)...)
			// Latest-only listing and listing all versions (decommission,
			// rebalance) must select the same version.
			for _, requested := range []int{1, 0} {
				for order, streams := range quorumVersionOrders(input) {
					got := mergeXLV2Versions(tt.quorum, false, requested, streams...)
					if tt.want < 0 {
						if len(got) != 0 {
							t.Fatalf("requested %d, order %d: subquorum groups were combined: %v", requested, order, got)
						}
						continue
					}
					if len(got) != 1 || got[0].header != versions[tt.want].header {
						t.Fatalf("requested %d, order %d: got %v, want group %d", requested, order, got, tt.want)
					}
					xl := xlMetaV2{versions: got}
					fi, err := xl.ToFileInfo("bucket", "object", "", false, true)
					if err != nil || !fi.IsValid() || fi.Erasure.DataBlocks != int(versions[tt.want].header.EcM) {
						t.Fatalf("requested %d, order %d: selected metadata is invalid: %+v, %v", requested, order, fi, err)
					}
				}
			}
		})
	}
}

func TestMergeXLV2LatestNullCrossParityScope(t *testing.T) {
	old := crossParityNullVersion(t, 100, 12, 4)
	newer := crossParityNullVersion(t, 200, 8, 8)
	for _, kind := range []string{"strict", "uuid", "delete", "free", "history", "legacy-modern-ec", "partial-ec"} {
		t.Run(kind, func(t *testing.T) {
			a, b := old, newer
			strict := false
			switch kind {
			case "strict":
				strict = true
			case "uuid":
				a.header.VersionID, b.header.VersionID = [16]byte{1}, [16]byte{1}
			case "delete":
				b.header.Type = DeleteType
			case "free":
				b.header.Flags |= xlFlagFreeVersion
			case "legacy-modern-ec":
				b.header.EcN, b.header.EcM = 0, 0
			case "partial-ec":
				b.header.EcN = 0
			}
			// These previously unresolved inputs remain outside the repair.
			// Strict and legacy-header cases use an older majority followed by
			// a newer minority; the other cases use the opposite grouping.
			input := make([][]xlMetaV2ShallowVersion, 16)
			for i := range input {
				input[i] = []xlMetaV2ShallowVersion{b}
				if i >= 12 {
					input[i] = []xlMetaV2ShallowVersion{a}
				}
			}
			if kind == "strict" || kind == "legacy-modern-ec" || kind == "partial-ec" {
				for i := range input {
					input[i] = []xlMetaV2ShallowVersion{a}
					if i >= 12 {
						input[i] = []xlMetaV2ShallowVersion{b}
					}
				}
			}
			if kind == "history" {
				history := old
				history.header.VersionID = [16]byte{1}
				input[0] = append(input[0], history)
			}
			for _, requested := range []int{1, 0} {
				if got := mergeXLV2Versions(8, strict, requested, input...); len(got) != 0 {
					t.Fatalf("requested %d: excluded input changed: %v", requested, got)
				}
			}
		})
	}
}

func TestCountXLV2MixedECGroups(t *testing.T) {
	a := crossParityNullVersion(t, 100, 12, 4)
	b := crossParityNullVersion(t, 100, 8, 8)
	c := crossParityNullVersion(t, 200, 10, 6)
	// Same-time groups remain separate, and equal counts have a deterministic
	// final EC tiebreak even though sortsBefore does not compare EC itself.
	input := [][]xlMetaV2ShallowVersion{{a}, {a}, {a}, {b}, {b}, {b}, {c}}
	for order, streams := range quorumVersionOrders(input) {
		tops := make([]xlMetaV2ShallowVersion, len(streams))
		for i := range streams {
			tops[i] = streams[i][0]
		}
		for range 20 {
			got, count := countXLV2Versions(tops, c.header, c, false, true)
			if count != 3 || got.header != a.header {
				t.Fatalf("order %d: got %v, count %d; want distinct group of three", order, got.header, count)
			}
		}
	}
	differentSig := a
	differentSig.header.Signature[0]++
	if _, count := countXLV2Versions([]xlMetaV2ShallowVersion{a, a, differentSig}, a.header, a, false, true); count != 3 {
		t.Fatalf("non-strict signature groups did not combine: count %d", count)
	}
	// Same EC with different time or flags must not accumulate votes either.
	flags := a
	flags.header.Flags ^= xlFlagInlineData
	for _, other := range []xlMetaV2ShallowVersion{crossParityNullVersion(t, 200, 12, 4), flags} {
		got, count := countXLV2Versions([]xlMetaV2ShallowVersion{a, a, other, other}, a.header, a, false, true)
		if count != 2 {
			t.Fatalf("incompatible header groups combined: %v, count %d", got.header, count)
		}
	}
}

// Exercise the regular full-metadata read and HTTP LIST with actual on-disk
// object metadata, not merely the metadata selection helper.
func TestListCrossParityReadableMajority(t *testing.T) {
	for _, size := range []int{1024, 256 << 10} {
		t.Run(fmt.Sprintf("bytes-%d", size), func(t *testing.T) {
			z, bucket, router := nullQuorumBackend(t)
			set := z.serverPools[0].sets[0]
			disks := set.getDisks()
			const object = "object"
			mtime := time.Now().UTC().Add(-time.Hour)
			oldBody := bytes.Repeat([]byte{'a'}, size)
			newBody := bytes.Repeat([]byte{'b'}, size)
			nullQuorumPut(t, z, bucket, object, oldBody, ObjectOptions{MTime: mtime})
			old := make([][]byte, len(disks))
			for i, disk := range disks {
				old[i] = mustReadNullQuorumMeta(t, disk, bucket, object)
			}
			nullQuorumPut(t, z, bucket, object, newBody, ObjectOptions{MTime: mtime.Add(time.Minute), MaxParity: true})
			for i := 12; i < len(disks); i++ {
				if err := disks[i].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, old[i]); err != nil {
					t.Fatal(err)
				}
			}
			for _, readData := range []bool{false, true} {
				fi, _, _, err := set.getObjectFileInfo(t.Context(), bucket, object, ObjectOptions{}, readData)
				if err != nil || !fi.ModTime.Equal(mtime.Add(time.Minute)) || fi.Erasure.DataBlocks != 8 {
					t.Fatalf("readData=%v: full metadata read lost readable majority: %+v, %v", readData, fi, err)
				}
			}
			if get := nullQuorumRequest(t, router, http.MethodGet, getGetObjectURL("", bucket, object)); get.Code != http.StatusOK || !bytes.Equal(get.Body.Bytes(), newBody) {
				t.Fatalf("GET lost readable majority: status %d", get.Code)
			}
			if code, keys := nullQuorumListV2Keys(t, router, bucket); code != http.StatusOK || !slices.Equal(keys, []string{object}) {
				t.Fatalf("LIST lost readable majority: %d %v", code, keys)
			}
		})
	}
}

// Decommission and rebalance list every version. A readable degraded overwrite
// must not be skipped there, or removing the pool loses it.
func TestMigrationCrossParityReadableMajority(t *testing.T) {
	z, bucket, _ := nullQuorumBackend(t)
	set := z.serverPools[0].sets[0]
	disks := set.getDisks()
	const object = "object"
	mtime := time.Now().UTC().Add(-time.Hour)
	oldBody := bytes.Repeat([]byte{'a'}, 256<<10)
	newBody := bytes.Repeat([]byte{'b'}, 256<<10)
	nullQuorumPut(t, z, bucket, object, oldBody, ObjectOptions{MTime: mtime})
	old := make([][]byte, len(disks))
	for i, disk := range disks {
		old[i] = mustReadNullQuorumMeta(t, disk, bucket, object)
	}
	nullQuorumPut(t, z, bucket, object, newBody, ObjectOptions{MTime: mtime.Add(time.Minute), MaxParity: true})
	for i := 12; i < len(disks); i++ {
		if err := disks[i].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, old[i]); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"rebalance", "decommission"} {
		t.Run(kind, func(t *testing.T) {
			var names []string
			consume := func(entry metaCacheEntry) {
				versions, err := entry.fileInfoVersions(bucket)
				if err != nil || len(versions.Versions) != 1 || !versions.Versions[0].ModTime.Equal(mtime.Add(time.Minute)) {
					t.Errorf("invalid migration metadata: %+v, %v", versions, err)
					return
				}
				reader, err := set.GetObjectNInfo(t.Context(), bucket, entry.name, nil, nil, ObjectOptions{VersionID: nullVersionID, NoLock: true, NoDecryption: true})
				if err != nil {
					t.Error(err)
					return
				}
				body, err := io.ReadAll(reader)
				reader.Close()
				if err != nil || !bytes.Equal(body, newBody) {
					t.Errorf("migration could not read selected object data: %v", err)
				}
				names = append(names, entry.name)
			}
			var err error
			if kind == "rebalance" {
				err = set.listObjectsToRebalance(t.Context(), bucket, consume)
			} else {
				err = set.listObjectsToDecommission(t.Context(), decomBucketInfo{Name: bucket}, consume)
			}
			if err != nil || !slices.Equal(names, []string{object}) {
				t.Fatalf("migration listing skipped a readable object: %v, %v", names, err)
			}
		})
	}
}
