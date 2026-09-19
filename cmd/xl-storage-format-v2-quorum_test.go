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
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"testing"
	"time"
)

// Use complete metadata so the selected version can also be decoded by LIST
// and the object read path, rather than testing only synthetic shallow headers.
func quorumNullVersion(t testing.TB, generation int64) xlMetaV2ShallowVersion {
	t.Helper()
	fi := newFileInfo("fixed/object", 12, 4)
	fi.Erasure.Index = 1
	fi.DataDir = "11111111-1111-1111-1111-111111111111"
	fi.ModTime = time.Unix(generation, 0).UTC()
	fi.Size = 8192
	fi.Parts = []ObjectPartInfo{{Number: 1, Size: fi.Size, ActualSize: fi.Size}}
	fi.Metadata = map[string]string{"etag": fmt.Sprintf("%032d", generation)}
	var xl xlMetaV2
	if err := xl.AddVersion(fi); err != nil {
		t.Fatal(err)
	}
	return xl.versions[0]
}

// Start with forward, reverse and interleaved orders, then fixed-seed shuffles.
func quorumVersionOrders(input [][]xlMetaV2ShallowVersion) [][][]xlMetaV2ShallowVersion {
	orders := [][][]xlMetaV2ShallowVersion{slices.Clone(input), slices.Clone(input)}
	slices.Reverse(orders[1])
	interleaved := make([][]xlMetaV2ShallowVersion, 0, len(input))
	for i, j := 0, len(input)-1; i <= j; i, j = i+1, j-1 {
		interleaved = append(interleaved, input[i])
		if i != j {
			interleaved = append(interleaved, input[j])
		}
	}
	orders = append(orders, interleaved)
	for seed := range int64(32) {
		order := slices.Clone(input)
		rand.New(rand.NewSource(seed)).Shuffle(len(order), func(i, j int) {
			order[i], order[j] = order[j], order[i]
		})
		orders = append(orders, order)
	}
	return orders
}

func TestMergeXLV2SingleNullQuorum(t *testing.T) {
	v := []xlMetaV2ShallowVersion{quorumNullVersion(t, 100), quorumNullVersion(t, 200), quorumNullVersion(t, 300)}
	for _, tt := range []struct {
		name   string
		counts [3]int
		empty  int
		quorum int
		want   int
	}{
		{"consistent", [3]int{16}, 0, 8, 0},
		{"old9-new7", [3]int{9, 7}, 0, 8, 0},
		{"old15-new1", [3]int{15, 1}, 0, 8, 0},
		{"old3-new1", [3]int{3, 1}, 0, 3, 0},
		{"two-quorums", [3]int{8, 8}, 0, 8, 1},
		{"empty-streams", [3]int{9, 1}, 6, 8, 0},
		{"two-subquorums", [3]int{7, 7}, 2, 8, -1},
		{"three-subquorums", [3]int{6, 5, 5}, 0, 8, -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var input [][]xlMetaV2ShallowVersion
			for g, n := range tt.counts {
				for range n {
					input = append(input, []xlMetaV2ShallowVersion{v[g]})
				}
			}
			input = append(input, make([][]xlMetaV2ShallowVersion, tt.empty)...)
			want := []xlMetaV2ShallowVersion{}
			if tt.want >= 0 {
				want = append(want, v[tt.want])
			}
			for order, versions := range quorumVersionOrders(input) {
				for _, strict := range []bool{false, true} {
					for _, requested := range []int{0, 1} {
						got := mergeXLV2Versions(tt.quorum, strict, requested, versions...)
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("order=%d strict=%v requested=%d: got %#v, want %#v", order, strict, requested, got, want)
						}
					}
				}
			}
		})
	}
}

func TestMergeXLV2SingleNullHeaderGroups(t *testing.T) {
	old := quorumNullVersion(t, 100)
	newer := quorumNullVersion(t, 200)
	differentSig := old
	differentSig.header.Signature[0]++
	differentFlags := old
	differentFlags.header.Flags ^= xlFlagInlineData
	for _, tt := range []struct {
		name   string
		input  [][]xlMetaV2ShallowVersion
		strict bool
		want   []xlMetaV2ShallowVersion
	}{
		{"signature-nonstrict", [][]xlMetaV2ShallowVersion{{old}, {old}, {differentSig}, {newer}}, false, []xlMetaV2ShallowVersion{differentSig}},
		{"signature-strict", [][]xlMetaV2ShallowVersion{{old}, {old}, {differentSig}, {newer}}, true, []xlMetaV2ShallowVersion{}},
		{"flags-nonstrict", [][]xlMetaV2ShallowVersion{{old}, {old}, {differentFlags}, {newer}}, false, []xlMetaV2ShallowVersion{}},
		{"flags-strict", [][]xlMetaV2ShallowVersion{{old}, {old}, {differentFlags}, {newer}}, true, []xlMetaV2ShallowVersion{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeXLV2Versions(3, tt.strict, 0, tt.input...)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestResolveSingleNullQuorum(t *testing.T) {
	old, newer := quorumNullVersion(t, 100), quorumNullVersion(t, 200)
	input := make([][]xlMetaV2ShallowVersion, 16)
	for i := range input {
		input[i] = []xlMetaV2ShallowVersion{old}
		if i >= 9 {
			input[i] = []xlMetaV2ShallowVersion{newer}
		}
	}
	for order, versions := range quorumVersionOrders(input) {
		entries := make(metaCacheEntries, len(versions))
		for i := range versions {
			xl := &xlMetaV2{versions: versions[i]}
			metadata, err := xl.AppendTo(nil)
			if err != nil {
				t.Fatal(err)
			}
			entries[i] = metaCacheEntry{name: "fixed/object", metadata: metadata}
		}
		selected, ok := entries.resolve(&metadataResolutionParams{objQuorum: 8, dirQuorum: 8, requestedVersions: 1})
		if !ok {
			t.Fatalf("order %d: a complete null object version has quorum but was omitted", order)
		}
		xl, err := selected.xlmeta()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(xl.versions, []xlMetaV2ShallowVersion{old}) {
			t.Fatalf("order %d: incorrect complete selected version: %#v", order, xl.versions)
		}
		fi, err := xl.ToFileInfo("bucket", "fixed/object", "", false, false)
		if err != nil || !fi.IsValid() || fi.Size != 8192 || !fi.ModTime.Equal(time.Unix(100, 0)) {
			t.Fatalf("order %d: selected metadata cannot be read: %+v, %v", order, fi, err)
		}
	}
}

// These are compatibility assertions for inputs outside the narrow repair.
// In particular, the mixed-version outputs below are not a new correctness
// contract for version enumeration; that behavior requires a separate change.
func TestMergeXLV2NullHistoriesUnchanged(t *testing.T) {
	old, newer := quorumNullVersion(t, 100), quorumNullVersion(t, 300)
	middle := quorumNullVersion(t, 200)
	middle.header.VersionID = [16]byte{1}
	highest := quorumNullVersion(t, 400)
	highest.header.VersionID = [16]byte{2}
	for _, tt := range []struct {
		name  string
		input [][]xlMetaV2ShallowVersion
		want  []xlMetaV2ShallowVersion
	}{
		{"mixed-forward", [][]xlMetaV2ShallowVersion{{old}, {old}, {old}, {newer, middle}, {middle}, {middle}}, []xlMetaV2ShallowVersion{middle}},
		{"mixed-reverse", [][]xlMetaV2ShallowVersion{{middle}, {middle}, {newer, middle}, {old}, {old}, {old}}, []xlMetaV2ShallowVersion{old}},
		{"history-pruned-first", [][]xlMetaV2ShallowVersion{{highest, old}, {highest, old}, {highest, old}, {highest, newer}}, []xlMetaV2ShallowVersion{highest}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeXLV2Versions(3, false, 0, tt.input...)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("excluded history changed: got %#v, want %#v", got, tt.want)
			}
		})
	}
	for _, kind := range []string{"delete", "free", "legacy", "mixed-ec", "legacy-modern-ec", "nonzero-strict"} {
		t.Run(kind, func(t *testing.T) {
			a, b := old, newer
			switch kind {
			case "delete":
				b.header.Type = DeleteType
			case "free":
				b.header.Flags |= xlFlagFreeVersion
			case "legacy":
				b.header.Type = LegacyType
			case "mixed-ec":
				b.header.EcN, b.header.EcM = 8, 8
			case "legacy-modern-ec":
				b.header.EcN, b.header.EcM = 0, 0
			case "nonzero-strict":
				a.header.VersionID, b.header.VersionID = [16]byte{1}, [16]byte{1}
			}
			for _, requested := range []int{0, 1} {
				got := mergeXLV2Versions(3, true, requested, []xlMetaV2ShallowVersion{a}, []xlMetaV2ShallowVersion{a}, []xlMetaV2ShallowVersion{a}, []xlMetaV2ShallowVersion{b})
				if len(got) != 0 {
					t.Fatalf("excluded input changed: requested=%d got %#v", requested, got)
				}
			}
		})
	}
	// All-legacy EC headers are eligible, unlike mixing legacy and modern EC.
	old.header.EcN, old.header.EcM = 0, 0
	newer.header.EcN, newer.header.EcM = 0, 0
	got := mergeXLV2Versions(3, false, 0, []xlMetaV2ShallowVersion{old}, []xlMetaV2ShallowVersion{old}, []xlMetaV2ShallowVersion{old}, []xlMetaV2ShallowVersion{newer})
	if !reflect.DeepEqual(got, []xlMetaV2ShallowVersion{old}) {
		t.Fatalf("all-legacy EC lost the old quorum: %#v", got)
	}
}

func BenchmarkResolveSingleNullQuorumPage(b *testing.B) {
	old, newer := quorumNullVersion(b, 100), quorumNullVersion(b, 200)
	for _, kind := range []string{"consistent", "old-first", "new-first"} {
		b.Run(kind, func(b *testing.B) {
			var templates [16]metaCacheEntry
			for i := range templates {
				v := old
				if kind == "old-first" && i >= 9 || kind == "new-first" && i < 7 {
					v = newer
				}
				xl := &xlMetaV2{versions: []xlMetaV2ShallowVersion{v}}
				data, err := xl.AppendTo(nil)
				if err != nil {
					b.Fatal(err)
				}
				templates[i] = metaCacheEntry{metadata: data}
			}
			var names [1000]string
			for i := range names {
				names[i] = fmt.Sprintf("fixed/%04d", i)
			}
			resolver := metadataResolutionParams{objQuorum: 8, dirQuorum: 8, requestedVersions: 1}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				for _, name := range names {
					entries := templates
					for i := range entries {
						entries[i].name = name
					}
					selected, ok := metaCacheEntries(entries[:]).resolve(&resolver)
					if ok && selected.reusable {
						metaDataPoolPut(selected.metadata)
					}
				}
			}
		})
	}
}

// mixedParityNullVersion builds a complete null version like quorumNullVersion
// but with the given parity regime, as produced by writes to a degraded set.
func mixedParityNullVersion(t testing.TB, generation int64, data, parity int) xlMetaV2ShallowVersion {
	t.Helper()
	fi := newFileInfo("fixed/object", data, parity)
	fi.Erasure.Index = 1
	fi.DataDir = "11111111-1111-1111-1111-111111111111"
	fi.ModTime = time.Unix(generation, 0).UTC()
	fi.Size = 8192
	fi.Parts = []ObjectPartInfo{{Number: 1, Size: fi.Size, ActualSize: fi.Size}}
	fi.Metadata = map[string]string{"etag": fmt.Sprintf("%032d", generation)}
	var xl xlMetaV2
	if err := xl.AddVersion(fi); err != nil {
		t.Fatal(err)
	}
	return xl.versions[0]
}

// A rolling restart makes writes use a reduced parity regime while a node is
// down (8 data + 8 parity on a 16-drive set) and the full regime otherwise
// (12 data + 4 parity). A key overwritten in both regimes is then split across
// two parity regimes, and the newest generation was written with write quorum
// (9 of the 12 asked drives). The merge must select the quorate generation
// regardless of the other generation's erasure parameters or the drive order.
// Captured from a failing ListObjects request in issue #218.
func TestMergeXLV2QuorateGenerationAcrossParityRegimes(t *testing.T) {
	newer := mixedParityNullVersion(t, 200, 8, 8)
	older := mixedParityNullVersion(t, 100, 12, 4)
	if newer.header.EcM == older.header.EcM {
		t.Fatalf("test expects two parity regimes, both have EcM %d", newer.header.EcM)
	}
	input := make([][]xlMetaV2ShallowVersion, 0, 12)
	for range 9 {
		input = append(input, []xlMetaV2ShallowVersion{newer})
	}
	for range 3 {
		input = append(input, []xlMetaV2ShallowVersion{older})
	}
	want := []xlMetaV2ShallowVersion{newer}
	for order, versions := range quorumVersionOrders(input) {
		for _, requested := range []int{0, 1} {
			got := mergeXLV2Versions(6, false, requested, versions...)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("order=%d requested=%d: got %#v, want the quorate newest version", order, requested, got)
			}
		}
		if got := mergeXLV2Versions(6, true, 1, versions...); !reflect.DeepEqual(got, want) {
			t.Fatalf("order=%d strict: got %#v, want the exact quorate header group", order, got)
		}
	}

	// The reverse shape is not readable: the older 12+4 generation has only 9
	// of its required 12 data blocks, while the newer generation is a minority.
	input = make([][]xlMetaV2ShallowVersion, 0, 12)
	for range 9 {
		input = append(input, []xlMetaV2ShallowVersion{older})
	}
	for range 3 {
		input = append(input, []xlMetaV2ShallowVersion{newer})
	}
	for order, versions := range quorumVersionOrders(input) {
		got := mergeXLV2Versions(6, false, 1, versions...)
		if len(got) != 0 {
			t.Fatalf("order=%d: got %#v, want no generation below its read quorum", order, got)
		}
	}

	// The older generation can be selected once all 12 required shards are
	// available, even with a newer failed-write minority.
	input = make([][]xlMetaV2ShallowVersion, 0, 16)
	for range 12 {
		input = append(input, []xlMetaV2ShallowVersion{older})
	}
	for range 4 {
		input = append(input, []xlMetaV2ShallowVersion{newer})
	}
	want = []xlMetaV2ShallowVersion{older}
	for order, versions := range quorumVersionOrders(input) {
		got := mergeXLV2Versions(8, false, 1, versions...)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("order=%d: got %#v, want the write-quorate older version", order, got)
		}
	}

	// A generation that lost one shard after a successful 8+8 write remains
	// readable with its 8 data blocks and must not disappear from LIST.
	input = make([][]xlMetaV2ShallowVersion, 0, 12)
	for range 8 {
		input = append(input, []xlMetaV2ShallowVersion{newer})
	}
	for range 4 {
		input = append(input, []xlMetaV2ShallowVersion{older})
	}
	want = []xlMetaV2ShallowVersion{newer}
	for order, versions := range quorumVersionOrders(input) {
		if got := mergeXLV2Versions(6, false, 1, versions...); !reflect.DeepEqual(got, want) {
			t.Fatalf("order=%d: got %#v, want the readable newer generation", order, got)
		}
	}

	// Below quorum nothing may be emitted, across parity regimes as well.
	input = make([][]xlMetaV2ShallowVersion, 0, 8)
	for range 5 {
		input = append(input, []xlMetaV2ShallowVersion{newer})
	}
	for range 3 {
		input = append(input, []xlMetaV2ShallowVersion{older})
	}
	for order, versions := range quorumVersionOrders(input) {
		if got := mergeXLV2Versions(6, false, 1, versions...); len(got) != 0 {
			t.Fatalf("order=%d: got %#v, want no version below quorum", order, got)
		}
	}
}

func TestPickLatestQuorumFilesInfoAcrossParityRegimes(t *testing.T) {
	newer := mixedParityNullVersion(t, 200, 8, 8)
	older := mixedParityNullVersion(t, 100, 12, 4)
	raw := make([]RawFileInfo, 16)
	errs := make([]error, 16)
	for i := range raw {
		var version xlMetaV2ShallowVersion
		switch {
		case i < 8:
			version = newer
		case i < 12:
			version = older
		default:
			errs[i] = errDiskNotFound
			continue
		}
		xl := xlMetaV2{versions: []xlMetaV2ShallowVersion{version}}
		var err error
		raw[i].Buf, err = xl.AppendTo(nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	metadata, errs := pickLatestQuorumFilesInfo(t.Context(), raw, errs, "bucket", "fixed/object", true, false)
	readQuorum, _, err := objectQuorumFromMeta(t.Context(), metadata, errs, 4)
	if err != nil || readQuorum != 8 {
		t.Fatalf("read quorum: got %d, %v; want 8, nil", readQuorum, err)
	}
	fi, err := findFileInfoInQuorum(t.Context(), metadata, time.Unix(200, 0).UTC(), "", readQuorum)
	if err != nil || !fi.ModTime.Equal(time.Unix(200, 0)) {
		t.Fatalf("readable cross-parity generation was not resolved: %+v, %v", fi, err)
	}
}

func TestMergeXLV2MixedParityHistoriesUnchanged(t *testing.T) {
	newer := mixedParityNullVersion(t, 200, 8, 8)
	older := mixedParityNullVersion(t, 100, 12, 4)
	history := mixedParityNullVersion(t, 50, 12, 4)
	history.header.VersionID = [16]byte{1}

	input := make([][]xlMetaV2ShallowVersion, 0, 12)
	for range 9 {
		input = append(input, []xlMetaV2ShallowVersion{newer, history})
	}
	for range 3 {
		input = append(input, []xlMetaV2ShallowVersion{older, history})
	}
	if got, want := mergeXLV2Versions(6, false, 1, input...), []xlMetaV2ShallowVersion{history}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mixed-version behavior changed: got %#v, want %#v", got, want)
	}
}
