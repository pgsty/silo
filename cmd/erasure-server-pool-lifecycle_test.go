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
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
)

// The scanner, the drive heal and a GET or HEAD of a version evaluate ILM on
// the versions of a key in one pool: IsLatest, NumVersions and SuccessorModTime
// count only these. A key can have versions in several pools: two concurrent
// first writes, overwrites that went to another pool. The expiry they decide
// runs in every pool.

// splitILM lays out the versions of keys in the two pools of migrationILM.
type splitILM struct {
	*migrationILM
	ids    map[string]string // object and label -> version ID
	bodies map[string]string // body -> label
}

func newSplitILM(t *testing.T, status versioning.State, rules string) *splitILM {
	t.Helper()
	return &splitILM{migrationILM: newMigrationILM(t, status, false, rules), ids: map[string]string{}, bodies: map[string]string{}}
}

// splitVersion is a version of a key in a test layout.
type splitVersion struct {
	pools  []int // the pools that hold a copy of it
	label  string
	days   float64 // its age
	marker bool
	tiered bool // its data is in a remote tier
	null   bool // a null version (unversioned or suspended bucket)
	size   int  // its size, at least the size of its label
}

func (s *splitILM) write(object string, v splitVersion) {
	s.t.Helper()
	ctx := s.t.Context()
	mtime := UTCNow().Add(-time.Duration(v.days * float64(24*time.Hour)))
	versionID := mustGetUUID()
	if v.null {
		versionID = ""
	}
	for _, pool := range v.pools {
		if v.marker {
			_, err := s.z.serverPools[pool].DeleteObject(ctx, s.bucket, object,
				ObjectOptions{Versioned: true, VersionID: versionID, DeleteMarker: true, MTime: mtime})
			if err != nil {
				s.t.Fatal(err)
			}
			continue
		}
		opts := ObjectOptions{Versioned: !v.null, VersionID: versionID, MTime: mtime}
		if v.null && s.status() == versioning.Suspended {
			opts = ObjectOptions{VersionSuspended: true, MTime: mtime}
		}
		body := object + " " + v.label
		if len(body) < v.size {
			body += strings.Repeat(".", v.size-len(body))
		}
		putConsistencyObject(s.t, s.z, s.bucket, object, pool, body, opts)
		s.bodies[body] = v.label
		if v.tiered {
			vid := versionID
			if vid == "" {
				vid = nullVersionID
			}
			infos, errs := readAllFileInfo(ctx, s.z.serverPools[pool].getHashedSet(object).getDisks(), "", s.bucket, object, vid, false, false)
			if errs[0] != nil {
				s.t.Fatal(errs[0])
			}
			fi := infos[0]
			fi.TransitionStatus, fi.TransitionTier, fi.TransitionedObjName = lifecycle.TransitionComplete, "WARM", "remote-"+v.label
			if err := s.z.serverPools[pool].DecomTieredObject(ctx, s.bucket, object, fi, ObjectOptions{}); err != nil {
				s.t.Fatal(err)
			}
		}
	}
	if v.marker {
		s.markers[s.key(object, versionID)] = v.label
	} else {
		s.labels[s.key(object, versionID)] = v.label
	}
	s.ids[object+" "+v.label] = versionID
	s.track(object)
}

func (s *splitILM) status() versioning.State {
	vc, _ := globalBucketVersioningSys.Get(s.bucket)
	if vc == nil {
		return ""
	}
	return vc.Status
}

// scan applies ILM to every object in a pool as the scanner of a drive of
// that pool does, from the xl.meta of that drive, and runs the queued
// expiries as an expiry worker does.
func (s *splitILM) scan(pool int) {
	s.t.Helper()
	ctx := s.t.Context()
	lc, err := globalLifecycleSys.Get(s.bucket)
	if err != nil {
		s.t.Fatal(err)
	}
	lr, err := globalBucketObjectLockSys.Get(s.bucket)
	if err != nil {
		s.t.Fatal(err)
	}
	vc, _ := globalBucketVersioningSys.Get(s.bucket)
	for _, object := range s.objects {
		disk := s.z.serverPools[pool].getHashedSet(object).getDisks()[0]
		rf, err := disk.ReadXL(ctx, s.bucket, object, false)
		if err != nil {
			continue // not in this pool
		}
		fivs, err := getFileInfoVersions(rf.Buf, s.bucket, object, false)
		if err != nil {
			s.t.Fatal(err)
		}
		objInfos := make([]ObjectInfo, len(fivs.Versions))
		for i, fi := range fivs.Versions {
			objInfos[i] = fi.ToObjectInfo(s.bucket, object, vc != nil && vc.Versioned(object))
		}
		item := scannerItem{bucket: s.bucket, objectName: object, lifeCycle: lc}
		item.applyActions(ctx, s.z, objInfos, lr, &sizeSummary{}, nil)
	}
	s.runQueue()
}

// head applies ILM to a version as a HEAD or GET with its versionId does.
func (s *splitILM) head(object, label string) lifecycle.Action {
	s.t.Helper()
	ctx := s.t.Context()
	oi, err := s.z.GetObjectInfo(ctx, s.bucket, object, ObjectOptions{VersionID: s.ids[object+" "+label]})
	if err != nil {
		s.t.Fatal(err)
	}
	lc, err := globalLifecycleSys.Get(s.bucket)
	if err != nil {
		s.t.Fatal(err)
	}
	lr, err := globalBucketObjectLockSys.Get(s.bucket)
	if err != nil {
		s.t.Fatal(err)
	}
	evt := evalActionFromLifecycle(ctx, *lc, lr, nil, oi)
	if evt.Action.Delete() {
		applyExpiryRule(evt, lcEventSrc_s3HeadObject, oi)
	}
	s.runQueue()
	return evt.Action
}

// runQueue runs the queued expiries with an expiry worker.
func (s *splitILM) runQueue() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		globalExpiryState.Worker(s.queue)
	}()
	s.queue <- nil // the worker returns once it ran every expiry queued before
	<-done
}

// get returns the label of the version a GET of object reads, or "-" when it
// reads as deleted.
func (s *splitILM) get(object string) string {
	s.t.Helper()
	ctx := s.t.Context()
	oi, err := s.z.GetObjectInfo(ctx, s.bucket, object, ObjectOptions{})
	if err != nil {
		if isErrObjectNotFound(err) || isErrVersionNotFound(err) || isErrMethodNotAllowed(err) {
			return "-"
		}
		return fmt.Sprintf("<%v>", err)
	}
	if oi.VersionID != "" && oi.VersionID != nullVersionID {
		return s.label(object, oi.VersionID, false)
	}
	// Copies of a null version in two pools are told apart by their data.
	gr, err := s.z.GetObjectNInfo(ctx, s.bucket, object, nil, nil, ObjectOptions{})
	if err != nil {
		return fmt.Sprintf("<%v>", err)
	}
	defer gr.Close()
	data, err := io.ReadAll(gr)
	if err != nil {
		s.t.Fatal(err)
	}
	if l, ok := s.bodies[string(data)]; ok {
		return l
	}
	return "?" + string(data)
}

// views returns the versions of each object in each pool, newest first.
func (s *splitILM) views() []map[string][]string {
	views := make([]map[string][]string, len(s.z.serverPools))
	for pool := range s.z.serverPools {
		views[pool] = s.view(pool)
	}
	return views
}

type splitKey struct {
	name     string
	versions []splitVersion
	before   string     // what a GET reads before ILM ran
	after    string     // what a GET reads once ILM ran
	want     [][]string // versions in each pool once ILM ran, nil to skip
}

// run lays out keys, runs two scanner cycles over all pools and checks that
// a GET of each key never reads anything but before or after, and the
// versions each pool holds at the end. The second cycle must not change
// anything.
func (s *splitILM) run(keys []splitKey) {
	s.t.Helper()
	for _, k := range keys {
		for _, v := range k.versions {
			s.write(k.name, v)
		}
		if got := s.get(k.name); got != k.before {
			s.t.Fatalf("%s: fixture reads %s, want %s", k.name, got, k.before)
		}
	}
	var first []map[string][]string
	for cycle := 1; cycle <= 2; cycle++ {
		for pool := range s.z.serverPools {
			s.scan(pool)
			for _, k := range keys {
				if got := s.get(k.name); got != k.before && got != k.after {
					s.t.Errorf("%s: reads %s after the scanner of pool %d (cycle %d), want %s", k.name, got, pool, cycle, k.after)
				}
			}
		}
		if cycle == 1 {
			first = s.views()
		}
	}
	last := s.views()
	for _, k := range keys {
		if got := s.get(k.name); got != k.after {
			s.t.Errorf("%s: reads %s once ILM ran, want %s", k.name, got, k.after)
		}
		for pool := range last {
			if !slices.Equal(first[pool][k.name], last[pool][k.name]) {
				s.t.Errorf("%s: the second scanner cycle changed pool %d from %v to %v", k.name, pool, first[pool][k.name], last[pool][k.name])
			}
			if k.want != nil && !slices.Equal(last[pool][k.name], k.want[pool]) {
				s.t.Errorf("%s: pool %d holds %v, want %v", k.name, pool, last[pool][k.name], k.want[pool])
			}
		}
	}
}

const splitILMRules = "<Rule><ID>exp</ID><Status>Enabled</Status><Filter><Prefix>exp-</Prefix></Filter>" +
	"<Expiration><Days>1</Days></Expiration></Rule>" +
	"<Rule><ID>eav</ID><Status>Enabled</Status><Filter><Prefix>eav-</Prefix></Filter>" +
	"<Expiration><Days>1</Days><ExpiredObjectAllVersions>true</ExpiredObjectAllVersions></Expiration></Rule>" +
	"<Rule><ID>edm</ID><Status>Enabled</Status><Filter><Prefix>edm-</Prefix></Filter>" +
	"<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>" +
	"<Rule><ID>dme</ID><Status>Enabled</Status><Filter><Prefix>dme-</Prefix></Filter>" +
	"<DelMarkerExpiration><Days>1</Days></DelMarkerExpiration></Rule>" +
	"<Rule><ID>ncv</ID><Status>Enabled</Status><Filter><Prefix>ncv-</Prefix></Filter>" +
	"<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>" +
	"<Rule><ID>exs</ID><Status>Enabled</Status><Filter><And><Prefix>exs-</Prefix><ObjectSizeGreaterThan>100</ObjectSizeGreaterThan></And></Filter>" +
	"<Expiration><Days>1</Days></Expiration></Rule>" +
	"<Rule><ID>nnv</ID><Status>Enabled</Status><Filter><Prefix>nnv-</Prefix></Filter>" +
	"<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>1</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule>"

func splitAt(label string, days float64, pools ...int) splitVersion {
	return splitVersion{pools: pools, label: label, days: days}
}

func splitMarker(label string, days float64, pools ...int) splitVersion {
	return splitVersion{pools: pools, label: label, days: days, marker: true}
}

func splitTiered(label string, days float64, pools ...int) splitVersion {
	return splitVersion{pools: pools, label: label, days: days, tiered: true}
}

func splitNull(label string, days float64, pools ...int) splitVersion {
	return splitVersion{pools: pools, label: label, days: days, null: true}
}

// splitILMOnePool are keys in one pool. ILM applies to them as usual.
func splitILMOnePool(pool int) []splitKey {
	in := func(vs ...string) [][]string {
		want := [][]string{nil, nil}
		want[pool] = vs
		return want
	}
	return []splitKey{
		{"exp-one", []splitVersion{splitAt("v1", 5, pool), splitAt("v2", 4, pool)}, "v2", "-", in("DM", "v2", "v1")},
		{"exp-one-tiered", []splitVersion{splitAt("v1", 5, pool), splitTiered("v2", 4, pool)}, "v2", "-", in("DM", "v2", "v1")},
		{"eav-one", []splitVersion{splitAt("v1", 5, pool), splitAt("v2", 4, pool)}, "v2", "-", in()},
		{"edm-one", []splitVersion{splitMarker("dm", 3, pool)}, "-", "-", in()},
		{"dme-one", []splitVersion{splitAt("v1", 5, pool), splitMarker("dm", 3, pool)}, "-", "-", in()},
		{"ncv-one", []splitVersion{splitAt("v1", 5, pool), splitAt("v2", 4, pool), splitAt("v3", 0.01, pool)}, "v3", "v3", in("v3", "v2")},
		{"nnv-one", []splitVersion{splitAt("v1", 5, pool), splitAt("v2", 4, pool), splitAt("v3", 3, pool), splitAt("v4", 2, pool)}, "v4", "v4", in("v4", "v3")},
	}
}

func TestPoolsLifecycleSplitObject(t *testing.T) {
	t.Run("versioned", func(t *testing.T) {
		s := newSplitILM(t, versioning.Enabled, splitILMRules)
		s.run([]splitKey{
			// Expiration with Days applies to the current version v2 only.
			{"exp-old-in-0", []splitVersion{splitAt("v1", 5, 0), splitAt("v2", 0.01, 1)}, "v2", "v2", [][]string{{"v1"}, {"v2"}}},
			{"exp-old-in-1", []splitVersion{splitAt("v2", 0.01, 0), splitAt("v1", 5, 1)}, "v2", "v2", [][]string{{"v2"}, {"v1"}}},
			{"exp-tiered-old-in-0", []splitVersion{splitTiered("v1", 5, 0), splitAt("v2", 0.01, 1)}, "v2", "v2", [][]string{{"v1"}, {"v2"}}},
			// v2 is old enough: one delete marker hides the key.
			{"exp-both-old", []splitVersion{splitAt("v1", 5, 0), splitAt("v2", 4, 1)}, "v2", "-", [][]string{{"DM", "v1"}, {"v2"}}},
			// The rule applies to v2 only by its size.
			{"exs-big-in-1", []splitVersion{splitAt("v1", 5, 0), {pools: []int{1}, label: "v2", days: 4, size: 200}}, "v2", "-", [][]string{{"DM", "v1"}, {"v2"}}},
			// The marker hides v1 and is not a marker without noncurrent
			// versions; v1 is not the current version.
			{"exp-marker-in-0", []splitVersion{splitAt("v1", 5, 1), splitMarker("dm", 3, 0)}, "-", "-", [][]string{{"dm"}, {"v1"}}},
			// ExpiredObjectAllVersions applies to the current version v2 only.
			{"eav-old-in-0", []splitVersion{splitAt("v1", 5, 0), splitAt("v2", 0.01, 1)}, "v2", "v2", [][]string{{"v1"}, {"v2"}}},
			{"eav-old-in-1", []splitVersion{splitAt("v2", 0.01, 0), splitAt("v1", 5, 1)}, "v2", "v2", [][]string{{"v2"}, {"v1"}}},
			{"eav-tiered-old-in-0", []splitVersion{splitTiered("v1", 5, 0), splitAt("v2", 0.01, 1)}, "v2", "v2", [][]string{{"v1"}, {"v2"}}},
			{"eav-both-old", []splitVersion{splitAt("v1", 5, 0), splitAt("v2", 4, 1)}, "v2", "-", [][]string{nil, nil}},
			// A copy of v1 in both pools, as an interrupted move leaves it.
			{"eav-copies", []splitVersion{splitAt("v1", 5, 0, 1)}, "v1", "-", [][]string{nil, nil}},
			// The marker hides v1 in the other pool.
			{"edm-marker-in-0", []splitVersion{splitAt("v1", 5, 1), splitMarker("dm", 3, 0)}, "-", "-", [][]string{{"dm"}, {"v1"}}},
			{"edm-marker-in-1", []splitVersion{splitAt("v1", 5, 0), splitMarker("dm", 3, 1)}, "-", "-", [][]string{{"v1"}, {"dm"}}},
			{"edm-copies", []splitVersion{splitMarker("dm", 3, 0, 1)}, "-", "-", [][]string{nil, nil}},
			// v2 in the other pool is the current version, the marker does
			// not expire.
			{"dme-new-in-1", []splitVersion{splitMarker("dm", 3, 0), splitAt("v2", 0.01, 1)}, "v2", "v2", [][]string{{"dm"}, {"v2"}}},
			{"dme-new-in-0", []splitVersion{splitAt("v2", 0.01, 0), splitMarker("dm", 3, 1)}, "v2", "v2", [][]string{{"v2"}, {"dm"}}},
			// The marker is the current version and expires with v1.
			{"dme-old-in-0", []splitVersion{splitAt("v1", 5, 0), splitMarker("dm", 3, 1)}, "-", "-", [][]string{nil, nil}},
			// v1 is noncurrent since v2 was written, v2 since v3 was.
			{"ncv-split", []splitVersion{splitAt("v1", 5, 0), splitAt("v2", 4, 1), splitAt("v3", 2, 0)}, "v3", "v3", [][]string{{"v3"}, {"v2"}}},
		})
	})
	t.Run("versioned/one-pool", func(t *testing.T) {
		for pool := range 2 {
			s := newSplitILM(t, versioning.Enabled, splitILMRules)
			s.run(splitILMOnePool(pool))
		}
	})
	t.Run("versioned/head-version", func(t *testing.T) {
		s := newSplitILM(t, versioning.Enabled, splitILMRules)
		keys := []splitKey{
			{"exp-old-in-0", []splitVersion{splitAt("v1", 5, 0), splitAt("v2", 0.01, 1)}, "v2", "v2", [][]string{{"v1"}, {"v2"}}},
			{"eav-old-in-0", []splitVersion{splitAt("v1", 5, 0), splitAt("v2", 0.01, 1)}, "v2", "v2", [][]string{{"v1"}, {"v2"}}},
		}
		for _, k := range keys {
			for _, v := range k.versions {
				s.write(k.name, v)
			}
			act := s.head(k.name, "v1")
			t.Logf("%s: HEAD of v1 evaluates %s", k.name, act)
			if got := s.get(k.name); got != k.after {
				t.Errorf("%s: reads %s after a HEAD of v1, want %s", k.name, got, k.after)
			}
			views := s.views()
			for pool := range views {
				if !slices.Equal(views[pool][k.name], k.want[pool]) {
					t.Errorf("%s: pool %d holds %v, want %v", k.name, pool, views[pool][k.name], k.want[pool])
				}
			}
		}
	})
	t.Run("suspended", func(t *testing.T) {
		s := newSplitILM(t, versioning.Suspended, splitILMRules)
		s.run([]splitKey{
			{"exp-null-old-in-0", []splitVersion{splitNull("v1", 5, 0), splitAt("v2", 0.01, 1)}, "v2", "v2", [][]string{{"v1"}, {"v2"}}},
		})
	})
	t.Run("unversioned", func(t *testing.T) {
		s := newSplitILM(t, "", splitILMRules)
		s.run([]splitKey{
			{"eav-old-in-0", []splitVersion{splitNull("old", 5, 0), splitNull("new", 0.01, 1)}, "new", "new", nil},
			{"exp-old-in-0", []splitVersion{splitNull("old", 5, 0), splitNull("new", 0.01, 1)}, "new", "new", nil},
		})
		views := s.views()
		for object, want := range map[string]int{"eav-old-in-0": 1, "exp-old-in-0": 0} {
			if len(views[0][object]) != want || len(views[1][object]) != 1 {
				t.Errorf("%s: pools hold %v and %v, want %d and 1 copies", object, views[0][object], views[1][object], want)
			}
		}
	})
}
