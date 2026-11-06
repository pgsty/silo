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
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/minio/minio/internal/bucket/lifecycle"
)

// An expiry of all versions that does not remove the key is counted by why,
// traced with that reason, and sends no removal event. The scanner does not
// queue one that the purge would refuse for a tiered version it holds, and
// it accounts the versions of a key under such an expiry at their sizes.

// incompleteDelta runs f and returns by how much each reason of
// expiry_incomplete_total grew.
func incompleteDelta(f func()) map[string]int64 {
	before := globalILMIncomplete.snapshot()
	f()
	after := globalILMIncomplete.snapshot()
	delta := map[string]int64{}
	for r, n := range after {
		if d := n - before[r]; d != 0 {
			delta[r] = d
		}
	}
	return delta
}

func TestPurgeAllVersionsRefusalReasons(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-reasons", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	o := observePurges(t)
	expect := func(what string, ops []expiryOp, reason, result string) map[string]string {
		t.Helper()
		o.drain()
		delta := incompleteDelta(func() { p.run(ops) })
		if delta[reason] != 1 {
			t.Errorf("%s: counted %v, want one %s", what, delta, reason)
		}
		events, traces := o.drain()
		if len(events) != 0 {
			t.Errorf("%s: sent %v", what, events)
		}
		if len(traces) != 1 || traces[0]["result"] != result || traces[0]["reason"] != reason {
			t.Fatalf("%s: traced %v, want one %s expiry for %s", what, traces, result, reason)
		}
		return traces[0]
	}

	// A version in a remote tier: refused, the key kept.
	p.tiered(0, "ea/tiered", "v1", 6)
	p.version(0, "ea/tiered", "v2", 5)
	expect("tiered", []expiryOp{p.deleteAllTask(0, "ea/tiered", lifecycle.DeleteAllVersionsAction)}, ilmIncompleteTierUnsupported, "refused")
	if got := p.held(0, "ea/tiered"); !slices.Equal(got, []string{"hot", "tiered"}) {
		t.Errorf("tiered key holds %v", got)
	}

	// A drive that cannot be read: failed, the key kept.
	p.version(0, "ea/unreadable", "v1", 5)
	ops := []expiryOp{p.deleteAllTask(0, "ea/unreadable", lifecycle.DeleteAllVersionsAction)}
	sets := z.serverPools[0]
	index := sets.getHashedSetIndex("ea/unreadable")
	sets.erasureDisksMu.Lock()
	prior := sets.erasureDisks[index][0]
	sets.erasureDisks[index][0] = authorityDisk{StorageAPI: prior, bucket: p.bucket, key: "ea/unreadable", failRead: true}
	sets.erasureDisksMu.Unlock()
	expect("unreadable drive", ops, ilmIncompleteHistoryUnavailable, "failed")
	sets.erasureDisksMu.Lock()
	sets.erasureDisks[index][0] = prior
	sets.erasureDisksMu.Unlock()
	if got := p.held(0, "ea/unreadable"); !slices.Equal(got, []string{"hot"}) {
		t.Errorf("key behind an unreadable drive holds %v", got)
	}

	// The budget: partial, with the versions removed so far; the next
	// expiry continues.
	for i, label := range []string{"v1", "v2", "v3"} {
		p.version(0, "ea/budget", label, float64(6-i))
	}
	saved := deleteAllBudget
	deleteAllBudget.versions = 1
	tr := expect("budget", []expiryOp{p.deleteAllTask(0, "ea/budget", lifecycle.DeleteAllVersionsAction)}, ilmIncompleteBudget, "partial")
	deleteAllBudget = saved
	if tr[ilmPartial] != "true" || tr[ilmVersionsRemoved] != "1" {
		t.Errorf("budget: traced %v, want a partial expiry of 1 version", tr)
	}
	if got := p.held(0, "ea/budget"); !slices.Equal(got, []string{"hot", "hot"}) {
		t.Errorf("after the budget the key holds %v, want the two newer versions", got)
	}
	p.expire(0, "ea/budget")
	if got := p.held(0, "ea/budget"); got != nil {
		t.Errorf("the next expiry left %v", got)
	}

	// Only a batch expiry names the latest version it matched; a changed
	// one is a refusal too.
	for err, want := range map[error]string{
		errDeleteAllChanged:            ilmIncompleteChanged,
		errDeleteAllTiered:             ilmIncompleteTierUnsupported,
		errDeleteAllBudget:             ilmIncompleteBudget,
		errDeleteAllHistoryUnavailable: ilmIncompleteHistoryUnavailable,
		errLifecycleNotApplicable:      ilmIncompleteNotApplicable,
	} {
		reason, counted := ilmExpiryNotDone(err)
		if !counted || reason != want {
			t.Errorf("%v: reason %q counted %v, want %q", err, reason, counted, want)
		}
		if refused := ilmExpiryRefused(reason); refused != (want == ilmIncompleteChanged || want == ilmIncompleteTierUnsupported || want == ilmIncompleteNotApplicable) {
			t.Errorf("%s: refused %v", reason, refused)
		}
	}
	// To an API caller the unreadable drive is a write quorum error.
	if !isErrWriteQuorum(errDeleteAllHistoryUnavailable) || toAPIErrorCode(t.Context(), errDeleteAllHistoryUnavailable) != ErrSlowDownWrite {
		t.Errorf("%v is not a write quorum error to callers", errDeleteAllHistoryUnavailable)
	}
}

// A drive whose metadata does not decode refuses the purge, as an
// unreadable one does. Object heal does not rewrite such metadata; once the
// drive holds readable metadata again, the next purge removes the key.
func TestPurgeAllVersionsRefusesCorruptDrive(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-corrupt", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	ctx := t.Context()
	const key = "ea/corrupt"
	p.put(0, key, "null", daysAgo(7), ObjectOptions{})
	p.version(0, key, "v1", 6)
	p.version(0, key, "v2", 5)
	ops := []expiryOp{p.deleteAllTask(0, key, lifecycle.DeleteAllVersionsAction)}

	disks := z.serverPools[0].getHashedSet(key).getDisks()
	bad := disks[len(disks)-1]
	metaPath := pathJoin(key, xlStorageFormatFile)
	good, err := bad.ReadAll(ctx, p.bucket, metaPath)
	if err != nil {
		t.Fatal(err)
	}
	buf := slices.Clone(good)
	buf[len(buf)/2] ^= 0xff
	if err := bad.WriteAll(ctx, p.bucket, metaPath, buf); err != nil {
		t.Fatal(err)
	}
	if raw, err := bad.ReadXL(ctx, p.bucket, key, false); err != nil {
		t.Fatalf("the corrupted metadata is not read: %v", err)
	} else if err := (&xlMetaV2{}).LoadOrConvert(raw.Buf); err == nil {
		t.Fatal("the corrupted metadata still decodes")
	}

	delta := incompleteDelta(func() { p.run(ops) })
	if delta[ilmIncompleteHistoryUnavailable] != 1 {
		t.Errorf("counted %v, want one %s", delta, ilmIncompleteHistoryUnavailable)
	}
	// The purge names the cause, and callers see a write quorum error.
	_, err = z.DeleteObject(ctx, p.bucket, key, ObjectOptions{DeleteAllVersions: true, Expiration: ExpirationOptions{Expire: true}})
	if !errors.Is(err, errDeleteAllHistoryUnavailable) || toAPIErrorCode(ctx, err) != ErrSlowDownWrite {
		t.Errorf("purge on a corrupt drive: %v, want %v as SlowDownWrite", err, errDeleteAllHistoryUnavailable)
	}
	if got := p.get(key); got != "v2" {
		t.Fatalf("the refused purge left %s readable", got)
	}

	if err := bad.WriteAll(ctx, p.bucket, metaPath, good); err != nil {
		t.Fatal(err)
	}
	p.run([]expiryOp{p.deleteAllTask(0, key, lifecycle.DeleteAllVersionsAction)})
	if got := p.held(0, key); got != nil {
		t.Errorf("the purge after the repair left %v", got)
	}
}

// The scanner of a pool that holds a tiered version of a key whose latest
// version is hot does not queue the expiry of all versions, which the purge
// would refuse, and counts that it skipped it. It accounts every version of
// a key under an expiry of all versions at its size, queued or not.
func TestScannerSkipsDeleteAllForTieredKey(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-scan-tiered", MakeBucketOptions{VersioningEnabled: true}, purgeRules)
	ctx := t.Context()

	p.tiered(0, "ea/tiered", "v1", 6)
	p.version(0, "ea/tiered", "v2", 5)
	p.tiered(0, "dm/tiered", "v1", 6)
	p.marker(0, "dm/tiered", 5)
	// A tiered latest version takes the transitioned expiry.
	p.version(0, "ea/tiered-latest", "v1", 6)
	p.tiered(0, "ea/tiered-latest", "v2", 5)
	// A free version is not a tiered version.
	fv := p.tiered(0, "ea/free", "v1", 6)
	if _, err := z.DeleteObject(ctx, p.bucket, "ea/free", ObjectOptions{Versioned: true, VersionID: fv.VersionID}); err != nil {
		t.Fatal(err)
	}
	p.version(0, "ea/free", "v2", 5)
	p.version(0, "ea/hot", "v1", 6)
	p.version(0, "ea/hot", "v2", 5)

	for _, tc := range []struct {
		key    string
		queued bool
	}{
		{"ea/tiered", false},
		{"dm/tiered", false},
		{"ea/tiered-latest", true},
		{"ea/free", true},
		{"ea/hot", true},
	} {
		var ops []expiryOp
		var sizes map[string]int64
		delta := incompleteDelta(func() { ops, sizes = p.scan(0, tc.key) })
		if got := queuesDeleteAll(ops); got != tc.queued {
			t.Errorf("%s: queued an expiry of all versions %v, want %v: %v", tc.key, got, tc.queued, ops)
		}
		skipped := int64(0)
		if !tc.queued {
			skipped = 1
		}
		if delta[ilmIncompleteTierSkipped] != skipped {
			t.Errorf("%s: counted %v, want %d %s", tc.key, delta, skipped, ilmIncompleteTierSkipped)
		}
		for _, oi := range p.scanned(0, tc.key) {
			size, _ := oi.GetActualSize()
			if got := sizes[deleteAllVersionID(oi.VersionID)]; got != size {
				t.Errorf("%s: version %s accounted at %d, want its size %d", tc.key, oi.VersionID, got, size)
			}
		}
	}

	// The skipped keys keep their versions and remote objects, and the
	// queued hot key is purged.
	remotes := p.remotes()
	for _, key := range []string{"ea/tiered", "dm/tiered", "ea/free", "ea/hot"} {
		if ops := p.scanQueue(0, key); len(ops) > 0 {
			p.run(ops)
		}
	}
	for key, want := range map[string][]string{
		"ea/tiered": {"hot", "tiered"},
		"dm/tiered": {"DM", "tiered"},
		"ea/free":   {"free"},
		"ea/hot":    nil,
	} {
		if got := p.held(0, key); !slices.Equal(got, want) {
			t.Errorf("%s holds %v, want %v", key, got, want)
		}
	}
	if got := p.remotes(); got != remotes {
		t.Errorf("tier holds %d remote objects, want %d", got, remotes)
	}
}

// A lifecycle expiry never deletes a prefix: the old combination of options
// that removed the keys under a key is refused, and a force delete of a
// prefix still works.
func TestPoolsDeleteObjectRejectsExpirePrefix(t *testing.T) {
	z := purgeSinglePool(t, 16)
	p := newPurgeTest(t, z, "purge-prefix-expire", MakeBucketOptions{VersioningEnabled: true}, "")
	ctx := t.Context()
	p.version(0, "pfx/key", "v1", 5)
	p.version(0, "pfx/key/child", "v1", 5)
	for _, opts := range []ObjectOptions{
		{DeletePrefix: true, Expiration: ExpirationOptions{Expire: true}},
		{DeletePrefix: true, DeletePrefixObject: true, Expiration: ExpirationOptions{Expire: true}},
	} {
		_, err := z.DeleteObject(ctx, p.bucket, "pfx/key", opts)
		var invalid InvalidArgument
		if !errors.As(err, &invalid) || !strings.Contains(err.Error(), "never deletes a prefix") {
			t.Errorf("%+v: err = %v, want InvalidArgument", opts, err)
		}
	}
	for _, key := range []string{"pfx/key", "pfx/key/child"} {
		if got := p.held(0, key); !slices.Equal(got, []string{"hot"}) {
			t.Errorf("%s holds %v after a refused delete", key, got)
		}
	}
	if _, err := z.DeleteObject(ctx, p.bucket, "pfx/key", ObjectOptions{DeletePrefix: true}); err != nil {
		t.Fatalf("force delete of the prefix: %v", err)
	}
	for _, key := range []string{"pfx/key", "pfx/key/child"} {
		if got := p.get(key); got != "-" {
			t.Errorf("%s reads %s after a force delete", key, got)
		}
	}
}
