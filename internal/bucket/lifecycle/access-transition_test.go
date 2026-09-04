// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
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

package lifecycle

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/object/lock"
)

const accessTieringXML = `<LifecycleConfiguration>
  <AccessTierQuota>500GiB</AccessTierQuota>
  <Rule>
    <ID>hot-logs</ID>
    <Status>Enabled</Status>
    <Filter><And><Prefix>logs/</Prefix><ObjectSizeGreaterThan>65536</ObjectSizeGreaterThan></And></Filter>
    <AccessTransition>
      <Window>10m</Window>
      <PromoteAfterAccesses>100</PromoteAfterAccesses>
      <DemoteAfterAccesses>5</DemoteAfterAccesses>
      <DemoteAfterIdle>24h</DemoteAfterIdle>
    </AccessTransition>
  </Rule>
</LifecycleConfiguration>`

func TestAccessTransitionParse(t *testing.T) {
	lc, err := ParseLifecycleConfig(strings.NewReader(accessTieringXML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := lc.Validate(lock.Retention{}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := lc.AccessQuotaBytes(); got != 500*1024*1024*1024 {
		t.Fatalf("quota = %d, want %d", got, 500*1024*1024*1024)
	}
	if !lc.HasAccessTransition() {
		t.Fatal("HasAccessTransition = false, want true")
	}
	at := lc.Rules[0].AccessTransition
	if at.Window.D() != 10*time.Minute {
		t.Fatalf("window = %v, want 10m", at.Window.D())
	}
	if at.DemoteAfterIdle.D() != 24*time.Hour {
		t.Fatalf("idle = %v, want 24h", at.DemoteAfterIdle.D())
	}
	if at.PromoteAfterAccesses != 100 || at.DemoteAfterAccesses != 5 {
		t.Fatalf("thresholds = %d/%d, want 100/5", at.PromoteAfterAccesses, at.DemoteAfterAccesses)
	}
}

// A round trip through Marshal must preserve both the rule element and the
// bucket-wide quota, since PutBucketLifecycle stores whatever we re-encode.
func TestAccessTransitionRoundTrip(t *testing.T) {
	lc, err := ParseLifecycleConfig(strings.NewReader(accessTieringXML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	buf, err := xml.Marshal(lc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(buf, []byte("<AccessTierQuota>500GiB</AccessTierQuota>")) {
		t.Fatalf("quota lost in round trip: %s", buf)
	}
	got, err := ParseLifecycleConfig(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if got.AccessQuotaBytes() != lc.AccessQuotaBytes() {
		t.Fatalf("quota %d != %d", got.AccessQuotaBytes(), lc.AccessQuotaBytes())
	}
	if got.Rules[0].AccessTransition != lc.Rules[0].AccessTransition {
		t.Fatalf("rule %+v != %+v", got.Rules[0].AccessTransition, lc.Rules[0].AccessTransition)
	}
}

// A rule with no AccessTransition must not emit an empty element - otherwise
// every existing lifecycle config would change shape on rewrite.
func TestAccessTransitionUnsetNotMarshalled(t *testing.T) {
	lc, err := ParseLifecycleConfig(strings.NewReader(`<LifecycleConfiguration><Rule>
		<ID>old</ID><Status>Enabled</Status><Filter><Prefix>a/</Prefix></Filter>
		<Expiration><Days>3</Days></Expiration></Rule></LifecycleConfiguration>`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	buf, err := xml.Marshal(lc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(buf, []byte("AccessTransition")) || bytes.Contains(buf, []byte("AccessTierQuota")) {
		t.Fatalf("unset elements emitted: %s", buf)
	}
	if lc.HasAccessTransition() {
		t.Fatal("HasAccessTransition = true for a plain expiry rule")
	}
}

func TestAccessTransitionValidate(t *testing.T) {
	tests := []struct {
		name string
		at   AccessTransition
		err  error
	}{
		{"ok", AccessTransition{Window: Duration(10 * time.Minute), PromoteAfterAccesses: 100, DemoteAfterAccesses: 5, DemoteAfterIdle: Duration(time.Hour), set: true}, nil},
		{"unset", AccessTransition{}, nil},
		{"zero window", AccessTransition{PromoteAfterAccesses: 100, DemoteAfterIdle: Duration(time.Hour), set: true}, errAccessInvalidWindow},
		{"zero promote", AccessTransition{Window: Duration(time.Minute), DemoteAfterIdle: Duration(time.Hour), set: true}, errAccessInvalidPromote},
		{"demote >= promote", AccessTransition{Window: Duration(time.Minute), PromoteAfterAccesses: 5, DemoteAfterAccesses: 5, DemoteAfterIdle: Duration(time.Hour), set: true}, errAccessInvalidDemote},
		{"negative demote", AccessTransition{Window: Duration(time.Minute), PromoteAfterAccesses: 5, DemoteAfterAccesses: -1, DemoteAfterIdle: Duration(time.Hour), set: true}, errAccessInvalidDemote},
		{"idle shorter than window", AccessTransition{Window: Duration(time.Hour), PromoteAfterAccesses: 5, DemoteAfterIdle: Duration(time.Minute), set: true}, errAccessInvalidIdle},
		{"zero idle", AccessTransition{Window: Duration(time.Minute), PromoteAfterAccesses: 5, set: true}, errAccessInvalidIdle},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.at.Validate(); err != tc.err {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
		})
	}
}

func TestAccessTierQuotaInvalid(t *testing.T) {
	lc, err := ParseLifecycleConfig(strings.NewReader(`<LifecycleConfiguration>
		<AccessTierQuota>not-a-size</AccessTierQuota>
		<Rule><ID>r</ID><Status>Enabled</Status><Expiration><Days>3</Days></Expiration></Rule>
		</LifecycleConfiguration>`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := lc.Validate(lock.Retention{}); err != errAccessInvalidQuotaSize {
		t.Fatalf("err = %v, want %v", err, errAccessInvalidQuotaSize)
	}
	// An invalid quota that somehow reached the evaluator means "unlimited",
	// never "zero bytes allowed".
	if got := lc.AccessQuotaBytes(); got != 0 {
		t.Fatalf("quota = %d, want 0 (unlimited)", got)
	}
}

func TestAccessTransitionBadDuration(t *testing.T) {
	_, err := ParseLifecycleConfig(strings.NewReader(`<LifecycleConfiguration><Rule>
		<ID>r</ID><Status>Enabled</Status>
		<AccessTransition><Window>ten minutes</Window><PromoteAfterAccesses>1</PromoteAfterAccesses></AccessTransition>
		</Rule></LifecycleConfiguration>`))
	if err == nil {
		t.Fatal("expected a parse error for a malformed duration")
	}
}

// AccessRule must reuse the standard rule filtering: prefix, tags, size and
// Status all have to be honored.
func TestAccessRuleFiltering(t *testing.T) {
	lc, err := ParseLifecycleConfig(strings.NewReader(accessTieringXML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tests := []struct {
		name string
		obj  ObjectOpts
		want bool
	}{
		{"match", ObjectOpts{Name: "logs/a.log", Size: 1 << 20, IsLatest: true}, true},
		{"wrong prefix", ObjectOpts{Name: "data/a.log", Size: 1 << 20, IsLatest: true}, false},
		{"too small", ObjectOpts{Name: "logs/a.log", Size: 1024, IsLatest: true}, false},
		{"no name", ObjectOpts{Size: 1 << 20}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, id, ok := lc.AccessRule(tc.obj)
			if ok != tc.want {
				t.Fatalf("ok = %v, want %v", ok, tc.want)
			}
			if ok && id != "hot-logs" {
				t.Fatalf("ruleID = %q, want hot-logs", id)
			}
		})
	}

	lc.Rules[0].Status = Disabled
	if _, _, ok := lc.AccessRule(ObjectOpts{Name: "logs/a.log", Size: 1 << 20, IsLatest: true}); ok {
		t.Fatal("disabled rule still matched")
	}
	if lc.HasAccessTransition() {
		t.Fatal("HasAccessTransition = true with only a disabled rule")
	}
}

func TestAccessTransitionCountsAsActiveRule(t *testing.T) {
	lc, err := ParseLifecycleConfig(strings.NewReader(accessTieringXML))
	if err != nil {
		t.Fatal(err)
	}
	if !lc.HasActiveRules("logs/2026") {
		t.Fatal("access-only lifecycle rule was not active for its prefix")
	}
	if lc.HasActiveRules("data/") {
		t.Fatal("access rule was active outside its prefix")
	}
}
