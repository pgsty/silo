// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"errors"
	"testing"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
	xhttp "github.com/minio/minio/internal/http"
)

func TestVersionRevisionRestoreFlags(t *testing.T) {
	base := authorityRevision(t, [16]byte{1}, 1, 1, "")
	cleared := base
	cleared.header.Flags &^= xlFlagUsesDataDir
	set := base
	set.header.Flags |= xlFlagUsesDataDir
	if versionRevision(cleared, xlMetaVersion) != versionRevision(set, xlMetaVersion) {
		t.Fatal("derived flag splits one revision")
	}
	for _, change := range []struct {
		name  string
		apply func(*xlMetaV2Object)
	}{
		{"data-dir", func(o *xlMetaV2Object) { o.DataDir[0]++ }},
		{"restore", func(o *xlMetaV2Object) { o.MetaUser[xhttp.AmzRestore] = `ongoing-request="true"` }},
		{"retention", func(o *xlMetaV2Object) { o.MetaUser["x-amz-object-lock-mode"] = "COMPLIANCE" }},
		{"layout", func(o *xlMetaV2Object) { o.ErasureM, o.ErasureN = 8, 8 }},
	} {
		t.Run(change.name, func(t *testing.T) {
			var v xlMetaV2Version
			if _, err := v.unmarshalV(xlMetaVersion, base.meta); err != nil {
				t.Fatal(err)
			}
			change.apply(v.ObjectV2)
			meta, err := v.MarshalMsg(nil)
			if err != nil {
				t.Fatal(err)
			}
			different := xlMetaV2ShallowVersion{header: cleared.header, meta: meta}
			if versionRevision(different, xlMetaVersion) == versionRevision(set, xlMetaVersion) {
				t.Fatal("real metadata change lost")
			}
		})
	}
	// Every other header flag remains part of identity, even if metadata is equal.
	for flag := xlFlags(1); flag != 0; flag <<= 1 {
		if flag == xlFlagUsesDataDir {
			continue
		}
		other := base
		other.header.Flags ^= flag
		if versionRevision(other, xlMetaVersion) == versionRevision(base, xlMetaVersion) {
			t.Fatalf("flag %d was normalized", flag)
		}
	}
	malformed := base
	malformed.meta = []byte{0xc1}
	other := malformed
	other.header.Flags ^= xlFlagUsesDataDir
	if versionRevision(malformed, xlMetaVersion) == versionRevision(other, xlMetaVersion) {
		t.Fatal("undecodable metadata was normalized")
	}
	marker := authorityMarker(t, [16]byte{2}, 2)
	other = marker
	other.header.Flags ^= xlFlagUsesDataDir
	if versionRevision(marker, xlMetaVersion) == versionRevision(other, xlMetaVersion) {
		t.Fatal("delete marker was normalized as an object")
	}
}

// Two drives are replaced one at a time after the restore expires. The old
// headers describe the pre-expiry state; heal writes the current derived flag.
func TestRestoreExpiryAcrossSuccessiveHeals(t *testing.T) {
	r := newRestoreSafetyTest(t, 2, versioning.Enabled)
	ctx := t.Context()
	oi := r.put("restored", false, true)
	r.restore(oi)
	before := r.fileInfo(oi.VersionID)
	disks := r.z.serverPools[0].getHashedSet(r.object).getDisks()
	// Model the headers written before wall-clock expiry without a timing race.
	for _, disk := range disks {
		rewriteTierTestMeta(t, disk, r.bucket, r.object, func(xl *xlMetaV2) { xl.versions[0].header.Flags |= xlFlagUsesDataDir })
	}
	for _, i := range []int{3, 2} {
		if err := disks[i].Delete(ctx, r.bucket, r.object, DeleteOptions{Recursive: true, Immediate: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.z.HealObject(ctx, r.bucket, r.object, oi.VersionID, madmin.HealOpts{ScanMode: madmin.HealNormalScan}); err != nil {
			t.Fatal(err)
		}
	}
	for i, disk := range disks {
		raw, err := disk.ReadXL(ctx, r.bucket, r.object, false)
		if err != nil {
			t.Fatal(err)
		}
		var xl xlMetaV2
		if err = xl.Load(raw.Buf); err != nil {
			t.Fatal(err)
		}
		if got := xl.versions[0].header.Flags&xlFlagUsesDataDir != 0; got != (i < 2) {
			t.Fatalf("drive %d has unexpected derived flag %v", i, got)
		}
	}
	if _, _, err := r.z.lifecycleEventsAllPools(ctx, r.bucket, r.object); err != nil {
		t.Fatalf("history with split flags: %v", err)
	}
	current, err := r.z.GetObjectInfo(ctx, r.bucket, r.object, r.opts(oi.VersionID))
	if err != nil {
		t.Fatal(err)
	}
	if err = expireTransitionedObject(ctx, r.z, &current, lifecycle.Event{Action: lifecycle.DeleteRestoredAction}, lcEventSrc_Scanner); err != nil {
		t.Fatalf("expire restored copy: %v", err)
	}
	if n := r.dataDirs(before.DataDir); n != 0 {
		t.Fatalf("restore cleanup left %d data directories", n)
	}
	if got := readCopyChecksumObject(t, r.z, r.bucket, r.object, r.opts(oi.VersionID)); string(got) != string(r.bodies["restored"]) {
		t.Fatal("tiered object is no longer readable")
	}
	r.put("newer", false, false)
	if _, _, err = r.z.lifecycleEventsAllPools(ctx, r.bucket, r.object); err != nil {
		t.Fatal(err)
	}
	if _, err = r.z.deleteAllHistory(ctx, r.bucket, r.object); err != nil {
		t.Fatalf("purge history with split flags: %v", err)
	}
	// The rule permits tiering, not a purge. Normalizing the header must not
	// turn a readable history into permission to remove the versions.
	if _, err = r.z.DeleteObject(ctx, r.bucket, r.object, ObjectOptions{DeleteAllVersions: true, Expiration: ExpirationOptions{Expire: true}}); !errors.Is(err, errLifecycleNotApplicable) {
		t.Fatalf("purge without an applicable rule: %v", err)
	}
	if _, err = r.z.GetObjectInfo(ctx, r.bucket, r.object, r.opts(oi.VersionID)); err != nil {
		t.Fatalf("refused purge removed the tiered version: %v", err)
	}
}
