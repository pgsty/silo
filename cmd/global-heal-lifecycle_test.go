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
	"testing"

	"github.com/minio/minio/internal/bucket/versioning"
)

// Drive heal evaluates lifecycle on the versions of one pool and enqueues
// the expiries it finds due. It must still heal those versions: the expiry
// is decided again under the object lock and can be refused, and a version
// left unhealed would stay without the replaced drive for as long as it is.

// startTestBackgroundHeal registers the background heal sequence and a heal
// worker, which drive healing needs for its bucket heals.
func startTestBackgroundHeal(t *testing.T, z ObjectLayer) {
	t.Helper()
	if globalBackgroundHealState == nil {
		globalBackgroundHealState = newHealState(GlobalContext, false)
	}
	if _, ok := globalBackgroundHealState.getHealSequenceByToken(bgHealingUUID); ok {
		// The test pools started background healing with its workers.
		return
	}
	ctx, cancel := context.WithCancel(t.Context())
	bgSeq := newBgHealSequence()
	go globalBackgroundHealRoutine.AddWorker(ctx, z, bgSeq)
	if _, apiErr, msg := globalBackgroundHealState.LaunchNewHealSequence(bgSeq, z); apiErr.Code != "" {
		cancel()
		t.Fatalf("launch background heal: %s %s", apiErr.Code, msg)
	}
	t.Cleanup(func() {
		cancel()
		bgSeq.stop()
		globalBackgroundHealState.Lock()
		delete(globalBackgroundHealState.healSeqMap, pathJoin(bgSeq.bucket, bgSeq.object))
		globalBackgroundHealState.Unlock()
	})
}

// healReplacedDrive removes object from one drive of its set in pool, as a
// replaced drive would lack it, heals that drive as drive healing does, and
// returns the drive and its tracker.
func (s *splitILM) healReplacedDrive(pool int, object string) (StorageAPI, *healingTracker) {
	s.t.Helper()
	ctx := s.t.Context()
	z := s.z.serverPools[pool]
	setIdx := z.getHashedSetIndex(object)
	er := z.sets[setIdx]
	disk := er.getDisks()[1]
	if err := disk.Delete(ctx, s.bucket, object, DeleteOptions{Recursive: true, Immediate: true}); err != nil {
		s.t.Fatal(err)
	}
	tracker := initHealingTracker(disk, mustGetUUID())
	if err := er.healErasureSet(ctx, []string{s.bucket}, tracker); err != nil {
		s.t.Fatal(err)
	}
	return disk, tracker
}

// requireVersionOn fails unless disk holds versionID of object with its data.
func (s *splitILM) requireVersionOn(disk StorageAPI, object, versionID string) {
	s.t.Helper()
	fi, err := disk.ReadVersion(s.t.Context(), "", s.bucket, object, versionID, ReadOptions{})
	if err != nil {
		s.t.Fatalf("%s: version %s of %s missing: %v", disk, versionID, object, err)
	}
	if fi.DataDir == "" || fi.InlineData() {
		return
	}
	if _, err := disk.StatInfoFile(s.t.Context(), s.bucket, pathJoin(object, fi.DataDir, "part.1"), false); err != nil {
		s.t.Fatalf("%s: data of version %s of %s missing: %v", disk, versionID, object, err)
	}
}

func TestHealDriveHealsVersionWithRefusedExpiry(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	startTestBackgroundHeal(t, s.z)
	const key = "exp-heal-refused"
	// Due in pool 0, where it is the latest version. A newer version in pool
	// 1 makes it noncurrent, so the expiry that pool 0 predicts is refused.
	s.write(key, splitVersion{pools: []int{0}, label: "v1", days: 5, size: 1 << 20})
	s.write(key, splitVersion{pools: []int{1}, label: "v2"})
	v1 := s.ids[key+" v1"]

	disk, tracker := s.healReplacedDrive(0, key)
	s.requireVersionOn(disk, key, v1)
	if tracker.ItemsFailed != 0 {
		t.Errorf("heal failures: %d", tracker.ItemsFailed)
	}

	s.runQueue()
	if _, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{VersionID: v1}); err != nil {
		t.Fatalf("refused expiry removed v1: %v", err)
	}
	if got := s.get(key); got != "v2" {
		t.Errorf("latest = %q, want v2", got)
	}
	s.requireVersionOn(disk, key, v1)
}

// An expiry that removes the object still does after the heal, on every
// drive, and the heal does not bring it back.
func TestHealDriveThenExpiryRemoves(t *testing.T) {
	s := newSplitILM(t, "", splitILMRules)
	startTestBackgroundHeal(t, s.z)
	const key = "exp-heal-removed"
	s.write(key, splitVersion{pools: []int{0}, label: "v1", days: 5, null: true, size: 1 << 20})

	disk, _ := s.healReplacedDrive(0, key)
	s.requireVersionOn(disk, key, nullVersionID)

	s.runQueue()
	if _, err := s.z.GetObjectInfo(t.Context(), s.bucket, key, ObjectOptions{}); !isErrObjectNotFound(err) {
		t.Fatalf("expired object still readable: %v", err)
	}
	for _, d := range s.z.serverPools[0].getHashedSet(key).getDisks() {
		if _, err := d.ReadVersion(t.Context(), "", s.bucket, key, nullVersionID, ReadOptions{}); err == nil {
			t.Errorf("%s still holds the expired object", d)
		}
	}
}

// An expiry of the latest version of a versioned bucket adds a delete marker;
// the version it hides stays, healed on every drive.
func TestHealDriveThenExpiryAddsMarker(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	startTestBackgroundHeal(t, s.z)
	const key = "exp-heal-marker"
	s.write(key, splitVersion{pools: []int{0}, label: "v1", days: 5, size: 1 << 20})
	v1 := s.ids[key+" v1"]

	disk, _ := s.healReplacedDrive(0, key)
	s.requireVersionOn(disk, key, v1)

	s.runQueue()
	if got := s.get(key); got != "-" {
		t.Fatalf("latest = %q, want a delete marker", got)
	}
	for _, d := range s.z.serverPools[0].getHashedSet(key).getDisks() {
		s.requireVersionOn(d, key, v1)
	}
}

// A version left on a minority of the drives, as by a delete that reached
// its write quorum, is not recreated on the healed drive.
func TestHealDriveDoesNotRestoreStaleMinority(t *testing.T) {
	s := newSplitILM(t, versioning.Enabled, splitILMRules)
	startTestBackgroundHeal(t, s.z)
	const key = "keep-heal-minority"
	s.write(key, splitVersion{pools: []int{0}, label: "v1", days: 5, size: 1 << 20})
	v1 := s.ids[key+" v1"]
	disks := s.z.serverPools[0].getHashedSet(key).getDisks()
	// Keep v1 on the first drive only; drive 1 is the one being healed.
	for _, d := range disks[1:] {
		if err := d.Delete(t.Context(), s.bucket, key, DeleteOptions{Recursive: true, Immediate: true}); err != nil {
			t.Fatal(err)
		}
	}

	disk, tracker := s.healReplacedDrive(0, key)
	if _, err := disk.ReadVersion(t.Context(), "", s.bucket, key, v1, ReadOptions{}); err == nil {
		t.Fatal("heal recreated a version from a stale minority")
	}
	if tracker.ItemsFailed != 0 {
		t.Errorf("heal failures: %d", tracker.ItemsFailed)
	}
}
