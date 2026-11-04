// Copyright (c) 2026 Feng Ruohang
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
	"os"
	"path/filepath"
	"testing"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/grid"
)

// A remote node must apply the caller's dry run to its local bucket heal.
// The request goes from remotePeerS3Client.HealBucket over a grid connection
// to the peer handler, as it does between the nodes of a deployment.
func TestPeerHealBucketDryRun(t *testing.T) {
	obj, roots, err := prepareErasure(t.Context(), 4)
	if err != nil {
		t.Fatal(err)
	}
	setObjectLayer(obj)
	defer removeRoots(roots)
	defer obj.Shutdown(t.Context())

	tg, err := grid.SetupTestGrid(2)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Cleanup()
	if err = healBucketRPC.Register(tg.Managers[1], (&peerRESTServer{}).HealBucketHandler); err != nil {
		t.Fatal(err)
	}
	conn := func() *grid.Connection { return tg.Managers[0].Connection(tg.Hosts[1]) }
	client := &remotePeerS3Client{gridConn: conn}

	const bucket = "peer-heal-dry-run"
	if err = obj.MakeBucket(t.Context(), bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	dirs := make([]string, len(roots))
	for i, root := range roots {
		dirs[i] = filepath.Join(root, bucket)
	}
	if err = os.Remove(dirs[0]); err != nil {
		t.Fatal(err)
	}
	exists := func(dir string) bool {
		_, err := os.Stat(dir)
		return err == nil
	}
	heal := func(opts madmin.HealOpts) {
		t.Helper()
		if _, err := client.HealBucket(t.Context(), bucket, opts); err != nil {
			t.Fatal(err)
		}
	}

	// Dry run must not recreate the missing bucket directory.
	heal(madmin.HealOpts{DryRun: true})
	if exists(dirs[0]) {
		t.Fatal("dry-run peer bucket heal created a missing bucket directory")
	}

	// Dry run must not remove the empty bucket directories.
	heal(madmin.HealOpts{DryRun: true, Remove: true})
	for _, dir := range dirs[1:] {
		if !exists(dir) {
			t.Fatalf("dry-run peer bucket heal removed %s", dir)
		}
	}

	// Controls. A message without the dry-run key, as sent by an older node,
	// still heals: the fixture reaches MakeVol.
	if _, err = healBucketRPC.Call(t.Context(), conn(), grid.NewMSSWith(map[string]string{
		peerS3Bucket:        bucket,
		peerS3BucketDeleted: "false",
	})); err != nil {
		t.Fatal(err)
	}
	if !exists(dirs[0]) {
		t.Fatal("control: peer bucket heal did not recreate the missing directory")
	}

	// A real heal with Remove reaches DeleteVol for the empty directories.
	heal(madmin.HealOpts{Remove: true})
	for _, dir := range dirs {
		if exists(dir) {
			t.Fatalf("control: peer bucket heal kept empty directory %s", dir)
		}
	}
}
