// Copyright (c) 2026 Denis Babchuk
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

package cmd

import (
	"testing"
	"time"
)

// A key below another key ("k/b" under "k") is a directory inside the
// directory of that key. The listing treats the directory of an object as a
// leaf, so a decommission walk does not see "k/b" while "k" is still in the
// pool. The walk has to be repeated once the keys above are gone, or the
// check after the bucket finds them and the decommission fails.

func keysBelowDecommission(t *testing.T, z *erasureServerPools) PoolDecommissionInfo {
	t.Helper()
	if err := z.StartDecommission(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	z.doDecommissionInRoutine(t.Context(), 0)
	z.poolMetaMutex.RLock()
	defer z.poolMetaMutex.RUnlock()
	return *z.poolMeta.Pools[0].Decommission
}

func keysBelowPools(t *testing.T) (*erasureServerPools, string, []string) {
	t.Helper()
	z, _ := migrationTestPools(t)
	const bucket = "keys-below"
	if err := z.MakeBucket(t.Context(), bucket, MakeBucketOptions{VersioningEnabled: true}); err != nil {
		t.Fatal(err)
	}
	keys := []string{"k", "k/b", "k/b/c"}
	for _, key := range keys {
		putConsistencyObject(t, z, bucket, key, 0, key, ObjectOptions{Versioned: true})
	}
	return z, bucket, keys
}

func TestDecommissionMovesKeysBelowAKey(t *testing.T) {
	z, bucket, keys := keysBelowPools(t)
	if info := keysBelowDecommission(t, z); !info.Complete || info.Failed {
		t.Errorf("decommission: complete %v, failed %v; want complete", info.Complete, info.Failed)
	}
	for _, key := range keys {
		if _, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, key, ObjectOptions{}); !isErrObjectNotFound(err) {
			t.Errorf("%s still in pool 0: %v", key, err)
		}
		if body := migrationTestBody(t, z.GetObjectNInfo, bucket, key, ""); body != key {
			t.Errorf("%s reads %q", key, body)
		}
	}
}

// An ILM expiry can remove the parent key during a decommission walk. That
// removal must count as progress, or the next key below the parent remains
// hidden from the listing and the source pool is left non-empty.
func TestDecommissionContinuesAfterLifecycleRemovesParent(t *testing.T) {
	z, _ := migrationTestPools(t)
	const bucket = "decommission-ilm-keys-below"
	if err := z.MakeBucket(t.Context(), bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	meta, err := globalBucketMetadataSys.Get(bucket)
	if err != nil {
		t.Fatal(err)
	}
	meta.LifecycleConfigXML = []byte(`<LifecycleConfiguration><Rule><ID>expire-old</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`)
	if err := meta.Save(t.Context(), z); err != nil {
		t.Fatal(err)
	}
	globalBucketMetadataSys.Set(bucket, meta)

	putConsistencyObject(t, z, bucket, "k", 0, "parent", ObjectOptions{MTime: UTCNow().Add(-72 * time.Hour)})
	putConsistencyObject(t, z, bucket, "k/b", 0, "child", ObjectOptions{MTime: UTCNow()})

	if info := keysBelowDecommission(t, z); !info.Complete || info.Failed {
		t.Fatalf("decommission: complete %v, failed %v; want complete", info.Complete, info.Failed)
	}
	if _, err := z.serverPools[0].GetObjectInfo(t.Context(), bucket, "k/b", ObjectOptions{}); !isErrObjectNotFound(err) {
		t.Fatalf("child still in source pool: %v", err)
	}
	if body := migrationTestBody(t, z.GetObjectNInfo, bucket, "k/b", ""); body != "child" {
		t.Fatalf("child reads %q", body)
	}
}
