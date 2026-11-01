//go:build consistency_strict

// Copyright (c) 2026 Feng Ruohang
//
// This file is part of Silo Object Storage.
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
	"strings"
	"testing"
	"time"
)

func TestPutObjectGenerationFollowsCommitLock(t *testing.T) {
	z, bucket := consistencyPools(t)
	for _, preserve := range []bool{false, true} {
		t.Run(map[bool]string{false: "generated", true: "preserved"}[preserve], func(t *testing.T) {
			const object = "ordered-generation"
			set := z.serverPools[0].getHashedSet(object)
			lock := set.NewNSLock(bucket, object)
			lc, err := lock.GetLock(t.Context(), globalOperationTimeout)
			if err != nil {
				t.Fatal(err)
			}
			locked := true
			defer func() {
				if locked {
					lock.Unlock(lc)
				}
			}()

			opts := ObjectOptions{}
			if preserve {
				opts.MTime = time.Unix(1234567890, 0)
			}
			reader := mustGetPutObjReader(t, strings.NewReader("payload"), 7, "", "")
			type result struct {
				info ObjectInfo
				err  error
			}
			done := make(chan result, 1)
			go func() {
				info, err := set.PutObject(t.Context(), bucket, object, reader, opts)
				done <- result{info, err}
			}()

			// Wait for the real writer to queue behind the held namespace
			// lock. No elapsed delay is used to infer its progress.
			deadline := time.Now().Add(5 * time.Second)
			for {
				set.nsMutex.lockMapMutex.Lock()
				entry := set.nsMutex.lockMap[pathJoin(bucket, object)]
				waiting := entry != nil && entry.ref == 2
				set.nsMutex.lockMapMutex.Unlock()
				if waiting {
					break
				}
				select {
				case got := <-done:
					t.Fatalf("PUT bypassed the held commit lock: %v", got.err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("PUT did not queue for the commit lock")
				}
				time.Sleep(time.Millisecond)
			}
			beforeUnlock := UTCNow()
			lock.Unlock(lc)
			locked = false
			got := <-done
			if got.err != nil {
				t.Fatal(got.err)
			}
			if preserve {
				if !got.info.ModTime.Equal(opts.MTime) {
					t.Fatalf("explicit modification time changed: %s", got.info.ModTime)
				}
			} else if got.info.ModTime.Before(beforeUnlock) {
				t.Fatalf("generation %s predates commit lock release %s", got.info.ModTime, beforeUnlock)
			}
			for i, disk := range set.getDisks() {
				fi, err := disk.ReadVersion(t.Context(), "", bucket, object, nullVersionID, ReadOptions{})
				if err != nil || !fi.ModTime.Equal(got.info.ModTime) {
					t.Errorf("disk %d stored a different generation: %s, %v", i, fi.ModTime, err)
				}
			}
		})
	}
}
