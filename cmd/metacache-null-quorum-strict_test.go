//go:build consistency_strict

// Preserved diagnostic for the deferred strict-read policy. This is not a
// maintenance release gate; failures record intentionally unresolved risks.

// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	madmin "github.com/minio/madmin-go/v3"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestStrictSingleNullQuorumReadAndConsumers(t *testing.T) {
	z, bucket, router := nullQuorumBackend(t)
	set := z.serverPools[0].sets[0]
	disks := set.getDisks()
	const object = "object"
	oldBody, newBody := bytes.Repeat([]byte{'a'}, 8192), bytes.Repeat([]byte{'b'}, 8192)
	oldTime := time.Now().UTC().Add(-time.Hour)
	put := func(body []byte, modTime time.Time) {
		t.Helper()
		_, err := z.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), ObjectOptions{MTime: modTime})
		if err != nil {
			t.Fatal(err)
		}
	}
	put(oldBody, oldTime)
	oldMeta := make([][]byte, len(disks))
	for i, disk := range disks {
		var err error
		oldMeta[i], err = disk.ReadAll(t.Context(), bucket, object+"/"+xlStorageFormatFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	put(newBody, oldTime.Add(time.Minute))
	newMeta := make([][]byte, len(disks))
	for i, disk := range disks {
		newMeta[i] = mustReadNullQuorumMeta(t, disk, bucket, object)
	}
	// Model an incomplete overwrite using real inline shards: fifteen old
	// copies retain a read quorum; the final disk contains the newer minority.
	// The old quorum does not prove that the newer overwrite was uncommitted.
	for i := range 15 {
		if err := disks[i].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, oldMeta[i]); err != nil {
			t.Fatal(err)
		}
	}
	checkRead := func(body []byte, modTime time.Time) {
		t.Helper()
		get := nullQuorumRequest(t, router, http.MethodGet, getGetObjectURL("", bucket, object))
		head := nullQuorumRequest(t, router, http.MethodHead, getGetObjectURL("", bucket, object))
		if get.Code != 200 || !bytes.Equal(get.Body.Bytes(), body) || head.Code != 200 || head.Header().Get("Content-Length") != "8192" {
			t.Fatalf("GET/HEAD lost readable quorum: GET=%d HEAD=%d body=%q", get.Code, head.Code, get.Body.String())
		}
		oi, err := z.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{})
		if err != nil || !oi.ModTime.Equal(modTime) {
			t.Fatalf("wrong readable generation: %v, %v", oi.ModTime, err)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := nullQuorumRequest(t, router, method, getGetObjectURL("", bucket, object))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s exposed an unresolved old quorum: %d", method, rec.Code)
		}
	}
	if _, err := z.HealObject(t.Context(), bucket, object, "", madmin.HealOpts{Remove: true}); !isErrReadQuorum(err) {
		t.Fatalf("heal accepted an unresolved old quorum: %v", err)
	}
	// Reading must not reinterpret the minority as absent or delete it.
	minority, err := disks[15].ReadVersion(t.Context(), "", bucket, object, "", ReadOptions{})
	if err != nil || !minority.ModTime.Equal(oldTime.Add(time.Minute)) {
		t.Fatalf("read mutated the minority: %+v, %v", minority, err)
	}
	// Now model the safe direction: the latest generation has the quorum.
	// Keep the migration, Walk and scanner assertions on that readable state.
	for i := range 15 {
		if err := disks[i].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, newMeta[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := disks[15].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, oldMeta[15]); err != nil {
		t.Fatal(err)
	}
	newTime := oldTime.Add(time.Minute)
	checkRead(newBody, newTime)
	for _, kind := range []string{"rebalance", "decommission"} {
		t.Run(kind, func(t *testing.T) {
			var names []string
			consume := func(entry metaCacheEntry) {
				versions, err := entry.fileInfoVersions(bucket)
				if err != nil || len(versions.Versions) != 1 || !versions.Versions[0].ModTime.Equal(newTime) {
					t.Errorf("invalid migration metadata: %+v, %v", versions, err)
					return
				}
				// Migration reopens the selected name/version on all drives;
				// it must not treat the selected listing metadata as disk agreement.
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
				t.Fatalf("migration listing dropped the quorum: %v, %v", names, err)
			}
		})
	}
	for _, latestOnly := range []bool{false, true} {
		results := make(chan itemOrErr[ObjectInfo], 16)
		if err := z.Walk(t.Context(), bucket, "", results, WalkOptions{AskDisks: "strict", LatestOnly: latestOnly}); err != nil {
			t.Fatal(err)
		}
		var names []string
		for result := range results {
			if result.Err != nil || !result.Item.ModTime.Equal(newTime) {
				t.Fatalf("Walk returned invalid metadata: %+v", result)
			}
			names = append(names, result.Item.Name)
		}
		if !slices.Equal(names, []string{object}) {
			t.Fatalf("Walk dropped the quorum: %v", names)
		}
	}

	// Exercise the scanner's actual abandoned-child path. Make the scan drive
	// miss the object, while keeping the latest quorum and an older minority on
	// the remaining disks. Its queued heal must read all disks and repair both.
	if err := disks[14].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, oldMeta[14]); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(disks[15].Endpoint().Path, bucket, object)); err != nil {
		t.Fatal(err)
	}
	scanNullQuorumAbandoned(t, z, bucket, object, newTime)
	for i, disk := range disks {
		fi, err := disk.ReadVersion(t.Context(), "", bucket, object, "", ReadOptions{Healing: true})
		if err != nil || !fi.ModTime.Equal(newTime) {
			t.Fatalf("scanner heal did not reconcile disk %d: %v, %v", i, fi.ModTime, err)
		}
	}
	checkRead(newBody, newTime)
	put(newBody, oldTime.Add(2*time.Minute))
	checkRead(newBody, oldTime.Add(2*time.Minute))
}
