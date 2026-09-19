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
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	madmin "github.com/minio/madmin-go/v3"
)

// Hold nine completed disk walks while a PUT overwrites one name. The other
// seven walks start after that PUT completes. Both generations come from real
// disk walkers and valid PUT metadata; only the reader schedule is controlled.
type nullQuorumWalkSchedule struct {
	bucket    string
	oldReady  chan struct{}
	resume    chan struct{}
	mu        sync.Mutex
	snapshots [16][]byte
}

type nullQuorumWalkDisk struct {
	StorageAPI
	schedule *nullQuorumWalkSchedule
	index    int
}

type failedMetadataWalkDisk struct {
	StorageAPI
}

func (d *failedMetadataWalkDisk) WalkDir(context.Context, WalkDirOptions, io.Writer) error {
	return errDiskNotFound
}

func (d *nullQuorumWalkDisk) WalkDir(ctx context.Context, opts WalkDirOptions, out io.Writer) error {
	if opts.Bucket != d.schedule.bucket {
		return d.StorageAPI.WalkDir(ctx, opts, out)
	}
	var stream bytes.Buffer
	if d.index < 9 {
		if err := d.StorageAPI.WalkDir(ctx, opts, &stream); err != nil {
			return err
		}
		select {
		case d.schedule.oldReady <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case <-d.schedule.resume:
	case <-ctx.Done():
		return ctx.Err()
	}
	if d.index >= 9 {
		if err := d.StorageAPI.WalkDir(ctx, opts, &stream); err != nil {
			return err
		}
	}
	d.schedule.mu.Lock()
	d.schedule.snapshots[d.index] = bytes.Clone(stream.Bytes())
	d.schedule.mu.Unlock()
	_, err := out.Write(stream.Bytes())
	return err
}

func nullQuorumBackend(t *testing.T) (*erasureServerPools, string, http.Handler) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	obj, dirs, err := prepareErasure16(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	t.Cleanup(func() {
		cancel()
		z.Shutdown(context.Background())
		removeRoots(dirs)
		setObjectLayer(previous)
	})
	bucket, router, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return z, bucket, router
}

func nullQuorumRequest(t *testing.T, router http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := newTestSignedRequestV4(method, target, 0, nil, globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(t.Context()))
	return rec
}

func TestListObjectsSingleNullQuorumHTTP(t *testing.T) {
	z, bucket, router := nullQuorumBackend(t)
	oldBody := bytes.Repeat([]byte{'a'}, 8192)
	newBody := bytes.Repeat([]byte{'b'}, 8192)
	oldTime := time.Now().UTC().Add(-time.Hour)
	newTime := oldTime.Add(time.Minute)
	var want []string
	for i := range 16 {
		name := fmt.Sprintf("fixed/%02d", i)
		want = append(want, name)
		_, err := z.PutObject(t.Context(), bucket, name, mustGetPutObjReader(t, bytes.NewReader(oldBody), int64(len(oldBody)), "", ""), ObjectOptions{MTime: oldTime})
		if err != nil {
			t.Fatal(err)
		}
	}
	const overwritten = "fixed/10"
	schedule := &nullQuorumWalkSchedule{bucket: bucket, oldReady: make(chan struct{}, 16), resume: make(chan struct{})}
	set := z.serverPools[0].sets[0]
	disks := set.getDisks()
	wrapped := make([]StorageAPI, len(disks))
	for i, disk := range disks {
		wrapped[i] = &nullQuorumWalkDisk{StorageAPI: disk, schedule: schedule, index: i}
	}
	set.getDisks = func() []StorageAPI { return wrapped }
	if globalAPIConfig.getListQuorum() != "strict" {
		t.Fatal("test requires strict listing across all sixteen disks")
	}
	writeDone := make(chan error, 1)
	putReader := mustGetPutObjReader(t, bytes.NewReader(newBody), int64(len(newBody)), "", "")
	go func() {
		defer close(schedule.resume)
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		for range 9 {
			select {
			case <-schedule.oldReady:
			case <-ctx.Done():
				writeDone <- ctx.Err()
				return
			}
		}
		_, err := z.PutObject(ctx, bucket, overwritten, putReader, ObjectOptions{MTime: newTime})
		writeDone <- err
	}()
	rec := nullQuorumRequest(t, router, http.MethodGet, getListObjectsV2URL("", bucket, "fixed/", "1000", "", "", ""))
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	var list ListObjectsV2Response
	if rec.Code != http.StatusOK || xml.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Fatalf("LIST: %d %s", rec.Code, rec.Body.String())
	}
	var got []string
	for _, object := range list.Contents {
		got = append(got, object.Key)
	}
	t.Logf("LIST HTTP=%d KeyCount=%d IsTruncated=%v keys=%v", rec.Code, list.KeyCount, list.IsTruncated, got)
	if list.KeyCount != 16 || list.IsTruncated || !slices.Equal(got, want) {
		t.Errorf("LIST omitted a name during overwrite: got %v, want %v", got, want)
	}

	// Verify the actual reader inputs, including shape and EC, instead of
	// assuming the scheduling barrier produced the intended resolver case.
	schedule.mu.Lock()
	snapshots := schedule.snapshots
	schedule.mu.Unlock()
	for i, snapshot := range snapshots {
		reader := newMetacacheReader(bytes.NewReader(snapshot))
		var found bool
		for {
			entry, err := reader.next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if entry.name != overwritten {
				continue
			}
			xl, err := entry.xlmeta()
			if err != nil || len(xl.versions) != 1 {
				t.Fatalf("disk %d: invalid input shape: %v", i, err)
			}
			header := xl.versions[0].header
			wantTime := oldTime
			if i >= 9 {
				wantTime = newTime
			}
			if header.ModTime != wantTime.UnixNano() || header.VersionID != [16]byte{} || header.Type != ObjectType || header.FreeVersion() {
				t.Fatalf("disk %d: unexpected header %v", i, header)
			}
			t.Logf("disk=%d versions=1 header=%v", i, header)
			found = true
		}
		reader.Close()
		if !found {
			t.Fatalf("disk %d did not emit the overwritten name", i)
		}
	}
	get := nullQuorumRequest(t, router, http.MethodGet, getGetObjectURL("", bucket, overwritten))
	head := nullQuorumRequest(t, router, http.MethodHead, getGetObjectURL("", bucket, overwritten))
	t.Logf("completed PUT readback: GET=%d bytes=%d HEAD=%d length=%s", get.Code, get.Body.Len(), head.Code, head.Header().Get("Content-Length"))
	if get.Code != http.StatusOK || !bytes.Equal(get.Body.Bytes(), newBody) || head.Code != http.StatusOK || head.Header().Get("Content-Length") != "8192" {
		t.Fatalf("completed PUT was not readable: GET=%d HEAD=%d", get.Code, head.Code)
	}
}

func TestListObjectsFallsBackToReadableMetadata(t *testing.T) {
	z, bucket, router := nullQuorumBackend(t)
	set := z.serverPools[0].sets[0]
	disks := set.getDisks()
	const object = "object"
	oldBody := bytes.Repeat([]byte{'a'}, 8192)
	newBody := bytes.Repeat([]byte{'b'}, 8192)
	oldTime := time.Now().UTC().Add(-time.Hour)

	if _, err := z.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, bytes.NewReader(oldBody), int64(len(oldBody)), "", ""), ObjectOptions{MTime: oldTime}); err != nil {
		t.Fatal(err)
	}
	oldMeta := make([][]byte, len(disks))
	for i, disk := range disks {
		oldMeta[i] = mustReadNullQuorumMeta(t, disk, bucket, object)
	}
	if _, err := z.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, bytes.NewReader(newBody), int64(len(newBody)), "", ""), ObjectOptions{MTime: oldTime.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}

	// The eight readable walk streams are split 3/5 across two generations;
	// the other eight streams fail. Neither generation is proven readable by
	// the listing inputs, so returning HTTP 200 would silently omit the key.
	for i := range 3 {
		if err := disks[i].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, oldMeta[i]); err != nil {
			t.Fatal(err)
		}
	}
	wrapped := make([]StorageAPI, len(disks))
	for i, disk := range disks {
		wrapped[i] = disk
		if i >= 8 {
			wrapped[i] = &failedMetadataWalkDisk{StorageAPI: disk}
		}
	}
	set.getDisks = func() []StorageAPI { return wrapped }

	rec := nullQuorumRequest(t, router, http.MethodGet, getListObjectsV2URL("", bucket, "", "1000", "", "", ""))
	var list ListObjectsV2Response
	if rec.Code != http.StatusOK || xml.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Fatalf("LIST failed to resolve readable metadata: %d %s", rec.Code, rec.Body.String())
	}
	if list.KeyCount != 1 || len(list.Contents) != 1 || list.Contents[0].Key != object {
		t.Fatalf("LIST omitted the readable key: %+v", list)
	}

	// The object itself still has a read quorum outside the failed walk
	// streams, demonstrating why the LIST must report uncertainty, not absence.
	get := nullQuorumRequest(t, router, http.MethodGet, getGetObjectURL("", bucket, object))
	if get.Code != http.StatusOK || !bytes.Equal(get.Body.Bytes(), newBody) {
		t.Fatalf("GET lost the readable generation: %d %q", get.Code, get.Body.String())
	}
}

// The fallback must read under the object read lock. A lock-free read of an
// object being overwritten stably reports a live object as absent, which is
// the omission this repair exists to remove. Hold the write lock and assert
// the listing waits for it rather than resolving straight through.
func TestListFallbackTakesObjectReadLock(t *testing.T) {
	z, bucket, router := nullQuorumBackend(t)
	set := z.serverPools[0].sets[0]
	disks := set.getDisks()
	const object = "object"
	oldBody, newBody := bytes.Repeat([]byte{'a'}, 8192), bytes.Repeat([]byte{'b'}, 8192)
	oldTime := time.Now().UTC().Add(-time.Hour)

	if _, err := z.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, bytes.NewReader(oldBody), int64(len(oldBody)), "", ""), ObjectOptions{MTime: oldTime}); err != nil {
		t.Fatal(err)
	}
	oldMeta := make([][]byte, len(disks))
	for i, disk := range disks {
		oldMeta[i] = mustReadNullQuorumMeta(t, disk, bucket, object)
	}
	if _, err := z.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, bytes.NewReader(newBody), int64(len(newBody)), "", ""), ObjectOptions{MTime: oldTime.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// Split the readable walk streams so the entry cannot be resolved from
	// the snapshots and the fallback has to run.
	for i := range 3 {
		if err := disks[i].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, oldMeta[i]); err != nil {
			t.Fatal(err)
		}
	}
	wrapped := make([]StorageAPI, len(disks))
	for i, disk := range disks {
		wrapped[i] = disk
		if i >= 8 {
			wrapped[i] = &failedMetadataWalkDisk{StorageAPI: disk}
		}
	}
	set.getDisks = func() []StorageAPI { return wrapped }

	lock := set.NewNSLock(bucket, object)
	lkctx, err := lock.GetLock(t.Context(), globalOperationTimeout)
	if err != nil {
		t.Fatal(err)
	}
	const hold = 300 * time.Millisecond
	released := make(chan struct{})
	go func() {
		time.Sleep(hold)
		lock.Unlock(lkctx)
		close(released)
	}()

	start := time.Now()
	rec := nullQuorumRequest(t, router, http.MethodGet, getListObjectsV2URL("", bucket, "", "1000", "", "", ""))
	elapsed := time.Since(start)
	<-released

	if elapsed < hold {
		t.Fatalf("listing fallback did not wait for the object lock: %v < %v", elapsed, hold)
	}
	var list ListObjectsV2Response
	if rec.Code != http.StatusOK || xml.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Fatalf("LIST failed after the lock was released: %d %s", rec.Code, rec.Body.String())
	}
	if list.KeyCount != 1 || len(list.Contents) != 1 || list.Contents[0].Key != object {
		t.Fatalf("LIST omitted the readable key: %+v", list)
	}
}

// A truncated xl.meta is what a concurrent overwrite looks like on one drive,
// and the walker skips that entry. Skipping is safe and deliberate: the key is
// only omitted when no generation reaches quorum, which listPath now resolves
// against the read path. Pin that, so the walker is not "hardened" into
// failing a whole listing over a minority of unreadable drives.
func TestListObjectsSurvivesTruncatedMetadataMinority(t *testing.T) {
	z, bucket, router := nullQuorumBackend(t)
	set := z.serverPools[0].sets[0]
	disks := set.getDisks()
	const object = "object"
	body := bytes.Repeat([]byte{'a'}, 8192)

	if _, err := z.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), ObjectOptions{}); err != nil {
		t.Fatal(err)
	}

	// Truncate xl.meta on a minority of drives, as an overwrite in flight does.
	for i := range 4 {
		meta := mustReadNullQuorumMeta(t, disks[i], bucket, object)
		if err := disks[i].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, meta[:len(meta)/2]); err != nil {
			t.Fatal(err)
		}
	}

	rec := nullQuorumRequest(t, router, http.MethodGet, getListObjectsV2URL("", bucket, "", "1000", "", "", ""))
	var list ListObjectsV2Response
	if rec.Code != http.StatusOK || xml.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Fatalf("a truncated minority failed the listing: %d %s", rec.Code, rec.Body.String())
	}
	if list.KeyCount != 1 || len(list.Contents) != 1 || list.Contents[0].Key != object {
		t.Fatalf("a truncated minority omitted the key: %+v", list)
	}
}

func TestSingleNullQuorumReadAndConsumers(t *testing.T) {
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
	newMinorityMeta := mustReadNullQuorumMeta(t, disks[14], bucket, object)
	// Model an incomplete overwrite using real inline shards: fifteen old
	// copies retain a read quorum; the final disk contains the newer minority.
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
	checkRead(oldBody, oldTime)
	// Reading must not reinterpret the minority as absent or delete it.
	minority, err := disks[15].ReadVersion(t.Context(), "", bucket, object, "", ReadOptions{})
	if err != nil || !minority.ModTime.Equal(oldTime.Add(time.Minute)) {
		t.Fatalf("read mutated the minority: %+v, %v", minority, err)
	}
	for _, kind := range []string{"rebalance", "decommission"} {
		t.Run(kind, func(t *testing.T) {
			var names []string
			consume := func(entry metaCacheEntry) {
				versions, err := entry.fileInfoVersions(bucket)
				if err != nil || len(versions.Versions) != 1 || !versions.Versions[0].ModTime.Equal(oldTime) {
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
				if err != nil || !bytes.Equal(body, oldBody) {
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
			if result.Err != nil || !result.Item.ModTime.Equal(oldTime) {
				t.Fatalf("Walk returned invalid metadata: %+v", result)
			}
			names = append(names, result.Item.Name)
		}
		if !slices.Equal(names, []string{object}) {
			t.Fatalf("Walk dropped the quorum: %v", names)
		}
	}

	// Exercise the scanner's actual abandoned-child path. Make the scan drive
	// miss the object, while keeping an older quorum and a newer minority on
	// the remaining disks. Its queued heal must read all disks and repair both.
	if err := disks[14].WriteAll(t.Context(), bucket, object+"/"+xlStorageFormatFile, newMinorityMeta); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(disks[15].Endpoint().Path, bucket, object)); err != nil {
		t.Fatal(err)
	}
	scanNullQuorumAbandoned(t, z, bucket, object, oldTime)
	for i, disk := range disks {
		fi, err := disk.ReadVersion(t.Context(), "", bucket, object, "", ReadOptions{Healing: true})
		if err != nil || !fi.ModTime.Equal(oldTime) {
			t.Fatalf("scanner heal did not reconcile disk %d: %v, %v", i, fi.ModTime, err)
		}
	}
	checkRead(oldBody, oldTime)
	put(newBody, oldTime.Add(2*time.Minute))
	checkRead(newBody, oldTime.Add(2*time.Minute))
}

func mustReadNullQuorumMeta(t *testing.T, disk StorageAPI, bucket, object string) []byte {
	t.Helper()
	data, err := disk.ReadAll(t.Context(), bucket, object+"/"+xlStorageFormatFile)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func scanNullQuorumAbandoned(t *testing.T, z *erasureServerPools, bucket, object string, oldTime time.Time) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	disks := z.serverPools[0].sets[0].getDisks()
	seq := newBgHealSequence()
	defer seq.cancelCtx()
	previousState, previousRoutine := globalBackgroundHealState, globalBackgroundHealRoutine
	globalBackgroundHealState = &allHealState{healSeqMap: map[string]*healSequence{"test": seq}}
	routine := &healRoutine{tasks: make(chan healTask)}
	globalBackgroundHealRoutine = routine
	defer func() { globalBackgroundHealState, globalBackgroundHealRoutine = previousState, previousRoutine }()
	workerDone := make(chan struct{})
	var healed []string
	go func() {
		defer close(workerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case task := <-routine.tasks:
				var result madmin.HealResultItem
				var err error
				if task.object == "" {
					result, err = z.HealBucket(ctx, task.bucket, task.opts)
				} else {
					healed = append(healed, task.object+"/"+task.versionID)
					result, err = z.HealObject(ctx, task.bucket, task.object, task.versionID, task.opts)
				}
				task.respCh <- healResult{result: result, err: err}
			}
		}
	}()
	cache := dataUsageCache{Info: dataUsageCacheInfo{Name: bucket}}
	cache.replace(bucket, "", dataUsageEntry{})
	cache.replace(bucket+"/"+object, bucket, dataUsageEntry{Size: 8192, Objects: 1, Versions: 1})
	scanner := folderScanner{
		root: disks[15].Endpoint().Path, oldCache: cache,
		newCache: dataUsageCache{Info: cache.Info}, updateCache: dataUsageCache{Info: cache.Info},
		disks: disks, disksQuorum: 8, healObjectSelect: 1,
		weSleep: func() bool { return false }, shouldHeal: func() bool { return true }, updateCurrentPath: func(string) {},
		getSize: func(item scannerItem) (sizeSummary, error) {
			if filepath.Base(item.Path) != xlStorageFormatFile {
				return sizeSummary{}, errSkipFile
			}
			data, err := os.ReadFile(item.Path)
			if err != nil {
				return sizeSummary{}, err
			}
			var xl xlMetaV2
			if err := xl.Load(data); err != nil {
				return sizeSummary{}, err
			}
			fi, err := xl.ToFileInfo(bucket, object, "", false, false)
			if err != nil || !fi.ModTime.Equal(oldTime) {
				return sizeSummary{}, fmt.Errorf("scanner re-read wrong generation: %v, %v", fi.ModTime, err)
			}
			return sizeSummary{totalSize: fi.Size, versions: 1}, nil
		},
	}
	var usage dataUsageEntry
	err := scanner.scanFolder(ctx, cachedFolder{name: bucket, objectHealProbDiv: 1}, &usage)
	cancel()
	<-workerDone
	if err != nil || len(healed) != 1 || healed[0] != object+"/"+nullVersionID && healed[0] != object+"/" {
		t.Fatalf("scanner did not queue a name-based heal: %v, %v", healed, err)
	}
	flat := scanner.newCache.sizeRecursive(bucket)
	if flat == nil || flat.Objects != 1 || flat.Size != 8192 {
		t.Fatalf("scanner lost the healed object from usage: %+v", flat)
	}
	t.Logf("scanner queued %v; healed old quorum, repaired minority/missing copies, and retained one 8192-byte object", healed)
}
