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
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/event"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/pubsub"
	"github.com/minio/mux"
)

func nativeRestoreSeed(t *testing.T, r *restoreTest, pool int, null, multipart bool) (ObjectInfo, []byte) {
	t.Helper()
	ctx := t.Context()
	opts := ObjectOptions{Versioned: !null, MTime: UTCNow().Add(-2 * time.Hour), UserDefined: map[string]string{
		"content-type": "application/x-restore-test", "x-amz-meta-preserve": "keep-me",
	}}
	body := bytes.Repeat([]byte("restore-payload"), 100000)
	var oi ObjectInfo
	var err error
	if multipart {
		parts := [][]byte{bytes.Repeat([]byte("a"), 5<<20), []byte("last-part")}
		body = bytes.Join(parts, nil)
		upload, err := r.z.serverPools[pool].NewMultipartUpload(ctx, r.bucket, r.object, opts)
		if err != nil {
			t.Fatal(err)
		}
		var complete []CompletePart
		for i, data := range parts {
			p, err := r.z.serverPools[pool].PutObjectPart(ctx, r.bucket, r.object, upload.UploadID, i+1,
				mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			complete = append(complete, CompletePart{PartNumber: i + 1, ETag: p.ETag})
		}
		oi, err = r.z.serverPools[pool].CompleteMultipartUpload(ctx, r.bucket, r.object, upload.UploadID, complete, opts)
		if err == nil && len(oi.Parts) != 2 {
			t.Fatalf("fixture has %d parts, want 2", len(oi.Parts))
		}
	} else {
		oi, err = r.z.serverPools[pool].PutObject(ctx, r.bucket, r.object,
			mustGetPutObjReader(t, bytes.NewReader(body), int64(len(body)), "", ""), opts)
	}
	if err != nil {
		t.Fatal(err)
	}
	oi.VersionID = restoreTestVersionKey(oi.VersionID)
	topts := r.opts(oi.VersionID)
	topts.MTime = oi.ModTime
	topts.Transition = TransitionOptions{Tier: "WARM", ETag: oi.ETag}
	if err := r.z.serverPools[pool].TransitionObject(ctx, r.bucket, r.object, topts); err != nil {
		t.Fatal(err)
	}
	// Use the production metadata writer to mark the request ongoing.
	topts.Transition = TransitionOptions{}
	topts.EvalMetadataFn = func(o *ObjectInfo, _ error) (ReplicateDecision, error) {
		o.UserDefined[xhttp.AmzRestore] = ongoingRestoreObj().String()
		return ReplicateDecision{}, nil
	}
	if _, err := r.z.PutObjectMetadata(ctx, r.bucket, r.object, topts); err != nil {
		t.Fatal(err)
	}
	return oi, body
}

func nativeRestoreSnapshot(t *testing.T, r *restoreTest) [][]FileInfo {
	t.Helper()
	result := make([][]FileInfo, len(r.z.serverPools))
	for p, pool := range r.z.serverPools {
		raw, err := pool.getHashedSet(r.object).getDisks()[0].ReadXL(t.Context(), r.bucket, r.object, false)
		if errors.Is(err, errFileNotFound) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		infos, err := getFileInfoVersions(raw.Buf, r.bucket, r.object, false)
		if err != nil {
			t.Fatal(err)
		}
		result[p] = append(infos.Versions, infos.FreeVersions...)
	}
	return result
}

func nativeRestoreOptions(r *restoreTest, id string) ObjectOptions {
	opts := r.opts(id)
	opts.Transition = TransitionOptions{RestoreRequest: &RestoreObjectRequest{Days: 1}}
	return opts
}

type nativeRestoreFailTier struct {
	WarmBackend
	failure error
}

func (b nativeRestoreFailTier) Get(context.Context, string, remoteVersionID, WarmBackendGetOpts) (io.ReadCloser, error) {
	return nil, b.failure
}

func TestNativeRestorePools(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, multipart := range []bool{false, true} {
			for _, fail := range []bool{false, true} {
				t.Run(fmt.Sprintf("pools=%d/multipart=%v/failure=%v", pools, multipart, fail), func(t *testing.T) {
					r := newRestoreSafetyTest(t, pools, versioning.Enabled)
					oi, body := nativeRestoreSeed(t, r, 0, false, multipart)
					before := nativeRestoreSnapshot(t, r)
					tier := globalTierConfigMgr.drivercache["WARM"].(*restoreTestTier)
					failure := errors.New("injected remote download failure")
					if fail {
						globalTierConfigMgr.drivercache["WARM"] = nativeRestoreFailTier{tier, failure}
					}
					ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
					defer cancel()
					err := r.z.RestoreTransitionedObject(ctx, r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
					if fail {
						if !errors.Is(err, failure) {
							t.Fatalf("restore error=%v, want remote failure", err)
						}
						got, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
						if err != nil || got.UserDefined[xhttp.AmzRestore] != "" {
							t.Fatalf("failed restore did not clear ongoing status: %v, %q", err, got.UserDefined[xhttp.AmzRestore])
						}
					} else {
						if err != nil {
							t.Fatal(err)
						}
						reads := tier.gets.Load()
						_, got, err := r.read(oi.VersionID)
						if err != nil || !bytes.Equal(got, body) {
							t.Fatalf("restored contents differ: %v", err)
						}
						if tier.gets.Load() != reads {
							t.Error("restored read still fetched the remote tier")
						}
					}
					after := nativeRestoreSnapshot(t, r)
					if len(after[0]) != len(before[0]) || after[0][0].VersionID != before[0][0].VersionID || after[0][0].TransitionedObjName != before[0][0].TransitionedObjName {
						t.Fatal("restore changed the version stack or remote object identity")
					}
					if after[0][0].Metadata["content-type"] != "application/x-restore-test" || after[0][0].Metadata["x-amz-meta-preserve"] != "keep-me" {
						t.Error("restore lost original metadata")
					}
				})
			}
		}
	}
}

func TestNativeRestoreVersionRouting(t *testing.T) {
	for _, pool := range []int{0, 1} {
		for _, null := range []bool{false, true} {
			t.Run(fmt.Sprintf("target-pool=%d/null=%v", pool, null), func(t *testing.T) {
				r := newRestoreSafetyTest(t, 2, versioning.Enabled)
				oi, body := nativeRestoreSeed(t, r, pool, null, false)
				latest := putConsistencyObject(t, r.z, r.bucket, r.object, 1-pool, "latest-stays", ObjectOptions{Versioned: true, MTime: oi.ModTime.Add(time.Hour)})
				before := nativeRestoreSnapshot(t, r)
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				if err := r.z.RestoreTransitionedObject(ctx, r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID)); err != nil {
					t.Fatal(err)
				}
				_, got, err := r.read(oi.VersionID)
				if err != nil || !bytes.Equal(got, body) {
					t.Fatalf("requested version not restored: %v", err)
				}
				after := nativeRestoreSnapshot(t, r)
				if !reflect.DeepEqual(before[1-pool], after[1-pool]) {
					t.Error("restore changed the latest version in another pool")
				}
				if len(after[pool]) != 1 || after[pool][0].VersionID != before[pool][0].VersionID {
					t.Error("restore created a version alias")
				}
				gotInfo, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, ObjectOptions{})
				if err != nil || gotInfo.VersionID != latest.VersionID {
					t.Errorf("latest changed: %v", err)
				}
				before = nativeRestoreSnapshot(t, r)
				if err := r.z.RestoreTransitionedObject(ctx, r.bucket, r.object, nativeRestoreOptions(r, mustGetUUID())); !isErrVersionNotFound(err) && !isErrObjectNotFound(err) {
					t.Errorf("missing version: %v", err)
				}
				if !reflect.DeepEqual(before, nativeRestoreSnapshot(t, r)) {
					t.Error("missing version restore mutated metadata")
				}
			})
		}
	}
}

func TestNativeRestoreInitialFailurePreservesMetadata(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	oi := putConsistencyObject(t, r.z, r.bucket, r.object, 0, "original-latest", ObjectOptions{Versioned: true, UserDefined: map[string]string{"content-type": "application/x-original", "x-amz-meta-preserve": "keep"}})
	before := nativeRestoreSnapshot(t, r)
	for _, missing := range []string{mustGetUUID(), nullVersionID} {
		err := r.z.RestoreTransitionedObject(t.Context(), r.bucket, r.object, nativeRestoreOptions(r, missing))
		if !isErrVersionNotFound(err) {
			t.Errorf("missing restore %s: %v", missing, err)
		}
		if !reflect.DeepEqual(before, nativeRestoreSnapshot(t, r)) {
			t.Error("initial restore failure changed stored metadata or version stack")
		}
	}
	_, body, err := r.read(oi.VersionID)
	if err != nil || string(body) != "original-latest" {
		t.Errorf("initial restore failure changed content: %v", err)
	}
}

func TestNativeRestoreWithoutOuterLock(t *testing.T) {
	for _, mode := range []string{"single-part", "multipart", "failure-metadata"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			oi, _ := nativeRestoreSeed(t, r, 0, false, mode == "multipart")
			tier := globalTierConfigMgr.drivercache["WARM"]
			failure := errors.New("injected remote failure")
			if mode == "failure-metadata" {
				globalTierConfigMgr.drivercache["WARM"] = nativeRestoreFailTier{tier, failure}
			}
			er := r.z.serverPools[0].getHashedSet(r.object)
			lock := er.NewNSLock(r.bucket, r.object)
			lkctx, err := lock.GetLock(t.Context(), globalOperationTimeout)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Unlock(lkctx)
			before := nativeRestoreSnapshot(t, r)
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			err = er.RestoreTransitionedObject(ctx, r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
			if err == nil {
				t.Error("restore wrote through another caller's lock")
			}
			if !reflect.DeepEqual(before, nativeRestoreSnapshot(t, r)) {
				t.Error("NoLock=false failed to protect the stored version")
			}
		})
	}
}

type nativeRestoreHTTPResult struct {
	opts ObjectOptions
	err  error
}
type nativeRestoreHTTPObserver struct {
	ObjectLayer
	done chan nativeRestoreHTTPResult
}

func (o nativeRestoreHTTPObserver) RestoreTransitionedObject(ctx context.Context, bucket, object string, opts ObjectOptions) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := o.ObjectLayer.RestoreTransitionedObject(ctx, bucket, object, opts)
	o.done <- nativeRestoreHTTPResult{opts, err}
	return err
}

func TestNativeRestorePOSTVersionIdentity(t *testing.T) {
	for _, state := range []versioning.State{versioning.Enabled, versioning.Suspended} {
		for _, target := range []int{0, 1} {
			for _, split := range []bool{false, true} {
				for _, multipart := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/target=%d/split=%v/multipart=%v", state, target, split, multipart), func(t *testing.T) {
						r := newRestoreSafetyTest(t, 2, state)
						initConfigSubsystem(t.Context(), r.z)
						oi, body := nativeRestoreSeed(t, r, target, !multipart, multipart)
						metaOpts := r.opts(oi.VersionID)
						metaOpts.MTime = oi.ModTime
						metaOpts.EvalMetadataFn = func(o *ObjectInfo, _ error) (ReplicateDecision, error) {
							o.UserDefined[xhttp.AmzRestore] = ""
							return ReplicateDecision{}, nil
						}
						if _, err := r.z.PutObjectMetadata(t.Context(), r.bucket, r.object, metaOpts); err != nil {
							t.Fatal(err)
						}
						if split {
							putConsistencyObject(t, r.z, r.bucket, r.object, 1-target, "newer-version", ObjectOptions{Versioned: true, MTime: oi.ModTime.Add(time.Hour)})
						}
						before := nativeRestoreSnapshot(t, r)
						observed := nativeRestoreHTTPObserver{r.z, make(chan nativeRestoreHTTPResult, 1)}
						api := objectAPIHandlers{ObjectAPI: func() ObjectLayer { return observed }}
						events := make(chan event.Event, 1)
						done := make(chan struct{})
						defer close(done)
						if err := globalHTTPListen.Subscribe(pubsub.MaskFromMaskable(event.ObjectRestoreCompleted), events, done, nil); err != nil {
							t.Fatal(err)
						}
						bodyXML := []byte(`<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>1</Days></RestoreRequest>`)
						path := "/" + r.bucket + "/" + r.object + "?restore"
						if split {
							path += "&versionId=" + url.QueryEscape(oi.VersionID)
						}
						req, err := newTestSignedRequestV4(http.MethodPost, path, int64(len(bodyXML)), bytes.NewReader(bodyXML), globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
						if err != nil {
							t.Fatal(err)
						}
						if err = req.ParseForm(); err != nil {
							t.Fatal(err)
						}
						req = mux.SetURLVars(req, map[string]string{"bucket": r.bucket, "object": r.object})
						rec := httptest.NewRecorder()
						api.PostRestoreObjectHandler(rec, req)
						if rec.Code != http.StatusOK {
							t.Fatalf("POST restore: %d %s", rec.Code, rec.Body.String())
						}
						select {
						case result := <-observed.done:
							if result.err != nil {
								t.Fatal(result.err)
							}
							if result.opts.VersionID != oi.VersionID || result.opts.Versioned != (state == versioning.Enabled) || result.opts.VersionSuspended != (state == versioning.Suspended) {
								t.Errorf("background options lost version context: %+v", result.opts)
							}
						case <-time.After(5 * time.Second):
							t.Fatal("background restore did not return")
						}
						select {
						case <-events:
						case <-time.After(5 * time.Second):
							t.Fatal("no restore completion event")
						}
						after := nativeRestoreSnapshot(t, r)
						if len(after[target]) != 1 || after[target][0].VersionID != before[target][0].VersionID || after[target][0].TransitionedObjName != before[target][0].TransitionedObjName {
							t.Fatal("POST restore added a version alias")
						}
						if !reflect.DeepEqual(before[1-target], after[1-target]) {
							t.Error("POST changed another pool's version")
						}
						_, got, err := r.read(oi.VersionID)
						if err != nil || !bytes.Equal(got, body) {
							t.Fatalf("POST-restored contents differ: %v", err)
						}
					})
				}
			}
		}
	}
}

// A restore request is internal context, not an exception for normal S3
// multipart overwrites or for a version that has never completed transition.
func TestNativeRestoreMultipartOverwriteBoundary(t *testing.T) {
	for _, mode := range []string{"matching-restore", "ordinary-complete", "not-tiered", "changed-time", "changed-size", "changed-etag"} {
		t.Run(mode, func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			oi, body := nativeRestoreSeed(t, r, 0, false, true)
			pool := r.z.serverPools[0]
			if mode == "not-tiered" {
				er := pool.getHashedSet(r.object)
				fi, _, _, err := er.getObjectFileInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID), false)
				if err != nil {
					t.Fatal(err)
				}
				fi.TransitionStatus = lifecycle.TransitionPending
				for _, disk := range er.getDisks() {
					if err := disk.WriteMetadata(t.Context(), "", r.bucket, r.object, fi); err != nil {
						t.Fatal(err)
					}
				}
			}
			current, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
			if err != nil {
				t.Fatal(err)
			}
			opts := putRestoreOpts(r.bucket, r.object, &RestoreObjectRequest{Days: 1}, current)
			opts.Transition.RestoreRequest = &RestoreObjectRequest{Days: 1}
			if mode == "ordinary-complete" {
				opts.Transition.RestoreRequest = nil
			}
			if mode == "changed-time" {
				opts.MTime = opts.MTime.Add(time.Second)
			}
			// Hold the ETag constant for the size case, so only size can reject it.
			if mode == "changed-size" {
				opts.UserDefined["etag"] = current.ETag
				body = append(body, 'x')
			}
			if mode == "changed-etag" {
				opts.UserDefined["etag"] = "different-etag"
			}
			upload, err := pool.NewMultipartUpload(t.Context(), r.bucket, r.object, opts)
			if err != nil {
				t.Fatal(err)
			}
			var complete []CompletePart
			for i, data := range [][]byte{body[:5<<20], body[5<<20:]} {
				part, err := pool.PutObjectPart(t.Context(), r.bucket, r.object, upload.UploadID, i+1,
					mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				complete = append(complete, CompletePart{PartNumber: i + 1, ETag: part.ETag})
			}
			if mode != "changed-size" && getCompleteMultipartMD5(complete) != current.ETag {
				t.Fatal("fixture multipart ETag does not match original")
			}
			before := nativeRestoreSnapshot(t, r)
			_, err = pool.CompleteMultipartUpload(t.Context(), r.bucket, r.object, upload.UploadID, complete, opts)
			if mode == "matching-restore" {
				if err != nil {
					t.Fatalf("matching restore rejected: %v", err)
				}
				_, got, err := r.read(oi.VersionID)
				if err != nil || !bytes.Equal(got, body) {
					t.Fatalf("matching restore contents: %v", err)
				}
				return
			}
			if !errors.Is(err, errAuthentication) {
				t.Fatalf("existing version overwrite: %v", err)
			}
			if !reflect.DeepEqual(before, nativeRestoreSnapshot(t, r)) {
				t.Error("rejected completion changed the target")
			}
		})
	}
}

// Hold the download after the restore snapshot has been read. Object Lock
// updates must serialize with both successful rehydration and failure cleanup.
type nativeRestoreBlockedTier struct {
	WarmBackend
	entered        chan struct{}
	release        chan struct{}
	once           sync.Once
	failure        error
	afterFirstPart bool
}

func (b *nativeRestoreBlockedTier) Get(ctx context.Context, object string, version remoteVersionID, opts WarmBackendGetOpts) (io.ReadCloser, error) {
	if b.afterFirstPart {
		r, err := b.WarmBackend.Get(ctx, object, version, opts)
		if err != nil {
			return nil, err
		}
		return &nativeRestorePartGateReader{ReadCloser: r, gate: b, ctx: ctx, remaining: 5 << 20}, nil
	}
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if b.failure != nil {
		return nil, b.failure
	}
	return b.WarmBackend.Get(ctx, object, version, opts)
}

func nativeRestoreLockRequest(ctx context.Context, t *testing.T, r *restoreTest, id, kind string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	sum := md5.Sum(body)
	req, err := newTestSignedRequestV4(http.MethodPut, "/"+r.bucket+"/"+r.object+"?"+kind+"&versionId="+url.QueryEscape(id), int64(len(body)), bytes.NewReader(body), globalActiveCred.AccessKey, globalActiveCred.SecretKey, map[string]string{xhttp.ContentMD5: base64.StdEncoding.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	req = mux.SetURLVars(req.WithContext(ctx), map[string]string{"bucket": r.bucket, "object": r.object})
	rec := httptest.NewRecorder()
	api := objectAPIHandlers{ObjectAPI: func() ObjectLayer { return r.z }}
	if kind == "legal-hold" {
		api.PutObjectLegalHoldHandler(rec, req)
	} else {
		api.PutObjectRetentionHandler(rec, req)
	}
	return rec
}

func TestNativeRestoreSerializesObjectLock(t *testing.T) {
	for _, kind := range []string{"legal-hold", "retention"} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failure=%v", kind, fail), func(t *testing.T) {
				r := newRestoreSafetyTest(t, 1, versioning.Enabled)
				initConfigSubsystem(t.Context(), r.z)
				enableBucketObjectLock(t, r.bucket)
				oi, _ := nativeRestoreSeed(t, r, 0, false, true)
				initial := []byte(`<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>OFF</Status></LegalHold>`)
				updated := []byte(`<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>ON</Status></LegalHold>`)
				keys := []string{strings.ToLower(xhttp.AmzObjectLockLegalHold), ReservedMetadataPrefixLower + ObjectLockLegalHoldTimestamp}
				if kind == "retention" {
					initial = retentionBody("COMPLIANCE", UTCNow().Add(24*time.Hour))
					updated = retentionBody("COMPLIANCE", UTCNow().Add(48*time.Hour))
					keys = []string{strings.ToLower(xhttp.AmzObjectLockMode), strings.ToLower(xhttp.AmzObjectLockRetainUntilDate), ReservedMetadataPrefixLower + ObjectLockRetentionTimestamp}
				}
				if rec := nativeRestoreLockRequest(t.Context(), t, r, oi.VersionID, kind, initial); rec.Code != http.StatusOK {
					t.Fatalf("initial protection: %d %s", rec.Code, rec.Body.String())
				}
				before, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
				if err != nil {
					t.Fatal(err)
				}
				blocked := &nativeRestoreBlockedTier{WarmBackend: globalTierConfigMgr.drivercache["WARM"], entered: make(chan struct{}), release: make(chan struct{})}
				if fail {
					blocked.failure = errors.New("injected download failure after snapshot")
				}
				globalTierConfigMgr.drivercache["WARM"] = blocked
				var release sync.Once
				unblock := func() { release.Do(func() { close(blocked.release) }) }
				defer unblock()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				result := make(chan error, 1)
				go func() {
					result <- r.z.RestoreTransitionedObject(ctx, r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
				}()
				select {
				case <-blocked.entered:
				case <-ctx.Done():
					t.Fatal("restore never started download")
				}
				updateCtx, updateCancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
				rec := nativeRestoreLockRequest(updateCtx, t, r, oi.VersionID, kind, updated)
				updateCancel()
				if rec.Code == http.StatusOK {
					t.Error("Object Lock update committed during restore's metadata snapshot")
					// On the unfixed path this update commits, and the restore
					// must not subsequently erase the acknowledged protection.
					readOpts := r.opts(oi.VersionID)
					readOpts.NoLock = true
					before, err = r.z.GetObjectInfo(t.Context(), r.bucket, r.object, readOpts)
					if err != nil {
						t.Fatal(err)
					}
				}
				if rec.Code != http.StatusOK && (rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "<Code>RequestTimeout</Code>")) {
					t.Errorf("update failed for an unrelated reason: %d %s", rec.Code, rec.Body.String())
				}
				unblock()
				select {
				case err := <-result:
					if !errors.Is(err, blocked.failure) {
						t.Fatalf("restore returned %v, want %v", err, blocked.failure)
					}
				case <-ctx.Done():
					t.Fatal("restore failed to finish")
				}
				after, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
				if err != nil {
					t.Fatal(err)
				}
				for _, key := range keys {
					if before.UserDefined[key] == "" || after.UserDefined[key] != before.UserDefined[key] {
						t.Errorf("restore changed protection %s: %q -> %q", key, before.UserDefined[key], after.UserDefined[key])
					}
				}
				if rec := nativeRestoreLockRequest(t.Context(), t, r, oi.VersionID, kind, updated); rec.Code != http.StatusOK {
					t.Fatalf("protection update after restore: %d %s", rec.Code, rec.Body.String())
				}
				final, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
				if err != nil {
					t.Fatal(err)
				}
				if !final.ModTime.Equal(before.ModTime) || final.ETag != before.ETag || final.Size != before.Size {
					t.Error("Object Lock update changed content identity")
				}
				changed := keys[0]
				if kind == "retention" {
					changed = keys[1]
				}
				if final.UserDefined[changed] == before.UserDefined[changed] || final.UserDefined[keys[len(keys)-1]] == before.UserDefined[keys[len(keys)-1]] {
					t.Error("new protection or its timestamp was not stored")
				}
			})
		}
	}
}

func TestNativeRestoreConcurrentCompletion(t *testing.T) {
	for _, separateSets := range []bool{false, true} {
		t.Run(fmt.Sprintf("separate-set-locks=%v", separateSets), func(t *testing.T) {
			r := newRestoreSafetyTest(t, 1, versioning.Enabled)
			if separateSets {
				// Local production sets share one map. Independent maps model the
				// distinct locker groups of distributed sets while reusing test disks.
				pool := r.z.serverPools[0]
				sets, count := pool.sets, pool.setCount
				t.Cleanup(func() { pool.sets, pool.setCount = sets, count })
				first, second := *sets[0], *sets[0]
				first.nsMutex, second.nsMutex = newNSLock(false), newNSLock(false)
				second.setIndex = 1
				pool.sets, pool.setCount = []*erasureObjects{&first, &second}, 2
				for i := 0; ; i++ {
					r.object = fmt.Sprintf("second-set-%d", i)
					if pool.getHashedSetIndex(r.object) == 1 {
						break
					}
				}
			}
			oi, body := nativeRestoreSeed(t, r, 0, false, true)
			blocked := &nativeRestoreBlockedTier{WarmBackend: globalTierConfigMgr.drivercache["WARM"], entered: make(chan struct{}), release: make(chan struct{}), afterFirstPart: true}
			globalTierConfigMgr.drivercache["WARM"] = blocked
			var once sync.Once
			unblock := func() { once.Do(func() { close(blocked.release) }) }
			defer unblock()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			restored := make(chan error, 1)
			go func() {
				restored <- r.z.RestoreTransitionedObject(ctx, r.bucket, r.object, nativeRestoreOptions(r, oi.VersionID))
			}()
			select {
			case <-blocked.entered:
			case <-ctx.Done():
				t.Fatal("restore never started")
			}
			// A client's exact-prefix listing can discover the internal upload. It can
			// try to complete the first part while native restore owns the object.
			uploads, err := r.z.ListMultipartUploads(t.Context(), r.bucket, r.object, "", "", "", 10)
			if err != nil || len(uploads.Uploads) != 1 {
				t.Fatalf("restore upload discovery: %+v, %v", uploads, err)
			}
			id := uploads.Uploads[0].UploadID
			parts, err := r.z.ListObjectParts(t.Context(), r.bucket, r.object, id, 0, 10, ObjectOptions{})
			if err != nil || len(parts.Parts) != 1 {
				t.Fatalf("restore must have published its first part: %+v, %v", parts, err)
			}
			part := parts.Parts[0]
			completed := make(chan struct{})
			var completeErr error
			go func() {
				_, completeErr = r.z.CompleteMultipartUpload(ctx, r.bucket, r.object, id, []CompletePart{{PartNumber: 1, ETag: part.ETag}}, r.opts(oi.VersionID))
				close(completed)
			}()
			waitForListingReadLock(t, r.z.serverPools[0].getHashedSet(r.object).nsMutex, r.bucket, r.object, completed)
			unblock()
			select {
			case err := <-restored:
				if err != nil {
					t.Errorf("restore blocked by concurrent completion: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("restore did not finish")
			}
			select {
			case <-completed:
			case <-time.After(5 * time.Second):
				t.Fatal("completion did not finish")
			}
			if !errors.As(completeErr, &InvalidUploadID{}) {
				t.Errorf("completion after native restore: %v, want InvalidUploadID", completeErr)
			}
			_, got, err := r.read(oi.VersionID)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatalf("restore contents after concurrent completion: %v", err)
			}
		})
	}
}

type nativeRestorePartGateReader struct {
	io.ReadCloser
	gate      *nativeRestoreBlockedTier
	ctx       context.Context
	remaining int
}

func (r *nativeRestorePartGateReader) Read(p []byte) (int, error) {
	if r.remaining > 0 {
		if len(p) > r.remaining {
			p = p[:r.remaining]
		}
		n, err := r.ReadCloser.Read(p)
		r.remaining -= n
		return n, err
	}
	r.gate.once.Do(func() { close(r.gate.entered) })
	select {
	case <-r.gate.release:
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}
	return r.ReadCloser.Read(p)
}

// Invalid upload paths must retain the backend's normal error precedence,
// rather than reacquiring the object lock as the upload lock.
func TestMultipartCompletionLockAlias(t *testing.T) {
	for _, pools := range []int{1, 2} {
		for _, id := range []string{"", ".", "./"} {
			t.Run(fmt.Sprintf("pools=%d/id=%q", pools, id), func(t *testing.T) {
				r := newRestoreSafetyTest(t, pools, versioning.Enabled)
				for _, missingBucket := range []bool{false, true} {
					bucket := r.bucket
					if missingBucket {
						bucket = "missing-bucket"
					}
					ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
					_, err := r.z.CompleteMultipartUpload(ctx, bucket, r.object, id, nil, ObjectOptions{})
					cancel()
					switch {
					case id != "":
						if !errors.As(err, &MalformedUploadID{}) {
							t.Errorf("malformed upload: %v", err)
						}
					case missingBucket:
						if !isErrBucketNotFound(err) {
							t.Errorf("missing bucket: %v", err)
						}
					default:
						if !errors.As(err, &InvalidUploadID{}) {
							t.Errorf("invalid upload: %v", err)
						}
					}
				}
			})
		}
	}
}
