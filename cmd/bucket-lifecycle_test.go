// Copyright (c) 2015-2021 MinIO, Inc.
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
	"bytes"
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/lifecycle"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	xhttp "github.com/minio/minio/internal/http"
)

// TestParseRestoreObjStatus tests parseRestoreObjStatus
func TestParseRestoreObjStatus(t *testing.T) {
	testCases := []struct {
		restoreHdr     string
		expectedStatus restoreObjStatus
		expectedErr    error
	}{
		{
			// valid: represents a restored object, 'pending' expiry.
			restoreHdr: `ongoing-request="false", expiry-date="Fri, 21 Dec 2012 00:00:00 GMT"`,
			expectedStatus: restoreObjStatus{
				ongoing: false,
				expiry:  time.Date(2012, 12, 21, 0, 0, 0, 0, time.UTC),
			},
			expectedErr: nil,
		},
		{
			// valid: represents an ongoing restore object request.
			restoreHdr: `ongoing-request="true"`,
			expectedStatus: restoreObjStatus{
				ongoing: true,
			},
			expectedErr: nil,
		},
		{
			// invalid; ongoing restore object request can't have expiry set on it.
			restoreHdr:     `ongoing-request="true", expiry-date="Fri, 21 Dec 2012 00:00:00 GMT"`,
			expectedStatus: restoreObjStatus{},
			expectedErr:    errRestoreHDRMalformed,
		},
		{
			// invalid; completed restore object request must have expiry set on it.
			restoreHdr:     `ongoing-request="false"`,
			expectedStatus: restoreObjStatus{},
			expectedErr:    errRestoreHDRMalformed,
		},
	}
	for i, tc := range testCases {
		actual, err := parseRestoreObjStatus(tc.restoreHdr)
		if err != tc.expectedErr {
			t.Fatalf("Test %d: got %v expected %v", i+1, err, tc.expectedErr)
		}
		if actual != tc.expectedStatus {
			t.Fatalf("Test %d: got %v expected %v", i+1, actual, tc.expectedStatus)
		}
	}
}

// TestRestoreObjStatusRoundTrip restoreObjStatus roundtrip
func TestRestoreObjStatusRoundTrip(t *testing.T) {
	testCases := []restoreObjStatus{
		ongoingRestoreObj(),
		completedRestoreObj(time.Now().UTC()),
	}
	for i, tc := range testCases {
		actual, err := parseRestoreObjStatus(tc.String())
		if err != nil {
			t.Fatalf("Test %d: parse restore object failed: %v", i+1, err)
		}
		if actual.ongoing != tc.ongoing || actual.expiry.Format(http.TimeFormat) != tc.expiry.Format(http.TimeFormat) {
			t.Fatalf("Test %d: got %v expected %v", i+1, actual, tc)
		}
	}
}

// TestRestoreObjOnDisk tests restoreObjStatus' OnDisk method
func TestRestoreObjOnDisk(t *testing.T) {
	testCases := []struct {
		restoreStatus restoreObjStatus
		ondisk        bool
	}{
		{
			// restore in progress
			restoreStatus: ongoingRestoreObj(),
			ondisk:        false,
		},
		{
			// restore completed but expired
			restoreStatus: completedRestoreObj(time.Now().Add(-time.Hour)),
			ondisk:        false,
		},
		{
			// restore completed
			restoreStatus: completedRestoreObj(time.Now().Add(time.Hour)),
			ondisk:        true,
		},
	}

	for i, tc := range testCases {
		if actual := tc.restoreStatus.OnDisk(); actual != tc.ondisk {
			t.Fatalf("Test %d: expected %v but got %v", i+1, tc.ondisk, actual)
		}
	}
}

// TestIsRestoredObjectOnDisk tests isRestoredObjectOnDisk helper function
func TestIsRestoredObjectOnDisk(t *testing.T) {
	testCases := []struct {
		meta   map[string]string
		ondisk bool
	}{
		{
			// restore in progress
			meta: map[string]string{
				xhttp.AmzRestore: ongoingRestoreObj().String(),
			},
			ondisk: false,
		},
		{
			// restore completed
			meta: map[string]string{
				xhttp.AmzRestore: completedRestoreObj(time.Now().Add(time.Hour)).String(),
			},
			ondisk: true,
		},
		{
			// restore completed but expired
			meta: map[string]string{
				xhttp.AmzRestore: completedRestoreObj(time.Now().Add(-time.Hour)).String(),
			},
			ondisk: false,
		},
	}

	for i, tc := range testCases {
		if actual := isRestoredObjectOnDisk(tc.meta); actual != tc.ondisk {
			t.Fatalf("Test %d: expected %v but got %v for %v", i+1, tc.ondisk, actual, tc.meta)
		}
	}
}

func TestObjectIsRemote(t *testing.T) {
	fi := newFileInfo("object", 8, 8)
	fi.Erasure.Index = 1
	if !fi.IsValid() {
		t.Fatalf("unable to get xl meta")
	}

	testCases := []struct {
		meta   map[string]string
		remote bool
	}{
		{
			// restore in progress
			meta: map[string]string{
				xhttp.AmzRestore: ongoingRestoreObj().String(),
			},
			remote: true,
		},
		{
			// restore completed
			meta: map[string]string{
				xhttp.AmzRestore: completedRestoreObj(time.Now().Add(time.Hour)).String(),
			},
			remote: false,
		},
		{
			// restore completed but expired
			meta: map[string]string{
				xhttp.AmzRestore: completedRestoreObj(time.Now().Add(-time.Hour)).String(),
			},
			remote: true,
		},
		{
			// restore never initiated
			meta:   map[string]string{},
			remote: true,
		},
	}
	for i, tc := range testCases {
		// Set transition status to complete
		fi.TransitionStatus = lifecycle.TransitionComplete
		fi.Metadata = tc.meta
		if got := fi.IsRemote(); got != tc.remote {
			t.Fatalf("Test %d.a: expected %v got %v", i+1, tc.remote, got)
		}
		oi := fi.ToObjectInfo("bucket", "object", false)
		if got := oi.IsRemote(); got != tc.remote {
			t.Fatalf("Test %d.b: expected %v got %v", i+1, tc.remote, got)
		}
	}
	// Reset transition status; An object that's not transitioned is not remote.
	fi.TransitionStatus = ""
	fi.Metadata = nil
	if got := fi.IsRemote(); got != false {
		t.Fatalf("Expected object not to be remote but got %v", got)
	}
}

func TestValidateTransitionTier(t *testing.T) {
	globalTierConfigMgr = NewTierConfigMgr()
	testCases := []struct {
		xml         []byte
		expectedErr error
	}{
		{
			// non-existent storage-class
			xml:         []byte(`<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>rule</ID><Prefix /><Status>Enabled</Status><Transition><Days>1</Days><StorageClass>"NONEXISTENT"</StorageClass></Transition></Rule></LifecycleConfiguration>`),
			expectedErr: errInvalidStorageClass,
		},
		{
			// no transition rule
			xml:         []byte(`<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>rule</ID><Prefix /><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`),
			expectedErr: nil,
		},
	}
	for i, tc := range testCases {
		lc, err := lifecycle.ParseLifecycleConfig(bytes.NewReader(tc.xml))
		if err != nil {
			t.Fatalf("Test %d: Failed to parse lifecycle config %v", i+1, err)
		}

		err = validateTransitionTier(lc)
		if err != tc.expectedErr {
			t.Fatalf("Test %d: Expected %v but got %v", i+1, tc.expectedErr, err)
		}
	}
}

// tierExpiryTestBackend is a remote tier held in memory.
type tierExpiryTestBackend struct {
	mu      sync.Mutex
	objects map[string][]byte
	removed []string
}

func (b *tierExpiryTestBackend) Put(ctx context.Context, object string, r io.Reader, length int64) (remoteVersionID, error) {
	return b.PutWithMeta(ctx, object, r, length, nil)
}

func (b *tierExpiryTestBackend) PutWithMeta(_ context.Context, object string, r io.Reader, _ int64, _ map[string]string) (remoteVersionID, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects[object] = data
	return "", nil
}

func (b *tierExpiryTestBackend) Get(_ context.Context, object string, _ remoteVersionID, opts WarmBackendGetOpts) (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.objects[object]
	if !ok {
		return nil, ObjectNotFound{Bucket: "tier", Object: object}
	}
	if opts.length > 0 {
		data = data[opts.startOffset : opts.startOffset+opts.length]
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (b *tierExpiryTestBackend) Remove(_ context.Context, object string, _ remoteVersionID) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.objects, object)
	b.removed = append(b.removed, object)
	return nil
}

func (b *tierExpiryTestBackend) InUse(context.Context) (bool, error) { return false, nil }

// The expiry of a transitioned latest version that only puts a delete marker
// on top of it must keep its remote object, so the version stays readable as
// a noncurrent version. The remote object goes when the version is deleted.
func TestExpireTransitionedObjectKeepsNoncurrentData(t *testing.T) {
	z, _ := migrationTestPools(t)
	ctx := t.Context()
	tier := &tierExpiryTestBackend{objects: map[string][]byte{}}
	prevTier := globalTierConfigMgr
	globalTierConfigMgr = NewTierConfigMgr()
	globalTierConfigMgr.drivercache["WARM"] = tier
	t.Cleanup(func() { globalTierConfigMgr = prevTier })

	const expire = `<LifecycleConfiguration><Rule><ID>exp</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>` +
		`<Expiration><Date>2020-01-01T00:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>`

	testCases := []struct {
		name       string
		versioning string   // "", Enabled or Suspended
		nullLatest bool     // the latest version is the null version
		keep       bool     // the latest version survives as noncurrent
		want       []string // versions after the expiry, newest first
	}{
		{name: "versioned", versioning: "Enabled", keep: true, want: []string{"DM", "v2", "v1"}},
		{name: "suspended", versioning: "Suspended", keep: true, want: []string{"DM", "v2", "v1"}},
		{name: "suspended-null", versioning: "Suspended", nullLatest: true, want: []string{"DM", "v1"}},
		{name: "unversioned", nullLatest: true, want: nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bucket := "tier-expiry-" + tc.name
			if err := z.MakeBucket(ctx, bucket, MakeBucketOptions{VersioningEnabled: tc.versioning != ""}); err != nil {
				t.Fatal(err)
			}
			meta, err := globalBucketMetadataSys.Get(bucket)
			if err != nil {
				t.Fatal(err)
			}
			if tc.versioning == "Suspended" {
				meta.VersioningConfigXML = []byte("<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>")
			}
			meta.LifecycleConfigXML = []byte(expire)
			if err := meta.Save(ctx, z); err != nil {
				t.Fatal(err)
			}
			globalBucketMetadataSys.Set(bucket, meta)

			// tiered writes a version whose data is in the remote tier.
			labels := map[string]string{}
			tiered := func(label string, opts ObjectOptions) ObjectInfo {
				t.Helper()
				oi := putConsistencyObject(t, z, bucket, "obj", 0, "obj "+label, opts)
				vid := migrationTestVersion(oi)
				infos, errs := readAllFileInfo(ctx, z.serverPools[0].getHashedSet("obj").getDisks(), "", bucket, "obj", vid, false, false)
				if errs[0] != nil {
					t.Fatal(errs[0])
				}
				fi := infos[0]
				fi.TransitionStatus, fi.TransitionTier, fi.TransitionedObjName = lifecycle.TransitionComplete, "WARM", bucket+"/"+label
				if _, err := tier.Put(ctx, fi.TransitionedObjName, strings.NewReader("obj "+label), -1); err != nil {
					t.Fatal(err)
				}
				if err := z.serverPools[0].DecomTieredObject(ctx, bucket, "obj", fi, ObjectOptions{}); err != nil {
					t.Fatal(err)
				}
				labels[vid] = label
				return oi
			}
			var latest ObjectInfo
			if tc.versioning != "" {
				tiered("v1", ObjectOptions{Versioned: true})
			}
			if tc.nullLatest {
				latest = tiered("v2", ObjectOptions{})
			} else {
				latest = tiered("v2", ObjectOptions{Versioned: true})
			}

			// Expire the latest version as the expiry worker does for the scanner.
			getOpts := ObjectOptions{Versioned: tc.versioning == "Enabled", VersionSuspended: tc.versioning == "Suspended"}
			oi, err := z.GetObjectInfo(ctx, bucket, "obj", getOpts)
			if err != nil {
				t.Fatal(err)
			}
			lc, err := globalLifecycleSys.Get(bucket)
			if err != nil {
				t.Fatal(err)
			}
			evt := evalActionFromLifecycle(ctx, *lc, objectlock.Retention{}, nil, oi)
			if evt.Action != lifecycle.DeleteAction || oi.TransitionedObject.Status != lifecycle.TransitionComplete {
				t.Fatalf("fixture: action %v, transition status %q", evt.Action, oi.TransitionedObject.Status)
			}
			if err := expireTransitionedObject(ctx, z, &oi, evt, lcEventSrc_Scanner); err != nil {
				t.Errorf("expiry: %v", err)
			}

			var got []string
			for _, set := range z.serverPools[0].sets {
				err := set.listObjectsToDecommission(ctx, decomBucketInfo{Name: bucket}, func(entry metaCacheEntry) {
					fivs, err := entry.fileInfoVersions(bucket)
					if err != nil {
						t.Error(err)
						return
					}
					for _, fi := range fivs.Versions {
						if fi.Deleted {
							got = append(got, "DM")
						} else {
							got = append(got, labels[migrationTestVersion(fi.ToObjectInfo(bucket, "obj", true))])
						}
					}
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("versions after expiry: got %v, want %v", got, tc.want)
			}
			remote := bucket + "/v2"
			if removed := slices.Contains(tier.removed, remote); removed == tc.keep {
				t.Errorf("remote object of the expired version removed: %v, want %v", removed, !tc.keep)
			}
			if tc.keep {
				body := migrationTestBody(t, z.GetObjectNInfo, bucket, "obj", migrationTestVersion(latest))
				if body != "obj v2" {
					t.Errorf("v2 reads %q after the expiry, want %q", body, "obj v2")
				}
			}
		})
	}
}
