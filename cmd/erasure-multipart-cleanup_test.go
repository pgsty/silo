// Copyright (c) 2026 clown15
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
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExtractModTimeFromUploadIDDir(t *testing.T) {
	now := time.Unix(1792056747, 123456789).UTC()
	nano := now.UnixNano()
	uuid := "d16ad42a-6fe5-4a3b-8092-69983142238f"

	testCases := []struct {
		name        string
		dirName     string
		expectedMod time.Time
		wantZero    bool
	}{
		{
			name:        "Modern Plaintext Format (<UUID>x<UnixNano>)",
			dirName:     fmt.Sprintf("%sx%d", uuid, nano),
			expectedMod: time.Unix(0, nano),
			wantZero:    false,
		},
		{
			// This valid UUID decodes to bytes containing 'x'. Checking
			// for that byte before parsing plaintext loses the timestamp.
			name:        "Plaintext Also Decodes To Base64 Containing x",
			dirName:     fmt.Sprintf("4eacd477-e733-4851-b821-6fd42785ff87x%d", nano),
			expectedMod: now,
		},
		{
			name:        "Legacy Format Without Timestamp (<UUID>)",
			dirName:     uuid,
			expectedMod: time.Time{},
			wantZero:    true,
		},
		{
			name:        "Base64 Encoded Format",
			dirName:     base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%sx%d", uuid, nano))),
			expectedMod: time.Unix(0, nano),
			wantZero:    false,
		},
		{
			name:        "Encoded Format With Deployment Prefix",
			dirName:     base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s.%sx%d", uuid, uuid, nano))),
			expectedMod: now,
		},
		{
			name:        "Malformed Suffix (<UUID>xinvalid)",
			dirName:     fmt.Sprintf("%sxnotanumber", uuid),
			expectedMod: time.Time{},
			wantZero:    true,
		},
		{
			name:     "Timestamp Overflow",
			dirName:  uuid + "x9223372036854775808",
			wantZero: true,
		},
		{
			name:     "Malformed Plaintext UUID",
			dirName:  fmt.Sprintf("not-a-uuidx%d", nano),
			wantZero: true,
		},
		{
			name:        "Empty Directory Name",
			dirName:     "",
			expectedMod: time.Time{},
			wantZero:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractModTimeFromUploadIDDir(tc.dirName)
			if tc.wantZero {
				if !got.IsZero() {
					t.Fatalf("expected zero time for %q, got %v", tc.dirName, got)
				}
				return
			}
			if !got.Equal(tc.expectedMod) {
				t.Fatalf("extractModTimeFromUploadIDDir(%q) = %v; want %v", tc.dirName, got, tc.expectedMod)
			}
		})
	}
}

type multipartCleanupDisk struct {
	StorageAPI
	root    string
	modTime time.Time
	readErr error
	reads   int
}

func (d *multipartCleanupDisk) Endpoint() Endpoint {
	return Endpoint{URL: &url.URL{Path: d.root}}
}

func (d *multipartCleanupDisk) ReadVersion(context.Context, string, string, string, string, ReadOptions) (FileInfo, error) {
	d.reads++
	return FileInfo{ModTime: d.modTime}, d.readErr
}

func (d *multipartCleanupDisk) StatVol(ctx context.Context, volume string) (VolInfo, error) {
	return (&xlStorage{drivePath: d.root}).StatVol(ctx, volume)
}

func TestCleanupStaleUploadsOnDisk(t *testing.T) {
	const uuid = "d16ad42a-6fe5-4a3b-8092-69983142238f"
	expiry := globalAPIConfig.getStaleUploadsExpiry()
	for _, tc := range []struct {
		name, prefix string
		age          time.Duration
		legacy       bool
		readErr      error
		wantReads    int
		wantDeleted  bool
	}{
		{name: "recent", prefix: uuid, age: expiry / 2, readErr: errFileNotFound},
		{name: "plaintext_base64_collision", prefix: "4eacd477-e733-4851-b821-6fd42785ff87", age: expiry / 2, readErr: errFileNotFound},
		{name: "expired", prefix: uuid, age: 2 * expiry, readErr: errFileNotFound, wantDeleted: true},
		{name: "legacy_recent", prefix: uuid, age: expiry / 2, legacy: true, wantReads: 1},
		{name: "legacy_expired", prefix: uuid, age: 2 * expiry, legacy: true, wantReads: 1, wantDeleted: true},
		{name: "legacy_metadata_missing", prefix: uuid, age: 2 * expiry, legacy: true, readErr: errFileNotFound, wantReads: 1},
		{name: "malformed_metadata_missing", prefix: "not-a-uuid", age: 2 * expiry, readErr: errFileNotFound, wantReads: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modTime := time.Now().Add(-tc.age)
			id := tc.prefix
			if !tc.legacy {
				id = fmt.Sprintf("%sx%d", tc.prefix, modTime.UnixNano())
			}
			disk := &multipartCleanupDisk{root: t.TempDir(), modTime: modTime, readErr: tc.readErr}
			uploadDir := filepath.Join(disk.root, minioMetaMultipartBucket, "sha", id)
			for _, dir := range []string{uploadDir, filepath.Join(disk.root, minioMetaTmpDeletedBucket)} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// An old parent must not bypass a skipped upload's age or read error.
			if err := os.Chtimes(filepath.Dir(uploadDir), modTime, modTime); err != nil {
				t.Fatal(err)
			}
			erasureObjects{}.cleanupStaleUploadsOnDisk(t.Context(), disk)
			if disk.reads != tc.wantReads {
				t.Errorf("ReadVersion calls = %d, want %d", disk.reads, tc.wantReads)
			}
			_, err := os.Stat(uploadDir)
			if tc.wantDeleted {
				if !os.IsNotExist(err) {
					t.Errorf("expired upload must be removed: %v", err)
				}
				if _, err := os.Stat(filepath.Dir(uploadDir)); !os.IsNotExist(err) {
					t.Errorf("empty hash directory must be removed in the same pass: %v", err)
				}
			} else if err != nil {
				t.Errorf("upload must be preserved: %v", err)
			}
		})
	}
}

func TestCleanupStaleUploadsEmptyHashDirectory(t *testing.T) {
	for _, age := range []time.Duration{0, 2 * globalAPIConfig.getStaleUploadsExpiry()} {
		t.Run(age.String(), func(t *testing.T) {
			disk := &multipartCleanupDisk{root: t.TempDir()}
			shaDir := filepath.Join(disk.root, minioMetaMultipartBucket, "sha")
			for _, dir := range []string{shaDir, filepath.Join(disk.root, minioMetaTmpDeletedBucket)} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			modTime := time.Now().Add(-age)
			if err := os.Chtimes(shaDir, modTime, modTime); err != nil {
				t.Fatal(err)
			}
			erasureObjects{}.cleanupStaleUploadsOnDisk(t.Context(), disk)
			if _, err := os.Stat(shaDir); !os.IsNotExist(err) {
				t.Fatalf("empty hash directory must be removed regardless of age: %v", err)
			}
		})
	}
}

func TestCleanupStaleUploadsSharedHashDirectory(t *testing.T) {
	disk := &multipartCleanupDisk{root: t.TempDir(), readErr: errFileNotFound}
	shaDir := filepath.Join(disk.root, minioMetaMultipartBucket, "sha")
	now := time.Now()
	expiredID := fmt.Sprintf("d16ad42a-6fe5-4a3b-8092-69983142238fx%d", now.Add(-2*globalAPIConfig.getStaleUploadsExpiry()).UnixNano())
	recentID := fmt.Sprintf("4eacd477-e733-4851-b821-6fd42785ff87x%d", now.UnixNano())
	for _, id := range []string{expiredID, recentID} {
		if err := os.MkdirAll(filepath.Join(shaDir, id), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	partPath := filepath.Join(shaDir, recentID, "part.1")
	const part = "recent upload part"
	if err := os.WriteFile(partPath, []byte(part), 0o600); err != nil {
		t.Fatal(err)
	}

	erasureObjects{}.cleanupStaleUploadsOnDisk(t.Context(), disk)
	if _, err := os.Stat(filepath.Join(shaDir, expiredID)); !os.IsNotExist(err) {
		t.Errorf("expired upload must be removed: %v", err)
	}
	if got, err := os.ReadFile(partPath); err != nil || string(got) != part {
		t.Errorf("recent upload must remain intact: got %q, err %v", got, err)
	}
}
