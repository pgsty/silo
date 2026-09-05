// Copyright (c) 2015-2025 MinIO, Inc.
// Copyright (c) 2025-2026 PGSTY
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"testing"

	"github.com/minio/madmin-go/v3"
)

func TestGetBucketQuotaSize(t *testing.T) {
	tests := []struct {
		name  string
		quota *madmin.BucketQuota
		want  uint64
	}{
		{name: "nil"},
		{name: "empty", quota: &madmin.BucketQuota{}},
		{name: "current size", quota: &madmin.BucketQuota{Type: madmin.HardQuota, Size: 1024}, want: 1024},
		{name: "legacy quota", quota: &madmin.BucketQuota{Type: madmin.HardQuota, Quota: 2048}, want: 2048},
		{name: "size takes precedence", quota: &madmin.BucketQuota{Type: madmin.HardQuota, Size: 1024, Quota: 2048}, want: 1024},
		{name: "missing type", quota: &madmin.BucketQuota{Size: 1024}},
		{name: "unsupported type", quota: &madmin.BucketQuota{Type: "fifo", Size: 1024}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getBucketQuotaSize(tt.quota); got != tt.want {
				t.Fatalf("getBucketQuotaSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestIsBktQuotaCfgReplicated(t *testing.T) {
	hardQuota := func(size, legacy uint64) *madmin.BucketQuota {
		return &madmin.BucketQuota{Type: madmin.HardQuota, Size: size, Quota: legacy}
	}

	tests := []struct {
		name   string
		quotas []*madmin.BucketQuota
		want   bool
	}{
		{name: "none configured", quotas: []*madmin.BucketQuota{nil, nil}, want: true},
		{name: "missing from one site", quotas: []*madmin.BucketQuota{hardQuota(1024, 0), nil}},
		{name: "matching size", quotas: []*madmin.BucketQuota{hardQuota(1024, 0), hardQuota(1024, 0)}, want: true},
		{name: "different size", quotas: []*madmin.BucketQuota{hardQuota(1024, 0), hardQuota(2048, 0)}},
		{name: "equivalent representations", quotas: []*madmin.BucketQuota{hardQuota(1024, 0), hardQuota(0, 1024)}, want: true},
		{name: "different typeless size", quotas: []*madmin.BucketQuota{{Size: 1024}, {Size: 2048}}},
		{name: "different type", quotas: []*madmin.BucketQuota{hardQuota(1024, 0), {Type: "fifo", Size: 1024}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBktQuotaCfgReplicated(len(tt.quotas), tt.quotas); got != tt.want {
				t.Fatalf("isBktQuotaCfgReplicated() = %v, want %v", got, tt.want)
			}
		})
	}
}
