// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/cachevalue"
)

func TestAccountInfoReflectsBucketMutations(t *testing.T) {
	ctx := t.Context()
	bed, err := prepareAdminErasureTestBed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer bed.TearDown()
	previousCache := listBucketsCache
	defer func() { listBucketsCache = previousCache }()

	// Hold a real pre-mutation snapshot past the assertions so the regression
	// cannot disappear merely because a slow test outlasted the cache TTL.
	freezeListing := func() {
		t.Helper()
		buckets, err := bed.objLayer.ListBuckets(ctx, BucketOptions{})
		if err != nil {
			t.Fatal(err)
		}
		listBucketsCache = cachevalue.NewFromFunc(time.Hour, cachevalue.Opts{}, func(context.Context) ([]BucketInfo, error) {
			return buckets, nil
		})
		if _, err := listBucketsCache.GetWithCtx(ctx); err != nil {
			t.Fatal(err)
		}
	}
	const bucket = "account-info-freshness"
	assertPresent := func(want bool) {
		t.Helper()
		req, err := buildAdminRequest(nil, http.MethodGet, "/accountinfo", 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		bed.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("account info: %d %s", rec.Code, rec.Body.String())
		}
		var info madmin.AccountInfo
		if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, item := range info.Buckets {
			if item.Name == bucket {
				found = true
			}
		}
		if found != want {
			t.Errorf("account info bucket present = %v, want %v", found, want)
		}
	}

	freezeListing()
	if err := bed.objLayer.MakeBucket(ctx, bucket, MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	assertPresent(true)
	freezeListing()
	if err := bed.objLayer.DeleteBucket(ctx, bucket, DeleteBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	assertPresent(false)
}
