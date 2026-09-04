// Copyright (c) 2015-2026 MinIO, Inc.

package ilm

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/minio/minio/internal/config"
)

func clearAccessEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		EnvILMAccessTiering, EnvILMAccessPools, EnvILMAccessMaxSize,
		EnvILMAccessPromoteWatermark, EnvILMAccessBinWidth, EnvILMAccessBins,
		EnvILMAccessFlush, EnvILMAccessMinResidency, EnvILMAccessWorkers,
		EnvILMAccessMaxTracked,
	} {
		// The env helper treats an empty value as unset. t.Setenv restores the
		// caller's exact value automatically when the test finishes.
		t.Setenv(name, "")
	}
}

func TestLookupAccessDefaults(t *testing.T) {
	clearAccessEnv(t)
	cfg, err := LookupConfig(DefaultKVS.Clone())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccessTiering {
		t.Fatal("access tiering must default off")
	}
	if cfg.AccessBinWidth != time.Minute || cfg.AccessBins != 12 || cfg.AccessFlush != time.Minute {
		t.Fatalf("unexpected counter defaults: width=%s bins=%d flush=%s", cfg.AccessBinWidth, cfg.AccessBins, cfg.AccessFlush)
	}
	if cfg.AccessWorkers != 10 || cfg.AccessMaxTracked != 1000000 {
		t.Fatalf("unexpected worker/map defaults: %d/%d", cfg.AccessWorkers, cfg.AccessMaxTracked)
	}
}

func TestLookupAccessEnabled(t *testing.T) {
	clearAccessEnv(t)
	kvs := DefaultKVS.Clone()
	kvs.Set(accessTiering, config.EnableOn)
	kvs.Set(accessPools, "2, 0, 1")
	kvs.Set(accessMaxSize, "2GiB")
	kvs.Set(accessPromoteWatermark, "90")
	kvs.Set(accessBinWidth, "30s")
	kvs.Set(accessBins, "20")
	kvs.Set(accessFlush, "15s")
	kvs.Set(accessMinResidency, "2h")
	kvs.Set(accessWorkers, "7")
	kvs.Set(accessMaxTracked, "1234")

	cfg, err := LookupConfig(kvs)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AccessTiering || !reflect.DeepEqual(cfg.AccessPools, []int{2, 0, 1}) {
		t.Fatalf("unexpected topology: enabled=%v pools=%v", cfg.AccessTiering, cfg.AccessPools)
	}
	if cfg.AccessMaxSize != 2<<30 || cfg.HistoryWindow() != 10*time.Minute {
		t.Fatalf("unexpected size/history: %d/%s", cfg.AccessMaxSize, cfg.HistoryWindow())
	}
	if hot, ok := cfg.HotPool(); !ok || hot != 2 {
		t.Fatalf("HotPool = %d/%v", hot, ok)
	}
	if cold, ok := cfg.ColdPool(); !ok || cold != 1 {
		t.Fatalf("ColdPool = %d/%v", cold, ok)
	}
}

func TestLookupAccessRejectsInvalidValues(t *testing.T) {
	clearAccessEnv(t)
	tests := []struct {
		key, value string
		want       error
	}{
		{accessPools, "0,0", ErrAccessPoolsInvalid},
		{accessPromoteWatermark, "0", ErrAccessWatermarkInvalid},
		{accessBinWidth, "500ms", ErrAccessBinWidthInvalid},
		{accessBins, "1", ErrAccessBinsInvalid},
		{accessFlush, "0s", ErrAccessFlushInvalid},
		{accessMinResidency, "-1s", ErrAccessResidencyInvalid},
		{accessWorkers, "0", ErrAccessWorkersInvalid},
		{accessMaxTracked, "0", ErrAccessTrackedInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			kvs := DefaultKVS.Clone()
			kvs.Set(tc.key, tc.value)
			_, err := LookupConfig(kvs)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}

	kvs := DefaultKVS.Clone()
	kvs.Set(accessTiering, config.EnableOn)
	kvs.Set(accessPools, "0")
	if _, err := LookupConfig(kvs); !errors.Is(err, ErrAccessPoolsTooFew) {
		t.Fatalf("error = %v, want %v", err, ErrAccessPoolsTooFew)
	}
}
