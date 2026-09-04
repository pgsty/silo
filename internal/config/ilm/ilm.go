// Copyright (c) 2015-2024 MinIO, Inc.
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

package ilm

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/minio/minio/internal/config"
	"github.com/pgsty/silo-pkg/v3/env"
)

// Errors returned when the access tiering configuration is unusable.
var (
	ErrAccessPoolsInvalid     = errors.New("ilm access_pools must be a comma separated list of distinct pool indices, hottest first, e.g. \"0,1\"")
	ErrAccessPoolsTooFew      = errors.New("ilm access_pools needs at least two pools to move objects between")
	ErrAccessWatermarkInvalid = errors.New("ilm access_promote_watermark must be between 1 and 100")
	ErrAccessBinsInvalid      = errors.New("ilm access_bins must be between 2 and 64")
	ErrAccessBinWidthInvalid  = errors.New("ilm access_bin_width must be at least 1s")
	ErrAccessFlushInvalid     = errors.New("ilm access_flush must be at least 1s")
	ErrAccessResidencyInvalid = errors.New("ilm access_min_residency cannot be negative")
	ErrAccessWorkersInvalid   = errors.New("ilm access_workers must be a positive integer")
	ErrAccessTrackedInvalid   = errors.New("ilm access_max_tracked must be a positive integer")
)

// DefaultKVS default configuration values for ILM subsystem
var DefaultKVS = config.KVS{
	config.KV{
		Key:   transitionWorkers,
		Value: "100",
	},
	config.KV{
		Key:   expirationWorkers,
		Value: "100",
	},
	config.KV{
		Key:   accessTiering,
		Value: config.EnableOff,
	},
	config.KV{
		Key:   accessPools,
		Value: "",
	},
	config.KV{
		Key:   accessMaxSize,
		Value: "0",
	},
	config.KV{
		Key:   accessPromoteWatermark,
		Value: "85",
	},
	config.KV{
		Key:   accessBinWidth,
		Value: "1m",
	},
	config.KV{
		Key:   accessBins,
		Value: "12",
	},
	config.KV{
		Key:   accessFlush,
		Value: "1m",
	},
	config.KV{
		Key:   accessMinResidency,
		Value: "24h",
	},
	config.KV{
		Key:   accessWorkers,
		Value: "10",
	},
	config.KV{
		Key:   accessMaxTracked,
		Value: "1000000",
	},
}

// Config represents the different configuration values for ILM subsystem
type Config struct {
	TransitionWorkers int
	ExpirationWorkers int

	// AccessTiering enables access-frequency driven relocation of objects
	// between server pools. Off by default: it moves data.
	AccessTiering bool
	// AccessPools lists pool indices hottest first, e.g. []int{0, 1}.
	AccessPools []int
	// AccessMaxSize caps total bytes held on the hottest pool, 0 == unlimited.
	AccessMaxSize uint64
	// AccessPromoteWatermark stops promotion once the hottest pool is this
	// percentage full.
	AccessPromoteWatermark int
	// AccessBinWidth and AccessBins size the rolling hit counter. Their
	// product is the longest rule Window that can be evaluated.
	AccessBinWidth time.Duration
	AccessBins     int
	// AccessFlush is how often each node publishes its counters and the
	// leader merges them and runs a promotion sweep.
	AccessFlush time.Duration
	// AccessMinResidency is the minimum time an object stays put after a
	// move, regardless of what the counters say.
	AccessMinResidency time.Duration
	AccessWorkers      int
	// AccessMaxTracked caps how many objects each node keeps counters for.
	AccessMaxTracked int
}

// HotPool returns the index of the hottest configured pool and whether access
// tiering is usable at all.
func (c Config) HotPool() (int, bool) {
	if !c.AccessTiering || len(c.AccessPools) < 2 {
		return -1, false
	}
	return c.AccessPools[0], true
}

// ColdPool returns the index of the coldest configured pool, i.e. where
// demoted objects go.
func (c Config) ColdPool() (int, bool) {
	if !c.AccessTiering || len(c.AccessPools) < 2 {
		return -1, false
	}
	return c.AccessPools[len(c.AccessPools)-1], true
}

// HistoryWindow is the longest window the rolling counter can answer for.
func (c Config) HistoryWindow() time.Duration {
	return time.Duration(c.AccessBins) * c.AccessBinWidth
}

// parseAccessPools parses "0,1" into []int{0, 1}, rejecting duplicates and
// negative indices. An empty string yields no pools, which disables the
// feature rather than erroring - operators enable the switch before they
// configure the topology.
func parseAccessPools(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var pools []int
	seen := make(map[int]struct{})
	for _, f := range strings.Split(s, ",") {
		idx, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || idx < 0 {
			return nil, ErrAccessPoolsInvalid
		}
		if _, dup := seen[idx]; dup {
			return nil, ErrAccessPoolsInvalid
		}
		seen[idx] = struct{}{}
		pools = append(pools, idx)
	}
	return pools, nil
}

// LookupConfig - lookup ilm config and override with valid environment settings if any.
func LookupConfig(kvs config.KVS) (cfg Config, err error) {
	cfg = Config{
		TransitionWorkers: 100,
		ExpirationWorkers: 100,
	}

	if err = config.CheckValidKeys(config.ILMSubSys, kvs, DefaultKVS); err != nil {
		return cfg, err
	}

	tw, err := strconv.Atoi(env.Get(EnvILMTransitionWorkers, kvs.GetWithDefault(transitionWorkers, DefaultKVS)))
	if err != nil {
		return cfg, err
	}

	ew, err := strconv.Atoi(env.Get(EnvILMExpirationWorkers, kvs.GetWithDefault(expirationWorkers, DefaultKVS)))
	if err != nil {
		return cfg, err
	}

	cfg.TransitionWorkers = tw
	cfg.ExpirationWorkers = ew

	if err := cfg.lookupAccess(kvs); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) lookupAccess(kvs config.KVS) (err error) {
	c.AccessTiering, err = config.ParseBool(env.Get(EnvILMAccessTiering, kvs.GetWithDefault(accessTiering, DefaultKVS)))
	if err != nil {
		return err
	}

	if c.AccessPools, err = parseAccessPools(env.Get(EnvILMAccessPools, kvs.GetWithDefault(accessPools, DefaultKVS))); err != nil {
		return err
	}
	// Enabling the feature without a usable topology is a configuration
	// error worth surfacing at set time rather than silently doing nothing.
	if c.AccessTiering && len(c.AccessPools) < 2 {
		return ErrAccessPoolsTooFew
	}

	maxSize := env.Get(EnvILMAccessMaxSize, kvs.GetWithDefault(accessMaxSize, DefaultKVS))
	if maxSize == "" || maxSize == "0" {
		c.AccessMaxSize = 0
	} else if c.AccessMaxSize, err = humanize.ParseBytes(maxSize); err != nil {
		return err
	}

	if c.AccessPromoteWatermark, err = strconv.Atoi(env.Get(EnvILMAccessPromoteWatermark, kvs.GetWithDefault(accessPromoteWatermark, DefaultKVS))); err != nil {
		return err
	}
	if c.AccessPromoteWatermark < 1 || c.AccessPromoteWatermark > 100 {
		return ErrAccessWatermarkInvalid
	}

	if c.AccessBinWidth, err = time.ParseDuration(env.Get(EnvILMAccessBinWidth, kvs.GetWithDefault(accessBinWidth, DefaultKVS))); err != nil {
		return err
	}
	if c.AccessBinWidth < time.Second {
		return ErrAccessBinWidthInvalid
	}
	if c.AccessBins, err = strconv.Atoi(env.Get(EnvILMAccessBins, kvs.GetWithDefault(accessBins, DefaultKVS))); err != nil {
		return err
	}
	if c.AccessBins < 2 || c.AccessBins > 64 {
		return ErrAccessBinsInvalid
	}

	if c.AccessFlush, err = time.ParseDuration(env.Get(EnvILMAccessFlush, kvs.GetWithDefault(accessFlush, DefaultKVS))); err != nil {
		return err
	}
	if c.AccessFlush < time.Second {
		return ErrAccessFlushInvalid
	}
	if c.AccessMinResidency, err = time.ParseDuration(env.Get(EnvILMAccessMinResidency, kvs.GetWithDefault(accessMinResidency, DefaultKVS))); err != nil {
		return err
	}
	if c.AccessMinResidency < 0 {
		return ErrAccessResidencyInvalid
	}

	if c.AccessWorkers, err = strconv.Atoi(env.Get(EnvILMAccessWorkers, kvs.GetWithDefault(accessWorkers, DefaultKVS))); err != nil {
		return err
	}
	if c.AccessWorkers < 1 {
		return ErrAccessWorkersInvalid
	}
	if c.AccessMaxTracked, err = strconv.Atoi(env.Get(EnvILMAccessMaxTracked, kvs.GetWithDefault(accessMaxTracked, DefaultKVS))); err != nil {
		return err
	}
	if c.AccessMaxTracked < 1 {
		return ErrAccessTrackedInvalid
	}
	return nil
}
