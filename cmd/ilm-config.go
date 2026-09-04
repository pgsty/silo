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

package cmd

import (
	"sync"
	"time"

	"github.com/minio/minio/internal/config/ilm"
)

var globalILMConfig = ilmConfig{
	cfg: ilm.Config{
		ExpirationWorkers: 100,
		TransitionWorkers: 100,
		// Access tiering stays off until configured, but the counter
		// geometry must be sane from the start: the tracker divides by
		// AccessBinWidth before any config is loaded.
		AccessPromoteWatermark: 85,
		AccessBinWidth:         time.Minute,
		AccessBins:             12,
		AccessFlush:            time.Minute,
		AccessMinResidency:     24 * time.Hour,
		AccessWorkers:          10,
		AccessMaxTracked:       1000000,
	},
}

type ilmConfig struct {
	mu  sync.RWMutex
	cfg ilm.Config
}

func (c *ilmConfig) getExpirationWorkers() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.cfg.ExpirationWorkers
}

func (c *ilmConfig) getTransitionWorkers() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.cfg.TransitionWorkers
}

// accessCfg returns a copy of the access tiering settings. Callers take the
// whole struct rather than one getter per field because the promotion and
// demotion paths need a consistent view of several knobs at once.
func (c *ilmConfig) accessCfg() ilm.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.cfg
}

// accessTieringEnabled is the cheap gate used on the scanner path.
func (c *ilmConfig) accessTieringEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, ok := c.cfg.HotPool()
	return ok
}

func (c *ilmConfig) update(cfg ilm.Config) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cfg = cfg
}
