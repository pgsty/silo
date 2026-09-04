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

import "github.com/minio/minio/internal/config"

const (
	transitionWorkers = "transition_workers"
	expirationWorkers = "expiration_workers"

	accessTiering          = "access_tiering"
	accessPools            = "access_pools"
	accessMaxSize          = "access_max_size"
	accessPromoteWatermark = "access_promote_watermark"
	accessBinWidth         = "access_bin_width"
	accessBins             = "access_bins"
	accessFlush            = "access_flush"
	accessMinResidency     = "access_min_residency"
	accessWorkers          = "access_workers"
	accessMaxTracked       = "access_max_tracked"

	// EnvILMTransitionWorkers env variable to configure number of transition workers
	EnvILMTransitionWorkers = "MINIO_ILM_TRANSITION_WORKERS"
	// EnvILMExpirationWorkers env variable to configure number of expiration workers
	EnvILMExpirationWorkers = "MINIO_ILM_EXPIRATION_WORKERS"

	// EnvILMAccessTiering env variable to enable access based tiering
	EnvILMAccessTiering = "MINIO_ILM_ACCESS_TIERING"
	// EnvILMAccessPools env variable listing pool indices hottest first
	EnvILMAccessPools = "MINIO_ILM_ACCESS_POOLS"
	// EnvILMAccessMaxSize env variable capping bytes held on the hottest pool
	EnvILMAccessMaxSize = "MINIO_ILM_ACCESS_MAX_SIZE"
	// EnvILMAccessPromoteWatermark env variable for the hottest pool fill limit
	EnvILMAccessPromoteWatermark = "MINIO_ILM_ACCESS_PROMOTE_WATERMARK"
	// EnvILMAccessBinWidth env variable for the access counter resolution
	EnvILMAccessBinWidth = "MINIO_ILM_ACCESS_BIN_WIDTH"
	// EnvILMAccessBins env variable for the number of access counter bins
	EnvILMAccessBins = "MINIO_ILM_ACCESS_BINS"
	// EnvILMAccessFlush env variable for the counter publish and sweep interval
	EnvILMAccessFlush = "MINIO_ILM_ACCESS_FLUSH"
	// EnvILMAccessMinResidency env variable for the anti-thrash floor
	EnvILMAccessMinResidency = "MINIO_ILM_ACCESS_MIN_RESIDENCY"
	// EnvILMAccessWorkers env variable to configure number of access tiering workers
	EnvILMAccessWorkers = "MINIO_ILM_ACCESS_WORKERS"
	// EnvILMAccessMaxTracked env variable capping tracked objects per node
	EnvILMAccessMaxTracked = "MINIO_ILM_ACCESS_MAX_TRACKED"
)

var (
	defaultHelpPostfix = func(key string) string {
		return config.DefaultHelpPostfix(DefaultKVS, key)
	}

	// Help holds configuration keys and their default values for the ILM
	// subsystem
	Help = config.HelpKVS{
		config.HelpKV{
			Key:         transitionWorkers,
			Type:        "number",
			Description: `set the number of transition workers` + defaultHelpPostfix(transitionWorkers),
			Optional:    true,
		},
		config.HelpKV{
			Key:         expirationWorkers,
			Type:        "number",
			Description: `set the number of expiration workers` + defaultHelpPostfix(expirationWorkers),
			Optional:    true,
		},
		config.HelpKV{
			Key:         accessTiering,
			Type:        "on|off",
			Description: `move objects between fast and slow server pools based on how often they are read` + defaultHelpPostfix(accessTiering),
			Optional:    true,
		},
		config.HelpKV{
			Key:         accessPools,
			Type:        "string",
			Description: `server pool indices for access tiering, hottest first, e.g. "0,1"` + defaultHelpPostfix(accessPools),
			Optional:    true,
		},
		config.HelpKV{
			Key:         accessMaxSize,
			Type:        "string",
			Description: `cap total bytes access tiering keeps on the fastest pool, e.g. "2TiB", 0 for unlimited` + defaultHelpPostfix(accessMaxSize),
			Optional:    true,
		},
		config.HelpKV{
			Key:         accessPromoteWatermark,
			Type:        "number",
			Description: `stop promoting once the fastest pool is this percent full` + defaultHelpPostfix(accessPromoteWatermark),
			Optional:    true,
		},
		config.HelpKV{
			Key:         accessBinWidth,
			Type:        "duration",
			Description: `resolution of the access counter` + defaultHelpPostfix(accessBinWidth),
			Optional:    true,
		},
		config.HelpKV{
			Key:         accessBins,
			Type:        "number",
			Description: `number of access counter bins; bins times bin width caps the rule Window` + defaultHelpPostfix(accessBins),
			Optional:    true,
		},
		config.HelpKV{
			Key:         accessFlush,
			Type:        "duration",
			Description: `how often access counters are published and a promotion sweep runs` + defaultHelpPostfix(accessFlush),
			Optional:    true,
		},
		config.HelpKV{
			Key:         accessMinResidency,
			Type:        "duration",
			Description: `minimum time an object stays on a pool after access tiering moved it` + defaultHelpPostfix(accessMinResidency),
			Optional:    true,
		},
		config.HelpKV{
			Key:         accessWorkers,
			Type:        "number",
			Description: `set the number of access tiering workers` + defaultHelpPostfix(accessWorkers),
			Optional:    true,
		},
		config.HelpKV{
			Key:         accessMaxTracked,
			Type:        "number",
			Description: `maximum number of objects each node keeps access counters for` + defaultHelpPostfix(accessMaxTracked),
			Optional:    true,
		},
	}
)
