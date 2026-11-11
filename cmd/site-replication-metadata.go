// Copyright (c) 2015-2026 MinIO, Inc.
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
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/logger"
)

// Read once at startup. Enable only after every participating node is fixed.
var globalSiteReplicationMetadataTombstones bool

func logBucketConfigReplication(ctx context.Context, bucket, file, reason string, at, created time.Time, detail string) {
	// LogOnceIf compares error text as well as its key. Keep both stable; changing
	// times and peer errors belong in ReqInfo, not in the error's message.
	req := &logger.ReqInfo{API: "SiteReplicationMetadata", BucketName: bucket}
	req.AppendTags("field", file)
	req.AppendTags("sourceTime", at.UTC().Format(time.RFC3339Nano))
	req.AppendTags("created", created.UTC().Format(time.RFC3339Nano))
	req.AppendTags("detail", detail)
	replLogOnceIf(logger.SetReqInfo(ctx, req), errors.New("bucket metadata replication: "+reason),
		"bucket-metadata/"+bucket+"/"+file+"/"+reason, logger.WarningKind)
}

func initialBucketConfigReplicationEvent(meta BucketMetadata, file string) (madmin.SRBucketMeta, bool, error) {
	data, at := replicatedBucketConfig(&meta, file)
	state, err := newBucketConfigState(meta.Name, file, *data, *at, meta.Created, len(meta.ObjectLockConfigXML) != 0)
	if err != nil {
		return madmin.SRBucketMeta{}, false, err
	}
	if !state.candidate() || (len(state.data) == 0 && !globalSiteReplicationMetadataTombstones) {
		return madmin.SRBucketMeta{}, false, nil
	}
	return newBucketConfigReplicationEvent(meta.Name, file, state), true, nil
}

func bucketConfigStateFromInfo(bucket, file string, meta madmin.SRBucketInfo) (bucketConfigState, error) {
	var payload *string
	var at time.Time
	switch file {
	case bucketPolicyConfig:
		return newBucketConfigState(bucket, file, meta.Policy, meta.PolicyUpdatedAt, meta.CreatedAt, false)
	case bucketTaggingConfig:
		payload, at = meta.Tags, meta.TagConfigUpdatedAt
	case bucketSSEConfig:
		payload, at = meta.SSEConfig, meta.SSEConfigUpdatedAt
	case bucketQuotaConfigFile:
		payload, at = meta.QuotaConfig, meta.QuotaConfigUpdatedAt
	case bucketVersioningConfig:
		payload, at = meta.Versioning, meta.VersioningConfigUpdatedAt
	case objectLockConfig:
		payload, at = meta.ObjectLockConfig, meta.ObjectLockConfigUpdatedAt
	}
	var data []byte
	if payload != nil {
		var err error
		data, err = base64.StdEncoding.DecodeString(*payload)
		if err != nil {
			return bucketConfigState{}, err
		}
	}
	lockEnabled := meta.ObjectLockConfig != nil && len(*meta.ObjectLockConfig) != 0
	return newBucketConfigState(bucket, file, data, at, meta.CreatedAt, lockEnabled)
}

func newBucketConfigReplicationEvent(bucket, file string, state bucketConfigState) madmin.SRBucketMeta {
	event := madmin.SRBucketMeta{Bucket: bucket, UpdatedAt: state.at}
	var payload *string
	if len(state.data) != 0 {
		encoded := base64.StdEncoding.EncodeToString(state.data)
		payload = &encoded
	}
	switch file {
	case bucketPolicyConfig:
		event.Type, event.Policy = madmin.SRBucketMetaTypePolicy, state.data
	case bucketTaggingConfig:
		event.Type, event.Tags = madmin.SRBucketMetaTypeTags, payload
	case bucketSSEConfig:
		event.Type, event.SSEConfig = madmin.SRBucketMetaTypeSSEConfig, payload
	case bucketQuotaConfigFile:
		event.Type, event.Quota = madmin.SRBucketMetaTypeQuotaConfig, state.data
	case bucketVersioningConfig:
		event.Type, event.Versioning = madmin.SRBucketMetaTypeVersionConfig, payload
	case objectLockConfig:
		event.Type, event.ObjectLockConfig = madmin.SRBucketMetaTypeObjectLockConfig, payload
	}
	return event
}

func latestBucketConfig(bucket, file string, info srStatusInfo) (bucketConfigState, bool) {
	var latest bucketConfigState
	found := false
	for id, status := range info.BucketStats[bucket] {
		if _, known := info.Sites[id]; !known || id == "" {
			continue
		}
		state, err := bucketConfigStateFromInfo(bucket, file, status.meta.SRBucketInfo)
		if err != nil || !state.candidate() {
			continue
		}
		if !found || compareBucketConfigStates(state, latest) > 0 {
			latest, found = state, true
		}
	}
	return latest, found
}

func (c *SiteReplicationSys) healBucketConfig(ctx context.Context, bucket, file string, info srStatusInfo) error {
	state, ok := c.stateSnapshot()
	if !ok {
		return nil
	}
	latest, found := latestBucketConfig(bucket, file, info)
	// Every reason keeps its own log key, so a site that did not report cannot
	// deduplicate away an unusable peer state or a real heal RPC failure for
	// the same bucket and field.
	if found {
		for id := range info.Sites {
			if _, present := info.BucketStats[bucket][id]; !present {
				logBucketConfigReplication(ctx, bucket, file, "unreachable", latest.at, time.Time{}, "peer "+id+" did not report")
			}
		}
	}
	for id, status := range info.BucketStats[bucket] {
		if _, known := info.Sites[id]; !known || id == "" {
			continue
		}
		target := status.meta.SRBucketInfo
		current, currentErr := bucketConfigStateFromInfo(bucket, file, target)
		// A peer without the bucket reports neither a field nor a creation
		// time; bucket healing covers that normal transient. Report only a
		// state that exists and still cannot be ordered.
		if currentErr != nil || (!current.valid && (len(current.data) != 0 || !current.at.IsZero())) {
			logBucketConfigReplication(ctx, bucket, file, "indeterminate", current.at, target.CreatedAt, "unusable peer "+id)
		}
		// Invalid existing state still needs a diagnosis when no source can
		// be selected. Only propagation depends on having a valid source.
		if !found || target.CreatedAt.IsZero() {
			continue
		}
		if latest.at.Before(target.CreatedAt) {
			logBucketConfigReplication(ctx, bucket, file, "before-created", latest.at, target.CreatedAt, "peer "+id)
			continue
		}
		// Versioning can be normalized differently until Object Lock itself has
		// converged. Compare what this target would actually persist.
		incoming, err := newBucketConfigState(bucket, file, latest.data, latest.at, target.CreatedAt,
			target.ObjectLockConfig != nil && len(*target.ObjectLockConfig) != 0)
		if err != nil || !incoming.candidate() {
			continue
		}
		if currentErr == nil && compareBucketConfigStates(incoming, current) <= 0 {
			continue
		}
		if id == globalDeploymentID() {
			_, err = globalBucketMetadataSys.updateAndParseMetadata(ctx, bucket, file, latest.data, false, false, &latest.at)
		} else {
			var client *madmin.AdminClient
			client, err = state.getAdminClient(id)
			if err == nil {
				err = client.SRPeerReplicateBucketMeta(ctx, newBucketConfigReplicationEvent(bucket, file, incoming))
			}
		}
		if err != nil {
			// A missing credential or unreachable peer must not abandon the other
			// targets simply because it happened to be visited first in this map.
			logBucketConfigReplication(ctx, bucket, file, "peer-error", latest.at, target.CreatedAt, "peer "+id+": "+err.Error())
		}
	}
	return nil
}
