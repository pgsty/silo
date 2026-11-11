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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/minio/minio-go/v7/pkg/tags"
	bucketsse "github.com/minio/minio/internal/bucket/encryption"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// Only these fields share the site-replication source-time ordering contract.
// Bulk apply/import process Object Lock before Versioning, whose effective
// document depends on it. Periodic heal retains its existing type order.
var replicatedBucketConfigs = [...]string{
	objectLockConfig, bucketVersioningConfig, bucketPolicyConfig,
	bucketTaggingConfig, bucketSSEConfig, bucketQuotaConfigFile,
}

func replicatedBucketConfig(meta *BucketMetadata, file string) (*[]byte, *time.Time) {
	switch file {
	case bucketPolicyConfig:
		return &meta.PolicyConfigJSON, &meta.PolicyConfigUpdatedAt
	case bucketTaggingConfig:
		return &meta.TaggingConfigXML, &meta.TaggingConfigUpdatedAt
	case bucketSSEConfig:
		return &meta.EncryptionConfigXML, &meta.EncryptionConfigUpdatedAt
	case bucketQuotaConfigFile:
		return &meta.QuotaConfigJSON, &meta.QuotaConfigUpdatedAt
	case bucketVersioningConfig:
		return &meta.VersioningConfigXML, &meta.VersioningConfigUpdatedAt
	case objectLockConfig:
		return &meta.ObjectLockConfigXML, &meta.ObjectLockConfigUpdatedAt
	}
	return nil, nil
}

// Callers that only need to know whether a file is under the contract must not
// probe replicatedBucketConfig with a throwaway BucketMetadata.
func isReplicatedBucketConfig(file string) bool {
	for _, replicated := range replicatedBucketConfigs {
		if replicated == file {
			return true
		}
	}
	return false
}

func bucketConfigUpdateOnly(file string) bool {
	return file == bucketVersioningConfig || file == objectLockConfig
}

// Reuse the persistence rule before comparison, so an accepted Versioning
// event and the document Save actually writes have the same comparison key.
func effectiveBucketVersioning(data []byte, lockEnabled bool) []byte {
	if lockEnabled {
		config, err := versioning.ParseConfig(bytes.NewReader(data))
		if err != nil || !config.Enabled() || config.PrefixesExcluded() {
			return enabledBucketVersioningConfig
		}
	}
	return data
}

// A parsed policy still contains map-backed sets with nondeterministic Marshal
// order. Sort every set array recursively, including statements and conditions.
// RawMessage keeps integer values intact; decoding through float64 would not.
func canonicalBucketPolicyJSON(data json.RawMessage) (json.RawMessage, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}
	switch data[0] {
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(data, &obj); err != nil {
			return nil, err
		}
		for key, value := range obj {
			var err error
			obj[key], err = canonicalBucketPolicyJSON(value)
			if err != nil {
				return nil, err
			}
		}
		return json.Marshal(obj)
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(data, &arr); err != nil {
			return nil, err
		}
		for i := range arr {
			var err error
			arr[i], err = canonicalBucketPolicyJSON(arr[i])
			if err != nil {
				return nil, err
			}
		}
		sort.Slice(arr, func(i, j int) bool { return bytes.Compare(arr[i], arr[j]) < 0 })
		return json.Marshal(arr)
	default:
		var compact bytes.Buffer
		if err := json.Compact(&compact, data); err != nil {
			return nil, err
		}
		return compact.Bytes(), nil
	}
}

// Encode the validated policy fields explicitly: BPStatement's required
// Action/Resource tags otherwise try to marshal empty sets for the supported
// NotAction/NotResource alternatives. This stays within the existing schema.
func canonicalBucketPolicy(cfg *policy.BucketPolicy) ([]byte, error) {
	if cfg.IsEmpty() {
		return nil, nil
	}
	doc := map[string]any{"Version": cfg.Version}
	if cfg.ID != "" {
		doc["ID"] = cfg.ID
	}
	statements := make([]map[string]any, 0, len(cfg.Statements))
	for _, st := range cfg.Statements {
		statement := map[string]any{"Effect": st.Effect, "Principal": st.Principal}
		if st.SID != "" {
			statement["Sid"] = st.SID
		}
		if len(st.Actions) != 0 {
			statement["Action"] = st.Actions
		}
		if len(st.NotActions) != 0 {
			statement["NotAction"] = st.NotActions
		}
		if len(st.Resources) != 0 {
			statement["Resource"] = st.Resources
		}
		if len(st.NotResources) != 0 {
			statement["NotResource"] = st.NotResources
		}
		if len(st.Conditions) != 0 {
			statement["Condition"] = st.Conditions
		}
		statements = append(statements, statement)
	}
	doc["Statement"] = statements
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return canonicalBucketPolicyJSON(data)
}

// Validate with the same parsers as Save. Policy's established empty-policy
// semantics are deletion; a parsed zero quota is still a live document.
func bucketConfigPayload(bucket, file string, data []byte, lockEnabled bool) ([]byte, []byte, error) {
	if len(data) == 0 {
		return nil, nil, nil
	}
	var err error
	key := data
	switch file {
	case bucketPolicyConfig:
		// Replication uses explicit null as a tombstone; ordinary policy PUTs
		// validate their JSON before entering this metadata path.
		if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
			return nil, nil, nil
		}
		var cfg *policy.BucketPolicy
		cfg, err = parseBucketPolicyStrictBytes(data, bucket)
		if err == nil {
			if cfg.IsEmpty() {
				return nil, nil, nil
			}
			key, err = canonicalBucketPolicy(cfg)
		}
	case bucketQuotaConfigFile:
		cfg, parseErr := parseBucketQuota(bucket, data)
		err = parseErr
		if err == nil {
			key, err = json.Marshal(cfg)
		}
	case bucketTaggingConfig:
		_, err = tags.ParseBucketXML(bytes.NewReader(data))
	case bucketSSEConfig:
		_, err = bucketsse.ParseBucketSSEConfig(bytes.NewReader(data))
	case objectLockConfig:
		_, err = objectlock.ParseObjectLockConfig(bytes.NewReader(data))
	case bucketVersioningConfig:
		data = effectiveBucketVersioning(data, lockEnabled)
		key = data
		_, err = versioning.ParseConfig(bytes.NewReader(data))
	}
	return data, key, err
}

type bucketConfigState struct {
	data, key   []byte
	at          time.Time
	real, valid bool
}

func newBucketConfigState(bucket, file string, data []byte, at, created time.Time, lockEnabled bool) (bucketConfigState, error) {
	data, key, err := bucketConfigPayload(bucket, file, data, lockEnabled)
	if err != nil {
		return bucketConfigState{}, err
	}
	if at.IsZero() {
		at = created
	}
	valid := !created.IsZero() && !at.Before(created)
	modified := valid && at.After(created)
	if bucketConfigUpdateOnly(file) && len(data) == 0 {
		modified = false
	}
	return bucketConfigState{data: data, key: key, at: at, real: modified, valid: valid}, nil
}

func (s bucketConfigState) candidate() bool {
	return s.valid && (s.real || len(s.data) != 0)
}

func compareBucketConfigStates(a, b bucketConfigState) int {
	if a.valid != b.valid {
		if a.valid {
			return 1
		}
		return -1
	}
	if a.real != b.real {
		if a.real {
			return 1
		}
		return -1
	}
	if a.real {
		if n := a.at.Compare(b.at); n != 0 {
			return n
		}
		// At equal source time a real deletion wins, preventing resurrection.
		if (len(a.data) == 0) != (len(b.data) == 0) {
			if len(a.data) == 0 {
				return 1
			}
			return -1
		}
	}
	return bytes.Compare(a.key, b.key)
}

func localBucketConfigUpdatedAt(meta BucketMetadata, file string, now time.Time) time.Time {
	_, at := replicatedBucketConfig(&meta, file)
	for _, lower := range []time.Time{meta.Created, *at} {
		if !now.After(lower) {
			now = lower.Add(time.Nanosecond)
		}
	}
	return now.UTC()
}

func ensureBucketMetadataCreated(ctx context.Context, obj ObjectLayer, meta *BucketMetadata) error {
	if !meta.Created.IsZero() {
		return nil
	}
	info, err := obj.GetBucketInfo(ctx, meta.Name, BucketOptions{NoMetadata: true})
	if err != nil {
		return err
	}
	if info.Created.IsZero() {
		return errors.New("bucket metadata creation time is unknown")
	}
	meta.Created = info.Created.UTC()
	return nil
}

// applyBucketConfig runs under metadata.lock, on freshly loaded metadata. It
// changes only the selected field; the caller persists once after all checks.
func applyBucketConfig(meta *BucketMetadata, file string, data []byte, at time.Time) (bool, error) {
	if bucketConfigUpdateOnly(file) && len(data) == 0 {
		return false, nil
	}
	current, currentAt := replicatedBucketConfig(meta, file)
	lockEnabled := len(meta.ObjectLockConfigXML) != 0
	incoming, err := newBucketConfigState(meta.Name, file, data, at, meta.Created, lockEnabled)
	if err != nil {
		return false, err
	}
	if !incoming.candidate() {
		return false, nil
	}
	local, err := newBucketConfigState(meta.Name, file, *current, *currentAt, meta.Created, lockEnabled)
	if err != nil {
		return false, err
	}
	if compareBucketConfigStates(incoming, local) <= 0 {
		return false, nil
	}
	*current, *currentAt = bytes.Clone(incoming.data), incoming.at.UTC()
	return true, nil
}

func rebaseBucketConfigDefaults(meta *BucketMetadata, oldCreated time.Time) {
	if meta.Created.Equal(oldCreated) {
		return
	}
	// These six fields alone use Created to distinguish a baseline from a
	// tombstone. Preserve actual source times when adopting an existing bucket.
	for _, file := range replicatedBucketConfigs {
		_, at := replicatedBucketConfig(meta, file)
		if at.IsZero() || at.Equal(oldCreated) {
			*at = meta.Created
		}
	}
}
