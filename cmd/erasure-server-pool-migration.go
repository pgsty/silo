// Copyright (c) 2026 Feng Ruohang
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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"errors"

	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/sync/errgroup"
)

func migrationVersionKey(versionID string) string {
	if versionID == "" || versionID == nullVersionID {
		return nullVersionID
	}
	return versionID
}

// countAbsentMigrationVersions counts snapshot versions that no source drive
// holds anymore, including free versions. A pool-level NotFound is insufficient:
// the ordinary read path can return it for inconsistent metadata. Only readable
// per-drive metadata (or physical absence) proves progress for another walk.
// The caller holds the object's writer lock while checking the source.
func (er erasureObjects) countAbsentMigrationVersions(ctx context.Context, bucket, object string, versions []FileInfo) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(versions) == 0 {
		return 0, nil
	}
	absent := make(map[string]struct{}, len(versions))
	for _, version := range versions {
		absent[migrationVersionKey(version.VersionID)] = struct{}{}
	}
	disks := er.getDisks()
	if len(disks) == 0 {
		return 0, toObjectErr(errErasureReadQuorum, bucket, object)
	}
	stored := make([][]FileInfo, len(disks))
	g := errgroup.WithNErrs(len(disks))
	for i := range disks {
		g.Go(func() error {
			if disks[i] == nil {
				return errDiskNotFound
			}
			raw, err := disks[i].ReadXL(ctx, bucket, object, false)
			if errors.Is(err, errFileNotFound) {
				// ReadXL also returns NotFound for an empty xl.meta, and may
				// ignore legacy metadata. Confirm physical absence before using
				// that result as progress. This does not descend into child keys.
				// Both reads run in parallel across drives, once per object.
				entries, err := disks[i].ListDir(ctx, "", bucket, object, -1)
				if err != nil && !errors.Is(err, errFileNotFound) && !errors.Is(err, errVolumeNotFound) {
					return err
				}
				for _, entry := range entries {
					if entry == xlStorageFormatFile || entry == xlStorageFormatFileV1 {
						return errFileCorrupt
					}
				}
				return nil
			}
			if errors.Is(err, errVolumeNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			// allParts=false omits part details, not free versions. Decode every
			// version before concluding absence, so corrupt metadata fails closed.
			fivs, err := getAllFileInfoVersions(raw.Buf, bucket, object, false)
			stored[i] = fivs.Versions
			return err
		}, i)
	}
	errs := g.Wait()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	for i, err := range errs {
		if err != nil {
			return 0, toObjectErr(err, bucket, object)
		}
		for _, version := range stored[i] {
			delete(absent, migrationVersionKey(version.VersionID))
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return len(absent), nil
}

// countAbsentMigrationVersions checks ignored walk entries without authorizing
// their deletion. A concurrent client delete may have uncovered child keys.
func (z *erasureServerPools) countAbsentMigrationVersions(ctx context.Context, bucket, object string, source int, versions []FileInfo) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(versions) == 0 {
		return 0, nil
	}
	object = encodeDirObject(object)
	lk := z.NewNSLock(bucket, object)
	lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, err
	}
	defer lk.Unlock(lkctx)
	return z.serverPools[source].getHashedSet(object).countAbsentMigrationVersions(lkctx.Context(), bucket, object, versions)
}

// migrationObjectMetadata restores tags removed from the read representation.
// Keep the original revision, including ordered empty states, for the existing
// locked reconciliation at PUT or multipart completion. Moving is not a new
// tagging mutation, and the write must not modify the reader's metadata map.
func migrationObjectMetadata(oi ObjectInfo) map[string]string {
	metadata := cloneMSS(oi.UserDefined)
	delete(metadata, xhttp.AmzObjectTagging)
	if oi.UserTags != "" {
		metadata[xhttp.AmzObjectTagging] = oi.UserTags
	}
	return metadata
}
