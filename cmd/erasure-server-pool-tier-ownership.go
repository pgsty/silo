// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// tierRemoteTuple is the complete identity of an object in a remote tier.
// The tier name is part of the identity: configuring a new backend under a
// different name must not make an old free record point at it.
type tierRemoteTuple struct {
	Tier      string
	Object    string
	VersionID string
}

func (t tierRemoteTuple) equal(other tierRemoteTuple) bool {
	return t == other
}

// tierFreeRecord retains the exact drive and free record that owns a remote
// tuple. Cleanup must not delete the same version ID on another drive where
// it may name a different tuple.
type tierFreeRecord struct {
	disk  StorageAPI
	info  FileInfo
	Tuple tierRemoteTuple
}

type tierHistory struct {
	liveTuples []tierRemoteTuple
	free       []tierFreeRecord
}

var (
	errTierOwnershipUnavailable = errors.New("tier ownership history is unavailable")
	errTierStillReferenced      = errors.New("remote tier object still has a live reference")
)

func tierOwnershipUnavailable(bucket, object string, err error) error {
	return fmt.Errorf("%w for %s/%s: %v: %w", errTierOwnershipUnavailable, bucket, decodeDirObject(object), err, InsufficientReadQuorum{
		Bucket: bucket,
		Object: decodeDirObject(object),
		Err:    errErasureReadQuorum,
		Type:   RQInconsistentMeta,
	})
}

// tierOwnership reads every drive in every pool and retains the transition
// evidence of every metadata revision. It deliberately does not use
// objectVersions or lifecycleEventsAllPools: those APIs merge duplicate
// versions and omit free versions, which is correct for reads but unsafe for
// deleting a remote tuple.
//
// The caller must hold the encoded object's writer lock. A matching live
// reference or an unreadable drive prevents remote deletion. Matching free
// records are returned so the caller can remove only the records that name
// this exact remote tuple.
func (z *erasureServerPools) tierOwnership(ctx context.Context, bucket, object string, tuple tierRemoteTuple) (live bool, free []tierFreeRecord, err error) {
	history, err := z.readTierHistory(ctx, bucket, object)
	if err != nil {
		return false, nil, err
	}
	for _, record := range history.free {
		if record.Tuple.equal(tuple) {
			free = append(free, record)
		}
	}
	for _, liveTuple := range history.liveTuples {
		// Incomplete transition fields cannot prove that this is a different
		// remote object. Keep the cleanup record until they are resolved.
		if (liveTuple.Tier == "" || liveTuple.Tier == tuple.Tier) &&
			(liveTuple.Object == "" || liveTuple.Object == tuple.Object) &&
			(liveTuple.VersionID == "" || tuple.VersionID == "" || liveTuple.VersionID == tuple.VersionID) {
			live = true
			break
		}
	}
	return live, free, nil
}

// readTierHistory is the full per-drive metadata scan used by both remote
// cleanup and delete-all. It keeps every live tuple so a hidden older version
// or a minority-drive revision cannot be discarded by a winner merge.
func (z *erasureServerPools) readTierHistory(ctx context.Context, bucket, object string) (tierHistory, error) {
	var history tierHistory
	if z == nil || len(z.serverPools) == 0 {
		return history, tierOwnershipUnavailable(bucket, object, errTierOwnershipUnavailable)
	}

	for _, p := range z.serverPools {
		set := p.getHashedSet(object)
		disks := slices.Clone(set.getDisks())
		if len(disks) == 0 {
			return history, tierOwnershipUnavailable(bucket, object, errTierOwnershipUnavailable)
		}
		raws, errs := readAllRawFileInfo(ctx, disks, bucket, object, false)
		if err := ctx.Err(); err != nil {
			return history, err
		}
		for drive := range disks {
			err := errs[drive]
			switch {
			case err == nil:
			case errors.Is(err, errFileNotFound), errors.Is(err, errVolumeNotFound):
				continue
			default:
				return history, tierOwnershipUnavailable(bucket, object, err)
			}

			var xl xlMetaV2
			if err := xl.LoadOrConvert(raws[drive].Buf); err != nil {
				return history, tierOwnershipUnavailable(bucket, object, err)
			}
			versions, err := xl.ListVersions(bucket, object, false)
			if err != nil {
				return history, tierOwnershipUnavailable(bucket, object, err)
			}
			for _, fi := range versions {
				got := tierRemoteTuple{
					Tier:      fi.TransitionTier,
					Object:    fi.TransitionedObjName,
					VersionID: fi.TransitionVersionID,
				}
				if fi.TierFreeVersion() {
					history.free = append(history.free, tierFreeRecord{
						disk:  disks[drive],
						info:  fi,
						Tuple: got,
					})
					continue
				}
				if tierRefusesDeleteAll(false, fi.TransitionStatus, fi.TransitionTier, fi.TransitionedObjName) {
					history.liveTuples = append(history.liveTuples, got)
				}
			}
		}
	}
	return history, nil
}

func deleteTierRemote(ctx context.Context, tuple tierRemoteTuple) error {
	err := deleteObjectFromRemoteTier(ctx, tuple.Object, tuple.VersionID, tuple.Tier)
	if err == nil || isErrObjectNotFound(err) || isErrVersionNotFound(err) {
		return nil
	}
	return err
}

// deleteTierTuple performs the only safe remote-tier cleanup sequence. The
// object lock covers the fresh ownership read, the remote delete and local
// free-record cleanup. A failed remote delete leaves every matching record as
// the durable retry point. A remote not-found is successful and still allows
// record cleanup.
func (z *erasureServerPools) deleteTierTuple(ctx context.Context, bucket, object string, tuple tierRemoteTuple) error {
	object = encodeDirObject(object)
	lk := z.NewObjectNSLock(bucket, object)
	lkctx, err := lk.GetLock(ctx, globalDeleteOperationTimeout)
	if err != nil {
		return err
	}
	ctx = lkctx.Context()
	defer lk.Unlock(lkctx)
	return z.deleteTierTupleLocked(ctx, bucket, object, tuple)
}

// deleteTierTupleLocked is the same sequence for callers that already hold
// the object's writer lock, such as a delete-all purge.
func (z *erasureServerPools) deleteTierTupleLocked(ctx context.Context, bucket, object string, tuple tierRemoteTuple) error {
	live, records, err := z.tierOwnership(ctx, bucket, object, tuple)
	if err != nil {
		return err
	}
	if live {
		return errTierStillReferenced
	}
	if len(records) == 0 {
		// An old queued sweeper is not evidence of ownership. In particular,
		// it must not delete a remote object after the free record is gone.
		return nil
	}
	if tuple.Tier == "" || tuple.Object == "" {
		return tierOwnershipUnavailable(bucket, object, errTierOwnershipUnavailable)
	}
	if err := deleteTierRemote(ctx, tuple); err != nil {
		return err
	}

	// Only the captured drives may lose these records. The storage operation
	// also checks the free marker and tuple, so a stale cleanup cannot remove
	// a different revision with the same local version ID.
	for _, record := range records {
		fi := FileInfo{
			VersionID:      record.info.VersionID,
			TransitionTier: tuple.Tier, TransitionedObjName: tuple.Object,
			TransitionVersionID: tuple.VersionID,
		}
		fi.SetTierFreeVersion()
		err := record.disk.DeleteVersion(ctx, bucket, object, fi, false, DeleteOptions{})
		if err != nil && !errors.Is(err, errFileNotFound) && !errors.Is(err, errFileVersionNotFound) {
			return err
		}
	}
	return nil
}
