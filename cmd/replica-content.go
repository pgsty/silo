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
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/minio/minio/internal/crypto"
	"github.com/minio/minio/internal/hash/sha256"
	xioutil "github.com/minio/minio/internal/ioutil"
)

type replicaContentGuardFn func(context.Context, string, string, ObjectInfo, func() (*GetObjectReader, error)) error

// verifyLockedReplica compares the actual data, never a sender's ETag or
// checksum assertion. A peer may retransmit a protected version to update its
// metadata, but may not replace its content. Call under the object write lock.
func verifyLockedReplica(ctx context.Context, incoming, stored ObjectInfo, openIncoming, openStored func() (*GetObjectReader, error)) error {
	if !enforceRetentionForDeletion(ctx, stored) {
		return nil
	}
	locked := ObjectLocked{Bucket: stored.Bucket, Object: stored.Name, VersionID: stored.VersionID}
	if storedObjectLockState(stored.UserDefined).complianceWouldWeaken(storedObjectLockState(incoming.UserDefined)) {
		return locked
	}
	inSSEC, oldSSEC := crypto.SSEC.IsEncrypted(incoming.UserDefined), crypto.SSEC.IsEncrypted(stored.UserDefined)
	if inSSEC != oldSSEC {
		return locked
	}
	if inSSEC {
		inSize, inErr := incoming.GetActualSize()
		oldSize, oldErr := stored.GetActualSize()
		if inErr != nil || oldErr != nil || inSize != oldSize {
			return locked
		}
		// Without the customer key, compare ciphertext and its interpretation.
		// Equal ciphertext with a changed seal or multipart framing is not the
		// same object, even if the supplied ETag and size are unchanged.
		for _, key := range []string{
			crypto.MetaIV, crypto.MetaAlgorithm, crypto.MetaSealedKeySSEC,
			ReservedMetadataPrefix + "compression",
		} {
			if incoming.UserDefined[key] != stored.UserDefined[key] {
				return locked
			}
		}
		if crypto.IsMultiPart(incoming.UserDefined) != crypto.IsMultiPart(stored.UserDefined) || incoming.isMultipart() != stored.isMultipart() {
			return locked
		}
		if crypto.IsMultiPart(incoming.UserDefined) {
			if len(incoming.Parts) != len(stored.Parts) {
				return locked
			}
			for i, p := range incoming.Parts {
				old := stored.Parts[i]
				if p.Number != old.Number || p.Size != old.Size {
					return locked
				}
			}
		}
	}
	in, err := openIncoming()
	if err != nil {
		return err
	}
	defer in.Close()
	old, err := openStored()
	if err != nil {
		return err
	}
	defer old.Close()
	ih, oh := sha256.New(), sha256.New()
	inSize, err := io.Copy(ih, in)
	if err != nil {
		return err
	}
	oldSize, err := io.Copy(oh, old)
	if err != nil {
		return err
	}
	if inSize != oldSize || !bytes.Equal(ih.Sum(nil), oh.Sum(nil)) {
		return locked
	}
	return nil
}

func (er erasureObjects) guardReplicaContent(ctx context.Context, bucket, object string, incoming ObjectInfo, openIncoming func() (*GetObjectReader, error)) error {
	opts := ObjectOptions{VersionID: incoming.VersionID, NoLock: true, NoAuditLog: true, ReplicationRequest: true}
	if opts.VersionID == "" {
		opts.VersionID = nullVersionID
	}
	stored, err := er.getObjectInfo(ctx, bucket, object, opts)
	if isErrObjectNotFound(err) || isErrVersionNotFound(err) || isErrMethodNotAllowed(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return verifyLockedReplica(ctx, incoming, stored, openIncoming, func() (*GetObjectReader, error) {
		return er.GetObjectNInfo(ctx, bucket, object, nil, http.Header{}, opts)
	})
}

func (z *erasureServerPools) guardReplicaContent(ctx context.Context, bucket, object string, incoming ObjectInfo, openIncoming func() (*GetObjectReader, error)) error {
	opts := ObjectOptions{VersionID: incoming.VersionID, NoLock: true, NoAuditLog: true, ReplicationRequest: true}
	if opts.VersionID == "" {
		opts.VersionID = nullVersionID
	}
	copies, err := z.objectPoolInfos(ctx, bucket, object, opts)
	if isErrObjectNotFound(err) || isErrVersionNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, copy := range copies {
		if err := verifyLockedReplica(ctx, incoming, copy.ObjInfo, openIncoming, func() (*GetObjectReader, error) {
			return z.serverPools[copy.Index].GetObjectNInfo(ctx, bucket, object, nil, http.Header{}, opts)
		}); err != nil {
			return err
		}
	}
	return nil
}

// checkReplicaContent reads the staged version before rename commits it. Its
// data is decoded/decrypted just like a GET (raw ciphertext for SSE-C), so this
// covers multipart, compression and destination SSE-S3/KMS re-encryption.
// disks and metadata are in erasure shard order, as passed to renameData.
func (er erasureObjects) checkReplicaContent(ctx context.Context, bucket, object, stageBucket, stageObject string, metadata []FileInfo, disks []StorageAPI, opts ObjectOptions) error {
	if (!opts.ReplicaLockReconcile && !opts.ReplicationRequest) || opts.DataMovement {
		return nil
	}
	var fi FileInfo
	for i, disk := range disks {
		if disk != nil {
			fi = metadata[i]
			break
		}
	}
	incoming := fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended)
	guard := opts.replicaContentGuard
	if guard == nil {
		guard = er.guardReplicaContent
	}
	return guard(ctx, bucket, object, incoming, func() (*GetObjectReader, error) {
		// A marker-only peer write does not reconcile the stored protection.
		// It therefore cannot replace a protected version, even with equal data.
		if !opts.ReplicaLockReconcile {
			return nil, ObjectLocked{Bucket: bucket, Object: decodeDirObject(object), VersionID: incoming.VersionID}
		}
		if incoming.IsCompressed() {
			// A replica may assert the source's logical size. A compressed GET
			// limits its output to that size, so verify it against the lengths
			// recorded while consuming the uploaded parts before comparing GETs.
			// Otherwise a forged zero size could hide a non-empty replacement.
			var actual int64
			for _, part := range incoming.Parts {
				actual += part.ActualSize
			}
			declared, err := incoming.GetActualSize()
			if err != nil || declared != actual {
				return nil, ObjectLocked{Bucket: bucket, Object: decodeDirObject(object), VersionID: incoming.VersionID}
			}
		}
		readOpts := ObjectOptions{NoDecryption: crypto.SSEC.IsEncrypted(incoming.UserDefined)}
		fn, off, length, err := NewGetObjectReader(nil, incoming, readOpts, http.Header{})
		if err != nil {
			return nil, err
		}
		// The ordinary reader expects original drive order, not shard order.
		readDisks, readMeta := make([]StorageAPI, len(disks)), make([]FileInfo, len(metadata))
		for i, shard := range fi.Erasure.Distribution {
			readDisks[i], readMeta[i] = disks[shard-1], metadata[shard-1]
			readMeta[i].Erasure.Index = shard
		}
		pr, pw := xioutil.WaitPipe()
		go func() {
			pw.CloseWithError(er.getObjectWithFileInfo(ctx, stageBucket, stageObject, off, length, pw, fi, readMeta, readDisks))
		}()
		reader, err := fn(pr, http.Header{}, func() { pr.CloseWithError(nil) })
		if err != nil {
			pr.CloseWithError(err)
		}
		return reader, err
	})
}
