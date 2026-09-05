// Copyright (c) 2015-2026 MinIO, Inc.
// Copyright (c) 2026 PGSTY
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package cmd

import (
	"context"
	"net/http"

	objectreplication "github.com/minio/minio/internal/bucket/replication"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/pgsty/silo-pkg/v3/policy"
)

type (
	replicationTrustKey struct{}
	replicaTrustKey     struct{}
)

// hasReplicationMarker reports whether the internal replication marker has
// its one accepted wire value. Header presence alone is never a trust signal.
func hasReplicationMarker(h http.Header) bool {
	values, ok := h[http.CanonicalHeaderKey(xhttp.MinIOSourceReplicationRequest)]
	return ok && len(values) == 1 && values[0] == "true"
}

func hasReplicationMarkerHeader(h http.Header) bool {
	_, ok := h[http.CanonicalHeaderKey(xhttp.MinIOSourceReplicationRequest)]
	return ok
}

func hasReplicaStatus(h http.Header) bool {
	return h.Get(xhttp.AmzBucketReplicationStatus) == objectreplication.Replica.String()
}

func withReplicationTrust(ctx context.Context, trusted, replicaTrusted bool) context.Context {
	ctx = context.WithValue(ctx, replicationTrustKey{}, trusted)
	return context.WithValue(ctx, replicaTrustKey{}, trusted && replicaTrusted)
}

func isTrustedReplication(ctx context.Context) bool {
	trusted, _ := ctx.Value(replicationTrustKey{}).(bool)
	return trusted
}

func isReplicaTrusted(ctx context.Context) bool {
	trusted, _ := ctx.Value(replicaTrustKey{}).(bool)
	return trusted
}

// replicationPermissionAllowed must be called only after the request's
// existing authentication/signature path has succeeded and populated ReqInfo.
// Replication peers are authenticated principals; an anonymous bucket-policy
// grant must not turn client-controlled internal headers into trusted state.
func replicationPermissionAllowed(ctx context.Context, r *http.Request, bucket, object string, action policy.Action) bool {
	reqInfo := logger.GetReqInfo(ctx)
	if reqInfo == nil || reqInfo.Cred.AccessKey == "" {
		return false
	}
	reqInfo.BucketName = bucket
	reqInfo.ObjectName = object
	return authorizeRequest(ctx, r, action) == ErrNone
}

// evaluateReplicationTrust decides whether a request may carry replication
// semantics for the given action. A request that declares itself a replica
// without holding the replication permission is rejected. trusted reports that
// the exact marker came from a permitted principal; replica additionally
// requires the request to declare REPLICA status.
func evaluateReplicationTrust(ctx context.Context, r *http.Request, bucket, object string, action policy.Action) (trusted, replica bool, s3Err APIErrorCode) {
	rawReplica := hasReplicaStatus(r.Header)
	markerExact := hasReplicationMarker(r.Header)
	permitted := false
	if rawReplica || markerExact {
		permitted = replicationPermissionAllowed(ctx, r, bucket, object, action)
	}
	if rawReplica && !permitted {
		return false, false, ErrAccessDenied
	}
	trusted = markerExact && permitted
	return trusted, trusted && rawReplica, ErrNone
}

// replicationRequestHeaders are internal request controls. They are removed
// only after signature verification when a request has not earned replication
// trust. Public S3/SSE/checksum headers, proxy loop guards, and replication
// validity/readiness probes are intentionally not listed here.
var replicationRequestHeaders = []string{
	xhttp.MinIOSourceReplicationRequest,
	xhttp.MinIOSourceETag,
	xhttp.MinIOSourceMTime,
	xhttp.MinIOSourceDeleteMarker,
	xhttp.MinIOSourceDeleteMarkerDelete,
	xhttp.MinIOSourceTaggingTimestamp,
	xhttp.MinIOSourceObjectRetentionTimestamp,
	xhttp.MinIOSourceObjectLegalHoldTimestamp,
	"X-Minio-Replication-Server-Side-Encryption-Sealed-Key",
	"X-Minio-Replication-Server-Side-Encryption-Seal-Algorithm",
	"X-Minio-Replication-Server-Side-Encryption-Iv",
	"X-Minio-Replication-Encrypted-Multipart",
	xhttp.MinIOReplicationActualObjectSize,
	ReplicationSsecChecksumHeader,
	xhttp.AmzBucketReplicationStatus,
}

// ssecReplicaSealHeaders are the internal headers a source site attaches to a
// raw SSE-C replica write. Their presence means the body is source ciphertext
// that the destination can neither decrypt nor re-frame.
var ssecReplicaSealHeaders = []string{
	"X-Minio-Replication-Server-Side-Encryption-Seal-Algorithm",
	"X-Minio-Replication-Server-Side-Encryption-Sealed-Key",
	"X-Minio-Replication-Server-Side-Encryption-Iv",
}

// isRawSSECReplica reports whether a request is a replica write carrying a
// source SSE-C seal. replicaTrusted must be the value evaluateReplicationTrust
// returned for this request: the headers alone are client controlled and are
// never a trust signal on their own.
func isRawSSECReplica(h http.Header, replicaTrusted bool) bool {
	if !replicaTrusted {
		return false
	}
	for _, name := range ssecReplicaSealHeaders {
		if h.Get(name) != "" {
			return true
		}
	}
	return false
}

func stripReplicationRequestHeaders(h http.Header) {
	for _, name := range replicationRequestHeaders {
		h.Del(name)
	}
}

func hasReplicationRequestHeaders(h http.Header) bool {
	for _, name := range replicationRequestHeaders {
		if _, ok := h[http.CanonicalHeaderKey(name)]; ok {
			return true
		}
	}
	return false
}

func cloneRequestWithoutReplicationHeaders(ctx context.Context, r *http.Request) *http.Request {
	clone := r.Clone(ctx)
	stripReplicationRequestHeaders(clone.Header)
	// A streaming body reader built from the original request fills r.Trailer
	// as the body is consumed; the checksum reader must observe that same map.
	clone.Trailer = r.Trailer
	return clone
}

// applyReplicationTrust binds the handler context to the effective request.
// The context marker is the authorization source of truth; header removal is
// defense in depth for option builders and future call sites.
func applyReplicationTrust(ctx context.Context, r *http.Request, trusted, replicaTrusted bool) (context.Context, *http.Request) {
	ctx = withReplicationTrust(ctx, trusted, replicaTrusted)
	if trusted {
		return ctx, r.WithContext(ctx)
	}
	return ctx, cloneRequestWithoutReplicationHeaders(ctx, r)
}
