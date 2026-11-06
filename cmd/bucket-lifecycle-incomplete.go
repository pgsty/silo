// Copyright (c) 2026 PGSTY
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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/event"
)

// An ILM expiry attempt that ends without removing what it addressed is
// incomplete: the rule no longer applied when it was checked again under the
// object lock, Object Lock protects the version, the history needed to decide
// could not be read, or another error. It is counted by reason, traced with
// the reason, and, unless it was refused, audited and logged. It never sends
// a removal notification: what it addressed is still there.
const (
	ilmIncompleteNotApplicable      = "not_applicable"
	ilmIncompleteLocked             = "locked"
	ilmIncompleteHistoryUnavailable = "history_unavailable"
	ilmIncompleteError              = "error"
)

// ilmIncompleteReasons are the reasons expiry_incomplete_total counts, a
// bounded set of label values.
var ilmIncompleteReasons = []string{
	ilmIncompleteNotApplicable,
	ilmIncompleteLocked,
	ilmIncompleteHistoryUnavailable,
	ilmIncompleteError,
}

// ilmIncompleteStats counts incomplete ILM expiries by reason.
type ilmIncompleteStats struct {
	counts map[string]*atomic.Int64
}

func newILMIncompleteStats(reasons ...string) *ilmIncompleteStats {
	s := &ilmIncompleteStats{counts: make(map[string]*atomic.Int64, len(reasons))}
	for _, r := range reasons {
		s.counts[r] = &atomic.Int64{}
	}
	return s
}

func (s *ilmIncompleteStats) add(reason string) {
	if c, ok := s.counts[reason]; ok {
		c.Add(1)
	}
}

// snapshot returns the counts by reason.
func (s *ilmIncompleteStats) snapshot() map[string]int64 {
	out := make(map[string]int64, len(s.counts))
	for r, c := range s.counts {
		out[r] = c.Load()
	}
	return out
}

var globalILMIncomplete = newILMIncompleteStats(ilmIncompleteReasons...)

// ilmExpiryNotDone classifies the error of an ILM expiry that did not remove
// what it addressed. A version that is already gone is not counted.
func ilmExpiryNotDone(err error) (reason string, counted bool) {
	switch {
	case err == nil || isErrObjectNotFound(err) || isErrVersionNotFound(err):
		return "", false
	case errors.Is(err, errLifecycleNotApplicable):
		return ilmIncompleteNotApplicable, true
	}
	var locked ObjectLocked
	if errors.As(err, &locked) {
		return ilmIncompleteLocked, true
	}
	if isErrReadQuorum(err) || isErrWriteQuorum(err) {
		return ilmIncompleteHistoryUnavailable, true
	}
	return ilmIncompleteError, true
}

// ilmExpiryRefused reports whether reason is a refusal, which changes
// nothing, rather than a failure.
func ilmExpiryRefused(reason string) bool {
	return reason == ilmIncompleteNotApplicable || reason == ilmIncompleteLocked
}

// reportILMExpiryNotDone reports an ILM expiry of oi that ended with err. It
// reports nothing and returns false when err says the version is already
// gone; the caller reports that as it did before.
func reportILMExpiryNotDone(ctx context.Context, oi ObjectInfo, lcEvent lifecycle.Event, src lcEventSrc, err error, logID string, traceFn func(event string, metadata map[string]string, err error)) bool {
	reason, counted := ilmExpiryNotDone(err)
	if !counted {
		return false
	}
	globalILMIncomplete.add(reason)
	if ilmExpiryRefused(reason) {
		traceFn(ILMExpiry, map[string]string{"result": "refused", "reason": reason, "version-id": oi.VersionID}, nil)
		return true
	}
	traceFn(ILMExpiry, map[string]string{"result": "failed", "reason": reason, "version-id": oi.VersionID}, err)
	tags := newLifecycleAuditEvent(src, lcEvent).Tags()
	tags["version-id"] = oi.VersionID
	tags["ilm-incomplete-reason"] = reason
	auditLogInternal(ctx, AuditLogOptions{
		Event:     ILMExpiry,
		APIName:   "ILMExpiry",
		Bucket:    oi.Bucket,
		Object:    oi.Name,
		VersionID: oi.VersionID,
		Error:     err.Error(),
		Tags:      tags,
	})
	ilmLogOnceIf(ctx, fmt.Errorf("ILM expiry of %s/%s (%s) not done: %w", oi.Bucket, oi.Name, oi.VersionID, err), logID)
	return true
}

// ilmExpiryEventName is the notification of an expiry that completed. An
// expiry that addressed no version ID (Expiration of a latest version in a
// versioned or suspended bucket) and whose result is a delete marker created
// that marker, also when the marker takes the null version ID of the version
// it replaces. Any other expiry removed the version it addressed, also when
// that version was itself a delete marker.
func ilmExpiryEventName(requestedVersionID string, result ObjectInfo) event.Name {
	if requestedVersionID == "" && result.DeleteMarker {
		return event.ObjectRemovedDeleteMarkerCreated
	}
	return event.ObjectRemovedDelete
}
