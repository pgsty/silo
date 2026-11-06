// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"slices"
	"strings"
	"sync"

	"github.com/minio/madmin-go/v3"
)

// batchCounts are outcomes of a batch job that a later run of the job would
// see again, and so must be persisted together with the cursor of the walk.
type batchCounts struct {
	objects             int64
	objectsFailed       int64
	deleteMarkersFailed int64
	versionsSkipped     int64
	keysRefused         int64
}

func (c *batchCounts) add(o batchCounts) {
	c.objects += o.objects
	c.objectsFailed += o.objectsFailed
	c.deleteMarkersFailed += o.deleteMarkersFailed
	c.versionsSkipped += o.versionsSkipped
	c.keysRefused += o.keysRefused
}

//msgp:ignore batchProgress batchProgressItem batchCounts

// batchProgress is the cursor of a walk whose items are done concurrently.
//
// The items of a walk are numbered in walk order. A key is done when every
// item of it, and every item before it, is done; only then does the cursor
// move past it and its counts become part of the job's counts. The cursor and
// the counts are persisted together, so a job resumed after the cursor
// neither skips an item that was not done nor counts an item twice.
type batchProgress struct {
	mu      sync.Mutex
	ri      *batchJobInfo
	bucket  string
	issued  uint64
	next    uint64
	pending map[uint64]batchProgressItem
	// key is the key of the item last committed, and held are the counts of
	// its items so far.
	key  string
	held batchCounts
}

type batchProgressItem struct {
	key    string
	counts batchCounts
}

func newBatchProgress(ri *batchJobInfo, bucket string) *batchProgress {
	return &batchProgress{ri: ri, bucket: bucket, pending: make(map[uint64]batchProgressItem)}
}

// begin numbers the next item of the walk.
func (p *batchProgress) begin() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	seq := p.issued
	p.issued++
	return seq
}

// done records item seq, of key, as done with counts.
func (p *batchProgress) done(seq uint64, key string, counts batchCounts) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending[seq] = batchProgressItem{key: key, counts: counts}
	for {
		item, ok := p.pending[p.next]
		if !ok {
			return
		}
		delete(p.pending, p.next)
		p.next++
		if item.key != p.key {
			p.commitLocked()
			p.key = item.key
		}
		p.held.add(item.counts)
	}
}

// finish commits the last key if every item of the walk is done. Call it
// once no item is in progress.
func (p *batchProgress) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.next == p.issued {
		p.commitLocked()
	}
}

func (p *batchProgress) commitLocked() {
	if p.key == "" {
		return
	}
	ri := p.ri
	ri.mu.Lock()
	ri.Bucket = p.bucket
	ri.Object = p.key
	ri.Objects += p.held.objects
	ri.ObjectsFailed += p.held.objectsFailed
	ri.DeleteMarkersFailed += p.held.deleteMarkersFailed
	ri.VersionsSkippedLocked += p.held.versionsSkipped
	ri.KeysRefused += p.held.keysRefused
	ri.mu.Unlock()
	p.held = batchCounts{}
}

// countRemoved counts versions a job removed. A removed version is gone for
// any later run, so it is counted at once, not at the cursor.
func (ri *batchJobInfo) countRemoved(bucket string, objects, markers int64) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	ri.Bucket = bucket
	ri.Objects += objects
	ri.DeleteMarkers += markers
}

// countSkipped counts a version a job left in place because Object Lock
// protects it, for a job that is counted per run rather than at a cursor.
func (ri *batchJobInfo) countSkipped() {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	ri.VersionsSkippedLocked++
}

// batchCanonicalPrefixes orders the prefixes of a walk and drops a prefix
// that another one covers. The keys of the walk are then visited once each,
// in one ascending order, which a single cursor can describe.
func batchCanonicalPrefixes(prefixes []string) []string {
	if len(prefixes) == 0 {
		return []string{""}
	}
	sorted := slices.Clone(prefixes)
	slices.Sort(sorted)
	out := sorted[:0]
	for _, p := range sorted {
		if len(out) > 0 && strings.HasPrefix(p, out[len(out)-1]) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// batchResumeAfter reports whether a resumed walk returned a key after the
// cursor. The cursor key is done; the walk forwards conservatively and
// returns it again. Keys compare as the walk orders them, by name, so a
// directory object comes before the keys under it.
func batchResumeAfter(cursor, name string) bool {
	return cursor == "" || name > cursor
}

// batchJobStatus is the status response: madmin.BatchJobStatus with the
// fields this server adds. The added fields are additive; a client that does
// not know them ignores them.
type batchJobStatus struct {
	LastMetric batchJobStatusMetric
}

type batchJobStatusMetric struct {
	madmin.JobMetric
	VersionsSkippedLocked int64  `json:"versionsSkippedLocked,omitempty"`
	KeysRefused           int64  `json:"keysRefused,omitempty"`
	FailureReason         string `json:"failureReason,omitempty"`
}

func (ri *batchJobInfo) statusMetric() batchJobStatusMetric {
	ri.mu.RLock()
	defer ri.mu.RUnlock()
	return batchJobStatusMetric{
		JobMetric:             ri.metric(),
		VersionsSkippedLocked: ri.VersionsSkippedLocked,
		KeysRefused:           ri.KeysRefused,
		FailureReason:         ri.FailureReason,
	}
}
