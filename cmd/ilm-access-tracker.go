// Copyright (c) 2015-2026 MinIO, Inc.
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
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/minio/internal/config/ilm"
	"github.com/zeebo/xxh3"
)

//go:generate msgp -file=$GOFILE -unexported
//msgp:ignore accessTracker mergedAccess

const (
	// accessTrackerPrefix is where each node publishes its own counters.
	// One object per node, merged by every node on a timer.
	accessTrackerPrefix = minioConfigPrefix + "/ilm/access"

	// accessQueueSize bounds the GET -> tracker handoff. Overflow drops
	// samples rather than slowing down reads.
	accessQueueSize = 100000

	// accessMaxDemoteCandidates bounds what the scanner may hand over in a
	// single flush interval.
	accessMaxDemoteCandidates = 100000

	// accessShardStaleFactor multiplies the flush interval to decide when a
	// peer's counters are too old to trust, e.g. after a node is removed.
	accessShardStaleFactor = 5
)

func accessShardFresh(now int64, shard accessShard, stale int64) bool {
	if shard.UpdatedAt <= 0 {
		return false
	}
	if stale <= 0 {
		return true
	}
	age := now - shard.UpdatedAt
	return age >= -stale && age <= stale
}

// accessEntry is a rolling hit counter for one object. Bins[0] is the current
// bin and each subsequent bin is one bin-width older, so a rule asking for
// "100 hits in 10 minutes" sums the newest ceil(10m/binWidth) bins.
//
// A fixed window is used rather than an exponentially decayed score because
// the rule is stated to operators in exactly those terms.
type accessEntry struct {
	Bins   []uint32 `msg:"b"`
	HeadAt int64    `msg:"h"` // unix seconds at the start of Bins[0]
	LastAt int64    `msg:"l"` // unix seconds of the most recent hit
}

// demoteCandidate is an object the scanner found sitting on a fast pool with
// no recent reads. Candidates ride the node's own counter shard so they reach
// the leader without a new peer RPC.
type demoteCandidate struct {
	Bucket string `msg:"b"`
	Object string `msg:"o"`
	Pool   int    `msg:"p"`
}

// accessShard is what one node publishes. BinWidth is carried so a peer that
// has not yet picked up a configuration change is ignored rather than merged
// with mismatched bins.
type accessShard struct {
	UpdatedAt int64                  `msg:"u"`
	BinWidth  int64                  `msg:"bw"`
	Entries   map[string]accessEntry `msg:"e"`
	Demote    []demoteCandidate      `msg:"d"`
}

// binStart truncates a unix timestamp to the start of its bin.
func binStart(now, binWidth int64) int64 {
	if binWidth <= 0 {
		return now
	}
	return now - now%binWidth
}

// rollTo advances the counter to now, zeroing the bins that elapsed since the
// last update and resizing if the configured bin count changed.
func (e *accessEntry) rollTo(now, binWidth int64, nbins int) {
	if nbins <= 0 || binWidth <= 0 {
		return
	}
	if len(e.Bins) != nbins {
		resized := make([]uint32, nbins)
		copy(resized, e.Bins)
		e.Bins = resized
	}
	head := binStart(now, binWidth)
	if e.HeadAt == 0 {
		e.HeadAt = head
		return
	}
	steps := (head - e.HeadAt) / binWidth
	if steps <= 0 {
		return
	}
	if steps >= int64(nbins) {
		clear(e.Bins)
	} else {
		copy(e.Bins[steps:], e.Bins[:nbins-int(steps)])
		clear(e.Bins[:steps])
	}
	e.HeadAt = head
}

// hits returns the number of accesses recorded over the newest bins covering
// window. A window longer than the configured history is clamped to it.
//
// The newest bin is partial, so the covered span is between window-binWidth
// and window. Operators tune resolution with ilm access_bin_width.
func (e accessEntry) hits(window time.Duration, binWidth int64) uint64 {
	if binWidth <= 0 || len(e.Bins) == 0 {
		return 0
	}
	n := int((int64(window/time.Second) + binWidth - 1) / binWidth)
	if n < 1 {
		n = 1
	}
	if n > len(e.Bins) {
		n = len(e.Bins)
	}
	var total uint64
	for _, v := range e.Bins[:n] {
		total += uint64(v)
	}
	return total
}

// total is the whole retained history, used to decide what to evict.
func (e accessEntry) total() uint64 {
	var t uint64
	for _, v := range e.Bins {
		t += uint64(v)
	}
	return t
}

// mergeFrom adds another node's counters for the same object. Both sides must
// already be rolled to the same head.
func (e *accessEntry) mergeFrom(o accessEntry) {
	for i := range e.Bins {
		if i < len(o.Bins) {
			total := uint64(e.Bins[i]) + uint64(o.Bins[i])
			if total > uint64(^uint32(0)) {
				total = uint64(^uint32(0))
			}
			e.Bins[i] = uint32(total)
		}
	}
	if o.LastAt > e.LastAt {
		e.LastAt = o.LastAt
	}
}

// mergedAccess is an immutable cluster-wide snapshot. Readers take it from an
// atomic pointer, so the hot scanner and sweep paths never take a lock.
type mergedAccess struct {
	entries  map[string]accessEntry
	binWidth int64
	at       int64
}

func (m *mergedAccess) hits(key string, window time.Duration) uint64 {
	if m == nil {
		return 0
	}
	e, ok := m.entries[key]
	if !ok {
		return 0
	}
	return e.hits(window, m.binWidth)
}

func (m *mergedAccess) lastAccess(key string) int64 {
	if m == nil {
		return 0
	}
	return m.entries[key].LastAt
}

// accessTracker records how often each object is read.
//
// Ownership is deliberately narrow: the live counter map is touched only by
// run()'s goroutine, so it needs no lock. Everything read from elsewhere goes
// through the immutable merged snapshot.
type accessTracker struct {
	ch      chan string
	enabled atomic.Bool
	merged  atomic.Pointer[mergedAccess]

	// Demote candidates arrive from scanner goroutines, so this one does
	// need a lock. It is small: only objects we previously promoted.
	demoteMu sync.Mutex
	demote   map[string]demoteCandidate

	dropped atomic.Uint64
}

var globalAccessTracker = newAccessTracker()

func newAccessTracker() *accessTracker {
	return &accessTracker{
		ch:     make(chan string, accessQueueSize),
		demote: make(map[string]demoteCandidate),
	}
}

// accessKey is the tracker's map key. Bucket names cannot contain '/', so the
// join is unambiguous.
func accessKey(bucket, object string) string {
	return bucket + "/" + object
}

func splitAccessKey(key string) (bucket, object string, ok bool) {
	bucket, object, ok = strings.Cut(key, "/")
	if !ok || bucket == "" || object == "" {
		return "", "", false
	}
	return bucket, object, true
}

// note records one read. It is called from the GET path and must never block
// or allocate meaningfully: on a full queue the sample is dropped.
func (t *accessTracker) note(bucket, object string) {
	if t == nil || !t.enabled.Load() {
		return
	}
	select {
	case t.ch <- accessKey(bucket, object):
	default:
		t.dropped.Add(1)
	}
}

// noteDemoteCandidate is called by the scanner for an object it found on a
// fast pool that has gone quiet. The leader picks these up on the next merge.
func (t *accessTracker) noteDemoteCandidate(bucket, object string, pool int) {
	if t == nil || !t.enabled.Load() {
		return
	}
	t.demoteMu.Lock()
	defer t.demoteMu.Unlock()
	if len(t.demote) >= accessMaxDemoteCandidates {
		return
	}
	t.demote[accessKey(bucket, object)] = demoteCandidate{Bucket: bucket, Object: object, Pool: pool}
}

// hits reports cluster-wide accesses to an object over window.
func (t *accessTracker) hits(bucket, object string, window time.Duration) uint64 {
	if t == nil {
		return 0
	}
	return t.merged.Load().hits(accessKey(bucket, object), window)
}

// lastAccess reports the cluster-wide time an object was last read. A zero
// time means "no read on record", which for demotion purposes is idle.
func (t *accessTracker) lastAccess(bucket, object string) time.Time {
	if t == nil {
		return time.Time{}
	}
	sec := t.merged.Load().lastAccess(accessKey(bucket, object))
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// snapshot returns the current merged view, or nil if none has been published.
func (t *accessTracker) snapshot() *mergedAccess {
	if t == nil {
		return nil
	}
	return t.merged.Load()
}

// takeDemoteCandidates drains and returns the pending candidates.
func (t *accessTracker) takeDemoteCandidates() []demoteCandidate {
	t.demoteMu.Lock()
	defer t.demoteMu.Unlock()
	if len(t.demote) == 0 {
		return nil
	}
	out := make([]demoteCandidate, 0, len(t.demote))
	for _, c := range t.demote {
		out = append(out, c)
	}
	t.demote = make(map[string]demoteCandidate)
	return out
}

// restoreDemoteCandidates puts candidates back when the publisher is still
// busy. Dropping access samples is acceptable; dropping the only scanner
// discovery of an idle promoted object would delay demotion by a full scan.
func (t *accessTracker) restoreDemoteCandidates(candidates []demoteCandidate) {
	if len(candidates) == 0 {
		return
	}
	t.demoteMu.Lock()
	defer t.demoteMu.Unlock()
	for _, c := range candidates {
		if len(t.demote) >= accessMaxDemoteCandidates {
			return
		}
		t.demote[accessKey(c.Bucket, c.Object)] = c
	}
}

// shardName is this node's counter object. The node name is hashed so that
// host:port never has to be escaped into an object key.
func (t *accessTracker) shardName() string {
	return fmt.Sprintf("%s/%016x.bin", accessTrackerPrefix, xxh3.HashString(globalLocalNodeName))
}

// run owns the live counter map. It drains reads, and on every flush interval
// hands a marshaled shard to a background publisher.
//
// Everything here is best effort: this is accounting for a background data
// movement decision, not a durability path.
func (t *accessTracker) run(ctx context.Context, objAPI ObjectLayer) {
	cfg := globalILMConfig.accessCfg()
	t.enabled.Store(cfg.AccessTiering)

	live := make(map[string]accessEntry)
	if cfg.AccessTiering {
		if buf, err := readConfig(ctx, objAPI, t.shardName()); err == nil {
			var previous accessShard
			if _, err = previous.UnmarshalMsg(buf); err == nil && previous.BinWidth == int64(cfg.AccessBinWidth/time.Second) {
				now := time.Now().Unix()
				for key, entry := range previous.Entries {
					entry.rollTo(now, previous.BinWidth, cfg.AccessBins)
					if entry.total() != 0 {
						live[key] = entry
					}
				}
			}
		}
	}
	ticker := time.NewTicker(cfg.AccessFlush)
	defer ticker.Stop()

	// One publisher goroutine keeps object-layer I/O off the drain loop.
	type pub struct {
		shard accessShard
		cfg   ilm.Config
	}
	pubCh := make(chan pub, 1)
	go func() {
		for p := range pubCh {
			t.publish(ctx, objAPI, p.shard, p.cfg)
		}
	}()
	defer close(pubCh)

	for {
		select {
		case <-ctx.Done():
			return

		case key := <-t.ch:
			now := time.Now().Unix()
			e := live[key]
			e.rollTo(now, int64(cfg.AccessBinWidth/time.Second), cfg.AccessBins)
			if len(e.Bins) > 0 {
				if e.Bins[0] != ^uint32(0) {
					e.Bins[0]++
				}
			}
			e.LastAt = now
			live[key] = e

		case <-ticker.C:
			newCfg := globalILMConfig.accessCfg()
			t.enabled.Store(newCfg.AccessTiering)
			if newCfg.AccessFlush != cfg.AccessFlush && newCfg.AccessFlush > 0 {
				ticker.Reset(newCfg.AccessFlush)
			}
			cfg = newCfg
			if !cfg.AccessTiering {
				// Feature turned off: release the counters rather than
				// holding a stale working set for the process lifetime.
				clear(live)
				t.merged.Store(nil)
				continue
			}

			now := time.Now().Unix()
			binWidth := int64(cfg.AccessBinWidth / time.Second)
			t.evict(live, now, binWidth, cfg)

			shard := accessShard{
				UpdatedAt: now,
				BinWidth:  binWidth,
				Entries:   make(map[string]accessEntry, len(live)),
				Demote:    t.takeDemoteCandidates(),
			}
			for k, e := range live {
				e.Bins = slices.Clone(e.Bins)
				shard.Entries[k] = e
			}
			select {
			case pubCh <- pub{shard: shard, cfg: cfg}:
			default:
				// Previous publish still running; skip this round
				// rather than queueing work we cannot keep up with.
				t.restoreDemoteCandidates(shard.Demote)
			}
		}
	}
}

// evict rolls every counter forward and drops the ones with no hits left in
// the retained history, then enforces the tracked-object cap.
//
// ponytail: amortized O(n) sweep on the flush tick; a heap would only pay off
// past ~10M tracked keys.
func (t *accessTracker) evict(live map[string]accessEntry, now, binWidth int64, cfg ilm.Config) {
	for k, e := range live {
		e.rollTo(now, binWidth, cfg.AccessBins)
		if e.total() == 0 {
			delete(live, k)
			continue
		}
		live[k] = e
	}
	if len(live) <= cfg.AccessMaxTracked {
		return
	}
	// Over the cap: keep the hottest and drop the rest. Objects that fall
	// out are cold by construction, which is exactly what the demotion path
	// already assumes about anything missing from the map.
	type kt struct {
		key   string
		total uint64
	}
	all := make([]kt, 0, len(live))
	for k, e := range live {
		all = append(all, kt{k, e.total()})
	}
	slices.SortFunc(all, func(a, b kt) int { return cmp.Compare(b.total, a.total) })
	for _, x := range all[cfg.AccessMaxTracked:] {
		delete(live, x.key)
	}
}

// publish writes this node's shard and rebuilds the merged snapshot from every
// node's shard. Both halves are best effort.
func (t *accessTracker) publish(ctx context.Context, objAPI ObjectLayer, shard accessShard, cfg ilm.Config) {
	buf, err := shard.MarshalMsg(nil)
	if err != nil {
		ilmLogIf(ctx, err)
		return
	}
	if err := saveConfig(ctx, objAPI, t.shardName(), buf); err != nil {
		ilmLogIf(ctx, err)
		// Still rebuild the snapshot below: our own counters are already
		// in hand and a stale peer view beats no view.
	}
	t.merged.Store(t.mergeShards(ctx, objAPI, shard, cfg))
}

// mergeShards sums every live node's counters, including our own in-memory
// shard so this node's most recent reads are never a flush behind.
func (t *accessTracker) mergeShards(ctx context.Context, objAPI ObjectLayer, own accessShard, cfg ilm.Config) *mergedAccess {
	now := time.Now().Unix()
	binWidth := int64(cfg.AccessBinWidth / time.Second)
	out := &mergedAccess{
		entries:  make(map[string]accessEntry, len(own.Entries)),
		binWidth: binWidth,
		at:       now,
	}

	add := func(s accessShard) {
		if s.BinWidth != binWidth {
			// A peer has not yet picked up a bin-width change; merging
			// its bins would silently mis-scale the counts.
			return
		}
		for k, e := range s.Entries {
			e.rollTo(now, binWidth, cfg.AccessBins)
			cur, ok := out.entries[k]
			if !ok {
				cur = accessEntry{Bins: make([]uint32, cfg.AccessBins)}
			}
			cur.mergeFrom(e)
			out.entries[k] = cur
		}
	}

	add(own)

	ownName := t.shardName()
	stale := int64(cfg.AccessFlush/time.Second) * accessShardStaleFactor
	for _, name := range t.listShards(ctx, objAPI) {
		if name == ownName {
			continue
		}
		buf, err := readConfig(ctx, objAPI, name)
		if err != nil {
			continue
		}
		var s accessShard
		if _, err := s.UnmarshalMsg(buf); err != nil {
			continue
		}
		if !accessShardFresh(now, s, stale) {
			continue // node is gone or wedged
		}
		add(s)
	}
	return out
}

func (t *accessTracker) listShards(ctx context.Context, objAPI ObjectLayer) []string {
	res, err := objAPI.ListObjects(ctx, minioMetaBucket, accessTrackerPrefix+"/", "", "", maxObjectList)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(res.Objects))
	for _, o := range res.Objects {
		if strings.HasSuffix(o.Name, ".bin") {
			names = append(names, o.Name)
		}
	}
	return names
}

// collectDemoteCandidates returns every node's pending demote candidates. Only
// the leader calls this, right before running a demotion pass.
//
// Our own shard is read back rather than skipped: run() drains the local map
// into the published shard, so anything found since the last leader pass lives
// there, not in memory. The local map is still drained here to pick up
// candidates recorded since that publish.
func (t *accessTracker) collectDemoteCandidates(ctx context.Context, objAPI ObjectLayer, cfg ilm.Config) []demoteCandidate {
	seen := make(map[string]struct{})
	var out []demoteCandidate

	for _, c := range t.takeDemoteCandidates() {
		key := accessKey(c.Bucket, c.Object)
		seen[key] = struct{}{}
		out = append(out, c)
	}

	now := time.Now().Unix()
	stale := int64(cfg.AccessFlush/time.Second) * accessShardStaleFactor
	for _, name := range t.listShards(ctx, objAPI) {
		buf, err := readConfig(ctx, objAPI, name)
		if err != nil {
			continue
		}
		var s accessShard
		if _, err := s.UnmarshalMsg(buf); err != nil {
			continue
		}
		if !accessShardFresh(now, s, stale) {
			continue
		}
		for _, c := range s.Demote {
			key := accessKey(c.Bucket, c.Object)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, c)
		}
	}
	return out
}
