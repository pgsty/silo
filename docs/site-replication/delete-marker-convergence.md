# Delete marker replication convergence with more than two sites (405 storm)

> **Scope:** site replication (SR) with **3 or more peer sites**, versioned buckets.
> **Status in silo:** PR #162 ("complete purges, expose MRF drops, and cancel
> resyncs reliably") fixed the *first-attempt* classification of marker purges
> (`DeleteObjectHandler`, heal and resync paths now send the purge as a version
> purge), made MRF drops observable, and hardened resync cancellation.
> This document describes the **remaining** convergence defects on the
> delete-marker path — purge *retries* short-circuited by the marker's creation
> status, purge outcomes recorded in the wrong field, and the MRF silently
> dropping every delete-marker entry — and the fix that closes them
> (see issues #152, #153; this completes what #162 started).
>
> All file/line references below are from the silo tree **with the fix applied**.

## TL;DR

Three defects in the delete-marker replication path combined into a permanent
non-convergence loop:

| # | Where | Defect | Consequence |
|---|-------|--------|-------------|
| 1 | `cmd/bucket-replication.go` `replicateDeleteToTarget` (early-out, :633) | The "already replicated" early-out tested the delete marker's **creation** status (`PrevReplicationStatus`) even when the operation is a **purge** of that marker | A purge whose first delivery to a site failed was **never retried** — that site kept a deleted marker forever |
| 2 | `cmd/bucket-replication.go` `replicateDeleteToTarget` (offline/error/success branches) | On `RemoveObject` success for a DM purge (`dobj.VersionID == ""`), the code set `ReplicationStatus = Completed` but never `VersionPurgeStatus = VersionPurgeComplete` | The source's per-target purge status stayed `PENDING` forever → the scanner re-queued the purge on every cycle; the purged version never left the source `xl.meta` |
| 3 | `cmd/bucket-replication.go` `queueMRFHeal` (:4059) | `GetObjectInfo(VersionID=<DM version>)` always returns `MethodNotAllowed` (`cmd/erasure-object.go:1001`), so the MRF `continue`d | Failed delete-marker replications saved to the MRF were silently dropped; the MRF could not heal them |

With 2 sites the first fan-out attempt almost always succeeds (single target), so
data converged even though the *status* metadata was broken (defect 2). With N > 2
sites there are N-1 targets per bucket; the probability that **at least one**
first-attempt delivery fails approaches 1, and once it does, defects 1+2 make
recovery impossible — while defect 3 removes the fastest retry path. The stuck
`PENDING` statuses then drive perpetual heal/resync traffic whose per-marker
probes are answered 405. In an 84M-version ILSF mesh this showed up as
~4,100 req/s with 96.8% of them answered 405 (issue #153).

---

## Background: how delete-marker replication works

### Wire format — creation and purge are indistinguishable

Both delete-marker operations are replicated as the **same S3 request shape** sent by
`replicateDeleteToTarget` (`cmd/bucket-replication.go:691-710`):

```
DELETE /<bucket>/<object>?versionId=X
    x-minio-source-deletemarker: true
    x-amz-replication-status: REPLICA
```

* **DM creation** — soft delete (`DELETE` without version ID) on the source creates
  delete marker version `X`, fanned out with
  `dobj{VersionID: "", DeleteMarkerVersionID: X}`.
* **DM purge** — `DELETE versionId=X` on the source marks the marker for
  replication-purge (`VersionPurgeStatusInternal = "arn1=PENDING;..."`). Since
  #162, the *single-object handler*, the heal path (`queueReplicationHeal`,
  :3772-3793) and the resync worker (`resyncBucket`, :3320-3342) classify a
  marker carrying purge state as a **version purge**
  (`dobj{VersionID: X, PurgeTargets: {...}}`). Anything that still arrives with
  the legacy shape `dobj{VersionID: "", DeleteMarkerVersionID: X}` and a
  non-empty `VersionPurgeStatus` must be handled correctly too — this is the
  shape this document's fix targets.

The receiver (`DeleteObjectHandler` → erasure `DeleteObject`) cannot tell the
wire shapes apart and resolves the ambiguity **by whether the version exists
locally**:

| Target state | Result of the replicated DELETE |
|---|---|
| `X` absent | delete marker `X` **created** (`xl-storage-format-v2.go` fallback `addVersion`, :1517) |
| `X` present | delete marker `X` **removed** |

There is **no tombstone** for a purged marker: if the "remove" delivery is re-sent
after the target already removed `X`, the fallback **re-creates** the marker (see
*Known remaining limitations*).

### State bookkeeping

A delete marker on the source carries two independent per-target maps (stored in
the marker version's `MetaSys`, reconstructed via `getInternalReplicationState`,
`cmd/erasure-metadata.go:687`):

* `Targets` / `ReplicationStatusInternal` — **creation** status per target
  (`"arn1=COMPLETED;arn2=COMPLETED;"`).
* `PurgeTargets` / `VersionPurgeStatusInternal` — **purge** status per target
  (`"arn1=PENDING;arn2=PENDING;"`), written only when a purge is in flight.

`ReplicationState.targetState(arn)` (`cmd/bucket-replication-utils.go:392`)
exposes both to `replicateDeleteToTarget`:

```go
PrevReplicationStatus: rs.Targets[arn],      // DM *creation* status
VersionPurgeStatus:    rs.PurgeTargets[arn], // DM *purge* status
```

### The 405

`HEAD/GET versionId=X` on a delete marker returns **405 MethodNotAllowed** with
the object info attached (`cmd/erasure-object.go:996-1002`). The replication
engine relies on this: the sender probes the target with
`IsReplicationReadyForDeleteMarker` (`cmd/bucket-replication.go:653-664`) and
treats 405 as "delete marker already replicated" for *creation* (`:666-671`).
This is why a *single* stuck probe is by design — the *storm* was the same probe
repeated forever because the state that would end it never advanced.

---

## The defects (pre-fix)

### Bug 1 — DM purge retries were short-circuited by the creation status

The early-out

```go
if dobj.VersionID == "" && rinfo.PrevReplicationStatus == replication.Completed && dobj.OpType != replication.ExistingObjectReplicationType {
```

was written for creation retries ("already replicated — don't re-send"). For a
**purge** retry `PrevReplicationStatus` is the marker's old **creation** status —
`COMPLETED` on every site that ever received the marker. The purge was therefore
returned as `Completed` **without ever being sent**, and the target kept the
marker.

Sequence (site A purges marker `X`; first delivery to C failed):

```
A: Targets={B:COMPLETED, C:COMPLETED} (creation), PurgeTargets={B:PENDING, C:PENDING}
   fan-out #1:  B ✔ purged   C ✘ network error → PurgeTargets={B:COMPLETE, C:FAILED}
scanner heal:   retry both targets
   B: early-out fires (PrevReplicationStatus=COMPLETED)  → no-op
   C: early-out fires (PrevReplicationStatus=COMPLETED)  → NO-OP — C keeps marker X
   → PurgeTargets re-persisted as-is → composite purge = FAILED → re-queued next cycle
   → repeat forever
```

Only `OpType == ExistingObjectReplicationType` (explicit site resync) bypassed
this early-out — which is why `mc admin replicate resync` was the *only* thing
that eventually moved a stuck purge, and why operators kept re-running resyncs
(feeding the 405 storm).

### Bug 2 — a successful DM purge never recorded `VersionPurgeComplete`

For a DM purge (`dobj.VersionID == ""`, `DeleteMarkerVersionID != ""`), success
was recorded in the **creation** field:

```go
} else {
    if dobj.VersionID == "" {
        rinfo.ReplicationStatus = replication.Completed   // wrong field for a purge
    } else {
        rinfo.VersionPurgeStatus = replication.VersionPurgeComplete
    }
}
```

`rinfo.VersionPurgeStatus` — which `getReplicationState` persists into
`VersionPurgeStatusInternal` — kept the `PENDING`/`FAILED` value seeded by
`targetState`. Consequences:

1. The composite purge status on the source never became `COMPLETE`, so
   `queueReplicationHeal` re-queued the purge on **every scanner cycle**, forever.
2. The final metadata rewrite could never take the "purge complete" removal path
   in `xlMetaV2.DeleteVersion` (`cmd/xl-storage-format-v2.go:1380-1393`), so the
   purged marker version was never dropped from the source — it lingered in
   `PENDING` state.

### Bug 3 — the MRF could never heal a delete marker

Failed replications are saved to the MRF (`queueMRFSave`) with
`versionID = DeleteMarkerVersionID` for DMs (`ToMRFEntry`,
`cmd/bucket-replication.go:1926`). The MRF heal pass used:

```go
oi, err := p.objLayer.GetObjectInfo(ctx, e.Bucket, e.Object, ObjectOptions{
    VersionID: vID,
})
if err != nil {
    continue // a delete marker version ALWAYS errors with MethodNotAllowed here
}
QueueReplicationHeal(p.ctx, e.Bucket, oi, e.RetryCount)
```

`GetObjectInfo` on a delete-marker version returns `MethodNotAllowed` **with
valid info** (`cmd/erasure-object.go:1001`), so every DM entry was dropped.
Failed DM replications were left to the scanner alone.

---

## Why "more than 2 sites" makes it visible

* Per bucket, SR creates **one rule per peer site** (`cmd/site-replication.go`),
  so a single delete fans out to `N-1` targets. The probability that a
  first-attempt delivery fails (brief offline target, bandwidth limit,
  replication race with the covered object version) grows with N; with 2 sites
  it usually succeeds outright.
* On failure the composite status becomes `PENDING`/`FAILED`, which re-queues
  healing — but bug 1 made each retry a no-op and bug 2 kept the queue alive.
  Data diverged (marker present on a subset of sites) while the source's status
  oscillated forever.
* Any site resync then walks **every** delete marker: for each marker still
  present on the resyncing site it probes all peers — 405 per marker per peer,
  on every resync, on every scanner-triggered heal.
* Additionally, a divergence created via the early-out is a **stale marker on a
  site**. A later resync *from that site* re-delivered the marker to sites where
  it was purged; the receiver's absent-version fallback re-created it. Combined
  with ongoing purges, marker state flip-flopped between sites and every flip
  surfaced as a fresh round of 405 probes (see limitations).

## Anatomy of the 405 storm

```
purge of DM X on A, delivery to C fails once
  └─ PurgeTargets{C:FAILED} persisted (bug 2: even B's success stays PENDING)
     └─ composite purge = PENDING/FAILED → scanner re-queues every cycle
        └─ retry short-circuited by creation status (bug 1) → state never advances
           └─ operator runs `mc admin replicate resync` (only bypass)
              └─ resync probes DM version X on every peer → 405 … per marker, per peer
              └─ (worst case) resync from a stale site re-creates purged markers
                 └─ next purge round → new probes → new 405s …
```

---

## The fix

A delete-marker **purge** is identified precisely as:

```go
isDMPurge := dobj.VersionID == "" && dobj.DeleteMarkerVersionID != "" && !rinfo.VersionPurgeStatus.Empty()
```

(the non-empty `VersionPurgeStatus` distinguishes a purge from a creation, whose
purge map is empty), applied in `replicateDeleteToTarget`:

1. **Do not short-circuit purge retries; preserve the creation status.** For a
   purge, `rinfo.ReplicationStatus` is pinned to `PrevReplicationStatus`, and
   the early-out is guarded with `!isDMPurge`. The per-target *creation* status
   stays intact in subsequent metadata rewrites (no status regression, no
   spurious re-queues).
2. **Record purge outcomes in the purge status.** The offline, error and
   success branches write `VersionPurgeStatus` whenever
   `dobj.VersionID != "" || isDMPurge`, and `ReplicationStatus` otherwise. A
   purge now converges: `PurgeTargets` reaches `COMPLETE` on every target →
   composite becomes `VersionPurgeComplete` → the source's final rewrite takes
   the `xlMetaV2.DeleteVersion` removal path and the marker version is dropped
   → the scanner stops re-queueing.
3. **Let the MRF heal delete markers.** `queueMRFHeal` no longer drops entries
   whose `GetObjectInfo` fails with `MethodNotAllowed`: the 405 case carries a
   fully populated `ObjectInfo` for the marker version, which
   `QueueReplicationHeal` routes back through the (now fixed) delete path.
   Entries without a usable name are still skipped.

### Behavior after the fix

| Scenario | Before | After |
|---|---|---|
| DM creation retry, target already has marker | 405 probe → `COMPLETED` | unchanged |
| DM creation retry, target not ready | `FAILED`, MRF drops it | `FAILED`, MRF heals it |
| DM purge, first delivery fails to site C | C keeps marker forever | purge retried by scanner **and** MRF until C confirms |
| DM purge, all deliveries succeed | source purge status stays `PENDING` forever; version lingers; re-queued every scan | status `COMPLETE`, marker version removed on source, queue drains |
| Legacy marker-path purge (pre-#162 state) | left `PENDING`, needed a heal re-queue | purge completes on the first proper delivery |
| Site resync of a stuck purge | bypass + probe → 405 per marker per peer, every resync | purge completes on first proper retry; resync probes become rare/one-shot |

Transient 405s during a *single* healing round remain — they are by design
("already replicated"). What disappears is the *unbounded repetition* driven by
states that could never advance.

---

## Reproduction (3 sites)

```bash
# 1. three sites, SR enabled (see docs/site-replication/run-multi-site-silo-idp.sh)
mc admin replicate add siteA siteB siteC
mc mb siteA/bk && mc cp f.txt siteA/bk/

# 2. soft delete on A → marker replicated to B and C (COMPLETED)
mc rm siteA/bk/f.txt
mc ls --versions siteB/bk/   # marker present on all sites

# 3. take C offline, then purge the marker version on A
mc rm --vid <MARKER-VERSION-ID> siteA/bk/f.txt

# 4. bring C back and wait
mc ls --versions siteC/bk/   # BUG (pre-fix): marker still present on C, forever
mc admin replicate status siteA   # purge statuses stuck PENDING/FAILED

# 5. resync A → burst of 405s on every remaining marker version
mc admin replicate resync start siteA
```

What to observe pre-fix: `minio_cluster_replication_*` failures, audit logs full
of `ReplicateDelete` with 405s, `mc ls --versions` divergence on C, purge status
never reaching COMPLETE. Post-fix: C's marker is removed shortly after it
returns, status converges, 405s subside.

## Regression tests

* `cmd/replication-delete-marker_test.go`
  * `TestReplicateDeleteMarkerTargetSemantics/marker-path_purge_*`: a purge in
    the legacy shape with `PrevReplicationStatus=COMPLETED,
    VersionPurgeStatus=PENDING` must NOT short-circuit; success yields
    `VersionPurgeStatus=VersionPurgeComplete` with the creation status preserved;
    rejection yields `VersionPurgeFailed`.
  * `TestReplicateDeleteMarkerPurge/recover_legacy_true`: a legacy-shaped purge
    delivered end-to-end through `replicateDelete` finalizes the source purge
    (marker version dropped on source and target) and schedules nothing further.
  * `TestReplicateDeleteMarkerPurge` (pre-existing, #162): the version-purge
    shape still removes the target version and completes the source purge.

## Known remaining limitations (follow-ups, not addressed by this fix)

1. **No tombstone for DM removal on the receiver.** The same wire request
   creates the marker when absent and removes it when present (absent-version
   fallback, `cmd/xl-storage-format-v2.go:1517`). Re-delivering a purge after
   the target already removed the marker **re-creates** it (e.g., a resync from
   a site that never saw the purge). A proper fix would carry explicit purge
   semantics on the wire (e.g., reuse the purge status header) or add tombstones.
2. **`getReplicationState` drops non-attempted targets.** If
   `GetRemoteTargetClient` returns `nil` for a target during a fan-out
   (`cmd/bucket-replication.go:516-533`), its per-target status is omitted from
   the persisted state (`cmd/bucket-replication-utils.go:402`), the composite
   silently becomes `COMPLETED`, and the target is never retried — silent
   divergence, only healable by resync. Preserving previous statuses for
   non-attempted targets would fix it.
3. **Replica delete markers are dead-ended.** A marker received as `REPLICA` is
   never re-propagated by the scanner, the MRF, or the delete handler. With the
   source's direct fan-out covering all sites this is usually fine, but if the
   source's own state is lost the marker can only be healed by a full site
   resync.
4. **Observability (from #153).** Replication counters per response code (405
   especially) and a gauge of versions with non-Completed status older than N
   hours do not exist natively. #162 exposed the MRF drop counters; per-code
   counters remain a follow-up.
5. **MRF re-enqueue with backoff (from #152).** Dropped entries still rely on
   the scanner for recovery; a bounded re-enqueue with backoff would shrink the
   recovery window.

## References

* `cmd/bucket-replication.go` — `replicateDelete` (:426), `replicateDeleteToTarget`
  (:608, `isDMPurge` :621), `queueReplicationHeal` (:3749), `resyncBucket`
  (:3209+), `queueMRFHeal` (:4059), `ToMRFEntry` (:1926)
* `cmd/bucket-replication-utils.go` — `ReplicationState`, `targetState` (:392),
  `getReplicationState` (:402)
* `cmd/erasure-object.go` — `GetObjectInfo` (:450), 405 generation (:996-1002)
* `cmd/erasure-metadata.go` — `getInternalReplicationState` (:687)
* `cmd/xl-storage-format-v2.go` — `DeleteVersion` (:1346), purge-complete
  removal path (:1380-1393), absent-version fallback (:1517)
* `cmd/object-handlers.go` — `DeleteObjectHandler` purge classification (:3224-3231)
* `cmd/site-replication.go` — per-peer rule creation, `startResync`
