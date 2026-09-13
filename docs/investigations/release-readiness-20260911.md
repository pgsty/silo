# Remaining release correctness work, 2026-09-11

> This is a dated investigation, with the source and runtime boundaries recorded
> below. It does not establish the current dependency pins or a later release.
> See [the current changelog](../../CHANGELOG.md) and
> [component matrix](https://silo.pgsty.com/compatibility/versions/).


This records the three work items agreed after the branch/PR consolidation:
OIDC #154, Linux restart/readback #116, and the related multi-pool defects
#133/#144. The maintained target is SILO with the PGSTY Console, mcli and
silo-pkg dependencies in the repository's current `go.mod`.

## Multi-pool writes and conditional deletion (#133, #144)

The pools layer now holds its object write lock across PUT and multipart
completion, as it already does for metadata updates and DELETE. Multipart
completion acquires the object lock before the upload lock. Queued healing and
drive healing use this namespace too; healing under a caller-owned lock retains
that lock's cancellation context. The destination-pool allocation policy is
unchanged.

Trusted replica writes resolve the addressed version in every pool, including
draining and rebalancing pools. Retention, legal hold and tags retain their
independent ordering timestamps. A timestamp-only removal survives a stale
retransmit. Completion resolves the version persisted in the upload, including
the null version, rather than taking a later latest version's metadata.

Successful replica replacement retires competing copies of that exact version,
so an equal-ModTime copy in an earlier pool cannot shadow the reconciled result.
Metadata updates evaluate their callback once against the merged version and
update all its copies. Replica metadata COPY rechecks ordering under the lock.
Cleanup failures propagate; a replacement may already have committed when
cleanup fails, and a retry can finish cleanup. Data movement keeps ownership of
its source cleanup.

Retiring copies preserves any remote-tier reference still held by a surviving
copy, including temporarily restored objects. Only the last copy of that tier
reference schedules remote contents for garbage collection. This also protects
the authoritative copy if the final conditional deletion fails; unrelated tier
contents remain eligible for cleanup.

Conditional DELETE evaluates its precondition against the logical latest or
explicitly addressed version. It checks all pools before mutation, removes
secondary copies before the authoritative one, and returns cleanup errors.
Versioned DELETE without a version ID creates a delete marker and preserves
version history. Retention and replication callbacks evaluate the reconciled
logical version. The existing all-pool delete helper also propagates errors
from non-first pools.

The deterministic two-pool, 32-drive fixtures cover version selection,
duplicate removal, delete failure propagation, PUT/DELETE and completion/DELETE
interleavings, independent lock winners, draining/rebalancing owners, null
versions, metadata COPY, metadata/healing serialization and cleanup retry.
Tiered-copy tests inspect the persisted garbage-collection markers after
metadata COPY, restored COPY, successful deletion and failed primary deletion,
with distinct remote references as cleanup controls.
The original branch reproduced the wrong-version lookup, surviving duplicate,
suppressed delete error, PUT/DELETE race, and PUT/completion lock-state failures
before the fixes were applied.

Before the final tier-reference guard, local validation passed the full `cmd`
suite (255.720 s), all `internal` tests, `go vet ./...`, generated-file checks
and the branding/entrypoint checks.
Focused race checks cover the pooled interleavings, SSE-C lock regressions,
conditional deletion, access-tier movement and TLS defaults. The two-pool and
related replica/delete/movement tests also passed as a Linux/arm64 test binary
in an isolated container with an 8 GiB `/tmp` tmpfs. Its initial 1 GiB tmpfs
was insufficient for the existing single-drive test fixtures' free-space guard.
The final tier-reference guard passed all six new cases in that Linux fixture;
the retained restart binary below predates this guard and has no remote tier
configured.

## Linux restart/readback (#116)

The [runner](issue-116/run-linux.py) creates four Linux/arm64 server containers
on one Docker Desktop Linux VM, with separate network identities and one drive
per node (EC 2+2). A holder container keeps four 256 MiB Linux tmpfs named
volumes mounted across full server stops. Docker's ordinary filesystem had
only 3.8 GiB free out of 2 TiB and correctly hit the server's free-space limit;
the test uses the separate tmpfs filesystems without changing that threshold.
This is the four-containers-on-one-Linux-host option explicitly accepted in
the [#116 V1 plan](https://github.com/pgsty/silo/issues/116).

This covers process/container restart and TCP peer reconnection on one Linux
host. It does not establish independent-host, host-reboot or physical-media
durability. Every resource created by the runner is removed in its cleanup.
The [retained summary](issue-116/evidence-20260911.json) records image identities,
per-coordinator observations and readback counts.

| Binary | Full restart to all admin views online | Admin gate to complete 4 PUT / 16 GET round | Timed readbacks | Final readback |
|---|---:|---:|---:|---:|
| 0806 release | 2.084 s | 14.449 s | 660 / 660 | 240 / 240 |
| 0903 release | 2.284 s | 0.191 s | 96 / 96 | 52 / 52 |
| Current fix candidate | 2.461 s | 14.489 s | 1356 / 1356 | 904 / 904 |

Each canary has one hard 60-second deadline covering setup, requests, response
body reads and sleeps, with SDK retries disabled. Every acknowledged PUT uses
a unique versioned key and immediately records its VersionId, size and SHA-256.
The timed checks reread these same objects through all four coordinators at
15, 30 and 60 seconds **after the data canary succeeds**. They do not replace
early acknowledgements with later writes. The final check also includes writes
made during the one-node outage and subsequent rejoin canary.

All three runs passed the bounded canary, scheduled readbacks, one-node-outage
read/write and rejoin readback. The candidate also showed a rejoin window:
admin online at 2.490 s, complete data canary 13.977 s later. These are individual
observations, not a latency guarantee or a comparison proving one version
faster. Admin/health readiness still must be followed by a data-path check.

To repeat with cached images and a native mcli executable:

```sh
uv run --with boto3==1.43.92 docs/investigations/issue-116/run-linux.py \
  0806 0903 --output /tmp/silo-linux-acceptance --mcli /path/to/mcli

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags kqueue -o /tmp/silo-linux .
uv run --with boto3==1.43.92 docs/investigations/issue-116/run-linux.py \
  current --output /tmp/silo-linux-candidate --mcli /path/to/mcli \
  --current-binary /tmp/silo-linux --source-revision "$(git rev-parse HEAD)"
```

The runner uses `--pull=never`; preload the two release images, `alpine:3.23`,
and the Linux base image selected with `--current-image`. Match the candidate
binary architecture to that image. Detailed local evidence, including the
acknowledgement ledger and full logs, remains in the requested output directory.

## OIDC (#154)

The TLS implementation fix was already merged in `48e1846525cc`: transports
honor Go's key-exchange defaults, so `GODEBUG=tlsmlkem=0` can opt out of ML-KEM
for an ingress that rejects it. It does not disable certificate validation or
force an automatic protocol downgrade. See the existing
[Go 1.27 investigation](go127-stack.md) and [issue investigation](issue-154.md).

A Linux build of main `b32f2d9dd01a` passed fresh isolated fixture checks:

- ML-KEM-intolerant IdP with `tlsmlkem=0`: discovery, IAM, Console login (204),
  authenticated bucket listing (200).
- Normal TLS 1.3 IdP without that override: the same complete login chain.
- Add OIDC through the real administration API with the compatibility setting.
- Invalid JWT signature and audience: no session cookie and bucket access 403.
- Untrusted CA: discovery fails and cluster readiness remains 503.

The affected customer's discovery URL and ingress configuration are still
unavailable. This establishes the supported local fix and its negative
controls, not the root cause or recovery of that hidden deployment. #154 stays
open for an affected-environment retest; no release date or published artifact
is implied by these checks.
