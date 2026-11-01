# Changelog

## RELEASE.2026-10-26T00-00-00Z

Package version: `20261026000000.0.0`; published from source `c3ad836aed0d`.
Artifacts are listed in the [GitHub release](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-10-26T00-00-00Z).
The coordinated [English release notes](https://silo.pgsty.com/blog/release/silo-20261026/)
and [Chinese release notes](https://silo.pgsty.com/zh/blog/release/silo-20261026/)
cover all components, upgrade guidance, and validation scope.

- Fix LDAP login for long normalized DNs without hiding unreadable IAM
  revocation records. Only length errors for valid keys with an ASCII path
  component over 255 bytes are treated as absent; long-DN writes still fail.
  Thanks to [@910patin](https://github.com/910patin) for the original fix and
  reproduction in [#250](https://github.com/pgsty/silo/pull/250).
- Build the server and standalone debugging tools with Go 1.27.3 and refresh
  Go dependencies, including silo-pkg v3.15.2, mcli 20261026
  and upstream minio-go `320af050c445` for multipart, read/seek,
  batch-delete and bucket-replication removal fixes. Retain output-format and NetBSD compatibility selections.
- Embed Console v2.5.1 source `fff1618d9abb`, including its GUI update,
  diagnostic WebSocket closing handshake, complete health-report decoding,
  group-membership preservation, OIDC group permissions, TLS-proxy session
  cookies, credential exports and accessibility fixes.
- Bundle mcli 20261026 in container builds, the verified client installer and
  Helm client jobs. Include client identity isolation, resync status and rate
  fixes, and bounded batch-status fallback. Scripts must handle the additive
  batch `pending` state and nonzero exits for partial resync mutations.
- Read current bucket inventory in account-info responses so Console refreshes
  immediately reflect successful creation and deletion. This management endpoint
  now performs a live list instead of returning a cached inventory.
- Restore the native built-in policy immediately after resetting an override.
  Peer and etcd notifications reload committed state, so delayed delete events
  preserve subsequent edits. Keep deletion revisions, policy-in-use checks and
  custom-policy deletion behavior; storage failures retain the previous policy.
- Reload policies without holding the authentication-cache lock, retain IAM
  write ordering and publish replacements only after a complete successful load.
  Propagate cancellation through IAM/KMS and SSE-S3 decryption without shortening
  the caller's policy-query deadline.
- Preserve authoritative copies when a multi-pool delete or bulk cleanup fails,
  choose an available pool for a new delete marker, and keep tier data referenced
  by surviving copies. This does not introduce strict cross-pool read recovery.
- Preserve remote tier data when lifecycle expiry only adds a delete marker,
  including non-null versions in suspended buckets. Forward `FULL_OBJECT`
  checksum type for multipart replicas. Thanks to
  [@botdeniska](https://github.com/botdeniska) for these lifecycle, replication
  and multi-pool deletion contributions.
- Preserve Kafka's default broker protocol 2.1 and terminal-width behavior;
  fix legacy DARE v1 key unsealing and verify DARE v1/v2 and MinKMS TLS compatibility.
- Forward storage RPC delete options, including the previous data directory
  needed by overwrite rollback. Preserve existing drive/RPC timeouts, request
  cancellation, object locking, read-quorum and healing behavior.
- Update bundled curl to 8.23.0 and require patched static libraries. Apply
  [Red Hat's compromised-CA mitigation](https://access.redhat.com/security/vulnerabilities/RHSB-2026-012);
  the root blocklist also rejects legitimate chains under the affected roots.
- Ship Windows platform archives as ZIP; Linux and macOS retain tar.gz.

Storage timeouts retain their existing meaning: a returned timeout does not
prove that the underlying disk operation stopped or that a write did not
commit. Late commits or delayed rollback can affect newer writes; stale reads
remain possible after partial failures, lease loss or network partitions. This
release does not provide distributed fencing or repair previously inconsistent
objects.

These source changes are not included in the published 20261018 artifacts.

## RELEASE.2026-10-18T00-00-00Z

Package version: `20261018000000.0.0`; published on 2026-10-18 from source
`0cd388c666f8211f552604ae73448a066e9c25ce`. This section covers the changes
after the public 20260916 source, `2a4d51406b7ed87af5fe6fe0f801f3290f96eb3c`.

Full [English release notes](https://silo.pgsty.com/blog/release/silo-20261018/)
and [Chinese release notes](https://silo.pgsty.com/zh/blog/release/silo-20261018/)
cover the upgrade contract, evidence and remaining limits.

- **Object Lock (#234, #235):** require `s3:PutObjectRetention` with request-body
  conditions before object lookup; weakening active GOVERNANCE additionally
  requires bypass intent and permission. Protect caller-addressed write versions,
  directory null versions and persisted multipart targets under the write lock;
  fail closed on unreadable lock state. See SN-2026-015/016 in the
  [advisory ledger](https://silo.pgsty.com/about/security-advisories/).
- **IAM Admin authorization (#242, `995439260`):** enforce explicit self denies,
  session restrictions and plugin decisions; prevent restricted delegation and
  non-root mutation of root-derived credentials under built-in authorization.
  Preserve empty-policy inheritance and damaged-key cleanup. Normalize bulk
  self-list aliases and allow ordinary policyless self inspection. See
  [SN-2026-017](https://silo.pgsty.com/blog/security/20261018-release-hardening/#sn-2026-017).
- **Scoped STS revocation (`0cd388c66`):** enumerate durable parent/type-selected
  tokens, propagate each committed tombstone to sibling nodes and sites, and
  recover missed notifications through existing refresh/healing. Tokens issued
  only at an isolated site are outside the requesting cluster's snapshot;
  propagation is eventual and newly issued keys remain valid.
- **Pool migration (#248, `60c7179dd`, `1748f62c7`):** prevent stale moved
  payloads from overwriting newer copies, preserve null/UUID delete markers,
  recheck source versions and clean only confirmed moved versions under the
  object lock. Added per-pool reads and per-version cleanup have maintenance
  costs; earlier data loss is not reconstructed.

- **LIST recovery (#239, `3dd53eb81`, `2080b3d03`):** confirm eligible uncertain
  latest-object groups under the appropriate read locks, distinguish absence
  from failure, preserve directory/common-prefix entries and terminal pagination
  errors, and make lock backoff cancelable. Resolved entries keep their fast path;
  version history, quorum and disk formats retain their contracts. The strict
  sub-5% performance target remains unconfirmed in the recorded comparison.
- **Multipart listing (`4733e1423`):** withdraw #243's default persistent scan.
  Public listing uses node-local cache or exact-key lookup; restart omissions,
  prefix and cache-pagination limits remain. The retired strict switch is ignored
  with a startup warning. **Former strict users lose durable listing and strict
  cancellation.** Keep identity metadata, path/wrong-target safety, default
  best-effort Abort and peer notification. Diagnostic `multipart-preflight`
  reports `mode=legacy`; its budgets do not gate public operations. #79 remains
  open, including delayed creation after cancellation.
- **Multipart cleanup (#236, `0f9199e0c`):** parse native timestamps before the
  Base64 fallback and remove empty hash parents without a second expiry wait.
  Keep active/unreadable uploads; default expiry/check intervals stay 24h/6h.
- **Commit errors (#232):** missing staged `xl.meta` at final commit becomes
  HTTP 503 `SlowDownWrite`; preserve this classification across storage RPC and
  healing. Real incomplete bodies retain their existing errors.
- **Reused metadata (#233):** clear absent legacy `EcM`/`Signature` and locally
  reset mutually exclusive scanner response fields without changing disk/RPC formats.
- **Checksum and Console errors (#225, #229, #238):** align Content-MD5 and
  algorithm-specific messages, retaining the generic unknown-algorithm message;
  embed Console's wrapped-error and `InvalidBucketState` handling.
- **Lambda and erasure documentation (#220, `2fde3cf53`):** fix inverted
  `TargetIDSet.IsEmpty`; document parity/quorum per object and erasure set.
- **Coordinated dependencies:** Console v2.4.2 (`ef2dd2c41d21`), mcli 20261018
  (`fa3b8bf72458`), silo-pkg v3.14.3, upstream minio-go v7.4.1 and Go 1.27.2.
  Standalone Console/mcli still declare pkg v3.14.2. The Server package update
  speeds admin-action classification without changing policy behavior. Refresh
  Go x/*, go-jose v4.1.6, LDAP v3.4.15, compress v1.20.3, msgp v1.6.5, etcd v3.7.2,
  fwd v1.2.1 and cpuid v2.4.1. OIDC RSA JWKs above 4096 bits are rejected.
  Keep the NetBSD go-systemd v22.6.0 replacement; parallel SDK GET/Compose remain opt-in.
- **Build and delivery:** gate releases on Object Lock regressions; use
  Git for rebrand scanning without a ripgrep dependency (`7007c164a`). Refresh UBI 9 pins,
  GoReleaser v2.18.3, nFPM v2.48.0, golangci-lint v2.15.0 and govulncheck v1.9.0.
  Update bundled client hashes/helper and the Helm client image to mcli 20261018.
  The chart's Server default stays at the public 20260916 image until publication.

Upgrade every writer and replication site; follow the
[IAM recovery guide](https://silo.pgsty.com/operations/replication/iam-upgrade/).
Old strict multipart users must review the capability loss before upgrading.
#217's multi-site delete-marker late creation and crash residue remain unresolved.
Source tests, draft artifacts, public images and production rollout are separate
acceptance boundaries; historical 20261015 test counts do not certify this source.

## RELEASE.2026-09-16T00-00-00Z

Package version: `20260916000000.0.0`; published source:
`2a4d51406b7ed87af5fe6fe0f801f3290f96eb3c`.

This release includes signed-header and payload-policy hardening (SN-2026-011/012),
durable IAM revocations (SN-2026-013), the bounded Console sharing proxy
(SN-2026-014), password-permission separation, multi-pool conditions/deletion/tag
repairs, encrypted/federated copy repairs, delete-marker retry fixes, opt-in strict
multipart discovery, Go-default TLS key exchange, absolute HTTP/1 header deadlines
and synchronized CPU metrics. It embeds Console v2.4.1, mcli 20260916 and pkg v3.14.1.

The complete release, contributor credits, historical artifact acceptance and
upgrade requirements are preserved in the canonical
[English](https://silo.pgsty.com/blog/release/silo-20260916/) and
[Chinese](https://silo.pgsty.com/zh/blog/release/silo-20260916/) release records.

## RELEASE.2026-09-03T13-18-01Z

Published source: `9b11dc9469e650815b775cb47b039610644f5da4`.
[Complete release notes](https://silo.pgsty.com/blog/release/silo-20260903/) ·
[GitHub release](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-09-03T13-18-01Z)

This release ships Go 1.27.1, silo-pkg v3.13.2, upstream minio-go `0e78d3f18efe`,
mcli 20260903 and embedded Console source `464a59d73ada` (v2.3.0 version identity).
Installing the newer standalone mcli or Console does not replace components
inside this existing Server binary or image.

Earlier releases: [release archive](https://github.com/pgsty/silo/releases).
