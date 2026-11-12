# Changelog

## RELEASE.2026-11-12T00-00-00Z

Package version: `20261112000000.0.0`. Publication status and artifacts are
listed in [GitHub Releases](https://github.com/pgsty/silo/releases). This
section covers the changes after the published 20261109 source `d998292387cc`,
adopting Go `1.27.4`, `silo-pkg v3.16.1`, embedded Console `v2.7.2`, and
bundled `mcli 20261112`. See the
[server compatibility notes](https://silo.pgsty.com/compatibility/server/)
for behavior and upgrade boundaries.

- Release checks verify the selected pkg and embedded Console versions and
  match the bundled mcli release to its source module, independently of local
  workspaces, before building release artifacts. Deploy SILO and mcli
  `RELEASE.2026-11-12T00-00-00Z` by default from Helm chart `7.0.5`.
- Replica writes and copies use the destination version's retention, legal
  hold and tags under its mutation lock, verify staged replica content and
  SSE-C/compressed metadata against stored locked versions before committing,
  and prevent newer peer timestamps from weakening unexpired COMPLIANCE
  retention. Cross-pool reconciliation preserves COMPLIANCE protection
  regardless of pool order, while authorized changes to GOVERNANCE retention
  and legal hold remain possible. Local lock revisions advance past stored
  revisions, unaddressed deletes under versioning suspension or excluded
  prefixes enforce Object Lock across single-pool and multi-pool deployments
  and fail closed when versioning or Object Lock metadata cannot be read,
  bucket metadata imports require versioning across prefix exclusions as well
  as suspension, and peer replication-trust headers must be signed with
  header-based SigV4 ([#336](https://github.com/pgsty/silo/issues/336)).
- Tagging proxies (`GET`, `PUT` and `DELETE`) authenticate and authorize every
  present replica, including its stored tags, fail closed on unreadable targets,
  and skip missing replicas caused by replication lag unless all targets are
  absent; active-active `GET` and `HEAD` proxies enforce `s3:ExistingObjectTag`
  and `s3:versionid` before returning peer responses, forward
  `X-Amz-Tagging-Directive: ACCESS` on `HEAD`, gate proxied
  `x-amz-tagging-count` and `X-Amz-Tagging` headers on tag-read authorization
  without emitting duplicate headers, and filter canonical-case peer
  `X-Amz-Object-Lock-*` headers when `s3:GetObjectRetention` or
  `s3:GetObjectLegalHold` is denied. Authenticated unsigned-trailer
  uploads enforce the request time window and header signatures, SigV4 header,
  presigned, streaming and POST policy verifiers bind the credential-scope date
  to the signed request timestamp, streaming trailer readers bound trailer memory
  and surface non-EOF stream errors without hanging on negative
  `X-Amz-Decoded-Content-Length`, and bucket metadata cache loads no longer
  overwrite fresher concurrent updates
  ([#337](https://github.com/pgsty/silo/issues/337),
  [#338](https://github.com/pgsty/silo/issues/338)).
- Object tag and version authorization now applies consistently across read,
  copy, list and archive endpoints: `GetObject`, `HeadObject` and
  `SelectObjectContent` evaluate `s3:ExistingObjectTag` and `s3:versionid`
  (preserving retryable `5xx` server errors for callers authorized by tag
  conditions when storage is unreadable, resolving the 20261109 limitation in
  [#293](https://github.com/pgsty/silo/issues/293) via
  [PR #294](https://github.com/pgsty/silo/pull/294)); `CopyObject` and
  `UploadPartCopy` authorize source `s3:ExistingObjectTag` and `s3:versionid`
  as well as destination `s3:RequestObjectTag` on copied tags; both
  `x-amz-tagging-count` and `X-Amz-Tagging` (`X-Amz-Tagging-Directive: ACCESS`)
  are omitted on `GET`/`HEAD` (including versioned reads, STS sessions,
  presigned/anonymous requests and replication proxies) unless
  `s3:GetObjectTagging` / `s3:GetObjectVersionTagging` (with no explicit `Deny`)
  or signed `s3:ReplicateTags` permits; `ListObjectsV2` / `ListObjectVersions` with `metadata=true` evaluate
  current-object and per-version metadata permissions respectively, using stored tags; and `GetObjectAttributes`,
  tagging handlers (`GET`/`PUT`/`DELETE`) and ZIP `GET`/`HEAD`/member listings
  authorize stored tags and version actions without mutating unindexed archives
  ([#342](https://github.com/pgsty/silo/issues/342)).
- Policy parsing rejects unknown JSON fields, trailing tokens and malformed
  principals across admin IAM policy/user/service-account endpoints, STS
  session policies, IAM imports/replication, bucket policies and bucket metadata
  imports instead of silently accepting empty or wildcard fallbacks. Validate
  the complete imported policy file before applying entries; retain supported
  historical snapshot semantics and explicit null bucket-policy replication
  tombstones. New session policies retain strict resource validation.
- Every explicit version removal in S3 `DeleteObjects`, including in buckets
  without Object Lock, now uses the sequential single-object path to check
  metadata, retention and replication under the mutation lock. Large version
  purges can take longer. Unaddressed deletes that can replace a locked null
  version also use the single-object path; other unaddressed deletes retain
  bulk execution.
- Decommission rescans keys hidden below another key only while source
  versions are actually removed, resolving the 20261109 limitation recorded
  in [#334](https://github.com/pgsty/silo/issues/334)
  ([PR #335](https://github.com/pgsty/silo/pull/335)). Decommission and rebalance
  clean up successfully migrated sibling versions after concurrent deletion
  of another version. Source-removal and final empty verification check every
  online drive and tolerate offline drives within the erasure set's read quorum,
  while rejecting online metadata remnants, corrupt metadata, directory errors
  and drive outages beyond parity. Cancellation returns an error, and a scan
  without physical progress stops. Free-version tier ownership and the final
  physical-empty check remain protected
  ([#340](https://github.com/pgsty/silo/issues/340)). See the
  [decommission procedure](https://silo.pgsty.com/operations/deployments/baremetal-decommission-server-pool/).
- Site-replication bucket healing, metadata healing, status collection and
  replication hooks snapshot site topology and release the state read lock
  before storage I/O and peer RPCs, avoiding deadlocks and state-map races
  when a configuration writer is waiting
  ([#341](https://github.com/pgsty/silo/issues/341)). IAM import preserves
  disabled service accounts and groups, reports group failures, and excludes
  derived session-policy claims from exported and replicated credentials
  ([#345](https://github.com/pgsty/silo/issues/345)).
- Lifecycle history revision counting treats old and healed `xl.meta` headers
  for the same version as one revision ([#332](https://github.com/pgsty/silo/issues/332)),
  and restore expiry no longer turns a time-derived data-directory flag into a
  different version revision; mixed healed headers can reach quorum and expired
  local restore data can be cleaned up ([#344](https://github.com/pgsty/silo/issues/344)).
  Historical-version self-copy plans its destination pool and data rewrite
  before encryption or compression, preserving multi-block compression seek
  indexes so a source version in another pool creates a readable new version.
  In-place metadata updates locate the exact requested version and preserve
  authoritative content on moving pools, while copies that require encryption
  or checksum recomputation select an active pool
  ([#343](https://github.com/pgsty/silo/issues/343)). Indexed `Range` reads into
  compressed, server-side encrypted (`SSE-S3`, `SSE-KMS`, `SSE-C`) objects also
  succeed when the target compressed block starts inside the first 64 KiB
  encrypted frame (`decryptSkip > 0`), without rewriting stored objects.
- Batch KMS rotation decodes and validates the configured encryption context
  as strict UTF-8 JSON before changing an object key and without adding
  validation-probe fields to object metadata, supports `SSE-S3` to `SSE-KMS`
  key migration and multipart metadata preservation, and rewrites legacy `XLV1`
  objects onto `XLv2` streams instead of failing in-place metadata updates
  ([#346](https://github.com/pgsty/silo/issues/346)). Incoming HTTP
  `X-Amz-Server-Side-Encryption-Context` headers on `PutObject`, `CopyObject`,
  `CreateMultipartUpload` and browser `POST` uploads reject empty values,
  malformed Base64/UTF-8/JSON, trailing tokens and non-string/non-`null` member
  values with `400 InvalidArgument` instead of `500 InternalError`. Batch variable
  preflight follows the pinned policy evaluator's literal and substitution
  rules, including BinaryEquals, while retaining refusal of unavailable
  request context. This does not add AWS special-variable escape semantics
  ([#347](https://github.com/pgsty/silo/issues/347)).
- Service-account and access-key create/edit normalize a missing policy Version
  to `2012-10-17`, reject malformed or unknown policy fields, and distinguish an
  omitted or `null` policy (preserve existing inline policy) from an explicit
  empty policy document such as `{}` or `{"Statement":[]}` (reset to parent
  inheritance), while keeping historical deny-all accounts carrying an empty
  embedded policy restricted until explicitly reset
  ([#339](https://github.com/pgsty/silo/issues/339),
  [Console #89](https://github.com/pgsty/silo-console/issues/89),
  [mcli #78](https://github.com/pgsty/mc/issues/78)). Previously,
  `mcli admin user svcacct disable`, `enable` and `edit` without `--policy`,
  the matching `admin accesskey` and `idp ldap/openid accesskey` commands, and
  any other `update-service-account` request without `newPolicy` removed the
  inline policy on the receiving site and on site-replication peers for
  non-root parent users. In the matching Console (`v2.7.2`), turn off **Restrict
  beyond user policy** or enter `{}` to remove an inline policy; clearing the
  editor while restriction is enabled prevents saving, save errors render inside
  the edit modal, and HTTP-to-HTTPS browser redirects preserve the request host
  or `CONSOLE_SECURE_TLS_HOST` when bound to `--host 0.0.0.0`
  (`unrolled/secure v1.18.0`). Freeze service-account edits on un-upgraded
  `20261109` nodes during rollout; after upgrading every site, review accounts
  that `svcacct info` reports with `Policy: implied` and re-apply restrictions
  where needed.

- S3 `DeleteObjects` on a single pool stops at an entry whose name fails the
  object name check: the entry returns `XMinioInvalidObjectName` and is not
  locked or sent to a drive, as with a single-object DELETE and with more than
  one pool. Until now such an entry still reached the drives of the node, where
  a name with a `..` segment was joined to the request bucket. A caller allowed
  to delete in one bucket could remove a version in another bucket, including
  one under Object Lock retention, and from a versioned bucket could put a
  delete marker on an object of another bucket or on stored system metadata
  such as a bucket's configuration. The other entries of a request are deleted
  as before.

- Site replication sends a service account or access key as the record its
  site has stored, whole: for a create, for every edit, at the first sync of a
  new site and when healing. IAM export writes that record too. Until now an
  edit was sent as the fields it changed. A peer that an earlier edit had not
  reached, or reached late, kept the old secret key, status or inline policy
  under the revision of the later edit, and healing took the sites for equal:
  a key that was rotated, disabled or restricted on one site stayed as it was
  on the other. Sync, heal and export took the claims and the inline policy, and
  heal the secret key and status as well, from the cache of the server that ran
  them, which can predate an edit made through another server of the site, and
  sent them under the revision of the stored record. A service account created
  for a user that had been deleted and created again did not reach the peers
  before healing. Peers on 20261109 and 20261026 apply the new items as they
  apply a healed account, and an edit that names no policy no longer removes the
  inline policy on such a peer; a site that is not upgraded still sends its own
  edits the old way. An edit now gives every site the whole account of the site
  that took it, so accounts that already differ between sites are not repaired
  by the upgrade, but by the next edit: after upgrading every site, review such
  accounts and edit each one at a site that has it right.

## RELEASE.2026-11-09T00-00-00Z

Package version: `20261109000000.0.0`; published from source `d998292387cc`.
Artifacts are listed in the [GitHub release](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-11-09T00-00-00Z).
The coordinated [English release notes](https://silo.pgsty.com/blog/release/silo-20261109/)
and [Chinese release notes](https://silo.pgsty.com/zh/blog/release/silo-20261109/)
cover all components, upgrade guidance, and validation scope since the
published 20261026 source `c3ad836aed0d`. Most fixes come from reports and
patches by [@botdeniska](https://github.com/botdeniska); see [CONTRIBUTORS.md](CONTRIBUTORS.md).

Lifecycle, multi-pool and tiering:

- Decide an ILM expiry under the object lock against the versions of the key
  in all pools, and refuse one that does not hold for the whole object or whose
  history or lock protection lacks an authoritative quorum. Decommission and
  rebalance move such versions instead of dropping them, and an approved
  version expiry deletes every copy ([#278](https://github.com/pgsty/silo/issues/278)).
- Expire the restored copy of a current version instead of the object
  ([#281](https://github.com/pgsty/silo/issues/281)). Keep lifecycle delete-all
  (`ExpiredObjectAllVersions`, `DelMarkerExpiration`, batch expiration with
  `retainVersions: 0`) on the expired key instead of the keys below it; a key
  with a tiered or Object Lock protected version is refused
  ([#297](https://github.com/pgsty/silo/issues/297)).
- Exclude the internal free-version marker of a deleted tiered version from
  visible version history and lifecycle decisions
  ([#263](https://github.com/pgsty/silo/issues/263)), apply rules whose only
  action is `DelMarkerExpiration` ([#268](https://github.com/pgsty/silo/issues/268)),
  and report and account only the removals that happened
  ([#305](https://github.com/pgsty/silo/issues/305)).
- Keep remote tier data that another pool still references after a version
  expiry or tier cleanup ([#306](https://github.com/pgsty/silo/issues/306),
  [#308](https://github.com/pgsty/silo/issues/308)). Heal versions whose queued
  expiry is refused ([#303](https://github.com/pgsty/silo/issues/303)), and read
  a key's history once in migration prechecks ([#304](https://github.com/pgsty/silo/issues/304)).
- Decommission and rebalance: move objects whose copies have two erasure
  layouts ([#261](https://github.com/pgsty/silo/issues/261)) and ILM-expired
  current versions ([#265](https://github.com/pgsty/silo/issues/265)), continue
  with later buckets when one cannot finish and keep cancellation
  ([#307](https://github.com/pgsty/silo/issues/307)), and do not panic when a
  rebalance stop finds no metadata ([#270](https://github.com/pgsty/silo/issues/270)).
- Do not replicate the delete markers and version purges that lifecycle
  creates, as in S3. [PR #240](https://github.com/pgsty/silo/pull/240) remains
  open as a proposal.

Native restore:

- Restore in two phases, without holding the object write lock during the tier
  download ([#284](https://github.com/pgsty/silo/issues/284)). Restores with more
  than one pool no longer hang, stay in progress or change the restored version
  ([#289](https://github.com/pgsty/silo/issues/289)), and a failed ordinary
  multipart completion stays usable ([#327](https://github.com/pgsty/silo/issues/327)).
  A failed or canceled restore returns at once and clears its marker in the
  background, instead of waiting up to a minute for the object lock.

Locking, conditional writes and storage:

- Lock every write and delete of a single pool in the object's own erasure set
  ([#298](https://github.com/pgsty/silo/issues/298)). Fix CopyObject waiting on
  its own lock for normalized aliases ([#299](https://github.com/pgsty/silo/issues/299))
  and starving its destination while waiting for the source
  ([#300](https://github.com/pgsty/silo/issues/300)); delete the set groups of a
  bulk delete concurrently ([#301](https://github.com/pgsty/silo/issues/301)).
- Evaluate `If-Match` and `If-None-Match` of a multi-pool CreateMultipartUpload
  against the current object ([#291](https://github.com/pgsty/silo/issues/291),
  [PR #292](https://github.com/pgsty/silo/pull/292)).
- Answer a retryable `503` instead of `NoSuchKey` when a node sees only some
  drives of an existing object ([#302](https://github.com/pgsty/silo/issues/302)), remove the empty object
  directory of a failed write ([#285](https://github.com/pgsty/silo/issues/285),
  [PR #286](https://github.com/pgsty/silo/pull/286)), classify `xl.meta`
  checksum failures for healing ([#309](https://github.com/pgsty/silo/issues/309)),
  and keep a heal dry run from deleting data
  ([PR #280](https://github.com/pgsty/silo/pull/280), thanks to
  [@dihmandrake](https://github.com/dihmandrake)).

Object Lock, IAM and batch jobs:

- Keep the target's legal hold and retention on a replicated delete; a source
  purge that bypassed GOVERNANCE retention is refused by a target copy that
  still carries it, and the source retries. Check a directory object's lock
  before a bulk delete removes its null version. S3 `DeleteObjects` checks
  physical version removals under the mutation lock and merges protection
  across pools, including concurrent legal-hold and retention updates. These
  removals in Object Lock buckets use the single-object path sequentially;
  large version-purge batches can take longer. Marker creation and ordinary
  buckets retain the bulk path.
- Batch jobs enforce the submitter's data permissions throughout execution and
  leave Object Lock protected versions alone ([#310](https://github.com/pgsty/silo/issues/310),
  [#311](https://github.com/pgsty/silo/issues/311)). Key rotation keeps other
  pool copies readable ([#312](https://github.com/pgsty/silo/issues/312)).
  Transient failures pause work instead of ending it, saved jobs are found
  after a failed startup scan, and running replication resumes
  ([#313](https://github.com/pgsty/silo/issues/313), [#314](https://github.com/pgsty/silo/issues/314),
  [#324](https://github.com/pgsty/silo/issues/324)). A completed expiration job
  stays completed after a restart ([#315](https://github.com/pgsty/silo/issues/315)).
  Authorization skips deleted policies a mapping still names, refuses a job
  only for a Deny that needs request context, and survives metadata edits and
  LDAP refreshes that keep the credential
  ([#318](https://github.com/pgsty/silo/issues/318)–[#320](https://github.com/pgsty/silo/issues/320)).
  Live metrics keep pause reasons and skipped or refused counts
  ([#325](https://github.com/pgsty/silo/issues/325)), and `make check-gen`
  leaves the runtime policy snapshot alone ([#326](https://github.com/pgsty/silo/issues/326)).
- IAM refuses incomplete policy loads, keeps cached authentication available
  during lazy loads, and applies edits, LDAP group refreshes and service-account
  creation to the stored record, so a stale node cannot restore old credentials
  or resurrect deleted identities ([#316](https://github.com/pgsty/silo/issues/316),
  [#317](https://github.com/pgsty/silo/issues/317), [#321](https://github.com/pgsty/silo/issues/321)–[#323](https://github.com/pgsty/silo/issues/323)).
- Log in LDAP users with long DNs on erasure sets, and root to the embedded
  Console with LDAP enabled ([#271](https://github.com/pgsty/silo/issues/271),
  [#272](https://github.com/pgsty/silo/issues/272)). Keep audit and logger
  webhook targets running on every server after a configuration reload
  ([#259](https://github.com/pgsty/silo/issues/259), reported by
  [@haf](https://github.com/haf)).

Components and packaging:

- Embed the published Console v2.7.0 source `4e91ae506e70`, including its
  ten-language UI, rebuilt frontend assets, Swagger array-validation fixes,
  Redoc routing, plain-HTTP folder-size and key-copy actions, usage-worker TLS
  roots and scan budgets, and malformed-multipart rejection. Select the
  published mcli 20261109 source `e1d4cc5abfe0` and silo-pkg v3.16.0 directly
  in the maintained dependency graph.
- Adopt go-jose/v4 v4.1.9, cpuid/v2 v2.4.2, YAML v3.0.6 and gjson v1.20.1,
  plus Console's runtime/server-middleware v0.33.4. Preserve Go 1.27.3, the
  verified upstream minio-go commit, networking/crypto security floors and
  terminal-width/NetBSD compatibility selections.
- Update NATS credentials to jwt/v2 v2.8.3 and nkeys v0.4.17, including
  rejection of identity-point and small-order public keys. Use nats-server
  v2.15.2 for notification integration tests.
- Update Google Cloud auth to v0.24.3 and oauth2adapt to v0.3.1 for REST
  request validation and AWS FIPS endpoint signing fixes.
- Bundle verified mcli 20261109 archives in source container builds and use
  that release by default in the integration-test client installer.
- Prevent replication worker metrics from panicking when the replication
  pool is absent, while retaining historical averages and peak counts.
- Give the distroless image the same CA roots as the standard image, and ship
  mcli's license files in both ([#295](https://github.com/pgsty/silo/pull/295)).
- Deploy SILO and mcli `RELEASE.2026-11-09T00-00-00Z` by default from Helm
  chart 7.0.4; the server image tag was left at 20260916 before
  ([#296](https://github.com/pgsty/silo/issues/296)).

Upgrade notes:

- A single pool whose erasure sets do not all use the same hosts (with the
  automatic layout, 18 or more hosts) needs a drained restart, not a rolling
  upgrade: old and new nodes lock deletes and copies in different sets and do
  not exclude each other. Stop every old process before a new one serves.
- During a rolling upgrade, upgraded nodes answer `POST ?restore` with `503`
  while any peer is old or unreachable. Pause new restores until every node is
  upgraded. Multi-pool lifecycle protection is complete only after a full
  upgrade.
- Stop batch submissions and drain or cancel unfinished jobs before changing
  versions. Unfinished legacy jobs require resubmission after all nodes upgrade;
  completed jobs stay completed. Submitter-bound manifests and progress reports
  use a new format that 20261026 cannot execute or resume. Do not downgrade
  with pending or paused new jobs. An old node can still execute old-format
  jobs, so mixed-version execution is not protected by the new authorization
  rules. Preserve job definitions and reconcile completed work before resubmitting.
- `healthcheck ready` remains a process/dependency probe and can succeed before
  storage or IAM load. `cluster` reports quorum, which can precede a restarted
  node reconnecting its remote drives. Before resuming applications, run bounded
  signed write/read checks through every node; neither HTTP probe alone proves
  data-path readiness. Preserve peer discovery during bootstrap.
- `helm upgrade --reuse-values` keeps the previously stored `image.tag`; set it
  explicitly when upgrading such a release.

Known issues: `ListMultipartUploads` prefix and paging
([#79](https://github.com/pgsty/silo/issues/79)), multi-site delete-marker purge
([#217](https://github.com/pgsty/silo/issues/217)), replayed bucket creation
under site replication ([PR #241](https://github.com/pgsty/silo/pull/241)), and
`403` instead of the server error for reads allowed only by object tags while
the object is unreadable ([PR #294](https://github.com/pgsty/silo/pull/294)).

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
