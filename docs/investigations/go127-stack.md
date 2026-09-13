# SILO stack: Go 1.27 compatibility audit

> This is a dated investigation, with the source and runtime boundaries recorded
> below. It does not establish the current dependency pins or a later release.
> See [the current changelog](../../CHANGELOG.md) and
> [component matrix](https://silo.pgsty.com/compatibility/versions/).


2026-09-09. Scope: the maintained Server, silo-pkg, mcli, and Console. This extends
the [OIDC #154 investigation](issue-154.md) to other paths using the same TLS
configuration and to adjacent standard-library changes. It records local
validation performed before commit. No pushes, issue comments, releases, or
production changes were made during the audit.

## Findings and changes

| Component | Finding | Change |
| --- | --- | --- |
| Server, baseline `d1105bbb3d4a0afa33b3a4ac11b821235038ed0e` | Eight TLS configuration sites explicitly use the same ML-KEM-containing curve list, overriding `tlsmlkem=0` in Go 1.27. | Remove the eight assignments and obsolete `TLSCurveIDs` helper. Retain Go defaults in HTTP clients, replication, cloud client-certificate transport, both grid links, etcd, and the S3 listener. Add wire-level regression tests. |
| silo-pkg, baseline `a92c54d` | No built-in explicit PQ curve list. Web environment transport uses defaults; LDAP/OIDC accept caller configuration. | Add a real web-environment TLS regression test and document runtime-default selection. Keep the Go 1.26 library floor. |
| mcli, baseline `fcd5cad8` | S3/Admin transport and alias/TOFU dialer use default curves. No instance of the Server's override bug found. | Add real S3/Admin transport and alias-dialer handshake tests; update Go/TLS upgrade notes. |
| Console, baseline `c103d08ec` | IdP, SILO/STS, Prometheus, and webhook clients share a transport using defaults. The HTTPS listener explicitly uses only P-256. | Add real IdP/SILO-client handshake tests; update Go/TLS upgrade notes. Retain the existing listener policy. |

The Server's general external HTTP transport is also used by OpenID discovery
and JWKS, identity plugins, notification/lambda checks, audit/log webhooks, and
S3 cloud backends. Fixing only the two OIDC callers would leave those other paths
affected. The broader correction supersedes the earlier OIDC-only candidate.

The retained defaults follow Go's implementation rather than duplicating its
`GODEBUG` parser. Go 1.27 explicitly changed the interaction between manually
selected curves and the `tlsmlkem`/`tlssecpmlkem` default controls. See the
[Go TLS release notes](https://go.dev/doc/go1.27#crypto/tls).

With no opt-out, default curves additionally include SecP256r1MLKEM768 and
SecP384r1MLKEM1024. With `GODEBUG=tlsmlkem=0`, hybrid exchanges are disabled for
default-configured TLS throughout the process. This is an intentional change
from the old fixed subset. `GODEBUG=tlssecpmlkem=0` disables just the SecP
hybrids while retaining X25519MLKEM768. TLS versions, cipher-suite policy,
certificate and hostname checks, client certificates, proxies, and HTTP/2 choices are not
relaxed by this patch. No automatic fallback after a TLS error is introduced.

## Reproduction and regression evidence

Before changing product code, the new Server test failed for all five tested
outbound constructors with `tlsmlkem=0`: general external HTTP, internode HTTP,
replication, cloud client certificates, and etcd. The server observed
`[X25519MLKEM768 X25519 P256 P384 P521]` in every case. Both TLS 1.2 and TLS 1.3
peers reproduced the problem. The inbound Server also accepted a PQ-only client
despite the same opt-out.

After the change, those tests pass on darwin/arm64 and linux/arm64. They exercise
20 outbound combinations (five constructors, two peer TLS versions, two debug
settings), plus inbound classical/PQ-only peers with the opt-out enabled and
disabled. The inbound opt-out case rejects a PQ-only peer while continuing to
accept P-256. The etcd test exercises its actual TLS configuration, not an etcd
cluster; the client-certificate test exercises construction/loading, not a full
mutual-authentication service.

The mc, Console, and silo-pkg handshake tests pass without product code changes.
All use a trusted synthetic certificate and inspect a real ClientHello. They
check both disabling and retaining ML-KEM. Console also retains its existing
unknown-CA, hostname, and endpoint-scoping regression checks.

A freshly source-built complete Linux Server then passed three isolated
integration scenarios using the existing synthetic IdP fixture:

| Scenario | Result |
| --- | --- |
| ML-KEM-intolerant IdP + `tlsmlkem=0` | Discovery/JWKS, IAM, Console, and authenticated Admin calls succeed; login 204 and bucket list 200. |
| Normal TLS 1.3 IdP, no opt-out | Same successful login, token exchange, STS, session, and bucket-list chain. |
| Add OIDC to a running Server | Actual Admin API accepts the provider under the compatibility setting. |

Both login scenarios reject modified JWT signatures and a wrong audience: no
session cookie is issued and authenticated bucket access returns 403. Login
currently reports these authentication failures as 500; that existing error
mapping is outside this TLS change. Curl in the same namespace returns HTTP/2
200. The containers use a pre-existing generic Debian image, `--network none`,
and no published ports; no Server or Console image was downloaded or used.

The fixture drives real Console HTTP APIs, not rendered browser interaction.
This is a conditional interoperability reproduction, not proof of the actual
customer ingress behavior. Grid's existing tests pass, but a production-style
distributed TLS cluster, external cloud providers, and real etcd/LDAP/Keycloak
deployments were not exercised. Disabling ML-KEM does not disable new ML-DSA
signature offers and does not repair an ingress that rejects those offers.

## Other Go changes checked

### macOS root certificates: a confirmed upgrade-visible change

Using the same public synthetic CA and `certs.GetRootCAs`, fresh-process probes
produce the following results when `SSL_CERT_FILE` points at that CA and
`SSL_CERT_DIR` points at an empty directory:

| Compiler / main module | CA from environment trusted? | Explicit CA argument trusted? |
| --- | --- | --- |
| Go 1.26.5 / `go 1.26.0` | No | Yes |
| Go 1.27.1 / `go 1.26.0` | No | Yes |
| Go 1.27.1 / `go 1.27.1` | Yes | Yes |

The Go 1.26 module built by Go 1.27 carries
`DefaultGODEBUG=...x509sslcertoverrideplatform=0`; explicitly setting that option
to `1` enables the new behavior. A Go 1.27 application can explicitly set it to
`0` to recover the previous platform behavior. The diagnostic source is
[cert-roots.go](issue-154/cert-roots.go). The consuming application's defaults
apply to library calls as well, so silo-pkg's older `go` directive does not
prevent the behavior in Server, mc, or Console.

This is expected standard-library behavior, not a reason to silently discard
configured CA variables or skip verification. Setting either variable replaces
Keychain trust with on-disk roots and Go's verifier; stale or incomplete paths
can break previously trusted connections. Unset inherited variables to restore
Keychain trust; explicit additional CAs still work. The three application
READMEs and the package README now document this. The package's Windows loader enumerates
the native ROOT store directly and does not call `SystemCertPool`; it does not
inherit this particular new setting. Windows behavior was reviewed in source,
not runtime-tested.

### JSON, HTTP, timers, and other compatibility controls

- **JSON:** checked owned JSON error handling and exercised policy/condition,
  config, and authentication tests. `quick` uses typed `SyntaxError` and
  `UnmarshalTypeError`; no owned decision depending on changed standard JSON
  error text was found. silo-pkg's full suite passes with both Go compilers;
  mc's command and Console's API/auth suites pass under Go 1.27. No broad
  `nojsonv2` opt-out or serialization rewrite is justified by these results.
- **HTTP response closing:** Go 1.27's standard-library drain is bounded at
  256 KiB and 50 ms. mc's actual early-close/cancel regression passes, including
  the compressed S3 Select stream. Existing owned drain helpers can still have
  independent timeout concerns; those are not newly caused by this Go change.
- **ALPN and custom connections:** mc's TLS dialer returns a real `*tls.Conn`;
  its deadline wrapper is on the TCP dial path. No new accidental HTTP/2 opt-in
  from the expanded `ConnectionState` interface support was identified in
  these transports. Console keeps its existing transport policy.
- **Removed switches:** no maintained runtime/config reliance on `tlsrsakex`,
  `tls3des`, `tls10server`, `x509keypairleaf`, or `asynctimerchan` was found.
  Existing explicit cipher policies continue to be explicit. Timer uses in
  package certificate reload and license refresh do not depend on buffered
  timer-channel length/capacity. Unix EOF error changes do not expose a matching
  owned error-type assumption on the reviewed Unix-socket paths.
- **Platform floor:** application READMEs now identify macOS 13 as the minimum
  for Go 1.27 binaries. No Windows, old macOS, or PowerPC runtime claim is made.

## Validation and delivery

- Server: focused TLS tests on macOS and Linux; macOS race run; crypto, HTTP,
  grid, and all `internal/config/...` tests; full Linux Server build and the
  three integration scenarios above.
- silo-pkg: `make test` (lint and full race suite) on Go 1.27.1; full suite on
  Go 1.26.5, preserving the library floor.
- mc: complete `./cmd` suite, including the new TLS test and existing S3 Select
  early-cancel test.
- Console: complete `./api/... ./pkg/...` suites, including identity and STS
  validation and the new handshake tests.

Go lint reports zero issues in all four repositories. Server's optional spelling
check is skipped because `typos` is not installed. Its lint target used the
already-installed matching golangci-lint v2.13.1 after a redundant download was
stopped; mc's lint was rerun serially after the global linter lock prevented the
first concurrent attempt. These tooling retries did not require source changes.

An independent Fable 5.1 Max review reproduced the old-code failures and ran the
new TLS tests with the race detector. Its shuffled mc and Console suites passed.
One shuffled silo-pkg run failed the untouched `certs.TestValidPairAfterWrite`;
that test passed three plain reruns, the same shuffle seed, and the full certs
package rerun. The certs package runs in a separate test binary from the changed
env tests; this was classified as an existing timing flake.

The review also found that committing the diagnostic fixture made rebrand CI
count synthetic IdP paths as product routes. The guard now excludes
`docs/investigations/`; the product compatibility baseline is unchanged.
The full proposed file set passes the guard, and a negative control adding a
product route still fails. After the review corrections, a fresh Linux Server
build passed all three integration scenarios again; the new binary identity and
rerun results are recorded in the evidence file's `post_review_validation`.

All source and dependency choices remain those of the maintained PGSTY stack.
`go.mod` and `go.sum` are unchanged in every repository. The Server uses its
existing pinned Console/pkg/mc modules; the companion changes are tests and
documentation, so no replacement graph or unpublished dependency version is
needed to build the runtime fix.

Validation used separate worktrees for Server, silo-pkg, mc, and Console, leaving
the original repositories and their `main` branches untouched. Build identities,
fixture results, and command outcomes are recorded in
[go127-stack-evidence.json](go127-stack-evidence.json). Absolute paths and branch
names in the captured evidence identify the environment at recording time.
The recorded module graph identifies the dependencies selected for those
builds; `go.sum` also retains checksums for unselected versions. Local image IDs
and temporary paths are historical evidence, not portable setup instructions.
