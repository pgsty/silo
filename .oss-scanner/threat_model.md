# PGSTY Silo security scope

Silo is PGSTY's independently maintained S3-compatible object-storage server,
derived from MinIO. It serves untrusted network requests and stores user data,
including PostgreSQL backups. Scan the current `pgsty/silo` `main` branch.
Read `/src/SECURITY.md`, `/src/VULNERABILITY_REPORT.md`, and `/src/CHANGELOG.md`.

## Repository boundaries and lineage

The Go module intentionally remains `github.com/minio/minio`. Historical
`MINIO_*` environment variables, S3 headers, `/minio/*` routes, and `.minio.sys`
storage names are compatibility interfaces, not evidence that upstream MinIO
is the target. Use this checkout's code and dependency versions for reproducers.

This enrollment covers the server code, including inherited code still present
in the supported branch and its PGSTY changes. The maintained Console, client,
and shared packages appear as dependencies in `go.mod`. Do not replace them
with upstream releases. They are not additional independent scan targets under
this enrollment. A server-side integration defect is in scope; clearly identify
a dependency-only root cause rather than attributing it to this repository.

## Attackers and important surfaces

- Unauthenticated S3/HTTP clients, including hostile object names, headers,
  query parameters, XML/JSON bodies, signatures, and multipart data.
- Authenticated users, service accounts, and temporary STS credentials whose
  authority must remain bounded by the effective IAM and bucket policies.
- Bucket owners and delegated administrators with explicitly limited actions;
  distinguish them from the unrestricted deployment/root administrator.
- Inputs from configured identity providers, replication/tiering targets, and
  webhooks where the configuration and permissions make an attack reachable.

Prioritize authentication/signature verification, IAM/STS and policy
composition, administrative API authorization, object/version isolation,
Object Lock retention and legal holds, multipart operations, replication,
lifecycle/tiering, and multi-pool deletion/migration. Include archive, XML,
JSON and S3 Select parsing when remotely reachable. Investigate credential
exposure, path traversal, unauthorized object access, SSRF across a meaningful
boundary, and attacks that corrupt or irreversibly delete other users' data.

The deployment administrator controls root credentials, storage directories,
trusted peers, and identity/KMS/replication endpoint configuration. Host root
access, stolen root credentials, or a malicious replacement of the server
binary do not by themselves demonstrate a vulnerability. An unprivileged
account gaining those capabilities does. An administrator's documented ability
to configure an outbound endpoint is not sufficient evidence of SSRF; show
an unauthorized actor, forbidden destination, or confused-deputy effect.

Object Lock has explicit retention semantics. Do not discard a retention bypass
just because the caller has some administrative permission: describe the mode,
version, legal hold, and exact IAM actions, and compare with the intended rules.
Likewise, do not assume bucket access implies access to other buckets or users.

Known consistency limitations are described in `CONTRIBUTING.md` and the
changelog. Tests tagged `consistency_strict` exercise stronger guarantees
outside the current maintenance contract and can fail. A failing diagnostic
alone is not a new vulnerability; demonstrate a reachable security impact.
These limitations do not excuse an authorization or retention bypass.

## Offline environment

Source is in `/src`; the unstripped server is `/usr/local/bin/silo`. Go, the
module cache, and the test build cache are retained. The scanner adds Git
history to `/src/.git` after building this image; a plain Docker build omits it.
The Dockerfile compiles the server and tests with the selected PGSTY dependency
replacements. `GOTOOLCHAIN=local` and `GOPROXY=off` prevent surprise downloads.
CGO is disabled as in the normal server/unit-test CI; enable it explicitly for
race tests when needed (the Go base image includes a C compiler).

Useful offline checks:

```sh
cd /src
silo --version
go test -tags kqueue,dev ./internal/auth ./internal/config/identity/... ./internal/s3select/... -count=1 -timeout=10m
go test -tags kqueue,dev ./cmd -run '^(TestGetRequestAuthType|TestS3SupportedAuthType|TestIsReqAuthenticated|TestCheckAdminRequestAuthType|TestValidateAdminSignature|TestDoesPolicySignatureMatch|TestDoesPresignedSignatureMatch|TestDoesPresignedV2SignatureMatch|TestSTSLDAPLogin.*|TestGetSTSLDAPLoginSourceIP.*)$' -count=1 -timeout=10m
```

For HTTP reproducers, start a disposable loopback server with synthetic
credentials and a fresh data directory:

```sh
MINIO_ROOT_USER=scanneradmin MINIO_ROOT_PASSWORD=scanner-local-test-only \
  silo server /tmp/silo-scanner-data \
  --address 127.0.0.1:9000 --console-address 127.0.0.1:9001
```

The broader suites are `go test -tags kqueue,dev ./internal/... -timeout=15m`
and `go test -tags kqueue,dev ./cmd -timeout=30m`. Some integration suites need
LDAP, OIDC, etcd, KMS, multiple servers, or IPv6; those services are not started
by this Dockerfile. Do not treat a missing external service as a security
finding. The focused commands above do not require those providers.

## Reports and severity

Include the commit, exact attacker privileges/policy, relevant deployment
settings, API requests or a standalone test, observed impact, and affected
versions where established. For data-loss or cross-pool reports, include the
object/version state and a deterministic sequence. Deduplicate by root cause
and distinguish a new flaw from an already documented limitation or fixed bug.

Unauthenticated code execution or broad credential/authorization compromise
can be critical. Cross-user object access, unauthorized destructive operations,
and retention bypass can be high or critical according to their demonstrated
reach. Rate availability issues by practical cost, scope and recovery; a
single malformed request and an authorized full-disk upload are different
threats. Do not claim exploitability solely from a static pattern.

Prefer minimal patches and regression tests that preserve S3/storage format
compatibility. Use only synthetic data and local test instances; do not test
against public Silo/MinIO deployments or real backup repositories.

## Maintaining the scanner image

Build from the repository root, then run the checks above without networking:

```sh
docker build -f .oss-scanner/Dockerfile -t silo-scanner:local .
docker run --rm -it --network=none silo-scanner:local bash
```

Keep the Go image version aligned with `go.mod`. The adjacent
`Dockerfile.dockerignore` preserves compressed test fixtures that the release
image's root `.dockerignore` excludes. Local build outputs, editor state, and
private working directories are excluded from the scanner context.

Enrollment lives in `anthropics/oss-scanner`, under `projects/silo/project.yaml`.
Once these files are published on `main`, that configuration can use
`dockerfile: .oss-scanner/Dockerfile` and
`threat_model: .oss-scanner/threat_model.md`; remove its adjacent copies in the
same update. Do not switch the enrollment paths before the files are public.
