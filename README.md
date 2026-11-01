<h1 align="center">
  <a href="https://silo.pgsty.com/">
    <img src=".github/silo-logo.svg" alt="Silo" width="160">
  </a>
</h1>


<p align="center">
  <strong>S3-compatible object storage — a MinIO fork maintained by PGSTY</strong>
</p>


<p align="center">
  <a href="https://silo.pgsty.com/">Website</a> ·
  <a href="https://silo.pgsty.com/docs/">Documentation</a> ·
  <a href="https://silo.pgsty.com/download/">Download</a> ·
  <a href="https://silo.pgsty.com/tags/silo/">Release Notes</a> ·
  <a href="https://silo.pgsty.com/compatibility/server/">Compatibility</a> ·
  <a href="https://silo.pgsty.com/about/manifesto/">Manifesto</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="README_ZH.md">中文</a>
</p>

<p align="center">
  <a href="https://silo.pgsty.com/"><img alt="Website" src="https://img.shields.io/badge/Website-silo.pgsty.com-1d588c"></a>
  <a href="https://github.com/pgsty/silo/releases"><img alt="GitHub Release" src="https://img.shields.io/github/v/release/pgsty/silo?include_prereleases&label=release&logo=github"></a>
  <a href="https://hub.docker.com/r/pgsty/silo"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/pgsty/silo?logo=docker"></a>
  <a href="go.mod"><img alt="Go Version" src="https://img.shields.io/github/go-mod/go-version/pgsty/silo?logo=go"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-AGPLv3-blue"></a>
</p>

> [!IMPORTANT]
> **PGSTY Silo** (hereinafter “Silo”) is an independent, community-maintained fork of the open-source MinIO server, published by [Pigsty](https://pigsty.io) from [`pgsty/silo`](https://github.com/pgsty/silo). It is not affiliated with, endorsed by, or sponsored by MinIO, Inc. “MinIO” is used only to identify the upstream project and compatibility lineage.

> [!NOTE]
> Renamed from `pgsty/minio` to `pgsty/silo`, default branch `master` → `main`, on 2026-08-06. Artifacts under the original MinIO identity stay published on the archived [`minio`](https://github.com/pgsty/silo/tree/minio) branch and in releases up to [`RELEASE.2026-08-04T00-00-00Z`](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-08-04T00-00-00Z).

## SILO 20261026000000

[SILO 20261026000000](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-10-26T00-00-00Z) is available as platform archives, Linux packages, and standard or distroless Docker images for amd64 and arm64. The release tag is `RELEASE.2026-10-26T00-00-00Z`; the package version is `20261026000000.0.0`, built from source `c3ad836aed0d`.

This release fixes LDAP long-DN login, IAM policy refresh, multi-pool deletion safety, tiered-object expiry, multipart replication checksums, and remote rollback-option propagation. It embeds Console v2.5.1 (`fff1618d9abb`) and uses silo-pkg v3.15.2, Go 1.27.3, and upstream minio-go `v7.4.2-0.20261025165926-320af050c445`. Use mcli 20261026 for administration; the container images bundle it as `mcli`.

The Server IAM cache repair enables Console's **Reset to default** action. Existing storage timeouts and cancellation behavior remain: a timeout does not prove that a disk operation stopped or a write did not commit. Read the [coordinated release notes](https://silo.pgsty.com/blog/release/silo-20261026/) and [remaining storage limits](CHANGELOG.md#release2026-10-26t00-00-00z) before upgrading. See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the people behind the code, reports, and documentation.

## Overview

PGSTY SILO keeps one maintained release line of the open-source MinIO server alive after upstream ended community distribution: builds, packages, multi-arch images, security fixes, and the full web console. Pigsty runs it in production as its PostgreSQL backup repository.

It follows one rule — **the product and its delivery surfaces are renamed; the protocol and your data are not.** Everything else lives on [silo.pgsty.com](https://silo.pgsty.com/).

**Related:** [`pgsty/mc`](https://github.com/pgsty/mc) client (shipped as `mcli`) · [`pgsty/silo-console`](https://github.com/pgsty/silo-console) · [`pgsty/silo-pkg`](https://github.com/pgsty/silo-pkg) · [`pgsty/pigsty`](https://github.com/pgsty/pigsty)

<p align="center">
  <img src="https://silo.pgsty.com/images/silo-console/console-metrics-simple.webp" alt="Silo Console">
</p>

## Quick Start

```bash
docker run -d --name silo -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=change-me-long-password \
  -v "$PWD/data:/data" \
  docker.io/pgsty/silo:RELEASE.2026-10-26T00-00-00Z server /data --console-address ":9001"
```

<p align="center">
  <img src="https://silo.pgsty.com/images/silo-console/console-login.webp" alt="Silo Console">
</p>

Console on <http://localhost:9001>, S3 API on <http://localhost:9000>. The image bundles the client as `mcli`:

```bash
docker exec silo mcli alias set local http://127.0.0.1:9000 minioadmin change-me-long-password
docker exec silo mcli mb local/demo && docker exec silo mcli ls local
```

> [!WARNING]
> For production, pin a release, use unique credentials and TLS, monitor the service, keep independent backups, and test recovery. Start from the [documentation](https://silo.pgsty.com/docs/).

## Install

| Method | Where |
| :-- | :-- |
| Container | [`pgsty/silo`](https://hub.docker.com/r/pgsty/silo), multi-arch for `linux/amd64` and `linux/arm64` |
| Binaries | [GitHub Releases](https://github.com/pgsty/silo/releases) — Linux, macOS, Windows on `amd64` and `arm64` |
| Packages | RPM, DEB, and APK, also via the [Pigsty repository](https://pigsty.io/docs/repo/) |
| Kubernetes | Helm chart, see [Download & Install](https://silo.pgsty.com/download/) |
| Source | `go build -o silo . && ./silo --version` |

Every release ships checksums, SPDX SBOMs, Sigstore-signed manifests, and GitHub build attestations. Installation methods and verification commands are documented at [Download & Install](https://silo.pgsty.com/download/); migrating from upstream MinIO — taking over an existing `minio.service` and its `/etc/default/minio`, and keeping data ownership stable with a `/etc/systemd/system/silo.service.d/10-legacy-user.conf` drop-in — is covered by the [migration guide](https://silo.pgsty.com/compatibility/migration/) and the [binary & service notes](https://silo.pgsty.com/compatibility/binary/).

## Compatibility

Silo preserves S3 and storage-format compatibility, including existing `MINIO_*` variables, `minio_*` metrics, `x-minio-*` headers, `/minio/*` routes, and `.minio.sys` data. CI guards selected compatibility identifiers; release notes document intentional security and behavior changes. Silo-owned delivery surfaces use the `silo` executable, package, service, Helm chart, and container image; no `minio` server binary alias is installed.

The supported release stack is `pgsty/silo` + `pgsty/silo-console` + `pgsty/mc` + `pgsty/silo-pkg`; compatibility with unmodified upstream MinIO/MC is best effort. The Server, Console, and client retain their historical module paths where needed, while maintained code imports `github.com/pgsty/silo-pkg/v3` directly. The SDK `github.com/minio/minio-go/v7` is an explicit upstream dependency. See the current [go.mod](go.mod) for versions and replacements.

Every divergence from upstream is listed in the code-verified [compatibility audit](https://silo.pgsty.com/compatibility/server/). Treat each release as a downstream upgrade: pin versions, read the [release notes](https://silo.pgsty.com/tags/silo/), and keep a rollback path.

### TLS and Go upgrades

Server 20260916 restored Go's default key exchange; Server 20261018 retains it with Go 1.27.2.
TLS key exchange follows Go's defaults across the S3 listener, node links,
replication, identity providers, etcd, and external HTTP services. If an endpoint
cannot accept ML-KEM, `GODEBUG=tlsmlkem=0` disables the default hybrid exchanges
for the process; certificate verification remains enabled. This option does not
disable ML-DSA signatures or resolve every TLS reset. Prefer updating the
incompatible endpoint before removing the temporary setting.
If only the new SecP hybrids cause problems, `GODEBUG=tlssecpmlkem=0` disables
those groups while retaining X25519MLKEM768.

For builds targeting Go 1.27, setting either `SSL_CERT_FILE` or `SSL_CERT_DIR`
on macOS replaces Keychain trust with on-disk roots and Go's verifier. Stale or
incomplete CA paths can break previously trusted connections; unset inherited
values to restore Keychain trust. Explicit certificates in the configured `CAs`
directory remain additive to the selected root pool.
Go 1.27 binaries require macOS 13 or later. See the
[Go release notes](https://go.dev/doc/go1.27) and the
[Go 1.27 TLS and OIDC discovery guide](https://silo.pgsty.com/blog/design/go127-tls-oidc-discovery/).

## Documentation ownership

User documentation is maintained at [silo.pgsty.com](https://silo.pgsty.com/docs/),
with source in [pgsty/silo.pgsty.com](https://github.com/pgsty/silo.pgsty.com).
The remaining `docs/` tree contains inherited references, examples, and tooling
fixtures. Investigation logs, AI work records, and temporary reports are kept
outside this repository; reusable findings belong in the companion site.
See [AGENTS.md](AGENTS.md) for repository ownership and maintenance rules.

## Security & Contributing

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md); every fix ships with a public [advisory](https://silo.pgsty.com/blog/security/). Contributions are accepted inbound=outbound under AGPL-3.0-or-later with no CLA — only DCO sign-off (`git commit -s`) is required; see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Contributors

<!-- Generated by silo.pgsty.com/bin/contributors.py. -->

Every human issue or pull-request author is part of the SILO community, including open and unmerged work. We also recognize security reports, including reports sent by email, with the reporter's permission. Merged fixes, adopted proposals, and actionable reports receive priority, with first participation guiding the remaining order. Gold rings highlight reviewed significant contributions.

<a href="CONTRIBUTORS.md">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/pgsty/silo/codex/repository-cards/contributors-dark.svg">
  <img src="https://raw.githubusercontent.com/pgsty/silo/codex/repository-cards/contributors-light.svg" alt="SILO community contributors">
</picture>
</a>

[View contribution notes and actual PR status](CONTRIBUTORS.md).

## Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/pgsty/silo/codex/repository-cards/star-history-dark.svg">
  <img src="https://raw.githubusercontent.com/pgsty/silo/codex/repository-cards/star-history-light.svg" alt="SILO GitHub star history">
</picture>

## Background

Upstream wound down its community edition: the web console was cut back to a stub, prebuilt community binaries stopped, and the community repository was archived. Silo exists to keep those deployments running. The fork is a means, not an identity — if upstream restores its community edition, we will narrow our scope and offer the fixes back.

The [**Manifesto**](https://silo.pgsty.com/about/manifesto/) is the project's public commitment in eleven articles, under one discipline: every article is either something already done with public evidence, or something explicitly refused. In short:

- **Compatibility contract** — the protocol and your data do not change, and every release documents its tested rollback target and path.
- **The license cannot change** — AGPLv3, no CLA, no copyright aggregation; nobody here, ourselves included, holds enough copyright to relicense on everyone else's behalf.
- **The never list**, append-only — no paywalling existing features, no registration wall on downloads, no telemetry (upstream's phone-home paths are removed outright), no CLA, no license change, no trademark enforcement against normal use.
- **Security and release discipline** — a public advisory for every fix, and a release every one to two months, at most a quarter apart. Judge both against the public record.

Essays: [MinIO Is Dead](https://silo.pgsty.com/blog/post/minio-is-dead/) · [Who Takes Over?](https://silo.pgsty.com/blog/post/minio-alternative/) · [Long Live MinIO](https://silo.pgsty.com/blog/post/minio-resurrect/) · [Promise Kept](https://silo.pgsty.com/blog/post/minio-promise-kept/)

## License & Trademark

Silo is [AGPL-3.0-or-later](LICENSE), derived from [`minio/minio`](https://github.com/minio/minio) with upstream copyright and third-party notices preserved in [`NOTICE`](NOTICE) and [`CREDITS`](CREDITS). MinIO is a trademark of MinIO, Inc.; the name is used here only to identify the upstream project and compatibility lineage.

Details: [license](https://silo.pgsty.com/about/license/) · [attribution](https://silo.pgsty.com/about/attribution/) · [trademark](https://silo.pgsty.com/about/trademark/)
