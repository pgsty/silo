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
  <a href="https://hub.docker.com/r/pgsty/silo"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/pgsty/minio?logo=docker"></a>
  <a href="go.mod"><img alt="Go Version" src="https://img.shields.io/github/go-mod/go-version/pgsty/silo?logo=go"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-AGPLv3-blue"></a>
</p>

> [!IMPORTANT]
> **PGSTY Silo** (hereinafter “Silo”) is an independent, community-maintained fork of the open-source MinIO server, published by [Pigsty](https://pigsty.io) from [`pgsty/silo`](https://github.com/pgsty/silo). It is not affiliated with, endorsed by, or sponsored by MinIO, Inc. “MinIO” is used only to identify the upstream project and compatibility lineage.

> [!NOTE]
> Renamed from `pgsty/minio` to `pgsty/silo`, default branch `master` → `main`, on 2026-08-06. Artifacts under the original MinIO identity stay published on the archived [`minio`](https://github.com/pgsty/silo/tree/minio) branch and in releases up to [`RELEASE.2026-08-04T00-00-00Z`](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-08-04T00-00-00Z).

## Current release and main branch

The latest published Server is [20260903](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-09-03T13-18-01Z).
As of 2026-09-13, the main branch has newer security, storage, Console and
shared-package changes that have not shipped in a Server release. See
[CHANGELOG.md](CHANGELOG.md) and the [component version matrix](https://silo.pgsty.com/compatibility/versions/)
for the exact release/source boundary, including SN-2026-011 and password-policy migration.

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
  docker.io/pgsty/silo:latest server /data --console-address ":9001"
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

The S3 API, `MINIO_*` variables, `minio_*` metrics, `x-minio-*` headers, `/minio/*` routes, the `github.com/minio/*` import paths, and the on-disk format (including `.minio.sys`) are preserved and held in place by a CI compatibility check. Only Silo-owned delivery surfaces change: the `silo` executable, package, service, Helm chart, and container image — no `minio` binary alias is installed.

Every divergence from upstream is listed in the code-verified [compatibility audit](https://silo.pgsty.com/compatibility/server/). Treat each release as a downstream upgrade: pin versions, read the [release notes](https://silo.pgsty.com/tags/silo/), and keep a rollback path.

### TLS and Go upgrades

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
[SILO stack investigation](docs/investigations/go127-stack.md).

## Security & Contributing

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md); every fix ships with a public [advisory](https://silo.pgsty.com/blog/security/). Contributions are accepted inbound=outbound under AGPL-3.0-or-later with no CLA — only DCO sign-off (`git commit -s`) is required; see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Contributors

**41 community contributors** build SILO, Console, mcli, shared packages, and related projects. The list includes maintainers and every human Issue or PR author, ordered by merged PRs, other PRs, then issue reports. Gold rings highlight significant contributions.

<p align="center">
<a href="https://github.com/Vonng"><img src="https://silo.pgsty.com/images/contributors/Vonng.svg" width="60" height="60" alt="@Vonng" title="@Vonng — Maintains SILO, Console, mcli, shared packages, releases, and documentation"></a>
<a href="https://github.com/h5vx"><img src="https://silo.pgsty.com/images/contributors/h5vx.svg" width="60" height="60" alt="@h5vx" title="@h5vx — Implemented per-bucket CORS configuration and enforcement"></a>
<a href="https://github.com/mrjavadseydi"><img src="https://silo.pgsty.com/images/contributors/mrjavadseydi.svg" width="60" height="60" alt="@mrjavadseydi" title="@mrjavadseydi — Fixed effective bucket quota metrics; proposed access-frequency ILM"></a>
<a href="https://github.com/Dansyuqri"><img src="https://silo.pgsty.com/images/contributors/Dansyuqri.svg" width="60" height="60" alt="@Dansyuqri" title="@Dansyuqri — Added ChecksumType to multipart completion responses"></a>
<a href="https://github.com/ycjlin"><img src="https://silo.pgsty.com/images/contributors/ycjlin.svg" width="60" height="60" alt="@ycjlin" title="@ycjlin — Fixed missing-bucket ListObjects semantics"></a>
<a href="https://github.com/pinginfo"><img src="https://silo.pgsty.com/images/contributors/pinginfo.svg" width="60" height="60" alt="@pinginfo" title="@pinginfo — Repaired bucket notification streaming"></a>
<a href="https://github.com/ZouhairCharef"><img src="https://silo.pgsty.com/images/contributors/ZouhairCharef.svg" width="60" height="60" alt="@ZouhairCharef" title="@ZouhairCharef — Patched CVE-2026-34986 in go-jose"></a>
<a href="https://github.com/mfredenhagen"><img src="https://silo.pgsty.com/images/contributors/mfredenhagen.svg" width="60" height="60" alt="@mfredenhagen" title="@mfredenhagen — Patched CVE-2026-39883 in OpenTelemetry"></a>
<a href="https://github.com/waterkip"><img src="https://silo.pgsty.com/images/contributors/waterkip.svg" width="60" height="60" alt="@waterkip" title="@waterkip — Repointed documentation links to the SILO portal"></a>
<a href="https://github.com/mikemikimike"><img src="https://silo.pgsty.com/images/contributors/mikemikimike.svg" width="60" height="60" alt="@mikemikimike" title="@mikemikimike — Contributed the replicated SSE-C plaintext part-size fix"></a>
<a href="https://github.com/metaneutrons"><img src="https://silo.pgsty.com/images/contributors/metaneutrons.svg" width="60" height="60" alt="@metaneutrons" title="@metaneutrons — Reported and proposed explicit-version delete authorization"></a>
<a href="https://github.com/magicxor"><img src="https://silo.pgsty.com/images/contributors/magicxor.svg" width="60" height="60" alt="@magicxor" title="@magicxor — Reported and proposed conditional DELETE support for If-Match"></a>
<a href="https://github.com/davinkevin"><img src="https://silo.pgsty.com/images/contributors/davinkevin.svg" width="60" height="60" alt="@davinkevin" title="@davinkevin — Proposed the distroless container image and dependency automation"></a>
<a href="https://github.com/lem21h"><img src="https://silo.pgsty.com/images/contributors/lem21h.svg" width="48" height="48" alt="@lem21h" title="@lem21h — Proposed robustness and goroutine improvements"></a>
<a href="https://github.com/sulin37392"><img src="https://silo.pgsty.com/images/contributors/sulin37392.svg" width="48" height="48" alt="@sulin37392" title="@sulin37392 — Proposed dependency updates"></a>
<a href="https://github.com/cbornet"><img src="https://silo.pgsty.com/images/contributors/cbornet.svg" width="60" height="60" alt="@cbornet" title="@cbornet — Reported multipart and streaming checksum defects and missing-bucket semantics"></a>
<a href="https://github.com/vampywiz17"><img src="https://silo.pgsty.com/images/contributors/vampywiz17.svg" width="60" height="60" alt="@vampywiz17" title="@vampywiz17 — Reported LDAP TLS and Console login regressions"></a>
<a href="https://github.com/orenyomtov"><img src="https://silo.pgsty.com/images/contributors/orenyomtov.svg" width="60" height="60" alt="@orenyomtov" title="@orenyomtov — Reported the unsigned-header CopyObject cross-object read (SN-2026-011)"></a>
<a href="https://github.com/mumu-lab"><img src="https://silo.pgsty.com/images/contributors/mumu-lab.svg" width="48" height="48" alt="@mumu-lab" title="@mumu-lab — Reported bucket quota metrics reading a deprecated field"></a>
<a href="https://github.com/jvasile"><img src="https://silo.pgsty.com/images/contributors/jvasile.svg" width="48" height="48" alt="@jvasile" title="@jvasile — Reported missing user, group, and defaults in Debian packages"></a>
<a href="https://github.com/pmezhuev"><img src="https://silo.pgsty.com/images/contributors/pmezhuev.svg" width="48" height="48" alt="@pmezhuev" title="@pmezhuev — Reported missing RPM package signatures"></a>
<a href="https://github.com/TLINDEN"><img src="https://silo.pgsty.com/images/contributors/TLINDEN.svg" width="48" height="48" alt="@TLINDEN" title="@TLINDEN — Reported the missing client in release tarballs"></a>
<a href="https://github.com/makinikm"><img src="https://silo.pgsty.com/images/contributors/makinikm.svg" width="48" height="48" alt="@makinikm" title="@makinikm — Reported the missing client in the container image"></a>
<a href="https://github.com/meesudzu"><img src="https://silo.pgsty.com/images/contributors/meesudzu.svg" width="48" height="48" alt="@meesudzu" title="@meesudzu — Requested the migration guide from upstream MinIO"></a>
<a href="https://github.com/kuldeep-link11"><img src="https://silo.pgsty.com/images/contributors/kuldeep-link11.svg" width="48" height="48" alt="@kuldeep-link11" title="@kuldeep-link11 — Reported NATS JWT credentials and target reload issues"></a>
<a href="https://github.com/sargarass"><img src="https://silo.pgsty.com/images/contributors/sargarass.svg" width="48" height="48" alt="@sargarass" title="@sargarass — Reported ListMultipartUploads prefix and pagination semantics"></a>
<a href="https://github.com/liuhaodongliu990-cmyk"><img src="https://silo.pgsty.com/images/contributors/liuhaodongliu990-cmyk.svg" width="48" height="48" alt="@liuhaodongliu990-cmyk" title="@liuhaodongliu990-cmyk — Reported indeterminate progress for prefix downloads"></a>
<a href="https://github.com/Xavier-777"><img src="https://silo.pgsty.com/images/contributors/Xavier-777.svg" width="48" height="48" alt="@Xavier-777" title="@Xavier-777 — Reported Console lifecycle management and file preview gaps"></a>
<a href="https://github.com/spaceg00se-r"><img src="https://silo.pgsty.com/images/contributors/spaceg00se-r.svg" width="48" height="48" alt="@spaceg00se-r" title="@spaceg00se-r — Requested cpuv1 support and reported a workflow token failure"></a>
<a href="https://github.com/kh0mka"><img src="https://silo.pgsty.com/images/contributors/kh0mka.svg" width="48" height="48" alt="@kh0mka" title="@kh0mka — Reported inter-node I/O timeouts in ReadFileStreamHandler"></a>
<a href="https://github.com/bagutzu"><img src="https://silo.pgsty.com/images/contributors/bagutzu.svg" width="48" height="48" alt="@bagutzu" title="@bagutzu — Requested KES-compatible external KMS and OpenBao support"></a>
<a href="https://github.com/DestroyLee"><img src="https://silo.pgsty.com/images/contributors/DestroyLee.svg" width="48" height="48" alt="@DestroyLee" title="@DestroyLee — Reported the missing documentation navigation"></a>
<a href="https://github.com/mosesdd"><img src="https://silo.pgsty.com/images/contributors/mosesdd.svg" width="48" height="48" alt="@mosesdd" title="@mosesdd — Requested a maintained Helm chart"></a>
<a href="https://github.com/zylpsrs"><img src="https://silo.pgsty.com/images/contributors/zylpsrs.svg" width="48" height="48" alt="@zylpsrs" title="@zylpsrs — Reported missing Console tiering and site replication"></a>
<a href="https://github.com/heroes1412"><img src="https://silo.pgsty.com/images/contributors/heroes1412.svg" width="48" height="48" alt="@heroes1412" title="@heroes1412 — Reported the unusable profiling option"></a>
<a href="https://github.com/redfoxfox"><img src="https://silo.pgsty.com/images/contributors/redfoxfox.svg" width="48" height="48" alt="@redfoxfox" title="@redfoxfox — Reported Chinese documentation availability"></a>
<a href="https://github.com/jiadzh"><img src="https://silo.pgsty.com/images/contributors/jiadzh.svg" width="48" height="48" alt="@jiadzh" title="@jiadzh — Requested Windows build guidance"></a>
<a href="https://github.com/AntonOfTheWoods"><img src="https://silo.pgsty.com/images/contributors/AntonOfTheWoods.svg" width="48" height="48" alt="@AntonOfTheWoods" title="@AntonOfTheWoods — Asked for clarity on Helm chart and operator options"></a>
<a href="https://github.com/chalukyaj"><img src="https://silo.pgsty.com/images/contributors/chalukyaj.svg" width="48" height="48" alt="@chalukyaj" title="@chalukyaj — Proposed making the SILO Operator easier to discover"></a>
<a href="https://github.com/nsanitate"><img src="https://silo.pgsty.com/images/contributors/nsanitate.svg" width="48" height="48" alt="@nsanitate" title="@nsanitate — Proposed CNCF Sandbox governance"></a>
<a href="https://github.com/Kesavaambati"><img src="https://silo.pgsty.com/images/contributors/Kesavaambati.svg" width="48" height="48" alt="@Kesavaambati" title="@Kesavaambati — Asked about community support and image maintenance"></a>
</p>

[View the full contribution record](CONTRIBUTORS.md) for each person's proposals, fixes, and reports.

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
