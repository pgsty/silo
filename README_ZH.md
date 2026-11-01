<h1 align="center">
  <a href="https://silo.pgsty.com/zh/">
    <img src=".github/silo-logo.svg" alt="Silo" width="160">
  </a>
</h1>


<p align="center">
  <strong>S3 兼容对象存储 —— 由 PGSTY 维护的 MinIO 社区分支</strong>
</p>


<p align="center">
  <a href="https://silo.pgsty.com/zh/">官网</a> ·
  <a href="https://silo.pgsty.com/zh/docs/">文档</a> ·
  <a href="https://silo.pgsty.com/zh/download/">下载</a> ·
  <a href="https://silo.pgsty.com/zh/tags/silo/">版本说明</a> ·
  <a href="https://silo.pgsty.com/zh/compatibility/server/">兼容性</a> ·
  <a href="https://silo.pgsty.com/zh/about/manifesto/">宣言</a> ·
  <a href="SECURITY.md">安全策略</a> ·
  <a href="README.md">English</a>
</p>

<p align="center">
  <a href="https://silo.pgsty.com/zh/"><img alt="官网" src="https://img.shields.io/badge/%E5%AE%98%E7%BD%91-silo.pgsty.com%2Fzh-1d588c"></a>
  <a href="https://github.com/pgsty/silo/releases"><img alt="GitHub Release" src="https://img.shields.io/github/v/release/pgsty/silo?include_prereleases&label=release&logo=github"></a>
  <a href="https://hub.docker.com/r/pgsty/silo"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/pgsty/silo?logo=docker"></a>
  <a href="go.mod"><img alt="Go Version" src="https://img.shields.io/github/go-mod/go-version/pgsty/silo?logo=go"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-AGPLv3-blue"></a>
</p>

> [!IMPORTANT]
> **PGSTY Silo**（以下简称 Silo）是由 [Pigsty](https://pigsty.cc) 独立维护、从 [`pgsty/silo`](https://github.com/pgsty/silo) 发布的开源 MinIO 社区分支。本项目与 MinIO, Inc. 不存在隶属、背书或赞助关系；文中使用 “MinIO” 仅用于说明上游项目及兼容谱系。

> [!NOTE]
> 2026-08-06，本仓库由 `pgsty/minio` 更名为 `pgsty/silo`，默认分支由 `master` 更名为 `main`。以原 MinIO 形态维持的归档构件仍位于归档的 [`minio`](https://github.com/pgsty/silo/tree/minio) 分支，以及截止 [`RELEASE.2026-08-04T00-00-00Z`](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-08-04T00-00-00Z) 的历次发布中。

## SILO 20261026000000

[SILO 20261026000000](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-10-26T00-00-00Z) 已正式发布，提供各平台归档包、Linux 软件包，以及 amd64／arm64 标准版和 distroless Docker 镜像。版本标签为 `RELEASE.2026-10-26T00-00-00Z`，包版本为 `20261026000000.0.0`，构建源码为 `c3ad836aed0d`。

本版修复 LDAP 长 DN 登录、IAM 策略刷新、多池删除安全、分层对象过期、分片复制校验和及远端回滚参数透传。内置 Console v2.5.1（`fff1618d9abb`），使用 silo-pkg v3.15.2、Go 1.27.3 与上游 minio-go `v7.4.2-0.20261025165926-320af050c445`。配套管理客户端为 mcli 20261026，容器镜像内置该版本的 `mcli`。

Server IAM 缓存修复使 Console **Reset to default（恢复默认）** 操作即时生效。存储超时与取消行为保持既有语义：超时不代表底层磁盘操作已停止，也不代表写入未提交。升级前请阅读[联合发布说明](https://silo.pgsty.com/zh/blog/release/silo-20261026/)与[仍存的存储限制](CHANGELOG.md#release2026-10-26t00-00-00z)。代码、问题报告和文档贡献者见 [CONTRIBUTORS.md](CONTRIBUTORS.md)。

## 概述

上游停止社区发行后，Silo 为开源 MinIO 服务端维护一条持续可用的版本线：构建、软件包、多架构镜像、安全修复与完整 Web 控制台。Pigsty 在生产环境中用它承载 PostgreSQL 备份存储。

它只遵循一条原则：**改名的是产品与交付物，不是协议与你的数据。** 其余内容都在 [silo.pgsty.com](https://silo.pgsty.com/zh/)。

**相关项目：**[`pgsty/mc`](https://github.com/pgsty/mc) 客户端（以 `mcli` 发行） · [`pgsty/silo-console`](https://github.com/pgsty/silo-console) · [`pgsty/silo-pkg`](https://github.com/pgsty/silo-pkg) · [`pgsty/pigsty`](https://github.com/pgsty/pigsty)

<p align="center">
  <img src="https://silo.pgsty.com/images/silo-console/console-metrics-simple.webp" alt="Silo 控制台">
</p>

## 快速上手

```bash
docker run -d --name silo -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=change-me-long-password \
  -v "$PWD/data:/data" \
  docker.io/pgsty/silo:RELEASE.2026-10-26T00-00-00Z server /data --console-address ":9001"
```

<p align="center">
  <img src="https://silo.pgsty.com/images/silo-console/console-login.webp" alt="Silo 控制台">
</p>

控制台位于 <http://localhost:9001>，S3 API 位于 <http://localhost:9000>。镜像内置客户端 `mcli`：

```bash
docker exec silo mcli alias set local http://127.0.0.1:9000 minioadmin change-me-long-password
docker exec silo mcli mb local/demo && docker exec silo mcli ls local
```

> [!WARNING]
> 生产环境应锁定版本，使用独立凭据与 TLS，配置监控，保留独立备份，并验证恢复流程。请从[文档](https://silo.pgsty.com/zh/docs/)开始。

## 安装

| 方式 | 位置 |
| :-- | :-- |
| 容器镜像 | [`pgsty/silo`](https://hub.docker.com/r/pgsty/silo)，支持 `linux/amd64` 与 `linux/arm64` |
| 二进制 | [GitHub Releases](https://github.com/pgsty/silo/releases)，覆盖 Linux、macOS、Windows 的 `amd64` 与 `arm64` |
| 软件包 | RPM、DEB、APK，也可通过 [Pigsty 软件仓库](https://pigsty.cc/docs/repo/) 安装 |
| Kubernetes | Helm Chart，参见[下载与安装](https://silo.pgsty.com/zh/download/) |
| 源码构建 | `go build -o silo . && ./silo --version` |

每个版本都附带校验和、SPDX SBOM、Sigstore 签名清单与 GitHub 构建证明。完整安装方式与验证命令见[下载与安装](https://silo.pgsty.com/zh/download/)；从上游 MinIO 迁移 —— 接管既有 `minio.service` 与 `/etc/default/minio`，并用 `/etc/systemd/system/silo.service.d/10-legacy-user.conf` drop-in 保持数据属主不变 —— 见[迁移指南](https://silo.pgsty.com/zh/compatibility/migration/)与[二进制与服务说明](https://silo.pgsty.com/zh/compatibility/binary/)。

## 兼容性

Silo 保留 S3 与存储格式兼容性，包括既有 `MINIO_*` 环境变量、`minio_*` 指标、`x-minio-*` 头、`/minio/*` 路由与 `.minio.sys` 数据。CI 守卫检查选定的兼容性标识，有意的安全与行为变化在发布说明中记录。Silo 自有交付面使用 `silo` 可执行文件、软件包、服务、Helm Chart 与容器镜像；原生交付物不会安装 `minio` 服务端二进制别名。

正式支持和发布验收的组合为 `pgsty/silo` + `pgsty/silo-console` + `pgsty/mc` + `pgsty/silo-pkg`，对未修改的上游 MinIO/MC 尽最大努力保持兼容。Server、Console 与客户端按需保留历史模块路径，维护源码直接导入 `github.com/pgsty/silo-pkg/v3`；SDK `github.com/minio/minio-go/v7` 是明确保留的上游依赖。具体版本与 replace 以当前 [go.mod](go.mod) 为准。

与上游的全部分歧，以逐项核验代码的[兼容性审计](https://silo.pgsty.com/zh/compatibility/server/)形式维护。每个版本仍应视为下游升级：锁定版本，阅读[版本说明](https://silo.pgsty.com/zh/tags/silo/)，并保留回滚路径。

### TLS 与 Go 升级

Server 20260916 已恢复 Go 默认密钥交换策略，20261018 在 Go 1.27.2 下保留该行为。
`GODEBUG=tlsmlkem=0`、`tlssecpmlkem=0` 的适用范围、macOS 根证书来源变化，
以及 OIDC discovery 的诊断方法见 [Go 1.27 TLS 与 OIDC 指南](https://silo.pgsty.com/zh/blog/design/go127-tls-oidc-discovery/)。

## 文档归属

用户文档统一维护在 [silo.pgsty.com](https://silo.pgsty.com/zh/docs/)，源码位于
[pgsty/silo.pgsty.com](https://github.com/pgsty/silo.pgsty.com)。本仓库保留的 `docs/`
主要是继承的参考材料、示例和工具测试夹具。调查日志、AI 工作记录与临时报告放在仓库外；
可复用的结论应整理进伴生文档站。仓库职责与维护规则见 [AGENTS.md](AGENTS.md)。

## 安全与贡献

请按照 [`SECURITY.md`](SECURITY.md) 私密报告漏洞；每项修复都会发布公开[安全公告](https://silo.pgsty.com/zh/blog/security/)。本项目不要求签署 CLA：贡献按 AGPL-3.0-or-later（inbound=outbound）接收，只需 DCO 签署（`git commit -s`），详见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

## 贡献者

<!-- Generated by silo.pgsty.com/bin/contributors.py. -->

每位 issue 或 PR 的作者，以及同意公开署名的安全报告者，都是 SILO 社区的一员，包括尚未合并的工作。已合并的修复、被采纳的方案和有效报告优先展示，其余参考首次参与时间；金色圆环突出经过审核的显著贡献。

<a href="CONTRIBUTORS.md">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/pgsty/silo/codex/repository-cards/contributors-dark.svg">
  <img src="https://raw.githubusercontent.com/pgsty/silo/codex/repository-cards/contributors-light.svg" alt="SILO 社区贡献者">
</picture>
</a>

[查看贡献记录与实际 PR 状态](CONTRIBUTORS.md)。

## Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/pgsty/silo/codex/repository-cards/star-history-dark.svg">
  <img src="https://raw.githubusercontent.com/pgsty/silo/codex/repository-cards/star-history-light.svg" alt="SILO GitHub 星标历史">
</picture>

## 背景

本项目因上游收缩社区版而生：Web 控制台被削减为残桩、社区预编译制品停发、社区仓库被归档。Silo 的存在就是让这些部署继续跑下去。Fork 是手段，不是身份 —— 若上游恢复社区版承诺，我们乐意收缩范围，并把修复回馈上游。

[**宣言**](https://silo.pgsty.com/zh/about/manifesto/)是项目的公开承诺，共十一条，通篇遵循一项纪律：**每一条，要么是已经在做且有公开证据的事实，要么是刻意拒绝的承诺。** 摘要：

- **兼容性合同** —— 协议与数据不改，每个版本都标注经过测试的回滚目标与路径。
- **许可证无法变更** —— AGPLv3、无 CLA、不做版权聚合；包括我们自己在内，没有人握有足够版权代表所有贡献者重新授权。
- **永不清单**（只增不减）—— 永不将既有功能移入付费墙、永不给下载设注册墙、永不加入遥测（上游回连路径已整体移除）、永不引入 CLA、永不变更许可证、永不以商标追究正常使用。
- **安全与发布纪律** —— 每项安全修复配一篇公开公告；通常每一到两个月发布一版，最长不超过一个季度。请拿公开记录检验这两条。

延伸阅读：[MinIO已死](https://silo.pgsty.com/zh/blog/post/minio-is-dead/) · [谁能接盘？](https://silo.pgsty.com/zh/blog/post/minio-alternative/) · [MinIO 复生](https://silo.pgsty.com/zh/blog/post/minio-resurrect/) · [承诺兑现](https://silo.pgsty.com/zh/blog/post/minio-promise-kept/)

## 许可证与商标

Silo 采用 [AGPL-3.0-or-later](LICENSE)，衍生自 [`minio/minio`](https://github.com/minio/minio)，上游版权与第三方声明完整保留于 [`NOTICE`](NOTICE) 与 [`CREDITS`](CREDITS)。MinIO 是 MinIO, Inc. 的商标，此处使用仅为标识上游项目与兼容谱系。

详见：[许可证](https://silo.pgsty.com/zh/about/license/) · [署名归属](https://silo.pgsty.com/zh/about/attribution/) · [商标声明](https://silo.pgsty.com/zh/about/trademark/)
