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
  <a href="https://hub.docker.com/r/pgsty/silo"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/pgsty/minio?logo=docker"></a>
  <a href="go.mod"><img alt="Go Version" src="https://img.shields.io/github/go-mod/go-version/pgsty/silo?logo=go"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-AGPLv3-blue"></a>
</p>

> [!IMPORTANT]
> **PGSTY Silo**（以下简称 Silo）是由 [Pigsty](https://pigsty.cc) 独立维护、从 [`pgsty/silo`](https://github.com/pgsty/silo) 发布的开源 MinIO 社区分支。本项目与 MinIO, Inc. 不存在隶属、背书或赞助关系；文中使用 “MinIO” 仅用于说明上游项目及兼容谱系。

> [!NOTE]
> 2026-08-06，本仓库由 `pgsty/minio` 更名为 `pgsty/silo`，默认分支由 `master` 更名为 `main`。以原 MinIO 形态维持的归档构件仍位于归档的 [`minio`](https://github.com/pgsty/silo/tree/minio) 分支，以及截止 [`RELEASE.2026-08-04T00-00-00Z`](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-08-04T00-00-00Z) 的历次发布中。

## 当前发行版与主分支

最新已发布的 Server 仍为 [20260903](https://github.com/pgsty/silo/releases/tag/RELEASE.2026-09-03T13-18-01Z)。
截至 2026-09-13，主分支已合入更新的安全、存储、Console 与共享包改动，但尚未发布新 Server。
准确的已发布/源码边界见 [CHANGELOG.md](CHANGELOG.md) 与[组件版本矩阵](https://silo.pgsty.com/zh/compatibility/versions/)，
其中包括 SN-2026-011 修复状态与密码权限迁移要求。

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
  docker.io/pgsty/silo:latest server /data --console-address ":9001"
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

S3 API、`MINIO_*` 环境变量、`minio_*` 指标、`x-minio-*` 头、`/minio/*` 路由、`github.com/minio/*` 导入路径与磁盘格式（含 `.minio.sys`）原样保留，并由 CI 兼容性门禁冻结。只有 Silo 自有交付面改名：`silo` 可执行文件、软件包、服务、Helm Chart 与容器镜像 —— 原生交付物不会安装 `minio` 二进制别名。

与上游的全部分歧，以逐项核验代码的[兼容性审计](https://silo.pgsty.com/zh/compatibility/server/)形式维护。每个版本仍应视为下游升级：锁定版本，阅读[版本说明](https://silo.pgsty.com/zh/tags/silo/)，并保留回滚路径。

## 安全与贡献

请按照 [`SECURITY.md`](SECURITY.md) 私密报告漏洞；每项修复都会发布公开[安全公告](https://silo.pgsty.com/zh/blog/security/)。本项目不要求签署 CLA：贡献按 AGPL-3.0-or-later（inbound=outbound）接收，只需 DCO 签署（`git commit -s`），详见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

## 贡献者

**41 位社区贡献者**共同建设 SILO、Console、mcli、公共包与相关项目。名单包含维护者，以及所有提出 Issue 或 PR 的真人作者；按已合并 PR、其他 PR、Issue 报告排序，黄圈标记显著贡献。

<p align="center">
<a href="https://github.com/Vonng"><img src="https://silo.pgsty.com/images/contributors/Vonng.svg" width="60" height="60" alt="@Vonng" title="@Vonng — 维护 SILO、Console、mcli、公共包、发行与文档"></a>
<a href="https://github.com/h5vx"><img src="https://silo.pgsty.com/images/contributors/h5vx.svg" width="60" height="60" alt="@h5vx" title="@h5vx — 实现单桶 CORS 配置与请求执行"></a>
<a href="https://github.com/mrjavadseydi"><img src="https://silo.pgsty.com/images/contributors/mrjavadseydi.svg" width="60" height="60" alt="@mrjavadseydi" title="@mrjavadseydi — 修复有效桶配额指标，并提交按访问频率分层的 ILM 方案"></a>
<a href="https://github.com/Dansyuqri"><img src="https://silo.pgsty.com/images/contributors/Dansyuqri.svg" width="60" height="60" alt="@Dansyuqri" title="@Dansyuqri — 为分片上传完成响应补充 ChecksumType"></a>
<a href="https://github.com/ycjlin"><img src="https://silo.pgsty.com/images/contributors/ycjlin.svg" width="60" height="60" alt="@ycjlin" title="@ycjlin — 修复缺失桶的 ListObjects 语义"></a>
<a href="https://github.com/pinginfo"><img src="https://silo.pgsty.com/images/contributors/pinginfo.svg" width="60" height="60" alt="@pinginfo" title="@pinginfo — 修复桶通知的流式输出"></a>
<a href="https://github.com/ZouhairCharef"><img src="https://silo.pgsty.com/images/contributors/ZouhairCharef.svg" width="60" height="60" alt="@ZouhairCharef" title="@ZouhairCharef — 修复 go-jose 中的 CVE-2026-34986"></a>
<a href="https://github.com/mfredenhagen"><img src="https://silo.pgsty.com/images/contributors/mfredenhagen.svg" width="60" height="60" alt="@mfredenhagen" title="@mfredenhagen — 修复 OpenTelemetry 中的 CVE-2026-39883"></a>
<a href="https://github.com/waterkip"><img src="https://silo.pgsty.com/images/contributors/waterkip.svg" width="60" height="60" alt="@waterkip" title="@waterkip — 将文档链接指向 SILO 门户"></a>
<a href="https://github.com/mikemikimike"><img src="https://silo.pgsty.com/images/contributors/mikemikimike.svg" width="60" height="60" alt="@mikemikimike" title="@mikemikimike — 提交 SSE-C 复制分片明文尺寸修复"></a>
<a href="https://github.com/metaneutrons"><img src="https://silo.pgsty.com/images/contributors/metaneutrons.svg" width="60" height="60" alt="@metaneutrons" title="@metaneutrons — 报告并提交显式版本删除鉴权方案"></a>
<a href="https://github.com/magicxor"><img src="https://silo.pgsty.com/images/contributors/magicxor.svg" width="60" height="60" alt="@magicxor" title="@magicxor — 报告并提交 DELETE If-Match 条件请求支持方案"></a>
<a href="https://github.com/davinkevin"><img src="https://silo.pgsty.com/images/contributors/davinkevin.svg" width="60" height="60" alt="@davinkevin" title="@davinkevin — 提交 distroless 容器镜像与依赖自动更新方案"></a>
<a href="https://github.com/lem21h"><img src="https://silo.pgsty.com/images/contributors/lem21h.svg" width="48" height="48" alt="@lem21h" title="@lem21h — 提交健壮性与 goroutine 改进"></a>
<a href="https://github.com/sulin37392"><img src="https://silo.pgsty.com/images/contributors/sulin37392.svg" width="48" height="48" alt="@sulin37392" title="@sulin37392 — 提交依赖更新"></a>
<a href="https://github.com/cbornet"><img src="https://silo.pgsty.com/images/contributors/cbornet.svg" width="60" height="60" alt="@cbornet" title="@cbornet — 报告分片与流式校验和缺陷及缺失桶语义问题"></a>
<a href="https://github.com/vampywiz17"><img src="https://silo.pgsty.com/images/contributors/vampywiz17.svg" width="60" height="60" alt="@vampywiz17" title="@vampywiz17 — 报告 LDAP TLS 与 Console 登录回归"></a>
<a href="https://github.com/orenyomtov"><img src="https://silo.pgsty.com/images/contributors/orenyomtov.svg" width="60" height="60" alt="@orenyomtov" title="@orenyomtov — 报告未签名头导致的 CopyObject 跨对象读取（SN-2026-011）"></a>
<a href="https://github.com/mumu-lab"><img src="https://silo.pgsty.com/images/contributors/mumu-lab.svg" width="48" height="48" alt="@mumu-lab" title="@mumu-lab — 报告桶配额指标读取已弃用字段的问题"></a>
<a href="https://github.com/jvasile"><img src="https://silo.pgsty.com/images/contributors/jvasile.svg" width="48" height="48" alt="@jvasile" title="@jvasile — 报告 Debian 包缺少用户、用户组与默认配置"></a>
<a href="https://github.com/pmezhuev"><img src="https://silo.pgsty.com/images/contributors/pmezhuev.svg" width="48" height="48" alt="@pmezhuev" title="@pmezhuev — 报告 RPM 包缺少 GPG 签名"></a>
<a href="https://github.com/TLINDEN"><img src="https://silo.pgsty.com/images/contributors/TLINDEN.svg" width="48" height="48" alt="@TLINDEN" title="@TLINDEN — 报告发布压缩包缺少客户端"></a>
<a href="https://github.com/makinikm"><img src="https://silo.pgsty.com/images/contributors/makinikm.svg" width="48" height="48" alt="@makinikm" title="@makinikm — 报告容器镜像缺少客户端"></a>
<a href="https://github.com/meesudzu"><img src="https://silo.pgsty.com/images/contributors/meesudzu.svg" width="48" height="48" alt="@meesudzu" title="@meesudzu — 提出从上游 MinIO 迁移的指南需求"></a>
<a href="https://github.com/kuldeep-link11"><img src="https://silo.pgsty.com/images/contributors/kuldeep-link11.svg" width="48" height="48" alt="@kuldeep-link11" title="@kuldeep-link11 — 报告 NATS JWT 凭据与通知目标重载问题"></a>
<a href="https://github.com/sargarass"><img src="https://silo.pgsty.com/images/contributors/sargarass.svg" width="48" height="48" alt="@sargarass" title="@sargarass — 报告 ListMultipartUploads 前缀与分页语义问题"></a>
<a href="https://github.com/liuhaodongliu990-cmyk"><img src="https://silo.pgsty.com/images/contributors/liuhaodongliu990-cmyk.svg" width="48" height="48" alt="@liuhaodongliu990-cmyk" title="@liuhaodongliu990-cmyk — 报告前缀下载进度显示异常"></a>
<a href="https://github.com/Xavier-777"><img src="https://silo.pgsty.com/images/contributors/Xavier-777.svg" width="48" height="48" alt="@Xavier-777" title="@Xavier-777 — 报告 Console 生命周期管理与文件预览缺失"></a>
<a href="https://github.com/spaceg00se-r"><img src="https://silo.pgsty.com/images/contributors/spaceg00se-r.svg" width="48" height="48" alt="@spaceg00se-r" title="@spaceg00se-r — 提出 cpuv1 支持需求并报告工作流令牌错误"></a>
<a href="https://github.com/kh0mka"><img src="https://silo.pgsty.com/images/contributors/kh0mka.svg" width="48" height="48" alt="@kh0mka" title="@kh0mka — 报告 ReadFileStreamHandler 节点间 I/O 超时"></a>
<a href="https://github.com/bagutzu"><img src="https://silo.pgsty.com/images/contributors/bagutzu.svg" width="48" height="48" alt="@bagutzu" title="@bagutzu — 提出兼容 KES 的外部 KMS 与 OpenBao 支持需求"></a>
<a href="https://github.com/DestroyLee"><img src="https://silo.pgsty.com/images/contributors/DestroyLee.svg" width="48" height="48" alt="@DestroyLee" title="@DestroyLee — 报告文档目录导航缺失"></a>
<a href="https://github.com/mosesdd"><img src="https://silo.pgsty.com/images/contributors/mosesdd.svg" width="48" height="48" alt="@mosesdd" title="@mosesdd — 提出维护 Helm Chart 的需求"></a>
<a href="https://github.com/zylpsrs"><img src="https://silo.pgsty.com/images/contributors/zylpsrs.svg" width="48" height="48" alt="@zylpsrs" title="@zylpsrs — 报告 Console 缺少分层与站点复制"></a>
<a href="https://github.com/heroes1412"><img src="https://silo.pgsty.com/images/contributors/heroes1412.svg" width="48" height="48" alt="@heroes1412" title="@heroes1412 — 报告性能分析选项不可用"></a>
<a href="https://github.com/redfoxfox"><img src="https://silo.pgsty.com/images/contributors/redfoxfox.svg" width="48" height="48" alt="@redfoxfox" title="@redfoxfox — 报告中文文档站点不可用"></a>
<a href="https://github.com/jiadzh"><img src="https://silo.pgsty.com/images/contributors/jiadzh.svg" width="48" height="48" alt="@jiadzh" title="@jiadzh — 提出 Windows 构建指导需求"></a>
<a href="https://github.com/AntonOfTheWoods"><img src="https://silo.pgsty.com/images/contributors/AntonOfTheWoods.svg" width="48" height="48" alt="@AntonOfTheWoods" title="@AntonOfTheWoods — 提出明确 Helm Chart 与 Operator 选项的需求"></a>
<a href="https://github.com/chalukyaj"><img src="https://silo.pgsty.com/images/contributors/chalukyaj.svg" width="48" height="48" alt="@chalukyaj" title="@chalukyaj — 提出改善 SILO Operator 可发现性的建议"></a>
<a href="https://github.com/nsanitate"><img src="https://silo.pgsty.com/images/contributors/nsanitate.svg" width="48" height="48" alt="@nsanitate" title="@nsanitate — 提出加入 CNCF Sandbox 的治理建议"></a>
<a href="https://github.com/Kesavaambati"><img src="https://silo.pgsty.com/images/contributors/Kesavaambati.svg" width="48" height="48" alt="@Kesavaambati" title="@Kesavaambati — 提出社区支持与容器镜像维护问题"></a>
</p>

[查看完整贡献记录](CONTRIBUTORS.md)，了解每位贡献者的提案、修复与问题报告。

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
