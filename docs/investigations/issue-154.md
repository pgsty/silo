# SILO #154：OIDC discovery 连接重置调查

> This is a dated investigation, with the source and runtime boundaries recorded
> below. It does not establish the current dependency pins or a later release.
> See [the current changelog](../../CHANGELOG.md) and
> [component matrix](https://silo.pgsty.com/compatibility/versions/).


前两轮调查时间：2026-09-09；公开 issue 最后核对于 07:53 UTC。第二轮补充同源码、同依赖、不同 Go 工具链的 Linux 完整 Server 对照和候选补丁认证链路验证。

**后续更新：用户已授权扩展至整个 SILO 技术栈并修复。现已确认 Server 其他 TLS 路径也存在同类覆盖问题，并在产品工作区完成统一使用 Go 默认曲线的修复。当前实现、验证和交付状态见 [全栈调查](go127-stack.md)。下文保留前两轮的诊断与当时的 OIDC 局部候选；“未修改产品”和“不要扩大范围”等表述仅适用于当时的调查阶段，局部候选已被后续全路径修复取代。**

## 判断与处理顺序

**目前可以确认是 Server 发出的 discovery GET 失败，随后 IAM 初始化等待，Console 初始化也被延后；还不能确认真实连接由谁、在哪个协议阶段重置。优先调查 SILO/Go 客户端与 IdP 前置 TLS 终止器、代理或 WAF 的互操作。** 现有证据不支持将其定性为证书错误、Keycloak 配置错误、JWT 校验错误或 `coreos/go-oidc` 回归。

有两项与版本相关、可在本地验证的 TLS 差异：

1. **Go 1.27 改变了 `GODEBUG=tlsmlkem=0` 与显式 `CurvePreferences` 的关系。** SILO 两个版本都显式包含 X25519MLKEM768。旧版 Go 1.26.5 会根据该环境选项移除它；Go 1.27.1 保留显式配置。在模拟拒绝 ML-KEM 的入口上，能重现“相同选项下旧 Server 启动成功，新 Server 持续 reset”。**客户是否设置过这个选项尚未知，不能把条件性复现当成客户根因。**
2. **Go 1.27 的 ClientHello 新增 ML-DSA 签名算法。** 没有上述环境选项时，新旧版本也会发送不同的握手。人为拒绝新算法编号的入口同样能产生旧成功、新失败。真实入口是否存在这种行为尚未知。

另外，HTTP User-Agent 从 `MinIO` 变成了 `Silo`；若连接在 TLS 完成、GET 发出之后被重置，应优先查 WAF、User-Agent 规则和 HTTP 路由，而不是继续调整 TLS。

最短路径：**先在故障进程所在环境拿到实际 Go 版本、是否设置 `tlsmlkem=0`、目标 IP 和 TLS 完成与否；再针对已证实的分支处理。** 优先修正入口兼容性或错误路由。若确认是上述环境选项失效，只为 OpenID 出站请求恢复 Go 默认曲线选择，是目前最小的代码候选。现阶段不宜做全局 TLS 改动或整体依赖回退。

## 第二轮结论：已隔离 Go 因素，局部候选修复通过 Linux 验证

**可以复现一种由 Go 1.26.5 → 1.27.1 单独触发的兼容性回归。建议保留 Go、针对已确认分支修复；整体回退只用于临时恢复服务。** 这里的“已确认”指本地实验机制，仍不等于已经确认客户入口的根因。

四个完整 Server 都从本地源码编译为 `linux/arm64`，在现成通用 Debian 12 基础镜像的 `--network none` 容器中运行；Server、合成 IdP、Console 和 curl 共用同一 loopback 网络，没有暴露端口。没有下载或运行 Server/Console 镜像。旧源码为 `d88f46ccee345a9c2fabe2d221d9a9e56bc11aec`，当前源码为 `d1105bbb3d4a0afa33b3a4ac11b821235038ed0e`。

旧源码两次构建使用完全相同的 `go.mod`、`go.sum` 和实际链接模块版本，仅替换编译器；当前源码与候选补丁构建的依赖图也完全相同。实际二进制 SHA-256、`go version -m` 依赖和构建选项保存在 [Linux 证据](issue-154/linux-evidence.json)。

下表的入口**人为设置为见到 X25519MLKEM768 就发 TCP RST**，Server 都设置 `GODEBUG=tlsmlkem=0`：

| 源码与编译器 | Server 初始 ClientHello | 完整 Server 结果 | 同容器 curl |
| --- | --- | --- | --- |
| 同一份旧源码 + Go 1.26.5 | 275 字节，无 ML-KEM | discovery、JWKS、IAM、Console 正常；cluster 200 | HTTP/2 200 |
| 同一份旧源码 + Go 1.27.1 | 1509 字节，仍包含 ML-KEM | `connection reset by peer`；IAM 等待；cluster 503；Console 未启动 | HTTP/2 200 |
| 当前源码 + Go 1.27.1 | 1509 字节，仍包含 ML-KEM | 同样失败 | HTTP/2 200 |
| 当前源码 + 局部候选补丁 + Go 1.27.1 | 287 字节，无 ML-KEM | 完整启动及合成 OIDC 登录成功 | HTTP/2 200 |

这将该条件下的回归定位到工具链行为，而非 Console、pkg、mc 或 `coreos/go-oidc` 升级。Go 1.27 的发布说明明确将此作为有意改变：`tlsmlkem` / `tlssecpmlkem` 只控制默认曲线集合，显式指定的集合可以继续启用这些算法。SILO 现有曲线列表显式包含该算法，因而原来的兼容开关在这条路径失效。[Go 1.27 crypto/tls 说明](https://go.dev/doc/go1.27#crypto/tls)。

共完成 **12 个 Linux 场景**，其中失败用例按预期失败：

- 正常 TLS 1.2 / P-256 / RSA / AES-256-GCM 的 IdP，旧源码用两个 Go 版本编译均正常，证明不是 Go 1.27 普遍无法连接这套 TLS。
- 上表四个对照均符合预期；候选补丁如果不设置 `tlsmlkem=0`，仍被 ML-KEM 拒绝规则拦截。补丁恢复显式兼容选项的作用，不会自行关闭后量子算法。
- 候选补丁在上述 TLS 1.2 兼容场景、以及无 GODEBUG 的正常 TLS 1.3 场景，都完成 Console 登录信息获取 → IdP authorization redirect → callback → token exchange → STS 凭据 → Console 会话 → 桶列表读取。登录 API 为 204，桶列表为 200。
- 两个登录场景分别提交错误签名与错误 audience 的 JWT，登录返回 500、桶列表返回 403，没有生成会话 cookie。这里只确认认证未放行，没有将现有 500 状态码行为改为另一项修复。
- 不信任 CA 时，候选 Server 仍因 `x509: certificate signed by unknown authority` 停在 IAM 初始化。没有关闭证书校验。
- 不配置 OIDC 启动后，经实际 Admin API 添加同一合成 provider：当前源码失败且返回 reset；候选补丁成功。
- 入口改为拒绝 ML-DSA 签名编号，候选补丁加 `tlsmlkem=0` 仍失败。这是另一条机制，当前补丁没有解决它。

认证流程由 Python 驱动真实 Console HTTP API；IdP 使用一次性合成授权码和自行签发的实验 JWT，没有客户账户。没有执行浏览器页面交互、登出、真实 Keycloak 或生产数据升级测试。TLS 1.3 对照实际协商 TLS 1.3/P-256，不是所有新增后量子曲线的互操作覆盖。

### 修复与回退的取舍

[候选补丁](issue-154/openid-default-curves.patch) 只有三个文件：增加 OpenID 专用 transport helper，将其 `TLSClientConfig.CurvePreferences` 设为 `nil`，再替换 IAM 初始化和 OpenID 配置校验两个调用点。测试时仅应用于隔离源码副本，当前产品工作区未应用；Go 版本与所有依赖保持不变。它让 Go 默认策略和现有兼容开关接管外部 IdP 的密钥交换，其他 TLS 参数继续来自现有构造函数。

如果客户证据确认此分支，建议采用该局部修复，并在客户实际入口复验。如果客户没有设置 `tlsmlkem=0`，它不能单独解释旧版成功：旧版默认也发送 ML-KEM。此时应继续区分 ML-DSA、其他握手变化、HTTP/WAF 规则与网络路径；不把此补丁直接宣称为 #154 的完整修复。

**不建议将当前产品直接改回 Go 1.26。** 实测以 Go 1.26.7 和 `GOTOOLCHAIN=local` 读取当前源码即被 `go.mod requires go >= 1.27.1` 拒绝；所固定的 Server、Console、mc 均声明 Go 1.27.1。回退需要进一步调整这些模块及可能的传递依赖，不是只换一个编译器版本。这个报错证明当前依赖图不能原样回编，并不证明经过额外适配后绝对无法回编。报告中已恢复服务的旧版可作为临时运行状态，不能把这种处置等同于完成兼容修复。

第二轮的运行脚本是 [run-linux.py](issue-154/run-linux.py)，结果是 [linux-evidence.json](issue-154/linux-evidence.json)，具体构建和运行步骤见文末。没有 issue 评论、提交、推送、合并或发布。

候选副本另通过 Go 1.27.1、darwin/arm64、CGO 关闭的 `go test -mod=readonly -count=1 ./internal/http ./internal/config/identity/openid`；补丁可以干净应用到调查基线。这些包级测试与上述 Linux 集成验证分别记录，不将其当成 Linux 单元测试结果。

## 范围、版本与公开证据

- 初始工作区干净，处于 detached HEAD；调查分支为 `codex/investigate-oidc-154`，基线与远端 main 均为 `d1105bbb3d4a0afa33b3a4ac11b821235038ed0e`。
- 已读取 `/Users/vonng/pgsty/silo/AGENTS.md` 及工作区适用说明。维护范围为 PGSTY 的 Server、Console、mc、silo-pkg；上游 MinIO 仅作参考。
- 第一轮 Server 与 transport 探针为本地源码构建的 darwin/arm64 程序，第二轮完整 Server 交叉构建为 linux/arm64；均使用 `CGO_ENABLED=0 GOWORK=off`。fixture 与 Admin 辅助程序也由本机 Go 构建。历史源码使用 `git archive` 导入隔离临时目录。没有下载或运行 Server/Console Docker 镜像，没有访问客户端点，没有改动真实服务或数据，没有评论 issue、推送、合并或发布。
- 产品源码、`go.mod`、`go.sum` 未修改。本目录中的 Go 文件是显式运行的调查工具，带 `//go:build ignore`，不进入正常构建。

| 项目 | 旧版：2026-08-04 | 报告故障版：2026-09-03 | 调查时 main |
| --- | --- | --- | --- |
| 完整 tag | `RELEASE.2026-08-04T00-00-00Z` | `RELEASE.2026-09-03T13-18-01Z` | 无新 release 声明 |
| 源码 commit | `d88f46ccee345a9c2fabe2d221d9a9e56bc11aec` | `9b11dc9469e650815b775cb47b039610644f5da4` | `d1105bbb3d4a0afa33b3a4ac11b821235038ed0e` |
| go.mod / Docker 构建定义 | Go 1.26.5 | Go 1.27.1 | Go 1.27.1 |
| 本地 Server / 探针实际编译器 | Go 1.26.5 | Go 1.27.1 | Go 1.27.1 |
| Console replacement | `v0.0.0-20260804042150-b952a1202869` | `v0.0.0-20260903111932-464a59d73ada` | `v0.0.0-20260908142700-c103d08ec36a` |
| mc replacement | `v0.0.0-20260801042411-ad10a2a10b76` | `v0.0.0-20260903063637-a2ef95c035d9` | `v0.0.0-20260909015522-fcd5cad8247f` |
| PGSTY silo-pkg | v3.11.0，替换历史 minio/pkg 路径 | v3.13.2，直接依赖 | v3.13.3，直接依赖 |
| coreos/go-oidc/v3 | v3.17.0 | v3.21.0 | v3.21.0 |
| x/crypto | v0.54.0 | v0.56.0 | v0.56.0 |
| x/net | v0.57.0 | v0.58.0 | v0.58.0 |
| x/oauth2 | v0.36.0 | v0.36.0 | v0.36.0 |

版本依据：[旧版 go.mod](https://github.com/pgsty/silo/blob/d88f46ccee345a9c2fabe2d221d9a9e56bc11aec/go.mod)、[故障版 go.mod](https://github.com/pgsty/silo/blob/9b11dc9469e650815b775cb47b039610644f5da4/go.mod)、[本次 main go.mod](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/go.mod)。还核对了各 tag 的 `Dockerfile.goreleaser` 和 release workflow。它们声明相应 Go 构建版本、禁用 CGO；历史归档、本次探针和 Server 均用 `go version -m` 核实实际编译器与 replacement。**这些不是客户实际镜像 digest 或其内二进制的取证，后者仍需 `--version` / build info 确认。**

[Issue #154](https://github.com/pgsty/silo/issues/154) 当前 OPEN，最后更新时间 `2026-09-08T05:30:42Z`，评论数为 0。报告包含升级后 Server 初始化失败、旧版回退恢复、测试实例添加 OIDC 失败，以及 curl 成功的输出。

curl 那次连接验证了所收到的证书链，并选择 TLS 1.2、`ECDHE-RSA-AES256-GCM-SHA384`、P-256 和 HTTP/2；解析得到两个 IPv4，记录中实际访问了其中一个。**公开命令使用 `docker run --rm` 新建容器，并非 `docker exec` 进入原故障容器；同镜像不能证明同网络命名空间、环境变量、CA 挂载、DNS 结果或出口。** 域名、realm、IP 已脱敏，本次不推测其真实值。

## 实际请求链

### IAM 与配置校验

```text
Server startup
  IAMSys.Init
    openid.LookupConfig
      parseDiscoveryDoc: GET .well-known/openid-configuration
      PopulatePublicKey: GET discovery 中的 jwks_uri
    IAM store 初始化
    Console 初始化

Console 添加 OIDC
  AdminClient.AddOrUpdateIDPConfig
    Server addOrUpdateIDPHandler
      validateConfig(identity_openid)
        同一个 openid.LookupConfig / NewHTTPTransport
```

`parseDiscoveryDoc` 是 SILO 自己的实现，用标准库 `http.Client` 发 GET，收到成功响应后才解码 JSON；这次日志中的 `Get ... read tcp ... reset` 发生在该调用返回响应之前，不能进一步区分 TLS 与 HTTP。请求本身不需要客户 client secret、token 或私钥。[IAM 调用点](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/iam.go#L278-L288)、[discovery 实现](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/internal/config/identity/openid/jwt.go#L261-L285)、[JWKS 实现](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/internal/config/identity/openid/jwt.go#L89-L110)。

Console 的添加表单通过 Admin API 触发 Server 配置校验。校验成功才写入配置；本地已重现该 API 返回同样的 reset，恢复 IdP 后再次创建成功并要求重启。[Console 调用](https://github.com/pgsty/silo-console/blob/c103d08ec36a/api/admin_idp.go#L79-L114)、[Admin 客户端](https://github.com/pgsty/silo-console/blob/c103d08ec36a/api/client-admin.go#L593-L595)、[Server 校验和保存边界](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/admin-handlers-idp-config.go#L127-L150)、[OpenID 配置校验](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/config-current.go#L353-L359)。

`coreos/go-oidc.NewProvider` 在 Server 中的使用是 `MockOpenIDTestUserInteraction` 测试辅助函数，不是这次 IAM discovery 调用链。升级此依赖不能单独解释或修复该 GET。`crypto/tls` 和这里的 `net/http` 属于 Go 标准库，不能用 go.mod 中 `x/crypto`、`x/net` 的版本代替它们的实际行为。[辅助函数](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/utils.go#L994-L1012)。

### transport 参数与环境

| 项目 | 实际行为及意义 |
| --- | --- |
| 构造 | `NewHTTPTransport()` → `NewHTTPTransportWithTimeout(time.Minute)` → `xhttp.ConnSettings`。每次 IAM 初始化重试都会重新构造。 |
| TLS 版本 | 未显式设置 Min/Max；所比较 Go 工具链的正常默认范围是 TLS 1.2–1.3。证书、主机名验证开启。 |
| 密码套件 | 显式 `TLSCiphersBackwardCompatible()`，包含 curl 成功使用的 ECDHE-RSA/AES-256-GCM。没有理由为本 issue 添加旧 RSA、3DES 或 SHA-1 例外。 |
| 曲线 | 显式 `{X25519MLKEM768, P256, X25519, P384, P521}`，两个 release 和当前 main 相同。实际上线顺序还受 Go 实现控制，见实验。 |
| ALPN / HTTP | `EnableHTTP2=false`，同时设置自定义 TLS config 和 DialContext；实测 ClientHello 没有 ALPN，GET 使用 HTTP/1.1。三个版本一致。`GODEBUG=http2client=0` 对此基线路径无修复价值。 |
| 代理 | `http.ProxyFromEnvironment`；HTTPS URL 使用 `HTTPS_PROXY` / `https_proxy` 与 `NO_PROXY` / `no_proxy`。这两版标准库均优先非空大写值，不使用 `ALL_PROXY`；设置在进程内缓存。不能根据 curl 的路由推断它。注意 go.mod 的 x/net v0.58.0 代码不是这里所用的标准库 vendored 实现。 |
| DNS | `globalDNSCache.LookupHost`，dnscache v0.1.1；默认刷新窗口在容器/Kubernetes 为 30 秒，其他环境为 10 分钟，可配置。按返回地址逐个尝试 TCP，首次 TCP 成功就返回；随后 TLS/HTTP 失败不会回到这个循环尝试另一 IP。代码注释称随机选择，但该循环没有 shuffle。 |
| Linux TCP 参数 | 使用 SILO 的自定义 dialer，包含 TCP fast open/keepalive 等设置，部分参数来自 Server CLI，包括 interface、buffer、user timeout。第二轮执行了完整 Linux Server 的正常 CLI 初始化，但只验证 loopback；不能排除实际出口设备、路由或非默认 CLI 参数的交互。 |
| CA | `silo-pkg/certs.GetRootCAs` 加载系统根、Kubernetes CA 目录和 `certs/CAs`；Server 还加入自己的公开服务证书。相关 pkg CA 加载实现未在这次版本比较中变化；实际文件和路径仍可能因部署变化不同。 |
| 超时 | TCP 拨号 5 秒，TLS 握手 10 秒，响应头 1 分钟；discovery/JWKS 的 Client 没有总超时，discovery 使用的 Request 也没有调用方 context。响应体停滞不受响应头超时保护。 |
| 复用 | keep-alive 开启，idle 15 秒，TLS session cache 100。一次初始化内 discovery 与 JWKS 可复用连接；初始化重试的新 transport 没有旧连接或 session。持续首次握手失败不能用清理空闲连接解释。 |
| 请求标识 | UA 包含产品、OS、架构、模式和构建信息，产品名从 `MinIO` 变为 `Silo`；传输层禁用自动压缩。UA 规则只能在 HTTPS 被终止、HTTP 请求可见之后起作用。 |

源码：[构造与超时](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/utils.go#L651-L670)、[HTTP/TLS 参数](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/internal/http/transports.go#L44-L94)、[密码套件与曲线](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/internal/crypto/crypto.go#L52-L78)、[DNS 拨号循环](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/internal/http/dial_dnscache.go#L42-L84)、[缓存刷新](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/common-main.go#L551-L578)、[CA 加载](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/server-main.go#L383-L395)、[UA](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/update.go#L228-L266)。

比较旧 tag 与故障 tag，OpenID discovery、transport、曲线实现的变动仅为 pkg 导入路径调整；IAM 另有品牌日志变更。比较故障 tag 与本次 main，这些关键实现没有变动。因此不能把当前依赖推进当成 #154 已解决的证据。

**Console 登录阶段是另一条出站路径。** 当前及故障版 Console 通过 `GetConsoleHTTPClient` / `GlobalTransport` 再获取 discovery、交换令牌，TLS config 未指定 CurvePreferences，仍做完整证书验证；不能把“添加配置走 Server”推广为所有 Console OIDC 请求都走 Server transport。任何修复最终都必须验证完整登录。`CONSOLE_MINIO_SERVER_TLS_SKIP_VERIFY` 只针对 SILO 端点，不能作为 IdP 修复。[Console transport](https://github.com/pgsty/silo-console/blob/c103d08ec36a/api/config.go#L68-L121)、[IdP 客户端](https://github.com/pgsty/silo-console/blob/c103d08ec36a/api/tls.go#L59-L70)、[Console discovery](https://github.com/pgsty/silo-console/blob/c103d08ec36a/pkg/auth/idp/oauth2/provider.go#L428-L449)。

## 本地实验与能排除的假设

工具与原始结果放在 [issue-154/](issue-154/)：

- `probe.go` 直接调用 `cmd.NewHTTPTransport()`，用同版本 `certs.GetRootCAs` 装入实验 CA；记录 TCP、TLS、HTTP 阶段。诊断参数仅修改被比较的一项。
- `fixture.go` 仅监听 IPv4 loopback；使用即时生成的 RSA 测试证书与专用 CA，提供 discovery 和有效 JWKS。正常基线限制 TLS 1.2、P-256、`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`，支持 HTTP/1.1 和 HTTP/2。
- `admin-check.go` 仅允许 loopback Server，验证 Console 使用的 Admin API；使用本地虚构配置和临时凭据。
- `evidence.json` 保存版本、握手参数、分阶段 trace 和完整 Server 实验结果；无客户信息、私钥或 token。
- 第二轮扩展 fixture 的合成授权码、token 和 JWKS 流程；`run-linux.py` 驱动 Linux 完整 Server 及 Console API，`linux-evidence.json` 保存十二组场景和构建身份。敏感运行值不写入结果。

### 正常服务及握手差异

三个源码版本的实际 transport 都能通过完整证书验证，以 TLS 1.2 / AES-256-GCM / HTTP/1.1 获取测试文档。**Go 1.27 本身并非不能连接 TLS 1.2、RSA 证书或这套密码套件。** 正常服务也接受诊断性的 HTTP/2。

| 构建与选项 | fixture 读到的初始握手字节数 | 支持的 group ID | 新增 ML-DSA 签名编号 |
| --- | ---: | --- | --- |
| 旧源码 + Go 1.26.5，默认 | 1497 | 4588, 29, 23, 24, 25 | 无 |
| 故障源码 + Go 1.27.1，默认 | 1509 | 同上 | 0x0904, 0x0905, 0x0906 |
| 当前源码 + Go 1.27.1，默认 | 1509 | 同上 | 同上 |
| 旧源码 + Go 1.26.5，`tlsmlkem=0` | 275 | 29, 23, 24, 25 | 无 |
| 故障/当前源码 + Go 1.27.1，`tlsmlkem=0` | 1509 | 4588, 29, 23, 24, 25 | 有 |
| 旧源码、旧依赖，只改为 Go 1.27.1 | 1509 | 4588, 29, 23, 24, 25 | 有；`tlsmlkem=0` 也不再移除 4588 |

4588 是 X25519MLKEM768，29 是 X25519，23/24/25 是 P-256/384/521。这些字节数包含本地 fixture 收到的 TLS record，测试 URL 是 IP，没有 DNS SNI；不能直接当成客户网络中的包长或 MTU 证据。默认新旧差异约 12 字节，没有证据支持“本次才突然出现巨大 ML-KEM 握手”的说法。设置上述环境选项时的差异则显著不同。

旧源码保留旧依赖、仅更换 Go 编译器后，行为随编译器变化，隔离了本次发现与 silo-pkg/Console 版本更新之间的关系。Go 1.27 官方说明也明确记录显式曲线配置不再受这些默认值开关限制，并新增 ML-DSA 支持。[Go 1.27 发布说明](https://go.dev/doc/go1.27)。本地进一步核对了两版 `crypto/tls/defaults.go`、`common.go` 的 `curvePreferences`/`supportsCurve` 和 `handshake_client.go`。

### 主动拒绝与对照结果

下列拒绝规则是人为设置的模型，**只证明机制可以产生相同症状，不证明真实 Keycloak 或其入口使用这些规则**。

| fixture 规则 | 对照结果 | 能支持的结论 |
| --- | --- | --- |
| ClientHello 带 ML-KEM 就发送 TCP RST | 旧版默认也失败；旧版 + `tlsmlkem=0` 成功；故障版 + 同选项失败；故障版显式 classical 曲线成功 | 需要旧环境选项或其他变化，才能用该机制解释升级回归。仅说 ML-KEM 不兼容不充分。 |
| ClientHello 带 ML-DSA 编号就 RST | 旧版默认成功；故障版默认/仅 classical 都失败；故障版 TLS 1.2-only 成功 | 新的签名算法列表是另一种可区分机制。ML-DSA 与 ML-KEM 不是同一项。TLS 1.2-only 会同时改变多项 ClientHello，成功不等于唯一定位 ML-DSA。 |
| 必须提供 h2 ALPN | 旧、新 Server transport 默认都失败；`-h2` 成功 | 可以解释 curl 与 Server 的不同，单独不能解释新旧版本差异。 |
| TLS 完成后，对 `Silo` UA 的 GET 发送 RST | 同一个新 transport，`MinIO` UA 成功、`Silo` UA 失败 | 报告的外层 `Get ... reset` 错误也可能来自 HTTP 层，必须先判断 TLS 是否完成。 |
| 不信任测试 CA | 返回 `*tls.CertificateVerificationError` / x509 类错误 | 与人为 RST 的错误不同；没有证据要求跳过证书验证。仍须比较客户实际连接收到的链。 |
| 正常连接复用 | 第二个请求 `reused=true`；关闭 idle 连接后重新建 TCP 可恢复 TLS session | keep-alive 与 TLS session 复用是两件事。首次新 transport 就失败时，此分支优先级低。 |

### 完整 Server、IAM 和恢复

使用三个本地编译的完整 Server，独立空数据/配置目录、独立 CA 和临时凭据；未登录真实 IdP。

| 场景 | 实际结果 |
| --- | --- |
| 旧版、故障版连接正常 IdP | discovery + JWKS 成功；一条 TLS 连接；cluster health 200；Console HTTP 200；Admin ListUsers 成功。 |
| 当前版连接持续 reset 的 IdP | IAM 持续等待；cluster health 503，`X-Minio-Server-Status: iam-offline`；Console 端口尚未提供服务；5 秒限时的 Admin ListUsers 未完成。 |
| 上述场景恢复 IdP，不重启 Server | 约 0.43 秒后 cluster/Console 200，ListUsers 成功。该时间是单次本地样本，不是恢复 SLA。 |
| 旧版 + `tlsmlkem=0`，IdP 拒绝 ML-KEM | 完整启动成功。 |
| 故障版 + `tlsmlkem=0`，相同拒绝规则 | IAM 等待、cluster 503；撤掉规则后约 1.38 秒内完整恢复，无需重启。 |
| 当前版 discovery 成功、JWKS 返回 503 | 同样阻塞 IAM；JWKS 恢复后约 0.33 秒内恢复。只验证 discovery 200 不够。 |
| 当前版先不配置 OIDC，再经 Admin API 添加 | IdP reset 时返回同型 `Get ... read tcp ... connection reset by peer`；恢复后同名创建成功，`restart=true`。失败校验没有保存该 provider。 |

在本地 IAM 阻塞的场景中，`/minio/health/live` 和 `/minio/health/ready` **仍为 200**。判断这次恢复应使用 `/minio/health/cluster` 并验证受认证操作和 Console，不能只看 ready。源码上 cluster 的 `checkHealth` 检查 IAM，而 ready 没有此检查；这是已有行为，本文不扩展为一次健康检查重构。[health 检查](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/healthcheck-handler.go#L32-L65)、[ready 检查](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/healthcheck-handler.go#L129-L186)。

现有 IAM 重试间隔随机为 0–3 秒，GET 本身还会占用网络等待时间；初始化成功前不会继续创建 IAM store，Console 又在 IAM 调用返回后启动。外部连接恢复可由现有重试自行恢复；这不意味着靠增加重试能修复持续不兼容。缺少整体请求期限、请求取消的部分是另外一个可单独修复的启动健壮性问题。[重试逻辑](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/iam.go#L342-L365)、[Console 启动顺序](https://github.com/pgsty/silo/blob/d1105bbb3d4a0afa33b3a4ac11b821235038ed0e/cmd/server-main.go#L1007-L1027)。

已通过：`CGO_ENABLED=0 GOWORK=off go test -mod=readonly -count=1 ./internal/http ./internal/config/identity/openid`。这些测试没有替代真实 Keycloak 登录或 Linux 故障网络的验证。

## 最少补充证据与诊断命令

先收集第一轮，按结果才展开后续。所有请求只取公开 discovery，不需要客户端密钥、密码、token 或私钥。不要求环境变量全量导出、配置导出或证书私钥。

### 第一轮：运行身份、网络一致性、协议阶段

在**已有故障容器/Pod 的实际网络环境**中运行；旧版也做同样检查。不要以新建默认网络容器替代。如果实际进程经启动脚本修改过环境，探针也应使用修改后的相关环境和同一 CA 挂载。

```sh
# 选择实际 Server 可执行文件；记录输出中的版本、Go、OS/架构。
silo --version
# 旧镜像的程序名可能是 minio。

# Linux：PID 设为实际 Server 进程 PID，不预设一定是 1。
# 只输出 Go 调试选项以及相关环境项是否存在，不输出代理凭据/地址。
tr '\0' '\n' < "/proc/$PID/environ" | awk '
  /^GODEBUG=/ { print; next }
  /^(HTTP_PROXY|HTTPS_PROXY|NO_PROXY|ALL_PROXY|http_proxy|https_proxy|no_proxy|all_proxy|SSL_CERT_FILE|SSL_CERT_DIR)=/ {
    split($0, a, "="); print a[1] "=<set>"
  }'

# OIDC_URL 仅在本地设为原 config_url；URL 不应带凭据或令牌。
export OIDC_URL
curl --http1.1 --connect-timeout 5 --max-time 20 -sS -o /dev/null \
  -w 'ip=%{remote_ip} http=%{http_version} status=%{http_code} verify=%{ssl_verify_result}\n' "$OIDC_URL"
curl --http2 --connect-timeout 5 --max-time 20 -sS -o /dev/null \
  -w 'ip=%{remote_ip} http=%{http_version} status=%{http_code} verify=%{ssl_verify_result}\n' "$OIDC_URL"

# 由维护者从对应源码构建的探针；OIDC_CA 是与 Server 相同的 CAs 目录。
./oidc-probe -ca "$OIDC_CA"
```

探针从 `OIDC_URL` 读取 URL。URL、响应体、请求头不会打印；输出的 IP 可按一致映射替换为 IP-A/IP-B。它使用真实 Server transport 构造函数，但添加 20 秒总期限、不跟随重定向、限制响应体读取为 1 MiB，并使用 `issue-154-probe` UA；因此是定位连接阶段的工具，不是完整 OIDC 流程。它没有执行 Server 的 CLI 初始化，也不继承该进程的 `--interface`、socket buffer、TCP user timeout 或存量 DNS 缓存；若使用这些非默认参数，必须对齐后才能归因。若 Server 将自己的公开服务证书也作为根信任，需要把相同公开证书加入探针的临时 CA 目录。

读结果的方法：

- `tls_start` 后 `tls_done ... err=reset`：先查 TLS ClientHello、代理 CONNECT 或 TLS 终止设备；尚不能从客户端确定 RST 由终端还是中间设备发出。
- `tls_done ... err=none`、`wrote_request` 后 reset：检查 HTTP/WAF/UA/入口路由。此时更换证书信任或密钥交换没有针对性。
- 出现 x509 类错误：比较该进程实际收到的证书链、SNI、系统 CA 和自定义 CA；保持验证开启。
- 两次 curl 的 IP 不同，或探针目标与 curl 不同：先做同 IP 对照。curl HTTP/1.1 成功也不代表 Go ClientHello 相同。
- 仅 curl h2 成功：确认实际协商的 `http_version` 是 2，再检查入口 HTTP/1.1 支持；不要先全局启用 Server HTTP/2。

### 只对命中的分支做 A/B

```sh
# TLS 阶段失败：仅移除 hybrid key exchange，仍支持 TLS 1.3 和验证证书。
./oidc-probe -ca "$OIDC_CA" -classical

# 如果旧进程确实使用 tlsmlkem=0，验证最小候选是否恢复其效果。
# 应保留原 GODEBUG 的其他相关选项；以下假定没有需要保留的其他值。
GODEBUG=tlsmlkem=0 ./oidc-probe -ca "$OIDC_CA" -default-curves

# 只有 classical 仍失败时，作为鉴别实验测试 TLS 1.2-only。
./oidc-probe -ca "$OIDC_CA" -tls12

# 只有 HTTP/ALPN 对照指向此分支时才测试。
./oidc-probe -ca "$OIDC_CA" -h2

# HTTP 阶段才失败：UA_OLD / UA_NEW 是两版实际请求的完整 UA，非密钥。
./oidc-probe -ca "$OIDC_CA" -ua "$UA_OLD"
./oidc-probe -ca "$OIDC_CA" -ua "$UA_NEW"
```

若 first-hop 使用代理，先比较两进程的代理选择和 `NO_PROXY`，不公开含密码的代理 URL。只在明确允许直连的部署中使用 `-direct`。确认直连后，可针对每个 DNS 地址运行以下两项，保留原 URL 主机名与 SNI，不能直接把 HTTPS URL 改成 IP：

```sh
curl --noproxy '*' --resolve "$OIDC_HOST:443:$IP_A" --http1.1 \
  --connect-timeout 5 --max-time 20 -sS -o /dev/null \
  -w 'ip=%{remote_ip} status=%{http_code} verify=%{ssl_verify_result}\n' "$OIDC_URL"
./oidc-probe -ca "$OIDC_CA" -direct -ip "$IP_A"
# 对 IP-B 重复；端口不是 443 时据实修改 --resolve。
```

仅第二次请求失败时才补 `-n 2` 与 `-n 2 -fresh`；后者重建 TCP，但同一 transport 的 TLS session cache 仍保留。若仍无法区分，下一步要的是入口侧同一时间窗口的握手失败原因/命中规则，或由客户自行脱敏后的 ClientHello 参数和 RST 阶段，不是完整认证流量包。

## 条件性最小修复方案

### 1. 路由、代理或入口策略差异已证实

优先统一有问题的 IdP 入口、修正具体域名的代理/NO_PROXY 或后端节点配置；更新错误拒绝合法 ClientHello 的 TLS 终止器/WAF。证书仍按原 hostname 和有效 CA 验证，OIDC issuer 不随意改名。若是 `Silo` UA 被规则拒绝，调整该规则；不把全产品 UA 改回 MinIO。

这是配置层处理，可以不改 SILO。工作量取决于入口归属；成功标准是原版故障二进制在原网络环境中完成 discovery、JWKS 和完整登录，而非仅 curl 200。

### 2. 证实旧环境依赖 `tlsmlkem=0`，且 classical / default-curves 对照成功

最小代码候选是为外部 OpenID 请求使用 Go 的默认曲线集合，恢复已有 GODEBUG 选项的效果；保留当前 trust pool、SNI、密码套件、超时、代理及 HTTP/1.1 行为。候选代码如下，**已在隔离副本完成上述验证，尚未应用到产品工作区**：

```go
func NewOpenIDHTTPTransport() *http.Transport {
    tr := NewHTTPTransport()
    tr.TLSClientConfig.CurvePreferences = nil
    return tr
}
```

当时的候选只将 `cmd/iam.go` 和 `cmd/config-current.go` 两处 OpenID 调用改用该 helper，通过现有 UA wrapper 传入 `openid.LookupConfig`。后续排查确认节点互联、复制、远端存储等连接也存在同样的问题，此局部方案已被 [SILO 跨组件修复](go127-stack.md) 取代；请勿再应用下面归档的 OIDC-only 补丁。

候选已在真实 transport 探针及第二轮完整 Linux Server 中验证：`CurvePreferences=nil` + Go 1.27.1 + `tlsmlkem=0` 会移除 ML-KEM，并通过 `reject-mlkem` fixture、配置添加和合成登录。它仍不能通过 `reject-mldsa` fixture，说明此方案针对的是一个明确分支。

影响需要明确：

- 不设置 GODEBUG 时会采用完整 Go 默认集合，实测额外提供 SecP256r1MLKEM768 和 SecP384r1MLKEM1024；这也是一项兼容性变化。第二轮默认 TLS 1.3 登录通过，仍不能称为完全无行为变化或所有曲线均已覆盖。
- `GODEBUG` 是进程级设置，其他使用 Go 默认曲线的客户端也可能受到影响；本次 helper 的改动范围是 OpenID，但该环境选项本身不是逐 provider 开关。
- 禁用 hybrid 后仍有标准 ECDHE/TLS 和证书验证，失去的是相应后量子密钥交换保护。优先修正入口，临时兼容设置应有撤销条件；不能自动遇到 reset 就降级重试。
- 当前 Console IdP transport 本来使用默认曲线，同一进程中的该 GODEBUG 策略可以与之保持一致；第二轮合成登录链路已经验证，真实 IdP 和浏览器验收仍待进行。
- 隔离源码副本中的候选实现及上述本地验证已完成；真实端点 A/B 证据、生产适用性和发布是尚未完成的步骤。

### 3. 未设置上述选项，或 classical 仍失败

不要套用方案 2。若同 IP、同代理、同 UA 下仅 Go 1.27 失败，优先收集入口对新签名算法/扩展的处理证据。`-tls12` 成功只能缩小到 ClientHello/TLS 特征集合；它同时移除 hybrid key share 和 TLS 1.3 特有签名编号，不能唯一证明 ML-DSA。

优先更新入口或获得 Go 上游可复现用例。只有真实证据证明 TLS 1.2 兼容模式是必要且有效、入口又短期无法处理时，才评估**明确限定于该 IdP**的临时 TLS 1.2 选项，并保留现代 ECDHE/AEAD 和证书验证。不要把 `MaxVersion=TLS12` 全局写死，不引入自定义 ClientHello/TLS 栈或未受支持的“关闭 ML-DSA”环境选项。该分支尚不足以确定补丁或工期。

### 4. 启动健壮性可单独改进

如需小幅改善可诊断性，应单独给 discovery/JWKS 加明确阶段标识和有限总请求期限，让 IAM 重试可感知取消；在请求完成前发生 stall 时及时释放资源。日志避免输出 client secret/token，错误保留原始 cause。保留已配置 OIDC 的失败关闭行为及 IdP 恢复后的自动初始化，不自动关闭 OIDC，也不把无限重试包装成根因修复。

这类改动约 0.5–1 个工程日，可分别回归 stalled body、取消、重试后恢复；它不会使持续 RST 的 TLS 连接成功，不应替代前面鉴别。

## 临时处置与验收边界

当前可沿用报告中已经恢复服务的旧版回退状态，尽快完成上述定位。不要将旧版本长期保留视为解决方案，也不要为了它整体降级新版本依赖。本次空数据实验不证明任意生产数据/配置的降级兼容；再次切换版本前应沿既有备份和升级边界操作。

修复应按以下范围验证，均从 PGSTY 源码本地构建：

1. 对确认的分支增加最小回归：实际 OpenID transport、匹配的 ClientHello/入口拒绝条件、默认设置与明确 opt-out；确保通用和 internode transport 不变。
2. TLS 1.2（报告密码套件）与 TLS 1.3、有效自定义 CA、错误 CA 和 hostname 拒绝；适用时覆盖代理及多地址入口。不放宽证书、JWT 签名或 audience 等认证校验。
3. 完整 Server 的 discovery 与 JWKS、IdP 中断后恢复、cluster health、受认证 Admin 操作；Console 添加配置、浏览器重定向、回调、令牌交换、STS 授权和登出。mc 添加/读取配置路径应一致。
4. 在实际 Linux 容器/Pod 网络和每个 IdP 入口地址复验。证据应绑定最终 Server/Console/pkg/mc commit 和编译器；发布、镜像及生产可用性属于后续独立验收。

第二轮完成 Linux loopback 上的合成 OAuth token/STS 登录；本次没有真实 Keycloak、真实 Linux 故障路径、浏览器页面或生产数据升级测试。当前 main 对正常 fixture 成功，并不能据此宣告 #154 修复。下一项最有价值的新增证据是**实际进程的 `tlsmlkem` 设置和一个带 TLS 完成事件的同环境 GET trace**。

## 复现实验

从本任务 worktree 根目录执行；工具均使用本地源码，输出目录必须是新建临时目录。

```sh
LAB_DIR=$(mktemp -d)
CGO_ENABLED=0 GOWORK=off go build -mod=readonly -tags kqueue \
  -o "$LAB_DIR/silo" .
CGO_ENABLED=0 GOWORK=off go build -mod=readonly -tags kqueue \
  -o "$LAB_DIR/probe" docs/investigations/issue-154/probe.go
go build -o "$LAB_DIR/fixture" docs/investigations/issue-154/fixture.go
go build -mod=readonly -o "$LAB_DIR/admin-check" docs/investigations/issue-154/admin-check.go
"$LAB_DIR/fixture" -dir "$LAB_DIR/idp" > "$LAB_DIR/hello.jsonl" 2> "$LAB_DIR/fixture.log" &
FIXTURE_PID=$!
trap 'kill "$FIXTURE_PID" 2>/dev/null || true' EXIT
attempt=0
while [ ! -s "$LAB_DIR/idp/url" ] && [ "$attempt" -lt 50 ]; do
  sleep 0.1
  attempt=$((attempt + 1))
done
test -s "$LAB_DIR/idp/url" || exit 1
# 私钥仅保存在 fixture 内存。
OIDC_URL="$(cat "$LAB_DIR/idp/url")/.well-known/openid-configuration"
export OIDC_URL
"$LAB_DIR/probe" -ca "$LAB_DIR/idp/ca.pem"
printf '%s' reject-mlkem > "$LAB_DIR/idp/mode"
GODEBUG=tlsmlkem=0 "$LAB_DIR/probe" -ca "$LAB_DIR/idp/ca.pem"
GODEBUG=tlsmlkem=0 "$LAB_DIR/probe" -ca "$LAB_DIR/idp/ca.pem" -default-curves
printf '%s' reject-mldsa > "$LAB_DIR/idp/mode"
"$LAB_DIR/probe" -ca "$LAB_DIR/idp/ca.pem" -classical
"$LAB_DIR/probe" -ca "$LAB_DIR/idp/ca.pem" -tls12
kill "$FIXTURE_PID"
```

完整 Server 实验使用上述临时目录下的 `certs/CAs` 和数据目录，设置虚构的 `MINIO_IDENTITY_OPENID_CLIENT_ID`、fixture URL、临时 root 凭据，并显式指定 `--config-dir`、`--certs-dir`、loopback API/Console 地址。用 mode 文件切换 `reset`/`bad-jwks` 到 `normal`，同时检查 cluster health 和 Admin ListUsers；结果已保存在 `evidence.json`。`admin-check add` 只操作 `LAB_SERVER=127.0.0.1:port` 的实验实例，读取临时 `LAB_USER`、`LAB_PASSWORD`、`LAB_OIDC_URL`，使用虚构 OIDC secret。

跨版本构建时从各 tag `git archive` 获取源码，把 `probe.go` 放入该 module 根目录；旧版探针仅将 certs 导入替换为 `github.com/minio/pkg/v3/certs`，由旧版 go.mod 选择 PGSTY v3.11.0。分别强制 `GOTOOLCHAIN=go1.26.5` / `go1.27.1`，使用 `-mod=readonly`，不修改历史 go.mod。另将旧源码原依赖用 Go 1.27.1 构建，隔离工具链因素。若为 Linux 客户端构建探针，按已确认的架构设置 `GOOS=linux GOARCH=amd64` 或 `arm64`，不使用 Server 镜像代替。

### 第二轮 Linux 完整 Server 对照

从本任务根目录运行以下 Bash 命令。需要预先准备 Go 1.26.5、1.27.1 及源码依赖缓存，以及带 Python 3、curl/OpenSSL/HTTP2 的通用 Linux 基础镜像。`GOTOOLCHAIN` 明确选定编译器，`-mod=readonly` 保留依赖版本；实际测试构建用已安装工具链的绝对路径配合 `GOTOOLCHAIN=local`，等价地避免自动切换编译器。以下固定 `arm64` 与本次实验一致。

```bash
LAB_DIR=$(mktemp -d)
mkdir -p "$LAB_DIR/old" "$LAB_DIR/head" "$LAB_DIR/candidate" "$LAB_DIR/bin" "$LAB_DIR/out"
git archive d88f46ccee345a9c2fabe2d221d9a9e56bc11aec | tar -x -C "$LAB_DIR/old"
git archive d1105bbb3d4a0afa33b3a4ac11b821235038ed0e | tar -x -C "$LAB_DIR/head"
git archive d1105bbb3d4a0afa33b3a4ac11b821235038ed0e | tar -x -C "$LAB_DIR/candidate"
git -C "$LAB_DIR/candidate" apply "$PWD/docs/investigations/issue-154/openid-default-curves.patch"

(cd "$LAB_DIR/old" && CGO_ENABLED=0 GOWORK=off GOOS=linux GOARCH=arm64 \
  GOTOOLCHAIN=go1.26.5 go build -mod=readonly -tags kqueue -o "$LAB_DIR/bin/old-go126" .)
(cd "$LAB_DIR/old" && CGO_ENABLED=0 GOWORK=off GOOS=linux GOARCH=arm64 \
  GOTOOLCHAIN=go1.27.1 go build -mod=readonly -tags kqueue -o "$LAB_DIR/bin/old-go127" .)
(cd "$LAB_DIR/head" && CGO_ENABLED=0 GOWORK=off GOOS=linux GOARCH=arm64 \
  GOTOOLCHAIN=go1.27.1 go build -mod=readonly -tags kqueue -o "$LAB_DIR/bin/head-go127" .)
(cd "$LAB_DIR/candidate" && CGO_ENABLED=0 GOWORK=off GOOS=linux GOARCH=arm64 \
  GOTOOLCHAIN=go1.27.1 go build -mod=readonly -tags kqueue -o "$LAB_DIR/bin/candidate-go127" .)
CGO_ENABLED=0 GOWORK=off GOOS=linux GOARCH=arm64 GOTOOLCHAIN=go1.27.1 \
  go build -mod=readonly -o "$LAB_DIR/bin/fixture" docs/investigations/issue-154/fixture.go
CGO_ENABLED=0 GOWORK=off GOOS=linux GOARCH=arm64 GOTOOLCHAIN=go1.27.1 \
  go build -mod=readonly -o "$LAB_DIR/bin/admin-check" docs/investigations/issue-154/admin-check.go

# 本机已存在的通用 Debian 12 arm64 基础镜像；不拉取镜像，不映射端口。
LINUX_BASE_IMAGE=sha256:307af7711e2e04ab75759cb42a1eef45c43c4404894c0e30dd19f742b107b922
docker run --rm --pull=never --network none \
  --mount "type=bind,source=$LAB_DIR/bin,target=/lab/bin,readonly" \
  --mount "type=bind,source=$LAB_DIR/out,target=/lab/out" \
  --mount "type=bind,source=$PWD/docs/investigations/issue-154/run-linux.py,target=/lab/run-linux.py,readonly" \
  --entrypoint python3 "$LINUX_BASE_IMAGE" /lab/run-linux.py
```

每组场景输出一行摘要，同时在独立输出目录保存 `result.json`。脚本用 `finally` 终止其 Server/fixture，容器结束自动删除。它没有导出会话 cookie、授权码、JWT、state 或临时密码；原始运行目录只用于该次隔离实验，交付证据只保留握手、结果和构建身份。
