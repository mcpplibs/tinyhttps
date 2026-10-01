# 执行计划 —— 0.3.4：在途请求可取消，三个入口一致，CI 覆盖库支持的全部平台

| | |
|---|---|
| 输入 | [`design-cancel-stop-token.md`](design-cancel-stop-token.md)：D1–D4 均按建议采纳 |
| 基线 | `origin/master @ f461940`（0.3.3） |
| 落地 | 全部做在 PR #23 上（`yspbwx2010:feat/cancel`，`maintainerCanModify: true`），squash 合入 |
| 目标版本 | **0.3.4** |
| 跨仓库 | `mcpplibs/tinyhttps` → gitcode `mcpp-res/tinyhttps`（CN 镜像）→ `mcpplibs/mcpp-index` |

---

## 0. 为什么是 0.3.4

- 只新增，不改已有行为：`send`、`send_stream`、`download_to_file` 都只加了尾部默认参数；`HttpResponse` 和 `DownloadToFileResult` 各在末尾追加一个字段；不传 token 时逐字节不变（不变式 I3）。
- 依赖写成 caret 范围 `tinyhttps = "^0.3.0"` 的项目会自动解析到它。**更正（发布后实测）：** mcpp 里裸写的 `"0.3.1"` 是精确版本，不会解析到 0.3.4；`"0.3.x"` 不是 mcpp 的合法写法。0.3.3 的发布说明里也沿用了这个说法。已用已发布的 index 实测：`"^0.3.1"` 在 GLOBAL 和 CN 两个源下都解析到 0.3.4。
- 唯一的源码不兼容点是对 `&HttpClient::send` 取成员函数指针（参数个数变了）。在 CHANGELOG 里点名说明。

## 1. 八个视角

| 视角 | 要求 | 落在哪 |
|---|---|---|
| **架构** | token 存在哪里、存活多久要有规则，不能靠每个调用点自己记得 | I1：只存在传输链最底层的 `Socket`，`TlsSocket` 只往下转发。I2：只在一次调用期间挂着，`PooledConnection::keep()` 把连接还回池时摘下 |
| **稳定性** | 取消不能引发重复执行、fd 泄漏或卡死 | 取消后不重试、不跟重定向；连接 drop；fd 计数测试；复用连接测试覆盖直连、http 代理、https 代理三种 |
| **优雅简洁** | 只有一套机制：在 `wait_fd` 里分片 `poll` | 不引入 pipe、shutdown 或回调；不增加配置项；`proxy_connect` 不加参数 |
| **用户体验** | 用 `std::jthread` 就能直接取消；结果用 bool 判断，不用匹配文本 | README 示例；两个结果结构都有 `cancelled`；README 说明 libc++ ≤22 的工具链问题 |
| **兼容性** | 升级不需要改代码 | §0；`HttpResponse{204, "No Content", {}, {}}` 这种聚合初始化仍然能用（mcpp-index 的测试断言了这一点） |
| **跨平台** | Linux（gcc、libc++）、macOS、Windows（msvc、clang）、openkal（linux-gnu、windows-musl）都要实测 | §4 CI 矩阵；openkal 示例增加一段不联网的取消检查 |
| **一致性** | 三个入口取消语义相同 | `download_to_file` 加 token（D1）；`isCancelled` 保留 |
| **无感升级** | 不传 token 时行为和 0.3.3 一样；不需要改依赖版本号 | I3；0.3.4 是补丁版本 |

## 2. 任务依赖图

```
T0 计划（本文）+ 设计文档纳入 PR
 │
 ├─ T1 src：I1（tls.cppm set_stop 转发给 lower_）
 │   └─ T2 src：I2（http.cppm PooledConnection::keep 时摘下 token）
 │       └─ T3 src：D1 download_to_file(…, stop) + DownloadToFileResult::cancelled
 │           └─ T4 src：D2 proxy_connect 去掉 stop 参数；源码注释
 │
 ├─ T5 测试（可与 T1–T4 并行编写，依赖它们才能通过）
 │     a. 复用连接矩阵：直连 / http 代理 / https 代理 × {旧 token 已 stop, 新 token 生效}
 │     b. SOCKS5 等待握手应答时取消
 │     c. download_to_file：等响应头时取消、读 body 时取消、已 stop 的 token
 │     d. libc++ 下 import std 的位置（M2）
 │
 ├─ T6 openkal：examples/openkal 增加不联网的取消检查（本地监听 + 握手中取消）
 │     运行时版本跟 mcpp-index 的 pins.toml 对齐；增加 windows-musl（Linux 上构建，windows-2022 上原生运行；本地用 wine）
 │
 ├─ T7 CI（依赖 T5d、T6）
 │     linux {gcc@16.1.0, llvm@22.1.8} 跑全部测试 · macos-15 llvm@22.1.8 跑全部测试
 │     windows {msvc, llvm@20.1.7} 跑不联网的测试 · openkal {x86_64-linux-gnu, x86_64-windows-musl}
 │
 ├─ T8 文档：README、CHANGELOG 0.3.4、mcpp.toml version、README 安装行
 │
 └─ T9 合入与发版（依赖全部）
       CI 全绿 → 自审 → squash 合入 → tag 0.3.4 + GitHub release
       → 本地 gtc 上传 gitcode mcpp-res/tinyhttps 的 0.3.4 tarball（核对 sha256）
       → mcpp-index PR：pkgs/t/tinyhttps.lua 加 0.3.4（三个平台），
         tests/examples/tinyhttps 升到 0.3.4 并加取消的 API 检查
       → 用已发布的 index 实测：新建项目解析到 0.3.4，GLOBAL 和 CN 两个源都验证
```

**关键路径**：T1 → T2 → T5 → T7 → T9。T3/T4、T6、T8 可以和关键路径并行。

## 3. 测试清单（test_cancel）

| 用例 | 覆盖 |
|---|---|
| PR 原有 13 个 | 首次建连各阶段、不重试、重定向、fd 泄漏、connect、http/https 代理 |
| `APooledTunnelCarriesNoTokenFromTheLastCall`，参数为直连 / http / https | I1 + I2，H1 的回归测试（一个 POST 只能执行一次） |
| `TheSecondCallsTokenReachesAReusedTunnel`，参数为直连 / http / https | I1 |
| `ASocks5ProxyThatNeverAnswersIsAbandoned` | 代理种类补齐 |
| `ADownloadWaitingForTheHeadersIsAbandoned` / `…ForTheBody…` / `…AlreadyStopped…` | D1 |

## 4. CI 矩阵（目标）

| job | 工具链 | 跑什么 |
|---|---|---|
| linux | gcc@16.1.0 / llvm@22.1.8 | 全部 `mcpp test`（`test_download`、`test_resolver` 需联网）+ 模板冒烟 |
| macos-15 | llvm@22.1.8 | 全部 `mcpp test` |
| windows-2022 | msvc / llvm@20.1.7 | `test_ca_store`，以及不联网的 `test_framing`、`test_pool`、`test_proxy`、`test_cancel`、`test_tls_verify` |
| openkal | llvm@22.1.8 + openkal-llvm-runtime | `examples/openkal` 在 x86_64-linux-gnu 上原生跑、x86_64-windows-musl 在 Linux 上构建、在 windows-2022 上原生跑（CI 装 wine 要 4–30 多分钟，且不稳定）|

某个平台上测试编不过时，**修测试，不删平台**。确实做不到的，单独开 issue 记下原因，并在 job 里写清楚。

## 5. 过程中发现并修复

- **x86_64-windows-musl 上 TLS 从来没通过。** mbedTLS 只有识别到 glibc 才用 `getrandom`，否则读 `/dev/urandom`，而 openkal-windows 没有这个文件。在 musl 平台上改用 musl 的 `getentropy`（`cfg(c-abi = "musl")` → `TINYHTTPS_GETENTROPY`）🔁。
- **Windows 目标没有名字解析**（openkal 没有解析器接口），已登记 [openkal-musl#46](https://github.com/mcpplibs/openkal-musl/issues/46)，README 已注明。
- **`test_pool` 在 Windows 上编不过**（`<windows.h>` 的 `max` 宏），因为以前从没在 Windows 上编译过；已修复。

## 6. 验收

- [x] PR #23 的 CI 全绿（10 个 job，`10e28b0`）
- [x] 自审：H1、M1、M2、D1、D2 全部落地；PR 描述更新
- [x] squash 合入（`156edeb`）；tag `0.3.4`；GitHub release
- [x] gitcode 上的 `tinyhttps-0.3.4.tar.gz` 与 GitHub archive 的 sha256 一致（`26e0e496…41e9`）
- [x] mcpp-index 合入（mcpplibs/mcpp-index#504）；`validate` 和 `openkal-compat`（tinyhttps 这一项，四个 target 均为 runs）通过
- [x] 新建项目用已发布的 index 解析到 0.3.4（`"^0.3.1"`），GLOBAL 和 CN 两个源都能构建并运行，并对 httpbin 做了真实的进行中取消（301 ms）
