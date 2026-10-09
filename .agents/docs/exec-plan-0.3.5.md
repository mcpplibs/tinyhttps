# 执行计划 —— 0.3.5：额外信任的 CA，TLS 握手有时限，Windows CI 恢复

| | |
|---|---|
| 输入 | [PR #24](https://github.com/mcpplibs/tinyhttps/pull/24) `feat/extra-ca-certs @ bd76c9e` · [PR #25](https://github.com/mcpplibs/tinyhttps/pull/25) `fix/tls-handshake-timeout @ cfdab98`（作者都是 yspbwx2010，`maintainerCanModify: true`） |
| 基线 | `origin/master @ 2cc7310`（0.3.4） |
| 落地 | 两个 PR 各自 squash 合入；对 #25 的修正直接追加在 #25 上（已推送 `97a0657`） |
| 目标版本 | **0.3.5**（D1–D4 按建议采纳） |
| 跨仓库 | `mcpplibs/tinyhttps` → gitcode `mcpp-res/tinyhttps`（CN 镜像）→ `mcpplibs/mcpp-index` |
| 文档日期 | 2026-10-10 |

**标注约定**：✅ 已核验源码 · 🔁 已在本地复现或跑通 · ❓ 推断，未实测

---

## 0. TL;DR

- **两个 PR 的方向都对，设计也符合本项目的约定**：只新增、尾部默认参数、新字段放最后、错误写进 `statusText`、状态只放在传输链最底层的 `Socket`（沿用 0.3.4 的 I1）、测试不联网（hermetic）。和业界通行做法也一致（§2）。
- **#24 可以直接合**，不需要追加 commit。剩下几处小问题不影响合入（§3.3）。
- **#25 有一个回归，已修复并推到 PR 上** 🔁：handshake 的等待改成了 `poll`，信号会让它以 EINTR 返回，即使 handler 装的是 SA_RESTART 也一样。结果是装了信号 handler 的进程（profiler、定时器）握手会被误报成 “TLS handshake timed out”。修复前新加的用例在 100 ms 就失败了（时限是 1000 ms）。
- **Windows CI 红是 runner 镜像的变化，和两个 PR 都无关** ✅：win22/20261004.326 带的是 Git for Windows 2.56，原来硬编码的 `mingw64/etc/ssl/certs/ca-bundle.crt` 不存在了。修复已随 #25 一起推送：向 git 查询 bundle 的路径，查不到再在安装目录里搜索。
- **合入顺序是 #25 → #24**：#25 带着 CI 修复，先合入后 master 才能变绿；#24 再同步 master，同时解决 CHANGELOG 的冲突。

### 待你决定

| # | 决策 | 建议 |
|---|---|---|
| D1 | 版本号用 0.3.5 还是 0.4.0 | **0.3.5**。#25 严格说改变了行为（握手超过 `connectTimeoutMs` 会失败），不符合 0.3.4 “补丁版本只新增”的约定。但它修的是一个永久卡死的问题；而且 0.4.0 不会被 `^0.3.x` 解析到，最需要这个修复的正是已经在用 `^0.3.x` 的项目。在 CHANGELOG 里用 “Behaviour change” 单列说明 |
| D2 | `connectTimeoutMs` 继续按阶段各自计时，还是改成整个建连过程共用一个 deadline | **0.3.5 保持按阶段计时**（和现有的代理应答等待一致，PR 已在文档里写明）。共用 deadline 和 curl 的语义一样，更符合直觉，留到 0.4 统一做（§4） |
| D3 | #24 是否同时提供内存中的 PEM（如 `extraCaPem`） | **这次不做**，作为后续单独的一项。路径方式已经覆盖代理、企业 CA 这些主要场景 |
| D4 | `Socket::set_deadline / deadline_hit / wait_before_recv` 都是 public（因为整个类是 export 的） | **接受**。`set_stop / stop_possible` 已经是这样，跨 partition 用 friend 在各家编译器上的风险更大；注释已写明它们是给 TLS 层用的 |

---

## 1. CI 失败分析（run 37911364113 / job 113757995241）

| 项 | 内容 |
|---|---|
| 现象 | `run (x86_64-windows-musl, above openkal, on Windows)` 运行 4 秒后失败：`cp: cannot stat '/c/Program Files/Git/mingw64/etc/ssl/certs/ca-bundle.crt'` ✅ |
| 根因 | runner 镜像从 win22/20260927.320 换成了 win22/20261004.326，Git for Windows 也从 2.55 升到 2.56 ✅。2.56 把环境从 MINGW64 换成了 UCRT64，bundle 现在在 `/c/Program Files/Git/ucrt64/etc/ssl/certs/ca-bundle.crt`（新 CI 日志里打印出来的路径）✅ |
| 影响 | 所有分支的这个 job 都会失败，在 smoke 程序运行之前就挂了。和 #24、#25 的代码都无关 |
| 修复 | 已推送到 #25 的 `bf99dbd`：先用 `git config --system http.sslcainfo` 查路径（经 `cygpath` 转换），查不到就在 `/c/Program Files/Git` 下搜索 `*/ssl/certs/ca-bundle.crt`，还找不到就报 `::error::` 并给出明确原因。同时打印 `git --version` 和最终用到的路径，方便下次镜像再变时定位 |
| 验证 | #25 的 CI run 37968516327：10 个 job 全绿，这个 job 用 `git config` 查到了 ucrt64 下的路径；smoke 输出 `cancellation: ok (stopped at 200 ms, returned after 261 ms)` ✅ |
| 顺带发现 | 这个 job 里 `framing parsers: ok` 和 `cancellation: ok` 之间有约 39 s 的空档，10-05 master 的运行里也有，所以不是这两个 PR 引入的。空档出现在计时开始之前，原因没有查 ❓，列入 §4 |

---

## 2. 设计评审

### 2.1 是否符合本项目的约定

| 约定（来源） | #24 | #25 |
|---|---|---|
| 只新增：尾部默认参数、新字段放最后（0.3.4 §0） | ✅ `extraCaFile` 放在最后；`proxy_tunnel` 加了尾部默认参数 | ✅ `connect_over` 加了尾部默认参数；CHANGELOG 点名说明了成员函数指针的不兼容 |
| 状态只放最底层 `Socket`，`TlsSocket` 只往下转发（0.3.4 I1） | 不涉及 | ✅ `set_deadline` / `deadline_hit` 都经 `lower_` 往下转发，https 代理隧道的情况有测试覆盖 |
| 状态只在调用期间存在（0.3.4 I2） | 不涉及 | ✅ 握手结束就清掉 deadline，有测试覆盖 |
| 不配置时行为不变（0.3.4 I3） | ✅ 字段为空时一行代码都不走 | ⚠️ 默认的 10 s 会生效，这是有意的行为变化（见 D1） |
| 失败原因写进 `statusText`，能直接看懂 | ✅ 错误信息里带文件路径 | ✅ 显示 `TLS handshake timed out`；代理那一跳还会带上代理地址 |
| 测试不联网，能在 Windows 上跑 | ✅ 已加进 Windows 的 hermetic 列表 | ⚠️ **原 PR 没有加**，现已补上（`bf99dbd`） |
| 不引入新的环境变量或全局状态 | ✅ 只增加一个字段 | ✅ 不新增配置项 |

### 2.2 语义和业界做法对照

**#24 `extraCaFile`：在默认 store 之外再追加信任的 CA**

| 实现 | 语义 |
|---|---|
| Node `NODE_EXTRA_CA_CERTS` | **追加**，和 #24 完全一样，名字也对应 |
| reqwest `add_root_certificate` | **追加**到内置根证书 |
| curl `--cacert` / `CURLOPT_CAINFO`、Python requests `verify=path`、Go `tls.Config.RootCAs` | **替换**（本库对应的是 `SSL_CERT_FILE`） |

结论：库里原本只有“替换”的方式（`SSL_CERT_FILE`），#24 补上了“追加”，这是业界常见的另一半。文件不可用时直接失败、不跳过，这个判断对：跳过的话，错误最后会变成一个不提文件的证书校验失败。

**#25 握手时限并入 `connectTimeoutMs`**

| 实现 | 握手的时限 |
|---|---|
| curl `CURLOPT_CONNECTTIMEOUT` | 包含 TLS 握手，并且整个建连阶段共用一个时限 |
| Go `http.Transport.TLSHandshakeTimeout` | 单独一项，`DefaultTransport` 默认 10 s |
| #25 | 包含握手，但**每个阶段各自计时** |

结论：并入 `connectTimeoutMs`（不新增配置项）和 curl 一致，默认 10 s 也和 Go 的默认值相同。差别在于各阶段各自计时，最坏情况下总时间是 N × timeout。PR 和 README 都已写明（见 D2）。

### 2.3 API 好不好用

| 点 | 评价 |
|---|---|
| `cfg.extraCaFile = "/etc/corp/root-ca.pem";` 一行就能用 | 好。代理那一跳自动生效，不用再配置一次 |
| 只接受文件路径 | 证书打包进程序、或者从配置中心拿到的场景要先落盘再用（D3） |
| 只能指定一个文件 | 和 Node 一样，可以把多个证书拼成一个文件，够用 |
| `verifySsl=false` 时文件读不到也会失败 | 有意设计（所有机器上报同样的错），README 里再补一句说明会更好 |
| 握手超时不需要任何改动就生效 | 好，解决的是默认配置下的卡死问题 |
| `connect_over(..., handshakeTimeoutMs = -1)` 和 `connect(..., timeoutMs, ...)` 的默认值不对称 | 为了兼容只能这样：`connect_over` 原本就不带超时 |

---

## 3. 问题清单与处理

### 3.1 #25（已推送：`cfdab98..97a0657`）

| # | 级别 | 问题 | 处理 |
|---|---|---|---|
| H1 | 高 | EINTR 被当成 deadline 到期。`wait_before_recv` 只要等待失败就设置 `deadline_hit_`，不看时钟。没有 token 时只调用一次 `poll`，信号一来就返回。master 上走的是阻塞的 `recv`，在 SA_RESTART 下会自动重启，所以这是回归 🔁 | `3013b98`：提前返回就按剩余时间继续等，只有时钟确实到了才算 deadline 到期。新用例 `ASignalDuringTheHandshakeIsNotATimeout`：时限 1000 ms，每 100 ms 用 `pthread_kill` 给握手线程发一次 SIGUSR1。修复前 100 ms 就失败，修复后通过 🔁 |
| M1 | 中 | `test_handshake_timeout` 没进 Windows 的 hermetic 列表，`WSAPoll` 路径没人测 | `bf99dbd` |
| M2 | 中 | Windows openkal job 的 bundle 路径（§1） | `bf99dbd` |
| L1 | 低 | CHANGELOG 没提导出的 `TlsSocket::connect` 现在也会限制握手时间 | `97a0657` |
| L2 | 低 | 移动构造和移动赋值复制了 `deadline_`，但没复制 `deadline_hit_` | `3013b98` |
| — | 已知限制 | 握手期间的 `send` 是阻塞的；`readTimeoutMs` 管不到阻塞的写（README 里的说法和实际不符） | 不在本版本处理，单列一项（§4） |

本地结果（Linux, LLVM 22）🔁：`test_handshake_timeout` 9/9、`test_cancel` 24、`test_proxy` 43、`test_pool` 27、`test_tls_verify` 6、`test_framing` 17，全部通过。

### 3.2 #24：可以直接合入，不追加 commit

本地结果 🔁：`test_extra_ca` 11/11，其余测试不受影响。#24 和 #25 合在一起后，全部测试也都通过（`test_extra_ca` + `test_handshake_timeout` 一起跑过）。

### 3.3 #24 的小问题（合入后视情况再处理，不阻塞本版本）

- 在 Linux 上，路径是目录时 `ifstream` 也能打开，错误信息变成 “cannot parse”，不是 “cannot read”。加一个 `is_regular_file` 判断就能修。
- 部分证书解析失败（`ret > 0`）不会报错，和默认 bundle 的处理一致，README 可以补一句。
- 每建一个新连接都要重新读、重新解析一次文件。默认 bundle 也是这样，暂时不缓存。

---

## 4. 0.3.5 之后（不在本版本范围内）

| 项 | 说明 |
|---|---|
| 写操作不阻塞 | `bio_send` / `write_all` 在阻塞 socket 上永远拿不到 WANT_WRITE，所以 `readTimeoutMs` 管不到阻塞的写，握手期间的写也不受 deadline 约束。这是 0.3.4 D4 留下的问题 |
| 整个建连共用一个 deadline（D2） | DNS、TCP（每个地址）、代理应答、两次握手共用一个 `connectTimeoutMs`。行为有变化，适合 0.4 |
| `extraCaPem`（D3） | 直接从内存加载 PEM |
| openkal Windows smoke 的 39 s 空档 | 见 §1，master 上已有，原因待查 |
| `poll_fd` 统一处理 EINTR | TCP connect 和代理应答的等待也有同样的问题，H1 只修了握手。可以在 `poll_fd` 一处统一修 |

---

## 5. 任务依赖图

```
T0 计划（本文）← 你在这里审
 │
 ├─ T1 #25 追加 commit（已推送 97a0657）→ CI 全绿 ✅（run 37968516327）
 │
 ├─ T2 更新 #25 的 PR 描述：Not covered 里关于 EINTR 的说法改成“已修复”；补充 CI 的变化
 │
 ├─ T3 squash 合入 #25（依赖 T1、T2）
 │
 ├─ T4 #24 同步 master：合并两边 CHANGELOG 的 “Unreleased” 段 → CI 全绿 → squash 合入
 │
 ├─ T5 发版 commit：CHANGELOG 的 Unreleased → 0.3.5；mcpp.toml version；README 安装行（mcpp add / 依赖示例）
 │
 └─ T6 发布（依赖全部）
       tag 0.3.5 + GitHub release
       → gitcode mcpp-res/tinyhttps 上传 0.3.5 tarball（核对和 GitHub archive 的 sha256 一致）
       → mcpp-index PR：pkgs/t/tinyhttps.lua 加 0.3.5（GLOBAL / CN，三个平台），
         tests/examples/tinyhttps 升到 0.3.5，加一条 `extraCaFile` 的 API 检查
       → 用已发布的 index 实测：新建项目写 "^0.3.1" 能解析到 0.3.5，GLOBAL 和 CN 两个源都验证
```

**关键路径**：T1（CI）→ T3 → T4 → T5 → T6。

## 6. 验收

- [x] #24、#25 以及两者合并后，hermetic 测试在本地全部通过 🔁
- [x] H1 能复现，修复后用例通过 🔁；已推送到 #25
- [x] #25 CI 全绿（run 37968516327，10/10），包括 Windows openkal 和 Windows hermetic（`test_handshake_timeout`）
- [x] #25 squash 合入（`9d4315e`）；#24 同步 master（合并时 CHANGELOG 和 Windows 测试列表都有冲突）后 CI 10/10 全绿，squash 合入（`a0f7749`）
- [ ] 版本号按 D1 确定；tag、GitHub release
- [ ] gitcode tarball 的 sha256 一致
- [ ] mcpp-index 合入；`"^0.3.1"` 在两个源下都解析到 0.3.5
