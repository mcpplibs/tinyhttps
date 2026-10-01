# 设计方案：请求取消（`std::stop_token`），基于 PR #23

| | |
|---|---|
| 基线 | `origin/master @ f461940`（0.3.3） |
| 输入 | [PR #23](https://github.com/mcpplibs/tinyhttps/pull/23) `feat/cancel @ 8996984`（作者 yspbwx2010，`maintainerCanModify: true`） |
| 落地方式 | 在 PR #23 上追加 commit，不另开 PR |
| 文档日期 | 2026-10-02 |

**标注约定**：✅ 已核验源码 · 🔁 已在本地复现或跑通 · ❓ 推断，未实测

---

## 0. TL;DR

- **应该进库。** 库外做不到：socket 是 `HttpClient` 的私有状态，`HttpClient` 本身又不是线程安全的。库里也已经有半个先例：`download_to_file` 的 `isCancelled` 只在 body 的块与块之间检查。
- **PR #23 的机制是对的，保留：** 等待只发生在 `Socket::wait_fd`，有 token 时按 50 ms 分片 `poll`；`bio_recv` 读之前先等。**它缺的是 token 的生命周期规则**，H1 就是这个缺口造成的 bug：经 https 代理复用连接时，一个 POST 会被执行两次。
- **架构收敛成三条不变式：** token 只放在传输链最底层的 `Socket` 上；token 只在调用期间挂着，连接回池时摘掉；不传 token 时行为和 0.3.3 完全一样。
- **改动量：** 在 PR 基础上，`src/` 约 +15 行（必需部分 +7 行），另加测试和 CI。必需部分已经做成原型跑通（§7）。
- **CI 目前对这个功能只有一个配置有效：** Linux + gcc 16。Windows job 不编译 `test_cancel`；Linux libc++（llvm 20/22）连链接都过不了；没有 macOS job。

### 决策（2026-10-02 均按建议采纳，执行见 [exec-plan-0.3.4-cancel.md](exec-plan-0.3.4-cancel.md)）

| # | 决策 | 建议 |
|---|---|---|
| D1 | `download_to_file` 是否同时加 `std::stop_token` 和 `DownloadToFileResult::cancelled` | **加**。理由见 §3.3 |
| D2 | 删掉 PR 给 `proxy_connect` 加的 `stop` 参数 | **删**。它是遗留的包装函数，只有 `proxy_tunnel` 内部需要 token |
| D3 | CI 新增 Linux llvm@22 job、Windows 跑 hermetic 测试 | **加**。macOS 视 mcpp 支持情况定（❓） |
| D4 | 写操作阻塞（对端不读）仍不可取消 | **本 PR 不做**，列为已知限制。后续单独做非阻塞发送 |

---

## 1. 该不该进库

**结论：进。**

| 论点 | 说明 |
|---|---|
| 库外无解 | 调用方拿不到 fd。唯一的绕法是把 `send` 丢到 detached 线程里等 `readTimeoutMs`。这期间 `HttpClient` 不能再用（不是线程安全的，`http.cppm` 里 `HttpClient` 的注释写明了），连接也一直占着，服务器还在继续生成响应 |
| 已有先例 | `download_to_file(..., isCancelled)` ✅ 说明库已经承认取消是它的职责。但 `isCancelled` 只在 body 块之间检查，等响应头、TLS 握手这些阶段照样卡死，正是 PR 要解决的问题 |
| 标准词汇 | `std::stop_token` 是 C++20 标准类型，和 `std::jthread` 天然配合，今后也能对接 `std::execution` 的 stop token。不需要自造回调或传 `atomic<bool>*` |
| 成本可控 | 不传 token 时零开销（I3）。传了 token 时，每个进行中的调用每秒多 20 次 `poll` 唤醒 |

**反方意见及回应：**“tiny 库不该长功能”。这里不是加功能，而是补全已有的取消语义（`isCancelled` 覆盖不全），并让三个入口一致。这和 #15 合并三个入口、只保留一份读取逻辑是同一个思路。

---

## 2. 架构：三条不变式

```
HttpClient::send / send_stream / download_to_file          ← 唯一接收 token 的地方
   │  perform_exchange: sock->set_stop(stop)               ← 挂上（每次调用、每次重试）
   │  PooledConnection::keep(): set_stop({})               ← 回池时摘下；drop() 直接销毁
   ▼
TlsSocket::set_stop ──转发──► lower_（https 代理隧道）──转发──► Socket
   │                         自己不存 token
   ▼
Socket::stop_  ── wait_fd()：分片 poll，片与片之间检查 stop_requested()
               ── bio_recv：有 token 时先 wait_readable(-1) 再 recv
               ── connect：每个地址、每次 DNS 回退前检查
```

| 不变式 | 内容 | 违反时的后果 |
|---|---|---|
| **I1 只存在底层** | token 只存在于传输链最底层的 `Socket`。`TlsSocket` 不存 token，只往下转发（不管下面是 `socket_` 还是 `lower_`） | **H1** 🔁：https 代理下 `set_stop` 只设了用不到的 `socket_`，复用的隧道一直带着第一个请求的 token |
| **I2 只在调用期间存在** | 进入 exchange 时挂上，`keep()` 把连接还回池时摘掉。**连接池里的连接永远不带 token** | **M1**：直连情况下现在不会出错（下次请求会覆盖），但只要以后加一个在挂 token 之前等待池中连接的路径（比如空闲探活），就会踩到和 H1 一样的坑 |
| **I3 没有 token 时行为不变** | `stop_possible()==false` 时 `wait_fd` 就是原来的单次 `poll_fd`，`bio_recv` 不预先等待 | 已满足 ✅ |

**为什么 token 必须作为状态存在 `Socket` 上，而不是作为参数一路传下去：** mbedtls 的 BIO 回调只有一个 `void* ctx`，在这里就是 `Socket*` ✅。握手和 TLS record 的后半段都是从 `bio_recv` 里阻塞的，没有别的通道能把 token 送进去。既然状态没法避免，就用 I1 和 I2 限定它在哪里、活多久。

### 考虑过、没有采用的方案

| 方案 | 不采用的原因 |
|---|---|
| `HttpClient::cancel()` 成员函数 | 需要从别的线程访问连接池，而 `HttpClient` 不是线程安全的。token 是不加锁就能跨线程传递的唯一渠道 |
| `std::stop_callback` + `shutdown(fd)` | 优点：没有轮询，还能覆盖阻塞的写（D4）。缺点：回调在发起 stop 的线程上执行，会和调用线程里 `drop()` 等所有关闭 fd 的路径竞争，必须加锁；另外 connect 进行中被 `shutdown` 时，macOS、Windows、openkal 上的语义都没有验证 ❓。**留作解决 D4 时的候选方案** |
| 第二个 fd（wake-up pipe）加 `poll` | Windows 没有 pipe；PR 作者说 openkal 上两个 fd 的 `poll` 会忙等（❓，未独立核实） |

---

## 3. 在 PR #23 基础上：保留、修改、删除

### 3.1 保留（✅ 已逐项核验）

- `Socket::wait_fd` 的分片 `poll`（50 ms，固定值，不做成配置项）；`bio_recv` 的预等待；connect 前、每个地址、DNS 回退前的 stop 检查。
- `perform_exchange` 的 `fail()`：stop 优先于真实错误，并在这里 drop 连接；重试循环开头检查 stop；取消后不跟重定向。
- `HttpResponse::cancelled`，以及它在响应头到达前后的两种形态（见 §4）。
- `proxy_tunnel` 尾部的默认参数 `stop`（内部需要）。
- `Socket` 的 move 会带走 `stop_`；`close()` 不清 `stop_`，所以 `set_stop` 必须在 `connect` 之前调用，现在的顺序是对的 ✅。

### 3.2 修改

| 项 | 改动 | 行数 | 状态 |
|---|---|---|---|
| **H1** | `TlsSocket::set_stop` 先转发给 `lower_`，再设 `socket_`（I1） | +3 | 🔁 原型通过 |
| **M1** | `PooledConnection::keep()` 把池中连接的 token 设为 `{}`（I2）。`drop()` 直接销毁连接，不用处理 | +5 | 🔁 原型通过 |
| **M2** | `test_cancel.cpp` 里 `import std` 的位置按标准库区分（§6.2） | +6 | 🔁 llvm 22 和 gcc 16 都通过 |
| 文档 | CHANGELOG 的 “Existing callers are unaffected” 改为：普通调用不受影响，但取 `&HttpClient::send` 成员函数指针的代码需要调整 | — | — |

### 3.3 D1：`download_to_file` 加 token（建议）

三个入口共用 `perform_exchange` 和 `read_body` ✅。PR 只改了其中两个入口，`download_to_file` 仍然只有 `isCancelled`，又回到了 #15 那张“修复只落到部分入口”的矩阵。具体改法：

- 签名加尾部默认参数：`download_to_file(url, dest, onProgress = nullptr, isCancelled = nullptr, std::stop_token stop = {})`。
- `DownloadToFileResult::cancelled`：`isCancelled` 或 token 任一触发都置为 true。`error` 文本保持现有的 `"cancelled"` 不变，原来匹配文本的代码不受影响。
- 实现：`perform_exchange(..., stop)`；body 的 sink 里检查 stop；重定向递归时把 stop 传下去。预计约 +15 行。
- `isCancelled` 保留，不标记废弃。它是轮询式谓词，和 token 不冲突。

### 3.4 D2：删除（建议）

- `proxy_connect(..., std::stop_token)`：这是只返回 `Socket` 的遗留包装函数，库内部不用它。加参数只会扩大导出面（YAGNI）。

---

## 4. 语义契约（README 和 CHANGELOG 要写清楚）

| 情形 | `statusCode` / `statusText` | `bodyComplete` / `bodyError` | `cancelled` | 连接 |
|---|---|---|---|---|
| 调用开始前 token 已经 stop | `0` / `"Cancelled"` | false / `"Cancelled"` | true | 不发起任何连接 |
| 响应头到达前取消（connect、代理、握手、等响应头） | `0` / `"Cancelled"` | false / `"Cancelled"` | true | drop |
| 响应头到达后取消（读 body、流式回调间隙） | 服务器给的值 | false / `"cancelled"` | true | drop |
| token 从未 stop | 和 0.3.3 一样 | 和 0.3.3 一样 | false | 和 0.3.3 一样 |

其他规则：

- `ok()` 不看 `cancelled`，就像它也不看 `bodyComplete`。取消的契约是那个 bool，不是文本。
- 取消后不做 stale-connection 重试，也不跟重定向。
- 真实失败和 stop 同时发生时，报告为取消。
- 响应时间约 50 ms（一个分片）。
- `close_notify` 只在握手完成之后的取消中发送。

**已知限制：**`getaddrinfo` 和 `socks5://` 对目标地址的解析不可中断；对端不读导致的阻塞写不可中断（socket 在 connect 之后被设回阻塞模式，`socket.cppm:257` ✅，见 D4）；openkal 上 connect 是同步完成的。

---

## 5. 测试

PR 已有 13 个用例，覆盖各阶段的首次建连 ✅。**缺口在“复用连接”这一维度**，H1 就漏在这里。补成下面这个矩阵：

| 新增用例 | 覆盖 | 状态 |
|---|---|---|
| 经 https 代理复用：第一个请求结束后它的 token 被 stop，第二个 POST 在目标服务器上**只执行一次**，代理只被连一次 | H1 / I1 | 🔁 修复前 3 次请求、2 次代理连接；修复后通过 |
| 经 https 代理复用：第二个请求自己的 token 在 500 ms 内生效 | H1 / I1 | 🔁 修复前要等满 3000 ms 读超时 |
| 同样的场景走 http:// 代理和直连（对照组） | I1 | 🔁 通过 |
| README 的 jthread 写法：请求完成后 jthread 析构（会 `request_stop`），下一个请求复用连接并成功 | I2 | 🔁（https 代理那一组就是这个写法） |
| `download_to_file`：等响应头时取消、读 body 时取消；`cancelled==true`；目标文件的处理和现有 `isCancelled` 一致 | D1 | 待写 |
| SOCKS5 代理在等握手应答时取消 | 补齐代理种类 | 待写（PR 只覆盖了 http 和 https 代理） |

时间断言使用 `kPromptMs = 500`。Windows 和 macOS 的 runner 比较慢，如果出现偶发失败，再按平台放宽，不要预先放宽。

---

## 6. CI 覆盖

### 6.1 现状 ✅

| job | 工具链 | 跑什么 | 对本功能的覆盖 |
|---|---|---|---|
| linux mcpp | gcc 16.1.0（mcpp 首次运行时引导安装的默认工具链） | 全部 `mcpp test` | ✅ 唯一有效的覆盖 |
| openkal | llvm + openkal libc++ | `examples/openkal` 的 `mcpp run` | 只编译库，不跑 `test_cancel` |
| windows msvc / llvm@20.1.7 | MSVC STL | **只跑 `mcpp test test_ca_store`** | ❌ 根本不编译 `test_cancel` |
| linux libc++ | — | — | ❌ 而且 `test_cancel` 在 llvm 20/22 上链接失败（§6.2） |
| macOS | — | — | ❌ 但 README 声称支持 macOS |

### 6.2 libc++ 链接问题（M2）🔁

- 在 llvm 20.1.7 和 22.1.8（libc++）上，先 `#include <thread>` 再 `import std;`，然后调用 `stop_source::request_stop()`，链接时报 `undefined hidden symbol __atomic_unique_lock<...>::__set_locked_bit`。llvm 23.1.0 和 gcc 16 正常。这是工具链 bug，不是本库的问题。
- 仓库测试文件的惯例是先 include 后 import，因为 gcc 必须这样：反过来在 gcc 16 上会报 `redefinition of std::byte` 等错误 🔁。
- 解决办法：在 `test_cancel.cpp` 里按标准库区分顺序（已验证 llvm 22 和 gcc 16 都能 16/16 通过）：

```cpp
// libc++ (≤22) fails to link stop_source::request_stop() when <stop_token>
// was included textually before `import std`; libstdc++ needs the opposite.
#include <version>
#ifdef _LIBCPP_VERSION
import std;
#endif
#include <gtest/gtest.h>
#include "proxy_test_server.hpp"
#include "tls_test_server.hpp"

import mcpplibs.tinyhttps;
#ifndef _LIBCPP_VERSION
import std;
#endif
```

- llvm 20 在 Linux 上两种顺序都编不过（import 在前时报 `requires clause differs`）🔁，显式实例化 `__atomic_unique_lock` 也不行 🔁，因此 **libc++ 只把 22 纳入 CI 矩阵**（Linux 和 macOS 都用 llvm@22.1.8；Windows 上的 llvm@20.1.7 用的是 MSVC STL，不受影响）。
- README 的 jthread 示例对“include 和 import std 混用、用 libc++ ≤22”的使用者同样会链接失败，需要在 README 里加一行说明。

### 6.3 目标

| 改动 | 内容 | 状态 |
|---|---|---|
| Linux job 改成矩阵 `[gcc@16.1.0, llvm@22.1.8]`，都跑全部 `mcpp test` | 覆盖 libc++。llvm 22 也是 mcpp 本地常见的默认工具链 | 🔁 本地 llvm 22 + M2 修复通过 |
| Windows 两个 job 追加 `mcpp test test_cancel`，最好再加 `test_framing`、`test_pool`、`test_proxy` | 覆盖 `WSAPoll` 分片和 Windows 上 connect 的等待 | ❓ 测试服务器有 `_WIN32` 分支（`proxy_test_server.hpp:28`），但从没在 Windows 上编译过，先试，编不过再移植 |
| 新增 macOS job（macos-14），跑 hermetic 测试 | PR 作者明确说没在 macOS 上跑过；macOS 上 `poll` 对进行中的 connect 的语义需要实测 | ❓ 要先确认 mcpp 的 macOS 工具链可用。如果不可用，就作为 follow-up 单独开 issue，不阻塞本 PR |
| openkal | 不变。库被编进 example，签名的编译已经覆盖到 | — |

---

## 7. 落地：在 PR #23 上追加的 commit

原型补丁（H1 + M1 + M2 + 3 个复现测试）已经在 PR 分支上跑通：`test_cancel` 16/16、`test_pool`、`test_proxy`、`test_framing` 通过（gcc 16），`test_cancel` 在 llvm 22 上也通过。之前那一轮（H1 + 复现测试）的全量 `mcpp test` 是 8/8 🔁。

| # | commit | 依赖 |
|---|---|---|
| 1 | `fix(tls): a stop token reaches the session a tunnelled one runs over`：H1，以及 https/http/直连三组复用测试 | — |
| 2 | `fix(http): a pooled connection carries no stop token`：M1，以及 jthread 析构场景的测试 | 1 |
| 3 | `test(cancel): import std before the includes under libc++`：M2 | — |
| 4 | `feat(download): download_to_file takes a stop token`：D1，以及 `DownloadToFileResult::cancelled` 和测试 | 2，D1 批准后 |
| 5 | `refactor(proxy): proxy_connect does not take a stop token`：D2 | D2 批准后 |
| 6 | `ci: linux on llvm 22 as well; windows runs the hermetic tests`（再加 macOS job，如果可行）：D3 | 3 |
| 7 | `docs: cancellation contract, download_to_file, libc++ note` | 4、5 |

顺序说明：1 和 2 是正确性修复，最先落地；3 必须在 6 之前，否则新加的 llvm job 第一次跑就会失败；6 失败时（比如 Windows 测试服务器不可移植），可以把 Windows 部分拆成 follow-up，不阻塞合并。
