# tinyhttps 修复 / 优化方案 —— issue #15 · #16 及连带发现

| | |
|---|---|
| 基准版本 | `origin/master @ 2cec1c1`,`mcpp.toml` version = **0.2.10** |
| 目标版本 | **0.2.11**(P0+P1)/ 0.3.0(P3 结构性) |
| 关联 issue | [#15](https://github.com/mcpplibs/tinyhttps/issues/15) 连接池污染 · [#16](https://github.com/mcpplibs/tinyhttps/issues/16) SIGPIPE |
| 文档日期 | 2026-09-06 |

> ⚠️ **动手前先 `git pull`。** 当前工作区在 `626c9d0`(0.2.8),落后 origin/master 两个提交(`965d805` #9、`2cec1c1` #14)。本文所有行号对应 **0.2.10**;本地 `src/http.cppm` 只有 1032 行,对不上。

**标注约定**:✅ = 已逐行核验源码 · 🔬 = 已独立复现 · ⚠️ = 推断,未实测

---

## 0. TL;DR

两个 issue **都是库的真 bug**,不是使用方法错误。核验过程中另外发现 **7 处同类问题**,其中 3 处在 `download_to_file_impl` 的**正常路径**上(重定向、非 2xx、文件打开失败),1 处是服务端可单凭一个 header 触发的整数截断。

合计 **19 个修复项**,分 4 档:

| 档 | 内容 | 项数 | 改动量 | 风险 |
|---|---|---|---|---|
| **P0** | SIGPIPE(#16)—— 库会杀死宿主进程 | 2 | ~10 行 | 零(成功路径不变) |
| **P1** | 连接池不变量(#15 + 4 处新发现) | 10 | ~30 行 | 低(只改早退路径) |
| **P2** | 纵深防御 + 解析加固 + API 缺口 | 9 | ~150 行 | 中(有 1 项 API 变更) |
| **P3** | 结构性重构(让这类 bug 编译期就写不出来) | 4 | 大 | 需单独 PR |

**建议提交顺序**:P0 单独一个 PR 先合 → P1 一个 PR → 发 0.2.11 → P2 分批 → P3 单独立项。

**P0 必须排在 P1 之前**:P1 的修复会让 `pool_.erase()` 在更多路径上执行,而 `erase` 会析构 `TlsSocket` → `close_notify` → `send()`。P0 没修之前,P1 等于**扩大** SIGPIPE 的触发面。

---

## 1. 问题全景

### 1.1 三个入口的加固覆盖矩阵 ✅

库里有三份几乎平行的响应读取实现:`send_impl`、`send_stream`、`download_to_file_impl`。历次修复各自只落到其中一两份:

| 加固措施 | 引入自 | `send_impl` | `send_stream` | `download_to_file_impl` |
|---|---|---|---|---|
| `parse_content_length`(严格) | #14 | ✅ `:516` | ✅ `:783` | ❌ `:1042-1048` 手写摘数字 |
| `contentLength` 用 `int64_t` | — | ❌ `:488` **`int`** | ✅ `:756` | ✅ `:1024` |
| `parse_chunk_size_line`(严格) | #9 | ❌ `:541` 仍是 `parse_hex` | ✅ `:831` | ✅ `:1134` |
| `read_complete_line`(区分超时/EOF) | #9 | ❌ | ❌ | ✅ `:1118/1145/1177` |
| 块后 CRLF 校验 | #9 | ❌ `:556` 丢弃返回值 | ❌ `:850` 丢弃返回值 | ✅ `:1177-1185` |
| 状态行 `HTTP/` 前缀校验 | — | ❌ | ❌ | ❌ |
| 早退时清理连接池 | — | ❌ 2 处 | ❌ 3 处 | ❌ **5 处** |
| 失败时能告诉调用方 | — | ❌ 无字段 | ❌ 无字段 | ✅ `result.error` |

**这张表本身就是最强的论据**:每一次修复都是在一份拷贝上打补丁,另外两份继续带病。`#14` 引入 P1-A1/A2 两处新回归,正是这个模式的最新一次复发。**不做 P3,下一次还会有。**

### 1.2 四个根因

| 根因 | 说明 | 派生问题 |
|---|---|---|
| **R1 池不变量没有被代码表达** | 「可复用」被编码成 `is_valid()`(fd 开着),真正的条件是「流干净 + 对端还在」。这个条件靠 10 个早退路径各自记得设 `connectionClose` 来维护 | P1 全部 |
| **R2 `read_line` 空返回三义** | `read_line`(`:169-191`)在**超时 / EOF / 真的读到空行**三种情况下都返回 `""`,调用方无从区分 | P1-B2、P2-C1 |
| **R3 `TlsSocket::read` 返回 0 二义** | `tls.cppm:124-130`:**「对端关闭」和「WANT_READ/WANT_WRITE 暂时无数据」都返回 0**。`read() <= 0` 因此分不清 EOF 与阻塞 | P2-D1 |
| **R4 库在自己的 fd 上用裸 `send`** | 缺 `MSG_NOSIGNAL`,把信号处置的责任推给了调用方 | P0 |

R2/R3 是同一个毛病的两个实例:**用一个哨兵值(空串 / 0)表示多种语义**。`#9` 已经引入了 `expected` / `optional` 版本的正确做法,只是没铺开。

---

## 2. P0 —— SIGPIPE(issue #16)

### 2.1 判定 🔬

**真 bug,最高优先级。** 一个库在自己管理的 fd 上调 `send()`,却让宿主进程被 `SIGPIPE` 杀死(exit 141),是库的责任。

**关键补充证据(issue 里没有)**:mbedtls 3.6.1 自己在 `library/net_sockets.c:114` 的 `net_prepare()` 里有 `signal(SIGPIPE, SIG_IGN)`,但 tinyhttps 在 `tls.cppm:82/94/240` 用 `mbedtls_ssl_set_bio()` 挂了自定义 BIO,**全仓库不存在任何 `mbedtls_net_init` / `mbedtls_net_context` 调用**(已 grep 确认)。

> 也就是说:换掉 mbedtls 网络层时,把它自带的那层防护一并丢掉了,却没补等价物。**这是引入型缺陷,不是「从来没考虑过」。**
>
> 反过来看这也是个改进机会:mbedtls 的做法(进程级 `SIG_IGN`)其实很粗暴,库不该改宿主的全局信号处置。**用 `MSG_NOSIGNAL` 比 mbedtls 原来的做法更干净。**

独立复现(`sigpipe_probe.c`,不依赖构建整个库):

```
[A] flags = 0            → KILLED by signal 13 (Broken pipe) → exit status 141   ← 与报告者实测一致
[B] flags = MSG_NOSIGNAL → send 返回 -1/EPIPE,进程正常退出
```

### 2.2 修复

全库 fd 只有**一个创建点**(`socket.cppm:125`),`proxy.cppm` 也复用 `Socket` 类,所以只需两处改动。

#### P0-1 `src/socket.cppm:176-179` —— 发送时抑制信号(Linux / Android / Termux)

```diff
     int write(const char* buf, int len) {
         if (!is_valid()) return -1;
-        return static_cast<int>(::send(fd_, buf, len, 0));
+        // A write to a socket whose peer has gone away raises SIGPIPE, and a
+        // program that has not disarmed it — the default — is killed rather
+        // than told. MSG_NOSIGNAL turns that into EPIPE, which this codebase
+        // already knows how to carry: bio_send (tls.cppm:49-51) maps a
+        // non-positive return to MBEDTLS_ERR_NET_SEND_FAILED, and
+        // TlsSocket::close (tls.cppm:151) already ignores what close_notify
+        // returns. Nothing downstream needs to change.
+        //
+        // #ifdef, not `if constexpr`: the macro does not exist on Windows, so
+        // both arms of an `if constexpr` would have to compile and one cannot.
+        // This is the trap 5e7d66f fixed in the resolver stubs.
+#ifdef MSG_NOSIGNAL
+        return static_cast<int>(::send(fd_, buf, len, MSG_NOSIGNAL));
+#else
+        return static_cast<int>(::send(fd_, buf, len, 0));
+#endif
     }
```

#### P0-2 `src/socket.cppm:125` 之后 —— macOS / *BSD 没有 `MSG_NOSIGNAL`

```diff
     bool connect_addrinfo(struct addrinfo* result, int timeoutMs) {
         for (auto* rp = result; rp != nullptr; rp = rp->ai_next) {
             SocketHandle fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
             if (fd == INVALID_SOCKET_FD) {
                 continue;
             }
 
+            // macOS and the BSDs spell it as a socket option instead of a send
+            // flag. Best-effort: a failure here only means the socket keeps the
+            // default disposition, which is what it had before this line.
+#ifdef SO_NOSIGPIPE
+            int nosigpipe = 1;
+            ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
+                         reinterpret_cast<const char*>(&nosigpipe), sizeof(nosigpipe));
+#endif
+
             // Set non-blocking
             if (!set_non_blocking(fd, true)) {
```

**平台矩阵**:Linux/Android 走 `MSG_NOSIGNAL`;macOS/BSD 走 `SO_NOSIGPIPE`;Windows 两个宏都不存在 → 自动走 `#else`,且本来就没有 `SIGPIPE`,无需额外分支。`socket.cppm:8-9` 已经在非 Windows 下 include 了 `<sys/socket.h>`,两个宏都在里面,**不需要新增 include**。

### 2.3 为什么这个修复是自包含的 ✅

失败会沿着**已经存在的**路径传播,零新增分支:

```
Socket::write → -1 (EPIPE)
  → bio_send (tls.cppm:49-51)   已有 if (ret <= 0) return MBEDTLS_ERR_NET_SEND_FAILED;
    → mbedtls_ssl_close_notify  返回错误
      → TlsSocket::close (tls.cppm:151)   本来就忽略返回值
```

**成功路径逐字节不变。**

---

## 3. P1 —— 连接池不变量(issue #15 + 4 处新发现)

### 3.1 判定 ✅

**真 bug,不是使用方法错误。**

| 报告者做的 | 是否合法 |
|---|---|
| 单个 `HttpClient` 跑多个请求 | ✅ 这正是连接池的用途 |
| `keepAlive` 用默认值(true) | ✅ 库的默认值 |
| `readTimeoutMs = 1000` | ✅ 激进但合法;**超时是正常事件,不是 API 误用** |
| 触发条件:服务端发一半 / 空闲后关连接 | ✅ **服务端的常规行为** |

规避手段只有「关掉 keep-alive」或「每次换 client」—— 都是放弃这个特性本身。**用户无法在正确使用 API 的前提下绕开 → 定义上就是库的 bug。**

### 3.2 完整泄漏路径清单(10 条)

`connectionClose` 列 = 走到清理点时该标志的值。

#### A. `send_stream` —— 🔴 **0.2.10 新引入的回归**

| ID | 位置 | 触发 | 现状 | 修复 |
|---|---|---|---|---|
| **A1** | `:878-880` | `wait_readable` 超时 → `break` | `false` → `:909` 保留 socket | 设 `connectionClose = true` |
| **A2** | `:884-885` | `read() <= 0` → `break` | `false` → 同上 | 设 `connectionClose = true` |
| **A3** | `:846-848` | `read_exact` 失败 → `break` | `false` → 同上 | 设 `connectionClose = true` |

**回归定位** ✅:`git log -S "A DECLARED LENGTH IS READ AND THE READER THEN STOPS"` → `2cec1c1` (#14)。0.2.3 的对应分支是:

```cpp
} else {
    // Not chunked — read until connection closes
    connectionClose = true;      // ← 无条件设置,池永远安全
```

`#14` 为修「keepAlive 下 error body 晚到一个 readTimeout」新增了 Content-Length 分支,**顺手把这句无条件赋值拿掉了**。A1/A2 是 0.2.10 才有的新回归;A3 是旧疾(0.2.3 同样存在)。

#### B. `send_impl`

| ID | 位置 | 触发 | 现状 | 修复 |
|---|---|---|---|---|
| **B1** | `:550-551` | `read_exact` 失败 → `break` | `false` → `:582` 不清理 | 设 `connectionClose = true` |
| **B2** | `:541-545` | `parse_hex("") == 0` → 当成终止块 | **把超时当成 body 正常结束** | 换 `parse_chunk_size_line` |

B2 细节:`parse_hex`(`:233-243`)遇到不认识的字符是 `break` 返回**已累积的值**,空串返回 0。所以

- 超时的空行 → `0` → `:542` 认为是终止块 → 池被污染 **且静默报告成功**
- 残留的 `"BBBB"` → `0xBBBB = 48059` → `read_exact` 去等 48059 个永不到来的字节

`parse_chunk_size_line`(`:277-288`)用 `from_chars` 全串校验,两种情况都返回 `nullopt`。**`send_impl:541` 是全库最后一个 `parse_hex` 调用点**,改完可以直接删掉 `parse_hex`。

#### C. `download_to_file_impl`

| ID | 位置 | 触发 | 现状 | 来源 |
|---|---|---|---|---|
| **C1** | `:1166-1171` | chunk 数据 `read_exact` 失败 → **直接 return** | 跳过 `:1223` 尾声 | issue #15 |
| **C2** | `:1195-1200` | CL body `read_exact` 失败 → **直接 return** | 同上 | issue #15 |
| **C3** | `:1060-1075` | **重定向** | 🆕 **正常路径** | 本次发现 |
| **C4** | `:1077-1081` | **非 2xx 返回** | 🆕 **正常路径** | 本次发现 |
| **C5** | `:1092-1096` | 输出文件打不开 | 🆕 | 本次发现 |

C1/C2 的对照:同一个函数里相邻的 `:1150-1153` 和 `:1180-1184` **写对了**(`sock->close(); pool_.erase(poolKey);`),这本身就证明是漏写而非取舍。

##### 🆕 C3 是本次分析最值得注意的一条

```cpp
1062:            // Drain any body to keep connection clean
1063:            if (connectionClose) {
1064:                sock->close();
1065:                pool_.erase(poolKey);
1066:            }
```

**注释说要 drain,但代码里没有任何 drain。** 只有在服务端主动送 `Connection: close` 时才清理。于是:

服务端回 `302` + `Content-Length: 123` + 一段 HTML + `keep-alive`(**这是绝大多数服务端的重定向响应**)
→ 123 字节 body 一个都没读
→ socket 带着这 123 字节回池
→ `:1073` 递归调用 `download_to_file_impl`
→ 若重定向到同一 host,`:954` 拿到这个被污染的 socket
→ `:1002` `read_line` 把重定向 body 的头几十个字节当成状态行

**这就是 #15 的失效模式,发生在完全正常的重定向路径上,不需要任何超时或截断。** `send_impl` 没有这个问题,因为它是先读完 body(`:524-579`)再处理重定向(`:588`);`download_to_file_impl` 的顺序反过来。

C4 同理:非 2xx 时 error body 未读就返回,socket 回池,同一 client 的下个请求中招。
C5 同理:文件打不开时 body 未读。

#### D. 🆕 整数截断

| ID | 位置 | 问题 |
|---|---|---|
| **D1** | `:488` | `int contentLength = -1;`,而 `send_stream:756` / `download:1024` 都是 `std::int64_t` |

`:516` `contentLength = parse_content_length(valStr).value_or(-1);` —— 右边是 `int64_t`,**赋给 `int` 静默截断**。

服务端发 `Content-Length: 4294967296`(2³²)→ 截断成 `int` **0** → `:560` `if (contentLength > 0)` 不成立 → **一个字节都不读** → `:582` `connectionClose` 为 false → **socket 带着 4 GiB 未读 body 回池**。

**这是唯一一条服务端单凭一个 header 就能触发的池污染,不需要超时、不需要截断、不需要任何时序配合。**

顺带:`:561` `response.body.resize(contentLength)` 在 `contentLength` 接近 `INT_MAX` 时会先分配 2 GiB(见 P2-E2)。

### 3.3 修复 diff

#### P1-A `src/http.cppm` —— `send_stream` 三处

```diff
@@ -844,7 +844,10 @@   (chunked 分支)
                 std::string chunkData(chunkSize, '\0');
                 if (!read_exact(*sock, chunkData.data(), chunkSize, config_.readTimeoutMs)) {
+                    // The body stopped mid-chunk: bytes are still owed on this
+                    // socket, so it must not go back into the pool.
+                    connectionClose = true;
                     break;
                 }
@@ -877,10 +880,12 @@   (Content-Length 分支)
             while (!stopped && remaining > 0) {
                 if (!sock->wait_readable(config_.readTimeoutMs)) {
+                    connectionClose = true;   // remaining > 0: bytes still owed
                     break;
                 }
                 ...
                 int ret = sock->read(buf, want);
-                if (ret <= 0) break;
+                // End of stream before the declared length — the framing is
+                // broken either way, so the connection cannot be reused.
+                if (ret <= 0) { connectionClose = true; break; }
```

> ✅ 已核验:`:909-912` 的清理本来就 key 在 `connectionClose || stopped` 上;正常终止路径(`remaining > 0` 循环条件自然结束、`:841` 终止块 break)**不经过**这三个出口。**成功路径零变化。**

#### P1-B `src/http.cppm` —— `send_impl` 两处

```diff
@@ -538,15 +538,21 @@
                 while (!sizeLine.empty() && (sizeLine.back() == ' ' || sizeLine.back() == '\t')) {
                     sizeLine.pop_back();
                 }
 
-                int chunkSize = parse_hex(sizeLine);
-                if (chunkSize == 0) {
+                // A CHUNK HEADER THAT DOES NOT PARSE IS NOT A TERMINAL CHUNK.
+                // parse_hex returned 0 for an empty line, and read_line returns
+                // an empty line on a timeout — so a stream that was cut short
+                // read as one that ended cleanly, and the socket went back into
+                // the pool with the rest of the body still owed on it.
+                // #9 established parse_chunk_size_line for exactly this; it
+                // reached send_stream and download_to_file but not this reader.
+                auto parsedChunkSize = parse_chunk_size_line(sizeLine);
+                if (!parsedChunkSize) {
+                    connectionClose = true;
+                    break;
+                }
+                int chunkSize = static_cast<int>(*parsedChunkSize);
+                if (chunkSize == 0) {
                     read_line(*sock, config_.readTimeoutMs);
                     break;
                 }
 
                 std::string chunkData(chunkSize, '\0');
                 if (!read_exact(*sock, chunkData.data(), chunkSize, config_.readTimeoutMs)) {
+                    connectionClose = true;
                     break;
                 }
```

改完后 `parse_hex`(`:233-243`)已无调用点 → **一并删除**。

#### P1-C `src/http.cppm` —— `download_to_file_impl` 五处

C1 / C2(照搬相邻 `:1151-1152` 的写法):

```diff
@@ -1166,6 +1166,8 @@
                     if (!read_exact(*sock, buf, toRead, config_.readTimeoutMs)) {
                         result.error = "Read error during chunked transfer";
                         ofs.close();
                         result.bytesWritten = downloaded;
+                        sock->close();
+                        pool_.erase(poolKey);
                         return result;
                     }
@@ -1195,6 +1197,8 @@
                 if (!read_exact(*sock, buf, toRead, config_.readTimeoutMs)) {
                     result.error = "Read error";
                     ofs.close();
                     result.bytesWritten = downloaded;
+                    sock->close();
+                    pool_.erase(poolKey);
                     return result;
                 }
```

C3 / C4 / C5 —— 最小改法是**无条件丢弃连接**(见 P2-E1 有更省的做法):

```diff
@@ -1059,10 +1063,12 @@   (重定向)
         if (result.statusCode >= 300 && result.statusCode < 400 &&
             !location.empty() && redirectCount < config_.maxRedirects) {
-            // Drain any body to keep connection clean
-            if (connectionClose) {
-                sock->close();
-                pool_.erase(poolKey);
-            }
+            // The comment here used to promise a drain that was never written:
+            // a 3xx normally carries a short body, and leaving it unread put a
+            // socket with owed bytes back into the pool — which the recursive
+            // call below then picks up for the very next request. Until there
+            // is a bounded drain (see P2-E1), the connection is not reusable.
+            sock->close();
+            pool_.erase(poolKey);

@@ -1077,7 +1083,8 @@   (非 2xx)
         if (result.statusCode < 200 || result.statusCode >= 300) {
             result.error = "HTTP " + std::to_string(result.statusCode);
-            if (connectionClose) { sock->close(); pool_.erase(poolKey); }
+            sock->close(); pool_.erase(poolKey);   // error body was never read
             return result;
         }

@@ -1092,7 +1099,8 @@   (文件打不开)
         if (!ofs) {
             result.error = "Cannot open file: " + destFile.string();
-            if (connectionClose) { sock->close(); pool_.erase(poolKey); }
+            sock->close(); pool_.erase(poolKey);   // body was never read
             return result;
         }
```

> 📌 **review 决策点**:C3 用「无条件丢连接」换正确性,代价是每次重定向多一次 TLS 握手。若在意,P2-E1 提供一个有上限的 drain 助手,可把这三处改回「drain 成功就留、失败就丢」。**建议先合无条件版本(正确性优先),drain 作为后续优化。**

#### P1-D `src/http.cppm:488` —— 类型对齐

```diff
         bool chunked = false;
-        int contentLength = -1;
+        std::int64_t contentLength = -1;   // matches send_stream:756 / download:1024
         bool connectionClose = false;
```

同时 `:560-565` 需要跟着调整(`resize` 的参数类型 + 上限,见 P2-E2)。

---

## 4. P2 —— 纵深防御 · 解析加固 · API 缺口

> P2 的价值:**即使 P1 将来又出漏洞,残留字节也不会被伪装成一个合法响应。** #15 里最危险的两档(静默数据损坏)都会退化成可见错误。

### P2-C1 状态行必须以 `HTTP/` 开头 ✅ 🆕

三个入口(`:456-484`、`:725`、`:1010-1020`)**都不校验前缀**,状态码提取还是「挑数字、静默跳过非数字」:

```
"BBB…B 999 XHTTP/1.1 200 OK"
       ↑ 第一个空格           → rest = "999 XHTTP/1.1 200 OK"
           ↑ 第二个空格       → code = "999", text = "XHTTP/1.1 200 OK"
```

这就是 issue #15 里 `statusCode=999` 的完整来源。而且 `X9Y9Z9` 也会被解析成 `999`。

建议抽一个共用的严格解析器:

```cpp
struct StatusLine { int code; std::string text; };

// A status line is HTTP-version SP status-code [SP reason] (RFC 9112 §4).
// Rejecting anything else is what stops another response's leftover bytes
// from being read as a status line — see issue #15.
static std::optional<StatusLine> parse_status_line(std::string_view line) {
    if (!line.starts_with("HTTP/")) return std::nullopt;
    auto sp = line.find(' ');
    if (sp == std::string_view::npos) return std::nullopt;
    auto rest = line.substr(sp + 1);
    auto sp2 = rest.find(' ');
    auto codeStr = (sp2 == std::string_view::npos) ? rest : rest.substr(0, sp2);
    if (codeStr.size() != 3) return std::nullopt;          // exactly three digits
    int code {};
    auto [end, ec] = std::from_chars(codeStr.data(), codeStr.data() + codeStr.size(), code);
    if (ec != std::errc{} || end != codeStr.data() + codeStr.size()) return std::nullopt;
    return StatusLine{ code, sp2 == std::string_view::npos
                             ? std::string{} : std::string(rest.substr(sp2 + 1)) };
}
```

三个入口统一改用它,失败一律 `pool_.erase` + `Invalid status line`。**导出它,理由和 `parse_chunk_size_line` 一样:这是 framing 里可以脱离服务端单测的那一半。**

### P2-C2 header 循环区分「超时」与「真空行」✅

`:491-495` / `:758-762` / `:1030-1032` 三处都是:

```cpp
std::string headerLine = read_line(*sock, config_.readTimeoutMs);
if (headerLine.empty()) break;   // "End of headers"
```

读 header 期间超时 → `read_line` 返回空 → 当成 header 读完 → 拿一份**残缺的 header 集合**去读 body(`contentLength` 还是 -1、`chunked` 还是 false)→ 走「读到连接关闭为止」分支。

那条分支会设 `connectionClose = true`,所以**池是安全的**,但**响应是静默错误的**:header 少一半,body 里混进剩下的 header 文本。

修复:三处都换成 `read_complete_line`(`:193-213`,返回 `expected`),`unexpected` → 明确报错并丢连接。**根因 R2 的正解,`#9` 已经写好了工具,只是没铺开。**

### P2-C3 块后 CRLF 校验 ✅

`send_impl:556` 和 `send_stream:850` 都是 `read_line(...)` 丢弃返回值;`download_to_file_impl:1177-1185` 是校验的(`"Missing CRLF after chunk data"`)。块长度算错时前两者会直接错位到下一个块头而不报错。照 download 的写法补齐。

### P2-C4 `download_to_file_impl` 的 Content-Length 解析 ✅

`:1042-1048` 仍是手写摘数字循环:

```cpp
if (iequals(key, "Content-Length")) {
    contentLength = 0;
    for (char c : valStr) { if (c >= '0' && c <= '9') contentLength = contentLength * 10 + (c - '0'); }
}
```

`:245-252` 的注释亲口描述的正是这个缺陷(「`12abc` 是 12,`abc` 是 0,溢出静默回绕」),`#14` 修了 `send_impl`/`send_stream`,**唯独漏了这里**。换成 `parse_content_length(valStr).value_or(-1)`。

### P2-E1 有上限的 body drain(可选,给 C3/C4 省一次握手)

```cpp
// Consume a body we are not going to hand to the caller, so the connection
// stays reusable. Bounded: past the cap it is cheaper to reconnect than to
// keep reading, and an endless body must not be able to stall us.
// Returns false if the body could not be fully consumed — drop the connection.
static bool drain_body(TlsSocket& sock, bool chunked, std::int64_t contentLength,
                       int timeoutMs, std::int64_t cap = 64 * 1024);
```

有了它,C3/C4 可以写成 `if (!drain_body(...)) { sock->close(); pool_.erase(poolKey); }`。

### P2-E2 分配上限(拒绝服务端诱导的巨额分配)🆕 ⚠️

- `send_impl:561` `response.body.resize(contentLength)` —— `contentLength` 最大到 `INT64_MAX`,`resize` 会抛 `std::length_error` / `std::bad_alloc`。**库没有文档说 `send()` 会抛异常**,调用方大概率没接。
- `send_impl:549` / `send_stream:845` `std::string chunkData(chunkSize, '\0')` —— 服务端一个 `7fffffff` 块头就能让客户端分配 2 GiB。

建议:加一个 `HttpClientConfig::maxResponseBodyBytes`(默认比如 64 MiB),超过就当作 framing 错误拒绝;chunk 数据改成按固定缓冲区分片读,不按块大小一次性分配。

### P2-D1 `TlsSocket::read` 区分 EOF 与 would-block(根因 R3)✅

`tls.cppm:120-134`:`PEER_CLOSE_NOTIFY`、`ret == 0`、`WANT_READ`、`WANT_WRITE` **全部返回 0**。调用方(`read_exact:157`、`read_line:178`、`send_stream:885`)因此分不清「对端关了」和「暂时没数据」,只好用「等一下再试一次」的土办法遮盖。

建议引入三态:

```cpp
enum class ReadStatus { Data, WouldBlock, Eof, Error };
```

或保留 `int` 但用 `-2` 表示 would-block。

> **与 P1 的关系**:P1-A2 把 `read() <= 0` 当成「流结束」丢连接。若那个 0 其实是瞬时 would-block,我们只是白丢一条连接 —— **正确性不受影响,只损失一点复用率**。所以 P1 不依赖 P2-D1,但修了 D1 之后 P1-A2 才精确。⚠️ 实践中 socket 在握手后被设回阻塞模式(`socket.cppm`),`WANT_*` 极少出现,影响应该很小,**未实测**。

### P2-D2 `write_all` 的 WANT_WRITE 处理 ✅ ⚠️

`http.cppm:216-230`:

```cpp
int ret = sock.write(...);
if (ret < 0) return false;
if (ret == 0) {
    ret = sock.write(...);      // 立刻重试一次,不等待
    if (ret <= 0) return false; // 再失败就放弃
}
```

`TlsSocket::write`(`tls.cppm:140-142`)在 `WANT_READ/WANT_WRITE` 时返回 0。所以 TLS 背压下会「忙重试一次然后放弃」→ 用户看到莫名其妙的 `"Write failed"`。应该改成 `wait_writable(timeoutMs)` 后重试,并给总时长设上限。⚠️ **未实测,按代码推断。**

### P2-F1 🆕 调用方无法得知 body 被截断了(API 缺口)✅

**这是 P1 修完之后剩下的最大问题。**

P1 只保证了「坏连接不会毒害下一个请求」,但当前请求返回给调用方的是:

- `send_impl` CL 短读(`:562-565`)→ 返回真实的 `statusCode=200` + 半截 body,**没有任何截断标记**
- `send_impl` / `send_stream` chunked 中断 → 同上
- `DownloadToFileResult` **有** `error` 字段 ✅,`HttpResponse` **没有** ❌

也就是说:**一个被截断的 200 响应,和一个完整的 200 响应,调用方分不出来。**

建议(**加字段,不改现有语义,非破坏性**):

```cpp
export struct HttpResponse {
    int statusCode { 0 };
    std::string statusText;
    std::map<std::string, std::string> headers;
    std::string body;

    // False when the body ended before its framing said it would — a read
    // timeout, an EOF mid-body, a chunk header that did not parse. The status
    // line and headers are still what the server sent; `body` is a prefix.
    // DownloadToFileResult has always carried this as `error`; send() and
    // send_stream() had no way to say it.
    bool bodyComplete { true };

    bool ok() const { return statusCode >= 200 && statusCode < 300; }
    // 若担心旧代码只看 ok(),可考虑让 ok() 也要求 bodyComplete —— 但这是行为变更,
    // 需要单独讨论。默认保持 ok() 语义不变。
};
```

在 P1 设 `connectionClose = true` 的每一处,同时设 `response.bodyComplete = false`。

> 📌 **review 决策点**:(a) 只加 `bodyComplete` 字段、`ok()` 不变(建议,非破坏性);(b) 让 `ok()` 也要求 `bodyComplete`(更安全,但会让现有代码行为变化)。

### P2-F2 🆕 `send_stream` 出错时会覆盖真实的 statusText ✅

`:833` `response.statusText = "Invalid chunk size: " + sizeLine;` —— 把服务端真实的 `"OK"` 覆盖掉了。有了 P2-F1 的 `bodyComplete` 之后,应该改成保留 `statusText`,把原因放进新字段(或一个 `bodyError` 字符串)。

---

## 5. P3 —— 结构性重构(建议单独立项)

> P1 是逐条堵漏。**但 §1.1 的矩阵说明:这个 bug 类会随着每次新增代码复发。** `#14` 就是最新一次。P3 的目标是让它写不出来。

### P3-A `PooledConn` —— 把默认行为从「留」翻成「丢」 ★ 最高性价比

当前所有 10 个 bug 的形状**完全一样**:一条早退路径**什么都没做**,而「什么都没做」的默认结果是**把脏连接留在池里**。

```cpp
// The pool's invariant — a pooled connection owes no bytes and its peer is
// still there — is not something is_valid() can check. So make dropping the
// default: any path that leaves without an explicit keep() drops the socket.
// Every defect in issue #15 was a path that did nothing.
class PooledConn {
public:
    PooledConn(std::map<std::string, TlsSocket>& pool, std::string key)
        : pool_(pool), key_(std::move(key)) {}
    ~PooledConn() {
        if (!keep_) {
            if (auto it = pool_.find(key_); it != pool_.end()) {
                it->second.close();
                pool_.erase(it);
            }
        }
    }
    // Call only where the body was consumed to its declared end and the
    // response did not say Connection: close.
    void keep() { keep_ = true; }
    PooledConn(const PooledConn&) = delete;
    PooledConn& operator=(const PooledConn&) = delete;
private:
    std::map<std::string, TlsSocket>& pool_;
    std::string key_;
    bool keep_ { false };
};
```

用法:每个入口开头建一个,只在 body **正常读完**的那唯一一处调 `keep()`。10 个 bug 一次全消,而且以后新增任何早退路径**天然安全**。

> ⚠️ **两个必须注意的陷阱(review 重点)**:
>
> 1. **递归重定向**。`send_impl:612` `return send_impl(redirectReq, redirectCount + 1);` 发生在 guard 析构**之前**。若重定向到同一 host,内层调用会往池里放一条新连接,外层 guard 析构时会把它**误删**。
>    → 递归前必须先 `guard.keep()` 或 `guard.release()`。`download_to_file_impl:1073` 同理。
>    **现状没有这个 bug**,因为现在的清理(`:582-585`)在重定向块之前执行 —— 改成 RAII 时必须专门处理。
> 2. **必须在 P0 之后做**。guard 析构 → `erase` → `~TlsSocket` → `close_notify` → `send()`。P0 没修就是在扩大 SIGPIPE 面。

### P3-B 三份 reader 合一

§1.1 的矩阵就是三份平行实现的代价。建议抽出:

```cpp
struct ResponseHead { int statusCode; std::string statusText;
                      std::map<std::string,std::string> headers;
                      bool chunked; std::int64_t contentLength; bool connectionClose; };

// 统一的 head 读取:状态行 + header,严格解析
static std::expected<ResponseHead, std::string> read_response_head(TlsSocket&, int timeoutMs);

// 统一的 body 读取,把 body 的去向抽象成 sink(string / SSE 回调 / ofstream)
enum class BodyEnd { Complete, Truncated, ClosedByPeer };
static BodyEnd read_body(TlsSocket&, const ResponseHead&, int timeoutMs,
                         std::function<bool(std::string_view)> sink);
```

`[[nodiscard]] BodyEnd` 让「读完之后要不要留连接」变成一个**必须处理的返回值**,而不是一个可以忘记设的 bool。**增量做法**:先抽 `read_response_head`(三处几乎逐字重复,最安全),body 之后再说。

### P3-C 带缓冲的读

`read_line` 现在是逐字节 `sock.read(&c, 1)`。除了慢(⚠️ 影响有限:`TlsSocket::wait_readable` 会先查 `mbedtls_ssl_get_bytes_avail`,所以并不是每字节一次 `poll()`,主要成本是每字节一次函数调用 —— **未做基准测试,不要当成性能修复来卖**),更重要的是:

**一个显式的读缓冲,才能让「这条连接干净吗」这个问题真正可回答**(= 缓冲区空 + body 已按 framing 读完)。现在这个问题只能靠人肉追踪 10 条路径。这是 P3-C 的主要理由,性能是副产品。

### P3-D 池连接失效时自动重连重试(issue #15 里被当引子带过的那条)

**即使 P0+P1+P2 全修完,这个场景依然会失败:**

服务端在两次请求之间关闭空闲 keep-alive 连接(**常规行为**)
→ `:357` `is_valid()` 为 true(fd 还开着)→ 复用
→ `:439` `write_all` 成功(第一个 TCP 写进缓冲区不报错)
→ `:447` `read_line` 返回空
→ `:449` → `statusCode=0, statusText="No response"`

报告者观察到「服务端日志里没有第二条连接、没有第二个请求」—— **客户端根本没重连**。

P0+P1 只是把「进程被杀」降级成「一个莫名其妙的 `No response`」。curl(`Curl_retry_request`)、Go `net/http`(`shouldRetryRequest`)、Python requests 都会在这种情况下静默重连重试一次,因为这个失败与请求内容无关,纯粹是池的簿记问题。

建议:

```
若 (连接取自池中的复用连接) 且 (在收到任何响应字节之前失败):
    丢弃连接 → 新建连接 → 重发一次(仅一次)
```

> 📌 **review 决策点 —— 要不要限制到幂等方法?**
>
> - Go 的策略保守:只重试幂等方法(GET/HEAD/OPTIONS/TRACE)或带 `Idempotency-Key` 的请求。
> - curl 的策略宽松:只要连接是复用的就重试,不看方法。
>
> **我倾向 curl 的做法**,理由:(1) tinyhttps 的主力场景是 LLM / API 客户端,POST 是绝对多数,限制到幂等方法等于这个修复基本没用;(2) 重试窗口极窄 —— 只在**一个响应字节都没收到**时才重试,此时服务端已经发过 FIN,应用层根本没看到这个请求;(3) 加一个 `HttpClientConfig::retryOnStaleConnection`(默认 true)让保守用户能关掉。
>
> ⚠️ 残留风险:服务端「收到并处理了请求 → 还没回响应就崩了/关了」这种情况下会重复执行。窄,但非零。**这一条请你拍板。**

---

## 6. 测试方案

### 6.1 现状 ✅

`tests/` 下只有 `test_download.cpp` 和 `test_resolver.cpp`,**零 keep-alive / 连接复用覆盖** —— 这就是 `#14` 的回归能全绿合进来的直接原因。

报告者主动提出「可以把 Content-Length 和 chunked 两个 case 写成对着本地 listener 的 gtest,风格照 `test_download.cpp`」,而且他手上已经有能跑的复现脚本(一个 Python server + 一个 `main.cpp` + `run.sh`)。**建议直接接受这个 offer**,这是最省事也最可信的路径。

### 6.2 必须覆盖的用例

| # | 用例 | 断言 | 覆盖 |
|---|---|---|---|
| T1 | 服务端发一半 CL body 后挂住 | 请求 2 `statusCode == 200`(不是 999/0/Invalid) | A1 |
| T2 | **同上,并断言服务端 TCP 连接数 == 2** | 🔴 **唯一能抓住「50 个 B」那种「看起来对了」的 case 的断言** | A1 |
| T3 | chunked 版本同上 | 同 T1 + T2 | A3 |
| T4 | 服务端发一半后关连接 | 请求 2 不崩 + 断言**进程未被信号杀死** | #16 |
| T5 | **`SIGPIPE` 保持默认处置**跑 T4(子进程) | `WIFSIGNALED == false`,退出码 != 141 | P0 |
| T6 | `Content-Length: 4294967296` | 不得静默当成 0;连接不得回池 | D1 |
| T7 | 302 + `Content-Length` body + keep-alive → 同 host | 重定向后的下载内容正确 + 连接数正确 | **C3** |
| T8 | 404 + error body + keep-alive,同 client 再发一个请求 | 第二个请求正确 | **C4** |
| T9 | chunk 头是 `zz` / 空行 | 报错,不得当成终止块 | B2 |
| T10 | 状态行是 `BBBB 999 XHTTP/1.1 200 OK` | `Invalid status line`,不是 `999` | P2-C1 |
| T11 | 截断的 body | `bodyComplete == false` | P2-F1 |

**T2 是整套测试里最关键的一条。** 没有连接数断言,issue #15 表格第三行(50 个 `B`,输出与对照组逐字节相同)**会静默通过**。

### 6.3 纯单元测试(不需要服务端)

`parse_status_line`(P2-C1 新增)、`parse_chunk_size_line`、`parse_content_length` 都是导出的纯函数,可以直接表驱动单测。`#9` 导出它们就是为了这个 —— 沿用这个模式。

---

## 7. 发布计划与回归风险

| 版本 | 内容 | 风险 |
|---|---|---|
| **0.2.11** | P0 + P1(全部 10 项) | **低**。全部只改早退路径,成功路径逐字节不变 |
| 0.2.12 | P2-C1~C4(解析加固) | 中。严格解析会把过去「蒙混过关」的畸形响应变成显式错误 —— **这是本意,但要写进 release note** |
| 0.2.13 | P2-E/D/F(分配上限、would-block、`bodyComplete`) | 中。`bodyComplete` 是加字段,非破坏性 |
| 0.3.0 | P3(结构性 + 重试) | 高,单独立项 |

**Release note 必须点名的两件事**:

1. **0.2.10 的 `send_stream` 回归**(A1/A2 由 `#14` 引入)。用 0.2.10 且用了 SSE 流式接口的用户应尽快升级。
2. **0.2.12 起,过去被静默接受的畸形响应会开始报错。** 这不是新 bug,是过去在静默损坏数据。

**P0 的兼容性**:需要在 Linux / macOS / Windows / Termux 四个平台各过一遍 CI。`MSG_NOSIGNAL` 和 `SO_NOSIGPIPE` 都在已 include 的 `<sys/socket.h>` 里,不需要新增 include。注意 `5e7d66f` 的教训 —— **必须 `#ifdef`,不能 `if constexpr`**。

---

## 附录 A:核验方法

```bash
# 本地 checkout 是 0.2.8,issue 行号对应 0.2.10,必须取 origin/master
git show origin/master:src/http.cppm   > v0210/http.cppm     # 1235 行
git show origin/master:src/socket.cppm > v0210/socket.cppm
git show origin/master:src/tls.cppm    > v0210/tls.cppm

# 全仓库确认无任何 SIGPIPE 处理
git grep -n "MSG_NOSIGNAL\|SIGPIPE\|NOSIGPIPE" origin/master          # 无命中

# A1/A2 回归定位
git log --oneline -S "A DECLARED LENGTH IS READ AND THE READER THEN STOPS" -- src/http.cppm
#   → 2cec1c1 (#14)
git show 0.2.3:src/http.cppm | sed -n '738,741p'                      # connectionClose = true 无条件

# mbedtls 自带的防护(被自定义 BIO 绕过)
grep -n "SIGPIPE" .../mbedtls-3.6.1/library/net_sockets.c             # :114 signal(SIGPIPE, SIG_IGN)
git grep -n "mbedtls_net_init" origin/master -- src/                  # 无命中

# 加固覆盖矩阵
grep -n "parse_content_length\|parse_hex\|parse_chunk_size_line\|read_complete_line" v0210/http.cppm

# SIGPIPE 机制独立复现
gcc -o sigpipe_probe sigpipe_probe.c && ./sigpipe_probe
#   flags=0 → signal 13 → exit 141;MSG_NOSIGNAL → 正常返回 -1/EPIPE
```

引用到的行号全部在 `origin/master @ 2cec1c1` (v0.2.10) 上逐条打开确认过。

## 附录 B:19 个修复项速查

| ID | 档 | 文件:行 | 一句话 |
|---|---|---|---|
| P0-1 | P0 | `socket.cppm:176-179` | `send` 加 `MSG_NOSIGNAL` |
| P0-2 | P0 | `socket.cppm:125` | macOS 加 `SO_NOSIGPIPE` |
| P1-A1 | P1 | `http.cppm:879` | `send_stream` CL 超时 → `connectionClose = true` |
| P1-A2 | P1 | `http.cppm:885` | `send_stream` CL EOF → `connectionClose = true` |
| P1-A3 | P1 | `http.cppm:847` | `send_stream` chunk 短读 → `connectionClose = true` |
| P1-B1 | P1 | `http.cppm:551` | `send_impl` chunk 短读 → `connectionClose = true` |
| P1-B2 | P1 | `http.cppm:541` | `parse_hex` → `parse_chunk_size_line`(并删除 `parse_hex`) |
| P1-C1 | P1 | `http.cppm:1166-1171` | download chunk 短读 → `close + erase` |
| P1-C2 | P1 | `http.cppm:1195-1200` | download CL 短读 → `close + erase` |
| P1-C3 | P1 | `http.cppm:1060-1075` | 🆕 **重定向未 drain body** |
| P1-C4 | P1 | `http.cppm:1077-1081` | 🆕 非 2xx 未 drain body |
| P1-C5 | P1 | `http.cppm:1092-1096` | 🆕 文件打开失败未 drain body |
| P1-D1 | P1 | `http.cppm:488` | 🆕 `int contentLength` → `int64_t`(整数截断) |
| P2-C1 | P2 | 三处状态行 | 🆕 校验 `HTTP/` 前缀 + 严格状态码 |
| P2-C2 | P2 | 三处 header 循环 | 用 `read_complete_line` 区分超时/空行 |
| P2-C3 | P2 | `:556` `:850` | 校验块后 CRLF |
| P2-C4 | P2 | `:1042-1048` | download 换 `parse_content_length` |
| P2-E2 | P2 | `:561` `:549` `:845` | 🆕 分配上限,防 2 GiB 分配 / 未文档化的异常 |
| P2-F1 | P2 | `HttpResponse` | 🆕 加 `bodyComplete` —— 调用方现在无法得知 body 被截断 |
