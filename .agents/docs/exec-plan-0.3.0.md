# 执行计划 —— 0.3.0:把连接池不变量写进类型里

| | |
|---|---|
| 输入 | [`fix-plan-issue-15-16.md`](fix-plan-issue-15-16.md)(19 项)+ openkal 体系适配 |
| 基线 | `origin/master @ 2cec1c1`(0.2.10) |
| 目标 | **0.3.0** —— 单 PR 全量实现 P0 + P1 + P2 + P3-A/B/D |
| 分支 | `fix/pool-invariants-and-sigpipe` |

---

## 0. 为什么是一个 PR、为什么是 0.3.0

原方案建议拆 4 个 PR(0.2.11 → 0.2.12 → 0.2.13 → 0.3.0)。这里合并成一个,理由是**依赖方向**而不是省事:

- P1 的十处补丁,和 P3-A 的 RAII guard,**是同一件事的两种写法**。先合 P1 再合 P3-A,等于把十个 `connectionClose = true` 写进去、下一个 PR 再全部删掉。
- P2-C1/C2/C4(状态行、header 循环、Content-Length)在三个入口各有一份拷贝。P3-B 把三份合成一份之后,这三项**只需要改一处**;不合并就要改九处再删六处。
- §1.1 的矩阵证明:**分批修 = 每批只落到一两份拷贝上**。`#14` 就是这样引入 A1/A2 回归的。一个 PR 是让这张矩阵不再存在的唯一方式。

版本取 **0.3.0** 而不是 0.2.11:`HttpResponse` / `HttpClientConfig` 加了字段(非破坏),严格解析会把过去静默接受的畸形响应变成显式错误(**行为变更**)。语义化版本下,行为变更进 minor。

**无感升级的边界**(release note 必须点名):
- ✅ 现有代码**不需要改一行**就能编译:只加字段,不改签名,`ok()` 语义不变。
- ⚠️ 过去被静默接受的畸形响应现在会报错 —— 这不是新 bug,是过去在静默损坏数据。

---

## 1. 八个视角,各自要什么

| 视角 | 要求 | 落在哪 |
|---|---|---|
| **架构** | 池不变量不能靠十个早退路径各自记得维护 | P3-A `PooledConnection`(默认丢弃)+ P3-B 三份 reader 合一 |
| **稳定性** | 库不得杀死宿主进程;不得因一个 header 分配 2 GiB | P0(`MSG_NOSIGNAL`/`SO_NOSIGPIPE`)、P2-E2(分配上限) |
| **优雅简洁** | 一个概念一处实现 | 删 `parse_hex`;`read_response_head` / `read_body` 各一份;`parse_status_line` 一份 |
| **用户体验** | 调用方要能知道 body 被截断了;空闲连接被服务端关掉不该变成 `No response` | P2-F1 `bodyComplete`+`bodyError`、P3-D 陈旧连接重试 |
| **兼容性** | 只加字段,不改签名,`ok()` 不变 | `HttpResponse` / `HttpClientConfig` 追加字段;`TlsSocket::read` 保留 |
| **跨平台** | Linux / macOS / Windows / Termux / **openkal** 全绿 | `#ifdef` 而非 `if constexpr`(5e7d66f 的教训);平台事实集中在 `platform.cppm` |
| **一致性** | `send` / `send_stream` / `download_to_file` 三个入口行为逐条相同 | P3-B 之后三者共用同一个 head/body reader |
| **无感升级** | 升级不需要改代码 | 见 §0 |

---

## 2. 任务依赖图

```
T0  分支 + 计划                                    ✔
 │
 ├─ T1  P0 SIGPIPE（socket.cppm）  ★ 必须最先
 │   │   P0-1 send() + MSG_NOSIGNAL
 │   │   P0-2 socket() 后 setsockopt(SO_NOSIGPIPE)
 │   │   理由：T5 让 pool_.erase() 在更多路径上执行，
 │   │        erase → ~TlsSocket → close_notify → send()。
 │   │        T1 没做之前，T5 等于扩大 SIGPIPE 触发面。
 │   │
 │   ├─ T2  P2-D1/D2（tls.cppm / http.cppm 的 write_all）
 │   │       read_some() 三态：Data / WouldBlock / Eof / Error
 │   │       write_all 遇 WANT_WRITE 改为 wait_writable + 总时限
 │   │       （T3 的 reader 建立在三态之上）
 │   │
 │   └─ T3  P3-B 统一 reader（http.cppm）  ← 吸收 P2-C1/C2/C4 + P1-D1
 │           parse_status_line（导出，严格）
 │           read_response_head → expected<ResponseHead, string>
 │           read_body → BodyOutcome{Complete|Truncated|ClosedByPeer|Stopped}
 │            ├ 吸收 P1-B2（parse_chunk_size_line，删 parse_hex）
 │            ├ 吸收 P2-C3（块后 CRLF 校验）
 │            └ 吸收 P2-E2（分配上限，chunk 分片读）
 │           │
 │           ├─ T4  P3-A PooledConnection（默认丢弃）← 吸收 P1-A/B/C 全部十项
 │           │   │   ⚠ 递归重定向：递归前必须 keep() 或 drop()，不能让析构跨过递归
 │           │   │
 │           │   ├─ T5  P2-E1 bounded drain（重定向/非 2xx/文件打不开时省一次握手）
 │           │   ├─ T6  P2-F1/F2 bodyComplete + bodyError（statusText 不再被覆盖）
 │           │   └─ T7  P3-D 陈旧连接重试（一次，仅在零响应字节时）
 │           │
 │           └─ T8  纯单测：parse_status_line / parse_chunk_size_line / parse_content_length
 │
 ├─ T9  集成测试:进程内 mbedtls TLS listener（T4 后）
 │       ⚠ tinyhttps 只支持 https，本地明文 listener 用不了 → 必须自带 TLS 服务端
 │       T1..T11 用例见 §4
 │
 ├─ T10 openkal 体系(与 T1..T9 并行调研,结论落地在 T1/platform.cppm)
 │
 └─ T11 文档 / release note / README ← 依赖全部
     └─ T12 CI 全绿 → 自审 → PR → release → gtc 补 gitcode → mcpp-index → 生态验证
```

**关键路径**:T1 → T3 → T4 → T9 → T12。
**可并行**:T8、T10 与 T2..T7 无共享状态。

---

## 3. 原方案 19 项 → 本计划落点

| 原 ID | 落在 | 备注 |
|---|---|---|
| P0-1 / P0-2 | T1 | 逐字采纳 |
| P1-A1/A2/A3、B1、C1/C2/C3/C4/C5 | **T4** | 十项全部由 `PooledConnection` 默认丢弃消除,不逐条打补丁 |
| P1-B2 | T3 | 并入统一 chunk reader;`parse_hex` 删除 |
| P1-D1 | T3 | `ResponseHead::contentLength` 只有 `int64_t` 一种类型 |
| P2-C1 | T3 | 新增导出 `parse_status_line` |
| P2-C2 | T3 | `read_response_head` 全程用 `read_complete_line` |
| P2-C3 | T3 | 块后 CRLF 必须是空行 |
| P2-C4 | T3 | 统一 `parse_content_length` |
| P2-E1 | T5 | `drain_body`,上限 64 KiB |
| P2-E2 | T3 | `maxResponseBodyBytes`(默认 64 MiB);chunk 按固定缓冲分片读,不按块大小分配 |
| P2-D1 | T2 | `TlsSocket::read_some` 三态;`read()` 保留 |
| P2-D2 | T2 | `write_all` 用 `wait_writable` |
| P2-F1 | T6 | `bodyComplete`,`ok()` 不变(方案 a,非破坏) |
| P2-F2 | T6 | `statusText` 不再被错误信息覆盖;原因进 `bodyError` |
| P3-A | T4 | 采纳 |
| P3-B | T3 | 采纳(head + body 都合) |
| P3-C 带缓冲的读 | **不做** | 见 §5 |
| P3-D | T7 | 采纳 curl 策略 + `retryOnStaleConnection` 开关(默认 true) |

### 两个 review 决策点的裁定

- **P2-F1 `ok()` 是否要求 `bodyComplete`** → **不要求**(方案 a)。目标写明「无感升级」;让 `ok()` 变严会让现有代码在**升级后**行为改变,与之直接冲突。截断可见性由新字段提供。
- **P3-D 是否限制到幂等方法** → **不限制**(curl 策略),加 `retryOnStaleConnection` 开关。重试窗口是「一个响应字节都没收到」,此时服务端已发 FIN、应用层没看到这个请求;限制到幂等方法等于对 LLM/API 客户端(POST 为主)这个修复基本无效。

---

## 4. 测试矩阵

### 4.1 纯单测(无需服务端)—— T8

`parse_status_line` / `parse_chunk_size_line` / `parse_content_length` / `append_within_limit` 表驱动。
其中 `parse_status_line` 必须覆盖 issue #15 的原始输入 `"BBBB 999 XHTTP/1.1 200 OK"` → 拒绝。

### 4.2 集成测试 —— T9

**为什么必须自带 TLS 服务端**:`send/send_stream/download_to_file` 三个入口开头都有
`if (parsed.scheme != "https") return "Only HTTPS is supported"`,本地明文 listener 根本进不去。
所以测试自带一个进程内 mbedtls TLS listener(自签证书,`verifySsl = false`),
`MBEDTLS_SSL_SRV_C` / `MBEDTLS_PEM_PARSE_C` 在依赖的 mbedtls 3.6.1 配置里已开启(已核验)。

| # | 用例 | 断言 | 覆盖 |
|---|---|---|---|
| T1 | 服务端发一半 CL body 后挂住 | 请求 2 `statusCode == 200` | P1-A1 |
| T2 | 同上,**并断言服务端 accept 次数 == 2** | 🔴 唯一能抓住「看起来对了」的断言 | P1-A1 |
| T3 | chunked 版本同上 | 同 T1+T2 | P1-A3 |
| T4 | 服务端发一半后关连接 | 不崩;进程未被信号杀死 | #16 |
| T5 | `SIGPIPE` 默认处置下跑 T4(子进程) | `WIFSIGNALED == false`,退出码 ≠ 141 | P0 |
| T6 | `Content-Length: 4294967296` | 不得当成 0;连接不得回池 | P1-D1 |
| T7 | 302 + CL body + keep-alive → 同 host | 内容正确 + accept 次数正确 | P1-C3 |
| T8 | 404 + error body + keep-alive,同 client 再发一个 | 第二个请求正确 | P1-C4 |
| T9 | chunk 头是 `zz` / 空行 | 报错,不得当成终止块 | P1-B2 |
| T10 | 状态行 `BBBB 999 XHTTP/1.1 200 OK` | `Invalid status line`,不是 999 | P2-C1 |
| T11 | 截断的 body | `bodyComplete == false` | P2-F1 |
| T12 | 正常 keep-alive 两请求 | accept 次数 == **1**(不能因为修得太狠而丢掉复用) | 回归护栏 |
| T13 | 服务端在两请求之间关闭空闲连接 | 请求 2 成功,accept 次数 == 2 | P3-D |

**T12 与 T2 是一对**:T2 保证脏连接被丢弃,T12 保证干净连接被保留。只有 T2 会让「关掉连接池」这种过度修复也通过。

---

## 5. 明确不做的,和为什么

| 项 | 不做的理由 |
|---|---|
| **P3-C 带缓冲的读** | 原方案自陈「不要当成性能修复来卖」,其主要理由是「让『这条连接干净吗』可回答」——而 T4 的 guard + T3 的严格 framing 已经把这个问题回答了:干净 = `read_body` 返回 `Complete`。缓冲区是第二种表达,不是必需的一种。单独立项。 |
| **openkal 原生 socket 后端** | 见 §6。 |

---

## 6. openkal 体系

调研 T10 输出决定落点;先记录已核验的事实:

- `openkal-musl/port/src/okm_net.c:546-550`:`MSG_NOSIGNAL` 被**接受并忽略**(注释原文:"asks that a signal not be raised. There are no signals here"),`rest = flags & ~(MSG_NOSIGNAL | MSG_DONTWAIT)`,其余 flag 返回 `-ENOSYS`。
  ⇒ **P0-1 在 openkal 体系上是正确且无副作用的**,而且必须写成 `#ifdef MSG_NOSIGNAL`(否则 macOS 分支编不过,见 `5e7d66f`)。
- `SO_NOSIGPIPE` 是 BSD/macOS 的拼法,musl 头文件不定义 ⇒ P0-2 在 openkal-musl 上自动不编入。

---

## 7. 交付顺序

1. T1 → T2 → T3 → T4 → T5/T6/T7(实现)
2. T8 / T9(测试)
3. T10 结论落地
4. T11 文档 + release note
5. 本地 `mcpp build && mcpp test` 全绿 → 推 PR → CI 全绿 → 自审 → 合并
6. tag + GitHub release → `gtc` 本地补 gitcode 资源(不等 release CI)
7. mcpp-index 增加 0.3.0 条目 → 生态真实验证
