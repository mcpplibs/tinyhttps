# Changelog

## 0.3.0

Closes [#15](https://github.com/mcpplibs/tinyhttps/issues/15) (a socket returned
to the pool with bytes still owed on it) and
[#16](https://github.com/mcpplibs/tinyhttps/issues/16) (a write to a departed
peer killing the host process).

**#15 named two of the eleven paths that could leak a connection.** All eleven
are fixed here. Four of the other nine turned up while verifying the report — a
redirect, a non-2xx and a failed file open, none of which involve a timeout or a
truncation at all, plus a `Content-Length` past 32 bits — and two more (the
streaming reader's `Content-Length` exits) were regressions 0.2.10 had
introduced.

### ⚠️ Read this first

**If you are on 0.2.10 and use `send_stream`, upgrade.** 0.2.10 added a
`Content-Length` branch to the streaming reader whose two exits — a read timeout
and an end of stream — left the connection marked reusable where the branch they
replaced never did. A stream cut short therefore poisoned the next request on
that client.

**Malformed responses that used to be accepted in silence now report an error.**
A status line that is not one, a chunk header that does not parse, a header
block cut short by a timeout: each of these used to produce a plausible-looking
result. They are not new failures — they are failures that were previously
invisible. `HttpResponse::bodyError` says which.

**Nothing in the API was removed or changed shape.** Existing code compiles
unchanged, and `ok()` means exactly what it did.

### Fixed

- **A write to a socket whose peer has gone away no longer raises `SIGPIPE`**
  (#16). `Socket::write` sends with `MSG_NOSIGNAL` where the platform has it and
  sets `SO_NOSIGPIPE` on the descriptor where it does not. Previously a program
  that had not disarmed the signal itself — the default — was killed with exit
  status 141, most often from inside the pool's own clean-up. The library no
  longer changes its host's signal disposition either, which is what mbedtls's
  own network layer does and what replacing that layer had silently dropped.
- **A connection is returned to the pool only when the body was read to the end
  its framing declared** (#15). Ten early-return paths each had to remember to
  mark the connection unusable and several did not; the invariant is now carried
  by a guard whose default is to drop, so a path that does nothing is safe.
  The paths that were leaking: a stream that timed out or ended mid-body, a
  chunk that was cut short, a chunked download that failed, a download whose
  declared body was cut short, **a redirect whose body was never read**, **a
  non-2xx whose error body was never read**, and **a download whose output file
  could not be opened**. The last three are ordinary paths with no timeout and
  no truncation involved.
- **A status line that is not a status line is rejected** rather than mined for
  digits. `BBBB 999 XHTTP/1.1 200 OK` — leftover body bytes read as a status
  line — used to be reported as an ordinary `999`.
- **A `Content-Length` past 32 bits is no longer truncated.** `send()` held it in
  an `int`, so `4294967296` became `0`, the body was taken for empty, and the
  socket went back into the pool with four gigabytes owed on it. This was the
  only pool defect a server could trigger with a single header.
- **A chunk header that does not parse is not a terminal chunk.** `send()` still
  used the salvaging hex parser, which returned `0` — the value that means "body
  ends here" — for an empty line, and an empty line is what a timed-out read
  produced.
- **A header block cut short by a timeout is an error**, not the end of the
  headers. The reader went on to the body with half the headers and no framing.
- **The CRLF after chunk data is verified** in `send()` and `send_stream`, as it
  already was in `download_to_file`.
- **`download_to_file` parses `Content-Length` strictly**, as the other two
  readers already did.
- **A response with no body is not read for one.** 204 and 304 carry a
  `Content-Length` describing what a `GET` would have returned; reading that many
  bytes consumed the next response instead. Only `HEAD` was handled.
- **An interim 1xx response is read past rather than returned as the answer**
  (RFC 9112 §2.1). A `103 Early Hints` — sent proactively by several CDNs — or a
  `100 Continue` — sent for any request carrying `Expect: 100-continue` — was
  reported to the caller as the result, and the real response was then read as
  its body. Found by review, along with the fact that skipping the body of a 1xx
  without also reading past it would have marked the connection clean with the
  real response still on it: issue #15 arriving by another door.
- **An end of stream is no longer reported as a transport error.** The BIO under
  mbedtls answered a peer's FIN with `MBEDTLS_ERR_NET_CONN_RESET`; mbedtls's own
  BIO passes the zero through, and `ssl_fetch_input` tests for exactly that zero
  to produce `SSL_CONN_EOF` (`ssl_msg.c:2251`). Since most servers close without
  a TLS `close_notify`, a body whose framing *is* the close — legal per RFC 9112
  §6.3 — read as truncated: `download_to_file` set `error` and `ok()` returned
  false for a file that had arrived complete and correct.
- **TLS back-pressure is waited on rather than retried once and abandoned.** A
  slow peer used to reach the caller as an unexplained `"Write failed"`.

### Added

- `HttpResponse::bodyComplete` and `HttpResponse::bodyError` — whether the body
  arrived in full, and why not. A truncated 200 and a complete 200 were
  previously indistinguishable. `ok()` does not consult them, so no existing
  behaviour changes.
- `HttpClientConfig::maxResponseBodyBytes` (default 64 MiB) — bounds what
  `send()` will hold in memory. A server could previously induce an allocation of
  any size by writing a header, and reach an undocumented `std::length_error`.
  Does not bound `download_to_file` or `send_stream`, which stream.
- `HttpClientConfig::retryOnStaleConnection` (default true) — resend once when a
  connection taken from the pool turns out to have been closed while idle, which
  is routine server behaviour the client cannot see until it writes. Without it
  such a request returned `statusCode = 0, "No response"` for a request the
  server never saw. The window is one attempt, on a pooled connection, before a
  single response byte has arrived.
- `parse_status_line`, exported and unit-testable without a server, alongside
  `parse_content_length` and `parse_chunk_size_line`.
- `TlsSocket::read_some`, returning `Data`/`WouldBlock`/`Eof`/`Error`. `read()`
  collapsed an end of stream and a transport that was not ready into the same
  `0`, which is why callers could not tell a finished body from a stalled one.
  `read()` is unchanged and still exported.
- `examples/openkal` — the library built above
  [openkal](https://github.com/mcpplibs/openkal), making a real HTTPS request
  through `kal_net_connect`. Run in CI.
- **Project templates**, scaffolded with `mcpp new --template tinyhttps[:name]`:
  `fetch` (default), `download` and `stream`, one per entry point.
  `tools/template_smoke.sh` renders and builds each of them against the working
  tree — a template can only be checked before the release that ships it, not
  after — and CI runs it.

### Changed

- `send`, `send_stream` and `download_to_file` share one status-line parser, one
  header reader and one body reader. They previously carried three near-copies,
  and every past hardening had landed on one or two of them — which is the whole
  of why #15 had eight instances rather than one.
- A short 3xx or error body is drained (up to 64 KiB) so the connection survives
  a redirect, instead of being dropped with it.
- `send_stream` no longer overwrites the server's reason phrase with a transfer
  error; the reason goes to `bodyError`.

### Tests

`tests/` had no keep-alive coverage at all, which is why the 0.2.10 regression
was merged green. It now has a scripted in-process TLS server, and every pool
test asserts **how many TCP connections the server saw** as well as what came
back — the report for #15 contains a case whose output is byte-for-byte correct
and whose only symptom is the connection count.

Each fix was checked by mutation: reverting it in the source makes specific tests
fail, and restoring it makes them pass.
