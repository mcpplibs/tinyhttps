# mcpplibs-tinyhttps

Minimal C++23 HTTP/HTTPS client library with SSE (Server-Sent Events) streaming support. Uses mbedTLS for TLS, zero external dependencies beyond that.

## Features

- HTTP/HTTPS client with connection pooling (keep-alive)
- SSE (Server-Sent Events) streaming
- Streaming downloads to a file, with progress and cancellation
- Proxy support (HTTP CONNECT over plain HTTP or TLS, with Basic authentication; SOCKS5)
- C++23 modules

## Usage

```lua
-- xmake.lua
add_requires("mcpplibs-tinyhttps")
target("myapp")
    add_packages("mcpplibs-tinyhttps")
```

```cpp
import mcpplibs.tinyhttps;

auto client = mcpplibs::tinyhttps::HttpClient({});
auto resp = client.send(mcpplibs::tinyhttps::HttpRequest::post(
    "https://api.example.com/data",
    R"({"key": "value"})"
));
```

### Knowing whether you received all of it

`ok()` reports what the server said. `bodyComplete` reports whether the body
arrived in full — a read that timed out, a connection that ended mid-body or a
chunk header that did not parse all leave a *prefix* of the body behind a
perfectly ordinary status code.

```cpp
auto resp = client.send(request);
if (!resp.ok())            { /* the server refused: resp.statusCode  */ }
else if (!resp.bodyComplete) { /* the transfer broke: resp.bodyError */ }
else                       { /* resp.body is all of it */ }
```

`ok()` deliberately does not consult `bodyComplete`, so existing `if (res.ok())`
means exactly what it did before.

### Cancelling a request

Pass a `std::stop_token` to `send`, `send_stream` or `download_to_file` and stop
its source from another thread. The call returns within about 50 ms with
`cancelled` set, and the connection is closed rather than pooled.

```cpp
HttpResponse response;
std::jthread worker([&](std::stop_token stop) { response = client.send(request, stop); });
// elsewhere:
worker.request_stop();
```

If the status line had not arrived, `statusCode` is 0 and `statusText` is
`Cancelled`; otherwise they are the server's and `bodyError` is `cancelled`.
As with `bodyComplete`, `ok()` does not look at `cancelled`. A cancelled request
is not retried and its redirect is not followed. `download_to_file` reports the
same in `DownloadToFileResult::cancelled` and `error`, whether the token or its
`isCancelled` callback asked.

It covers connecting, a proxy's handshake, the TLS handshake, waiting for the
response and reading it. Name resolution and a write blocked on a server that is
not reading cannot be interrupted. Without a token nothing changes.

With libc++ 20 or 22, a file that includes a standard header such as `<thread>`
and then `import std;` fails to link `std::stop_source::request_stop()` (an
inline helper of libc++'s is never emitted). Put `import std;` before the
includes in that file, or use libc++ 23 or libstdc++.

### Configuration

| field | default | what it decides |
| --- | --- | --- |
| `connectTimeoutMs` | 10000 | TCP connect |
| `readTimeoutMs` | 60000 | any single read, and the total wait on a blocked write |
| `verifySsl` | true | verify the server certificate against the CA bundle (`SSL_CERT_FILE`, else the Windows `ROOT` certificate store in Windows Sockets builds, else a system location); the connection fails if the certificate is not trusted, has expired or is for another host, or if no bundle is found |
| `keepAlive` | true | reuse connections between requests |
| `maxRedirects` | 10 | 0 disables redirect following |
| `maxResponseBodyBytes` | 64 MiB | the most `send()` will hold in memory; does not bound `download_to_file` or `send_stream` |
| `retryOnStaleConnection` | true | resend once when a pooled connection turns out to have been closed while idle |
| `proxy` | none | proxy URL, see below |

### Proxies

Set `proxy` to a URL and every request is tunnelled through it with `CONNECT`:

```cpp
cfg.proxy = "http://user:pass@proxy.example:3128";
```

The scheme is `http` (a bare `host:port` means the same), `https`, `socks5` or
`socks5h`.

An `https://` proxy is reached over TLS first, the `CONNECT` is sent inside that
session, and the connection to the target is a second TLS session inside the
tunnel; the two connections are set up alike, `verifySsl` included.

With `socks5` the target's name is resolved here and the proxy is given an
address; with `socks5h` the proxy is given the name and resolves it itself,
which is what to use when the proxy is the only thing that can see the target's
DNS. An address literal is sent as an address either way. The client offers the
SOCKS5 proxy no authentication, plus the username/password method when the URL
has credentials. SOCKS4 is not supported.

Credentials are read from the URL and sent as Basic `Proxy-Authorization` (or as
the SOCKS5 username and password); percent-escape any character that is special
in a URL (`p%40ss` for `p@ss`). The port defaults to 8080, 443 for `https`, and
1080 for the SOCKS schemes.

When the proxy refuses the tunnel, `statusCode` is 0 and `statusText` carries
its answer: `proxy rejected the credentials: 407 Proxy Authentication Required`,
`proxy refused CONNECT: 403 Forbidden`, `proxy refused CONNECT: connection
refused (SOCKS5 reply 5)`. Any other scheme (`socks4://`, say) fails the same
way instead of being read as HTTP.

## Project templates

The package ships starting points in `templates/`. Scaffold one with `mcpp new`
— the template comes from the library, so it is always the version you asked
for:

```bash
mcpp new --list-templates tinyhttps      # what this library provides
mcpp new myapp --template tinyhttps      # the default (fetch)
mcpp new grab  --template tinyhttps:download
mcpp new chat  --template tinyhttps@0.3.0:stream
```

| Template | What it starts you with |
| --- | --- |
| `fetch` (default) | One request, and how to tell a complete answer from a truncated one |
| `download` | A file streamed to disk, with a progress bar, cancellation and `ETag`/`Last-Modified` |
| `stream` | Server-Sent Events — a streaming LLM chat completion, token by token |

The selector is `[namespace.]name[@version][:template]`; omit `:template` for
the default. Templates are pure data — rendered and copied, with no hooks and no
script execution — and the placeholder vocabulary is mcpp's:
`{{project.name}}`, `{{template.package.name}}`, `{{template.package.version}}`
and a few more.

A template is part of the release that ships it, so it has to be checked before
that release exists in the index:

```bash
bash tools/template_smoke.sh    # renders, builds and runs every template
```

It repoints each generated project at this checkout, so it verifies the
templates against the working tree rather than against whatever is published.
CI runs it.

## Platforms

Linux, macOS, Windows, Android/Termux — and above
[openkal](https://github.com/mcpplibs/openkal), the portable kernel ABI, where
the C library is musl ported onto openkal rather than the host's.

`examples/openkal` builds this library from the checkout against the published
openkal stack and makes a real HTTPS request through it; CI runs it on every
push. See the platform table at the top of `src/platform.cppm` for what actually
differs between them.

```bash
cd examples/openkal && mcpp run
```

Above openkal two things differ from a host build. Both follow from the layer
beneath and not from this library:

- On Windows the socket interface is the POSIX one, because the C library is
  musl, so the Windows `ROOT` certificate store is not read. Set `SSL_CERT_FILE`
  to a PEM bundle of trusted roots; without one every HTTPS connection is
  refused, and `statusText` says so.
- `connectTimeoutMs` does not bound the TCP connect. `kal_net_connect` has no
  form that begins a connection and reports its outcome later, so the connect
  completes or fails before it returns. A stop token is checked before the
  connect, not during it.
- On Windows there is no name resolution: openkal has no resolver interface,
  and musl's reads `/etc/resolv.conf`, which Windows does not have. A URL with
  an address in it connects.

CI runs `examples/openkal` for x86_64-linux-gnu, x86_64-linux-musl,
aarch64-linux-musl (under qemu) and x86_64-windows-musl (under wine).

## 使用 mcpp 构建

### 添加依赖

```bash
mcpp add tinyhttps@0.3.4
```

或在 `mcpp.toml` 中手动添加：

```toml
[dependencies]
tinyhttps = "0.3.4"
```

### 构建

```bash
mcpp build
mcpp test
```

### 代码示例

```cpp
import mcpplibs.tinyhttps;

mcpplibs::tinyhttps::HttpClient client;
auto result = client.download_to_file(
    "https://example.com/big.tar.gz", "out/big.tar.gz",
    [](std::int64_t total, std::int64_t done) { /* progress */ });
if (!result.ok()) {
    // result.error says why; result.writeFailed says the local file is at
    // fault (a full disk, a refused write) and not the server.
}
```

## License

Apache-2.0
