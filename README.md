# mcpplibs-tinyhttps

Minimal C++23 HTTP/HTTPS client library with SSE (Server-Sent Events) streaming support. Uses mbedTLS for TLS, zero external dependencies beyond that.

## Features

- HTTP/HTTPS client with connection pooling (keep-alive)
- SSE (Server-Sent Events) streaming
- Streaming downloads to a file, with progress and cancellation
- Proxy support (HTTP CONNECT)
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

### Configuration

| field | default | what it decides |
| --- | --- | --- |
| `connectTimeoutMs` | 10000 | TCP connect |
| `readTimeoutMs` | 60000 | any single read, and the total wait on a blocked write |
| `verifySsl` | true | verify the server certificate |
| `keepAlive` | true | reuse connections between requests |
| `maxRedirects` | 10 | 0 disables redirect following |
| `maxResponseBodyBytes` | 64 MiB | the most `send()` will hold in memory; does not bound `download_to_file` or `send_stream` |
| `retryOnStaleConnection` | true | resend once when a pooled connection turns out to have been closed while idle |

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

## 使用 mcpp 构建

### 添加依赖

```bash
mcpp add tinyhttps@0.3.0
```

或在 `mcpp.toml` 中手动添加：

```toml
[dependencies]
tinyhttps = "0.3.0"
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
if (!result.ok()) { /* result.error */ }
```

## License

Apache-2.0
