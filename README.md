# mcpplibs-tinyhttps

Minimal C++23 HTTP/HTTPS client library with SSE (Server-Sent Events) streaming support. Uses mbedTLS for TLS, zero external dependencies beyond that.

## Features

- HTTP/HTTPS client with connection pooling (keep-alive)
- SSE (Server-Sent Events) streaming
- Proxy support (HTTP CONNECT)
- Segmented parallel downloads via HTTP Range (aria2-style)
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

## Parallel downloads

`download_to_file_parallel()` probes the server with `Range: bytes=0-0`; when
the server answers 206 the file is split into segments fetched concurrently
into a pre-allocated file. It falls back to a plain sequential download when
the server ignores Range (200) or the file is too small to split.

```cpp
import mcpplibs.tinyhttps;
namespace https = mcpplibs::tinyhttps;

https::HttpClientConfig cfg;
cfg.maxConnectionsPerFile = 8;          // concurrent segment workers
cfg.maxSegments         = 16;           // aria2 -s: split count (0 = tie to connections)
cfg.minSegmentBytes     = 4 << 20;      // aria2 --min-split-size: 4 MiB

https::HttpClient client(cfg);
auto result = client.download_to_file_parallel(
    "https://example.com/big.iso",
    "big.iso",
    [](std::int64_t total, std::int64_t done) {
        // monotonic progress; total is 0 when unknown
    },
    [] { return false; }                // return true to cancel
);
if (result.ok()) { /* result.bytesWritten, result.expectedBytes, ... */ }
```

Behavior notes:

- Segment boundaries never overlap; interrupted segments resume mid-range on
  retry (up to 2 retries per segment).
- Progress callbacks are serialized and monotonically increasing.
- The pre-allocated target file is removed if the download fails.

## 使用 mcpp 构建

### 添加依赖

```bash
mcpp add tinyhttps@0.2.2
```

或在 `mcpp.toml` 中手动添加：

```toml
[dependencies]
tinyhttps = "0.2.2"
```

### 构建

```bash
mcpp build
```

### 代码示例

```cpp
import mcpplibs.tinyhttps;
// ... usage example
```

## License

Apache-2.0
