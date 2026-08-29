export module mcpplibs.tinyhttps:http;

import :tls;
import :socket;
import :sse;
import :proxy;
import std;

namespace mcpplibs::tinyhttps {

export enum class Method { GET, POST, PUT, DELETE_, PATCH, HEAD };

export struct HttpRequest {
    Method method { Method::GET };
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;

    static HttpRequest post(std::string_view url, std::string_view body) {
        return { Method::POST, std::string(url),
                 {{"Content-Type", "application/json"}},
                 std::string(body) };
    }
};

export struct HttpResponse {
    int statusCode { 0 };
    std::string statusText;
    std::map<std::string, std::string> headers;
    std::string body;

    bool ok() const { return statusCode >= 200 && statusCode < 300; }
};

export struct HttpClientConfig {
    std::optional<std::string> proxy;
    int connectTimeoutMs { 10000 };
    int readTimeoutMs { 60000 };
    bool verifySsl { true };
    bool keepAlive { true };
    int maxRedirects { 10 };   // 0 = don't follow redirects
};

// Progress callback for streaming downloads: (totalBytes, downloadedBytes)
// totalBytes is 0 when Content-Length is unknown (chunked/connection-close).
export using DownloadProgressFn = std::function<void(std::int64_t total, std::int64_t downloaded)>;

export struct DownloadToFileResult {
    int statusCode { 0 };
    std::string error;
    std::int64_t bytesWritten { 0 };
    std::optional<std::int64_t> expectedBytes;
    std::string finalUrl;
    std::string etag;
    std::string lastModified;
    bool ok() const { return statusCode >= 200 && statusCode < 300 && error.empty(); }
};

export template<typename F>
concept SseCallback = std::invocable<F, const SseEvent&> &&
                      std::same_as<std::invoke_result_t<F, const SseEvent&>, bool>;
                      // return false to stop receiving

export using SseCallbackFn = std::function<bool(const SseEvent&)>;

struct ParsedUrl {
    std::string scheme;
    std::string host;
    int port { 443 };
    std::string path;
};

static ParsedUrl parse_url(std::string_view url) {
    ParsedUrl result;

    // Extract scheme
    auto schemeEnd = url.find("://");
    if (schemeEnd == std::string_view::npos) {
        return result;
    }
    result.scheme = std::string(url.substr(0, schemeEnd));
    url = url.substr(schemeEnd + 3);

    // Extract host (and optional port)
    auto pathStart = url.find('/');
    std::string_view authority;
    if (pathStart == std::string_view::npos) {
        authority = url;
        result.path = "/";
    } else {
        authority = url.substr(0, pathStart);
        result.path = std::string(url.substr(pathStart));
    }

    // Check for port
    auto colonPos = authority.find(':');
    if (colonPos != std::string_view::npos) {
        result.host = std::string(authority.substr(0, colonPos));
        auto portStr = authority.substr(colonPos + 1);
        result.port = 0;
        for (char c : portStr) {
            if (c >= '0' && c <= '9') {
                result.port = result.port * 10 + (c - '0');
            }
        }
    } else {
        result.host = std::string(authority);
        result.port = (result.scheme == "https") ? 443 : 80;
    }

    if (result.path.empty()) {
        result.path = "/";
    }

    return result;
}

// Check if user headers contain a key (case-insensitive)
static bool has_header(const std::map<std::string, std::string>& headers, std::string_view key) {
    for (const auto& [k, v] : headers) {
        if (k.size() == key.size()) {
            bool match = true;
            for (std::size_t i = 0; i < k.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(k[i])) !=
                    std::tolower(static_cast<unsigned char>(key[i]))) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
    }
    return false;
}

static std::string_view method_to_string(Method m) {
    switch (m) {
        case Method::GET:     return "GET";
        case Method::POST:    return "POST";
        case Method::PUT:     return "PUT";
        case Method::DELETE_: return "DELETE";
        case Method::PATCH:   return "PATCH";
        case Method::HEAD:    return "HEAD";
    }
    return "GET";
}

// Read exactly n bytes from socket, using wait_readable for timeout
static bool read_exact(TlsSocket& sock, char* buf, int n, int timeoutMs) {
    int total = 0;
    while (total < n) {
        if (!sock.wait_readable(timeoutMs)) {
            return false;
        }
        int ret = sock.read(buf + total, n - total);
        if (ret < 0) return false;
        if (ret == 0) {
            // Try again after wait
            if (!sock.wait_readable(timeoutMs)) return false;
            ret = sock.read(buf + total, n - total);
            if (ret <= 0) return false;
        }
        total += ret;
    }
    return true;
}

// Read a line (ending with \r\n) from socket
static std::string read_line(TlsSocket& sock, int timeoutMs) {
    std::string line;
    char c;
    while (true) {
        if (!sock.wait_readable(timeoutMs)) {
            break;
        }
        int ret = sock.read(&c, 1);
        if (ret < 0) break;
        if (ret == 0) {
            // Try once more
            if (!sock.wait_readable(timeoutMs)) break;
            ret = sock.read(&c, 1);
            if (ret <= 0) break;
        }
        line += c;
        if (line.size() >= 2 && line[line.size() - 2] == '\r' && line[line.size() - 1] == '\n') {
            line.resize(line.size() - 2);
            break;
        }
    }
    return line;
}

static std::expected<std::string, std::string>
read_complete_line(TlsSocket& sock, int timeoutMs) {
    std::string line;
    char c {};
    while (true) {
        if (!sock.wait_readable(timeoutMs)) {
            return std::unexpected("timeout or EOF before CRLF");
        }
        int ret = sock.read(&c, 1);
        if (ret <= 0) {
            return std::unexpected("EOF before CRLF");
        }
        line += c;
        if (line.size() >= 2
            && line[line.size() - 2] == '\r'
            && line[line.size() - 1] == '\n') {
            line.resize(line.size() - 2);
            return line;
        }
    }
}

// Write all data to socket
static bool write_all(TlsSocket& sock, const std::string& data) {
    int total = 0;
    int len = static_cast<int>(data.size());
    while (total < len) {
        int ret = sock.write(data.c_str() + total, len - total);
        if (ret < 0) return false;
        if (ret == 0) {
            // Try again
            ret = sock.write(data.c_str() + total, len - total);
            if (ret <= 0) return false;
        }
        total += ret;
    }
    return true;
}

// Parse hex string to int
static int parse_hex(std::string_view s) {
    int result = 0;
    for (char c : s) {
        result <<= 4;
        if (c >= '0' && c <= '9') result |= (c - '0');
        else if (c >= 'a' && c <= 'f') result |= (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') result |= (c - 'A' + 10);
        else break;
    }
    return result;
}

// `Content-Length`, rejected rather than salvaged.
//
// Both readers parsed this by walking the characters and keeping the digits, so
// `12abc` was 12, `abc` was 0 — indistinguishable from a genuine `0` — and a
// value past the width of the accumulator wrapped in silence. A length is the
// number of bytes the reader will then trust, so a wrong one is not a cosmetic
// error: too small leaves the next response's bytes in the stream, and too
// large waits for bytes that are not coming.
//
// Shaped like `parse_chunk_size_line` above, and exported for the same reason:
// it is the half of the body framing that can be examined without a server.
export std::optional<std::int64_t>
parse_content_length(std::string_view value) {
    // A field value may carry optional whitespace on either side (RFC 9110).
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
        value.remove_suffix(1);
    if (value.empty()) return std::nullopt;

    std::uint64_t parsed {};
    auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), parsed, 10);
    if (error != std::errc{} || end != value.data() + value.size()
        || parsed > static_cast<std::uint64_t>(
            std::numeric_limits<std::int64_t>::max())) {
        return std::nullopt;
    }
    return static_cast<std::int64_t>(parsed);
}

export std::optional<std::int64_t>
parse_chunk_size_line(std::string_view line) {
    if (line.empty()) return std::nullopt;
    std::uint64_t value {};
    auto [end, error] = std::from_chars(
        line.data(), line.data() + line.size(), value, 16);
    if (error != std::errc{} || end != line.data() + line.size()
        || value > static_cast<std::uint64_t>(
            std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    return static_cast<std::int64_t>(value);
}

// A streaming request that fails is answered with an error document, not an
// event stream, so SseParser finds no event boundary in it and yields nothing.
// The bytes are still worth keeping: without them a caller can report the
// status line but never the reason. Bounded, so a server answering 5xx with an
// endless body cannot grow the buffer without limit.
export inline constexpr std::size_t stream_error_body_limit = 1024 * 1024;

// Appends as much of `data` as `limit` still allows. Returns false once the
// buffer is full, so a caller can stop copying without tracking sizes itself.
export bool append_within_limit(std::string& buffer, std::string_view data,
                                std::size_t limit) {
    if (buffer.size() >= limit) return false;
    const std::size_t room = limit - buffer.size();
    // Not std::min: <winsock2.h> defines a `min` macro on Windows.
    const std::size_t take = data.size() < room ? data.size() : room;
    buffer.append(data.substr(0, take));
    return take == data.size();
}

// Case-insensitive string comparison
static bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
    }
    return true;
}

export class HttpClient {
public:
    // Thread-safety: HttpClient owns a mutable connection pool and is not synchronized.
    // Keep each instance isolated to a single caller/task unless you add external locking.
    explicit HttpClient(HttpClientConfig config = {})
        : config_(std::move(config)) {}

    ~HttpClient() = default;

    // Non-copyable (connection pool owns TLS sockets)
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;
    HttpClient(HttpClient&&) = default;
    HttpClient& operator=(HttpClient&&) = default;

    HttpResponse send(const HttpRequest& request) {
        return send_impl(request, 0);
    }

private:
    HttpResponse send_impl(const HttpRequest& request, int redirectCount) {
        HttpResponse response;

        auto parsed = parse_url(request.url);
        if (parsed.scheme != "https") {
            response.statusCode = 0;
            response.statusText = "Only HTTPS is supported";
            return response;
        }

        std::string poolKey = parsed.host + ":" + std::to_string(parsed.port);

        // Get or create connection
        TlsSocket* sock = nullptr;
        auto it = pool_.find(poolKey);
        if (it != pool_.end() && it->second.is_valid()) {
            sock = &it->second;
        } else {
            // Remove stale entry if exists
            if (it != pool_.end()) {
                pool_.erase(it);
            }
            // Create new connection
            auto [insertIt, ok] = pool_.emplace(poolKey, TlsSocket{});
            sock = &insertIt->second;
            bool connected = false;
            if (config_.proxy.has_value()) {
                auto proxyConf = parse_proxy_url(config_.proxy.value());
                auto tunnel = proxy_connect(proxyConf.host, proxyConf.port,
                                           parsed.host, parsed.port,
                                           config_.connectTimeoutMs);
                if (tunnel.is_valid()) {
                    connected = sock->connect_over(std::move(tunnel),
                                                   parsed.host.c_str(),
                                                   config_.verifySsl);
                }
            } else {
                connected = sock->connect(parsed.host.c_str(), parsed.port,
                                         config_.connectTimeoutMs, config_.verifySsl);
            }
            if (!connected) {
                pool_.erase(poolKey);
                response.statusCode = 0;
                response.statusText = "Connection failed";
                return response;
            }
        }

        // Build request
        std::string reqStr;
        reqStr += method_to_string(request.method);
        reqStr += " ";
        reqStr += parsed.path;
        reqStr += " HTTP/1.1\r\n";
        // Add Host header (skip if user provided)
        if (!has_header(request.headers, "Host")) {
            reqStr += "Host: ";
            reqStr += parsed.host;
            if (parsed.port != 443) {
                reqStr += ":";
                reqStr += std::to_string(parsed.port);
            }
            reqStr += "\r\n";
        }

        // Add Content-Length if body present (skip if user provided)
        if (!request.body.empty() && !has_header(request.headers, "Content-Length")) {
            reqStr += "Content-Length: ";
            reqStr += std::to_string(request.body.size());
            reqStr += "\r\n";
        }

        // Add user headers
        for (const auto& [key, value] : request.headers) {
            reqStr += key;
            reqStr += ": ";
            reqStr += value;
            reqStr += "\r\n";
        }

        // Add connection header (skip if user provided)
        if (!has_header(request.headers, "Connection")) {
            if (config_.keepAlive) {
                reqStr += "Connection: keep-alive\r\n";
            } else {
                reqStr += "Connection: close\r\n";
            }
        }

        reqStr += "\r\n";

        // Append body
        if (!request.body.empty()) {
            reqStr += request.body;
        }

        // Send request
        if (!write_all(*sock, reqStr)) {
            pool_.erase(poolKey);
            response.statusCode = 0;
            response.statusText = "Write failed";
            return response;
        }

        // Read status line
        std::string statusLine = read_line(*sock, config_.readTimeoutMs);
        if (statusLine.empty()) {
            pool_.erase(poolKey);
            response.statusCode = 0;
            response.statusText = "No response";
            return response;
        }

        // Parse status line: HTTP/1.1 200 OK
        {
            auto spacePos = statusLine.find(' ');
            if (spacePos == std::string::npos) {
                pool_.erase(poolKey);
                response.statusCode = 0;
                response.statusText = "Invalid status line";
                return response;
            }
            auto rest = std::string_view(statusLine).substr(spacePos + 1);
            auto spacePos2 = rest.find(' ');
            if (spacePos2 != std::string_view::npos) {
                auto codeStr = rest.substr(0, spacePos2);
                response.statusCode = 0;
                for (char c : codeStr) {
                    if (c >= '0' && c <= '9') {
                        response.statusCode = response.statusCode * 10 + (c - '0');
                    }
                }
                response.statusText = std::string(rest.substr(spacePos2 + 1));
            } else {
                // No status text, just code
                response.statusCode = 0;
                for (char c : rest) {
                    if (c >= '0' && c <= '9') {
                        response.statusCode = response.statusCode * 10 + (c - '0');
                    }
                }
            }
        }

        // Read headers
        bool chunked = false;
        int contentLength = -1;
        bool connectionClose = false;

        while (true) {
            std::string headerLine = read_line(*sock, config_.readTimeoutMs);
            if (headerLine.empty()) {
                break; // End of headers (empty line after stripping \r\n)
            }

            auto colonPos = headerLine.find(':');
            if (colonPos != std::string::npos) {
                std::string key = headerLine.substr(0, colonPos);
                std::string_view value = std::string_view(headerLine).substr(colonPos + 1);
                // Trim leading whitespace from value
                while (!value.empty() && value[0] == ' ') {
                    value = value.substr(1);
                }
                std::string valStr(value);
                response.headers[key] = valStr;

                if (iequals(key, "Transfer-Encoding") && iequals(valStr, "chunked")) {
                    chunked = true;
                }
                if (iequals(key, "Content-Length")) {
                    // Rejected rather than salvaged; parse_content_length says
                    // why. A malformed value leaves this at -1, which is the
                    // same state as an absent header and is a framing this
                    // reader already handles.
                    contentLength = parse_content_length(valStr).value_or(-1);
                }
                if (iequals(key, "Connection") && iequals(valStr, "close")) {
                    connectionClose = true;
                }
            }
        }

        // Read body
        if (request.method == Method::HEAD) {
            // HEAD responses have no body
        } else if (chunked) {
            // Chunked transfer encoding
            while (true) {
                std::string sizeLine = read_line(*sock, config_.readTimeoutMs);
                // Strip any chunk extensions (after semicolon)
                auto semiPos = sizeLine.find(';');
                if (semiPos != std::string::npos) {
                    sizeLine = sizeLine.substr(0, semiPos);
                }
                // Trim whitespace
                while (!sizeLine.empty() && (sizeLine.back() == ' ' || sizeLine.back() == '\t')) {
                    sizeLine.pop_back();
                }

                int chunkSize = parse_hex(sizeLine);
                if (chunkSize == 0) {
                    // Read trailing \r\n after last chunk
                    read_line(*sock, config_.readTimeoutMs);
                    break;
                }

                // Read chunk data
                std::string chunkData(chunkSize, '\0');
                if (!read_exact(*sock, chunkData.data(), chunkSize, config_.readTimeoutMs)) {
                    break;
                }
                response.body += chunkData;

                // Read trailing \r\n after chunk
                read_line(*sock, config_.readTimeoutMs);
            }
        } else if (contentLength >= 0) {
            // Read exactly contentLength bytes
            if (contentLength > 0) {
                response.body.resize(contentLength);
                if (!read_exact(*sock, response.body.data(), contentLength, config_.readTimeoutMs)) {
                    pool_.erase(poolKey);
                    return response;
                }
            }
        } else {
            // Read until connection closed
            connectionClose = true;
            char buf[4096];
            while (true) {
                if (!sock->wait_readable(config_.readTimeoutMs)) {
                    break;
                }
                int ret = sock->read(buf, sizeof(buf));
                if (ret <= 0) break;
                response.body.append(buf, ret);
            }
        }

        // Handle connection pooling
        if (connectionClose) {
            sock->close();
            pool_.erase(poolKey);
        }

        // Follow 3xx redirects if configured
        if (config_.maxRedirects > 0 &&
            response.statusCode >= 300 && response.statusCode < 400 &&
            redirectCount < config_.maxRedirects) {
            std::string location;
            for (const auto& [k, v] : response.headers) {
                if (iequals(k, "location")) {
                    location = v;
                    break;
                }
            }
            if (!location.empty()) {
                // Resolve relative URLs
                if (location.starts_with("/")) {
                    location = parsed.scheme + "://" + parsed.host +
                               (parsed.port != 443 ? ":" + std::to_string(parsed.port) : "") +
                               location;
                }
                HttpRequest redirectReq = request;
                redirectReq.url = location;
                // Change POST to GET on 301/302/303 (standard behavior)
                if (response.statusCode != 307 && response.statusCode != 308) {
                    redirectReq.method = Method::GET;
                    redirectReq.body.clear();
                }
                return send_impl(redirectReq, redirectCount + 1);
            }
        }

        return response;
    }

public:
    // Streaming SSE request — reads response body incrementally, feeding
    // chunks through SseParser to the caller's callback.  The callback
    // receives each SseEvent and returns true to continue or false to stop.
    HttpResponse send_stream(const HttpRequest& request, SseCallbackFn callback) {
        HttpResponse response;

        auto parsed = parse_url(request.url);
        if (parsed.scheme != "https") {
            response.statusCode = 0;
            response.statusText = "Only HTTPS is supported";
            return response;
        }

        std::string poolKey = parsed.host + ":" + std::to_string(parsed.port);

        // Get or create connection
        TlsSocket* sock = nullptr;
        auto it = pool_.find(poolKey);
        if (it != pool_.end() && it->second.is_valid()) {
            sock = &it->second;
        } else {
            if (it != pool_.end()) {
                pool_.erase(it);
            }
            auto [insertIt, ok] = pool_.emplace(poolKey, TlsSocket{});
            sock = &insertIt->second;
            bool connected = false;
            if (config_.proxy.has_value()) {
                auto proxyConf = parse_proxy_url(config_.proxy.value());
                auto tunnel = proxy_connect(proxyConf.host, proxyConf.port,
                                           parsed.host, parsed.port,
                                           config_.connectTimeoutMs);
                if (tunnel.is_valid()) {
                    connected = sock->connect_over(std::move(tunnel),
                                                   parsed.host.c_str(),
                                                   config_.verifySsl);
                }
            } else {
                connected = sock->connect(parsed.host.c_str(), parsed.port,
                                         config_.connectTimeoutMs, config_.verifySsl);
            }
            if (!connected) {
                pool_.erase(poolKey);
                response.statusCode = 0;
                response.statusText = "Connection failed";
                return response;
            }
        }

        // Build request — same as send()
        std::string reqStr;
        reqStr += method_to_string(request.method);
        reqStr += " ";
        reqStr += parsed.path;
        reqStr += " HTTP/1.1\r\n";
        if (!has_header(request.headers, "Host")) {
            reqStr += "Host: ";
            reqStr += parsed.host;
            if (parsed.port != 443) {
                reqStr += ":";
                reqStr += std::to_string(parsed.port);
            }
            reqStr += "\r\n";
        }
        if (!request.body.empty() && !has_header(request.headers, "Content-Length")) {
            reqStr += "Content-Length: ";
            reqStr += std::to_string(request.body.size());
            reqStr += "\r\n";
        }
        for (const auto& [key, value] : request.headers) {
            reqStr += key;
            reqStr += ": ";
            reqStr += value;
            reqStr += "\r\n";
        }
        if (!has_header(request.headers, "Connection")) {
            if (config_.keepAlive) {
                reqStr += "Connection: keep-alive\r\n";
            } else {
                reqStr += "Connection: close\r\n";
            }
        }
        reqStr += "\r\n";
        if (!request.body.empty()) {
            reqStr += request.body;
        }

        if (!write_all(*sock, reqStr)) {
            pool_.erase(poolKey);
            response.statusCode = 0;
            response.statusText = "Write failed";
            return response;
        }

        // Read status line
        std::string statusLine = read_line(*sock, config_.readTimeoutMs);
        if (statusLine.empty()) {
            pool_.erase(poolKey);
            response.statusCode = 0;
            response.statusText = "No response";
            return response;
        }

        // Parse status line
        {
            auto spacePos = statusLine.find(' ');
            if (spacePos == std::string::npos) {
                pool_.erase(poolKey);
                response.statusCode = 0;
                response.statusText = "Invalid status line";
                return response;
            }
            auto rest = std::string_view(statusLine).substr(spacePos + 1);
            auto spacePos2 = rest.find(' ');
            if (spacePos2 != std::string_view::npos) {
                auto codeStr = rest.substr(0, spacePos2);
                response.statusCode = 0;
                for (char c : codeStr) {
                    if (c >= '0' && c <= '9') {
                        response.statusCode = response.statusCode * 10 + (c - '0');
                    }
                }
                response.statusText = std::string(rest.substr(spacePos2 + 1));
            } else {
                response.statusCode = 0;
                for (char c : rest) {
                    if (c >= '0' && c <= '9') {
                        response.statusCode = response.statusCode * 10 + (c - '0');
                    }
                }
            }
        }

        // Read headers
        bool chunked = false;
        bool connectionClose = false;
        std::int64_t contentLength = -1;

        while (true) {
            std::string headerLine = read_line(*sock, config_.readTimeoutMs);
            if (headerLine.empty()) {
                break;
            }
            auto colonPos = headerLine.find(':');
            if (colonPos != std::string::npos) {
                std::string key = headerLine.substr(0, colonPos);
                std::string_view value = std::string_view(headerLine).substr(colonPos + 1);
                while (!value.empty() && value[0] == ' ') {
                    value = value.substr(1);
                }
                std::string valStr(value);
                response.headers[key] = valStr;

                if (iequals(key, "Transfer-Encoding") && iequals(valStr, "chunked")) {
                    chunked = true;
                }
                if (iequals(key, "Connection") && iequals(valStr, "close")) {
                    connectionClose = true;
                }
                // send() reads this and send_stream() did not, which is the
                // same asymmetry this change exists to remove. See the body
                // loop below for what its absence cost.
                if (iequals(key, "Content-Length")) {
                    contentLength = parse_content_length(valStr).value_or(-1);
                }
            }
        }

        // Stream body incrementally, feeding chunks to SseParser
        SseParser parser;
        bool stopped = false;
        // send() fills `body` on every path including failures; without this
        // send_stream would be the one entry point that drops it. Capturing is
        // additive — events are still parsed and dispatched exactly as before.
        const bool captureBody = !response.ok();

        auto dispatch = [&](std::string_view data) -> bool {
            if (captureBody) {
                append_within_limit(response.body, data, stream_error_body_limit);
            }
            auto events = parser.feed(data);
            for (const auto& ev : events) {
                if (!callback(ev)) {
                    stopped = true;
                    return false;
                }
            }
            return true;
        };

        if (chunked) {
            // Incrementally decode chunked transfer-encoding
            while (!stopped) {
                std::string sizeLine = read_line(*sock, config_.readTimeoutMs);
                auto semiPos = sizeLine.find(';');
                if (semiPos != std::string::npos) {
                    sizeLine = sizeLine.substr(0, semiPos);
                }
                while (!sizeLine.empty() && (sizeLine.back() == ' ' || sizeLine.back() == '\t')) {
                    sizeLine.pop_back();
                }

                // A CHUNK HEADER THAT DOES NOT PARSE IS NOT A TERMINAL CHUNK.
                //
                // `parse_hex` returned what it had accumulated when it met a
                // character it did not recognise, and zero for an empty line —
                // and `read_line` returns an empty line on a timeout or a
                // closed connection. So a stream that was cut short read as a
                // stream that ended cleanly, and this loop reported success.
                // #9 established `parse_chunk_size_line` for exactly this and
                // it reached only `download_to_file`.
                auto parsedChunkSize = parse_chunk_size_line(sizeLine);
                if (!parsedChunkSize) {
                    response.statusText = "Invalid chunk size: " + sizeLine;
                    connectionClose = true;
                    break;
                }
                int chunkSize = static_cast<int>(*parsedChunkSize);
                if (chunkSize == 0) {
                    // Terminal chunk — read trailing \r\n
                    read_line(*sock, config_.readTimeoutMs);
                    break;
                }

                // Read chunk data
                std::string chunkData(chunkSize, '\0');
                if (!read_exact(*sock, chunkData.data(), chunkSize, config_.readTimeoutMs)) {
                    break;
                }
                // Read trailing \r\n after chunk
                read_line(*sock, config_.readTimeoutMs);

                if (!dispatch(chunkData)) {
                    break;
                }
            }
        } else if (contentLength >= 0) {
            // A DECLARED LENGTH IS READ AND THE READER THEN STOPS.
            //
            // This branch did not exist: a response that was not chunked was
            // read until the connection closed, whatever its headers said. On
            // the library's own defaults — `keepAlive = true`, so the request
            // carries `Connection: keep-alive` — the server does not close,
            // and the loop below ran until `readTimeoutMs` expired.
            //
            // Measured against httpbin's `/status/418`, which answers with a
            // Content-Length and keeps the connection:
            //
            //     keepAlive = false   status=418 body=135   elapsed  1370 ms
            //     keepAlive = true    status=418 body=135   elapsed  9379 ms   (readTimeoutMs = 8000)
            //
            // The error body arrived either way, and on the defaults it arrived
            // a full read timeout late — sixty seconds, as the defaults stand.
            // `send()` has had this branch throughout, which is why the same
            // request through it returns at once.
            std::int64_t remaining = contentLength;
            char buf[4096];
            while (!stopped && remaining > 0) {
                if (!sock->wait_readable(config_.readTimeoutMs)) {
                    break;
                }
                const auto want = static_cast<std::size_t>(
                    remaining < static_cast<std::int64_t>(sizeof buf)
                        ? remaining : static_cast<std::int64_t>(sizeof buf));
                int ret = sock->read(buf, want);
                if (ret <= 0) break;
                remaining -= ret;
                if (!dispatch(std::string_view(buf, static_cast<std::size_t>(ret)))) {
                    break;
                }
            }
        } else {
            // Neither chunked nor a declared length: the end of the body is the
            // end of the connection, so the connection must not be reused.
            connectionClose = true;
            char buf[4096];
            while (!stopped) {
                if (!sock->wait_readable(config_.readTimeoutMs)) {
                    break;
                }
                int ret = sock->read(buf, sizeof(buf));
                if (ret <= 0) break;
                if (!dispatch(std::string_view(buf, static_cast<std::size_t>(ret)))) {
                    break;
                }
            }
        }

        // Clean up connection
        if (connectionClose || stopped) {
            sock->close();
            pool_.erase(poolKey);
        }

        return response;
    }

    // Download URL to file with streaming progress.
    // Follows redirects. Calls onProgress periodically during body read.
    // isCancelled is checked after each block — return true to abort.
    DownloadToFileResult download_to_file(
        const std::string& url,
        const std::filesystem::path& destFile,
        DownloadProgressFn onProgress = nullptr,
        std::function<bool()> isCancelled = nullptr)
    {
        return download_to_file_impl(url, destFile, std::move(onProgress),
                                     std::move(isCancelled), 0);
    }

    HttpClientConfig& config() { return config_; }
    const HttpClientConfig& config() const { return config_; }

private:
    DownloadToFileResult download_to_file_impl(
        const std::string& url,
        const std::filesystem::path& destFile,
        DownloadProgressFn onProgress,
        std::function<bool()> isCancelled,
        int redirectCount)
    {
        DownloadToFileResult result;

        auto parsed = parse_url(url);
        if (parsed.scheme != "https") {
            result.error = "Only HTTPS is supported";
            return result;
        }

        std::string poolKey = parsed.host + ":" + std::to_string(parsed.port);

        // Get or create connection
        TlsSocket* sock = nullptr;
        auto it = pool_.find(poolKey);
        if (it != pool_.end() && it->second.is_valid()) {
            sock = &it->second;
        } else {
            if (it != pool_.end()) pool_.erase(it);
            auto [insertIt, ok] = pool_.emplace(poolKey, TlsSocket{});
            sock = &insertIt->second;
            bool connected = false;
            if (config_.proxy.has_value()) {
                auto proxyConf = parse_proxy_url(config_.proxy.value());
                auto tunnel = proxy_connect(proxyConf.host, proxyConf.port,
                                           parsed.host, parsed.port,
                                           config_.connectTimeoutMs);
                if (tunnel.is_valid()) {
                    connected = sock->connect_over(std::move(tunnel),
                                                   parsed.host.c_str(),
                                                   config_.verifySsl);
                }
            } else {
                connected = sock->connect(parsed.host.c_str(), parsed.port,
                                         config_.connectTimeoutMs, config_.verifySsl);
            }
            if (!connected) {
                pool_.erase(poolKey);
                result.error = "Connection failed";
                return result;
            }
        }

        // Build GET request
        std::string reqStr = "GET ";
        reqStr += parsed.path;
        reqStr += " HTTP/1.1\r\nHost: ";
        reqStr += parsed.host;
        if (parsed.port != 443) {
            reqStr += ":";
            reqStr += std::to_string(parsed.port);
        }
        reqStr += "\r\nUser-Agent: tinyhttps/1.0\r\nAccept: */*\r\n";
        reqStr += config_.keepAlive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
        reqStr += "\r\n";

        if (!write_all(*sock, reqStr)) {
            pool_.erase(poolKey);
            result.error = "Write failed";
            return result;
        }

        // Read status line
        std::string statusLine = read_line(*sock, config_.readTimeoutMs);
        if (statusLine.empty()) {
            pool_.erase(poolKey);
            result.error = "No response";
            return result;
        }

        // Parse status code
        {
            auto sp = statusLine.find(' ');
            if (sp != std::string::npos) {
                auto rest = std::string_view(statusLine).substr(sp + 1);
                for (char c : rest) {
                    if (c >= '0' && c <= '9')
                        result.statusCode = result.statusCode * 10 + (c - '0');
                    else break;
                }
            }
        }

        // Read headers
        bool chunked = false;
        std::int64_t contentLength = -1;
        bool connectionClose = false;
        std::string location;
        std::string etag;
        std::string lastModified;

        while (true) {
            std::string line = read_line(*sock, config_.readTimeoutMs);
            if (line.empty()) break;
            auto colon = line.find(':');
            if (colon == std::string::npos) continue;
            std::string key = line.substr(0, colon);
            std::string_view val = std::string_view(line).substr(colon + 1);
            while (!val.empty() && val[0] == ' ') val = val.substr(1);
            std::string valStr(val);

            if (iequals(key, "Transfer-Encoding") && iequals(valStr, "chunked"))
                chunked = true;
            if (iequals(key, "Content-Length")) {
                contentLength = 0;
                for (char c : valStr) {
                    if (c >= '0' && c <= '9')
                        contentLength = contentLength * 10 + (c - '0');
                }
            }
            if (iequals(key, "Connection") && iequals(valStr, "close"))
                connectionClose = true;
            if (iequals(key, "Location"))
                location = valStr;
            if (iequals(key, "ETag"))
                etag = valStr;
            if (iequals(key, "Last-Modified"))
                lastModified = valStr;
        }

        // Follow redirects
        if (result.statusCode >= 300 && result.statusCode < 400 &&
            !location.empty() && redirectCount < config_.maxRedirects) {
            // Drain any body to keep connection clean
            if (connectionClose) {
                sock->close();
                pool_.erase(poolKey);
            }
            // Resolve relative URL
            if (location.starts_with("/")) {
                location = parsed.scheme + "://" + parsed.host +
                           (parsed.port != 443 ? ":" + std::to_string(parsed.port) : "") +
                           location;
            }
            return download_to_file_impl(location, destFile, std::move(onProgress),
                                         std::move(isCancelled), redirectCount + 1);
        }

        if (result.statusCode < 200 || result.statusCode >= 300) {
            result.error = "HTTP " + std::to_string(result.statusCode);
            if (connectionClose) { sock->close(); pool_.erase(poolKey); }
            return result;
        }

        result.finalUrl = url;
        result.etag = std::move(etag);
        result.lastModified = std::move(lastModified);
        if (contentLength >= 0) result.expectedBytes = contentLength;

        // Open output file
        std::error_code ec;
        std::filesystem::create_directories(destFile.parent_path(), ec);
        std::ofstream ofs(destFile, std::ios::binary);
        if (!ofs) {
            result.error = "Cannot open file: " + destFile.string();
            if (connectionClose) { sock->close(); pool_.erase(poolKey); }
            return result;
        }

        std::int64_t totalBytes = contentLength > 0 ? contentLength : 0;
        std::int64_t downloaded = 0;

        // Check cancellation between blocks
        auto cancelled = [&]() -> bool {
            if (isCancelled && isCancelled()) {
                result.error = "cancelled";
                ofs.close();
                result.bytesWritten = downloaded;
                sock->close();
                pool_.erase(poolKey);
                return true;
            }
            return false;
        };

        // Read body and stream to file
        if (chunked) {
            while (true) {
                if (cancelled()) return result;
                auto sizeResult = read_complete_line(
                    *sock, config_.readTimeoutMs);
                if (!sizeResult) {
                    result.error = "Invalid chunk size line: "
                        + std::move(sizeResult).error();
                    result.bytesWritten = downloaded;
                    sock->close();
                    pool_.erase(poolKey);
                    return result;
                }
                std::string sizeLine = std::move(*sizeResult);
                auto semi = sizeLine.find(';');
                if (semi != std::string::npos) sizeLine = sizeLine.substr(0, semi);
                while (!sizeLine.empty() && (sizeLine.back() == ' ' || sizeLine.back() == '\t'))
                    sizeLine.pop_back();

                auto parsedChunkSize = parse_chunk_size_line(sizeLine);
                if (!parsedChunkSize) {
                    result.error = "Invalid chunk size: " + sizeLine;
                    result.bytesWritten = downloaded;
                    sock->close();
                    pool_.erase(poolKey);
                    return result;
                }
                int chunkSize = static_cast<int>(*parsedChunkSize);
                if (chunkSize == 0) {
                    for (;;) {
                        auto trailer = read_complete_line(
                            *sock, config_.readTimeoutMs);
                        if (!trailer) {
                            result.error = "Invalid chunk trailer: "
                                + std::move(trailer).error();
                            result.bytesWritten = downloaded;
                            sock->close();
                            pool_.erase(poolKey);
                            return result;
                        }
                        if (trailer->empty()) break;
                    }
                    break;
                }

                int remaining = chunkSize;
                char buf[8192];
                while (remaining > 0) {
                    if (cancelled()) return result;
                    int toRead = remaining > static_cast<int>(sizeof(buf))
                               ? static_cast<int>(sizeof(buf)) : remaining;
                    if (!read_exact(*sock, buf, toRead, config_.readTimeoutMs)) {
                        result.error = "Read error during chunked transfer";
                        ofs.close();
                        result.bytesWritten = downloaded;
                        return result;
                    }
                    ofs.write(buf, toRead);
                    downloaded += toRead;
                    remaining -= toRead;
                    if (onProgress) onProgress(totalBytes, downloaded);
                }
                auto delimiter = read_complete_line(
                    *sock, config_.readTimeoutMs);
                if (!delimiter || !delimiter->empty()) {
                    result.error = "Missing CRLF after chunk data";
                    result.bytesWritten = downloaded;
                    sock->close();
                    pool_.erase(poolKey);
                    return result;
                }
            }
        } else if (contentLength > 0) {
            char buf[8192];
            std::int64_t remaining = contentLength;
            while (remaining > 0) {
                if (cancelled()) return result;
                int toRead = remaining > static_cast<std::int64_t>(sizeof(buf))
                           ? static_cast<int>(sizeof(buf))
                           : static_cast<int>(remaining);
                if (!read_exact(*sock, buf, toRead, config_.readTimeoutMs)) {
                    result.error = "Read error";
                    ofs.close();
                    result.bytesWritten = downloaded;
                    return result;
                }
                ofs.write(buf, toRead);
                downloaded += toRead;
                remaining -= toRead;
                if (onProgress) onProgress(totalBytes, downloaded);
            }
        } else {
            connectionClose = true;
            char buf[8192];
            while (true) {
                if (cancelled()) return result;
                if (!sock->wait_readable(config_.readTimeoutMs)) break;
                int ret = sock->read(buf, sizeof(buf));
                if (ret <= 0) break;
                ofs.write(buf, ret);
                downloaded += ret;
                if (onProgress) onProgress(totalBytes, downloaded);
            }
        }

        ofs.close();
        result.bytesWritten = downloaded;

        if (connectionClose) {
            sock->close();
            pool_.erase(poolKey);
        }

        return result;
    }

    HttpClientConfig config_;
    std::map<std::string, TlsSocket> pool_;
};

} // namespace mcpplibs::tinyhttps
