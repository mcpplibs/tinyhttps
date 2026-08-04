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
    // Parallel download controls (aria2-style):
    int maxConnectionsPerFile { 1 };            // concurrency cap: how many segment workers run at once (1 = sequential)
    int maxSegments { 0 };                       // max split count (-s). 0 = tie split count to maxConnectionsPerFile (legacy)
    std::int64_t minSegmentBytes { 1 << 20 };    // minimum bytes per segment (--min-split-size)
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

// Parse the numeric status code from a status line ("HTTP/1.1 206 Partial Content").
// Returns 0 on a malformed line.
static int parse_status_code(std::string_view statusLine) {
    auto sp = statusLine.find(' ');
    if (sp == std::string_view::npos) return 0;
    int code = 0;
    for (char c : statusLine.substr(sp + 1)) {
        if (c < '0' || c > '9') break;
        code = code * 10 + (c - '0');
    }
    return code;
}

// Parse the total size from a Content-Range header, e.g. "bytes 0-0/10485760".
// Returns nullopt when the total is absent or unknown ("bytes 0-0/*").
static std::optional<std::int64_t> parse_content_range_total(std::string_view value) {
    auto slash = value.rfind('/');
    if (slash == std::string_view::npos) return std::nullopt;
    std::string_view totalStr = value.substr(slash + 1);
    if (totalStr == "*") return std::nullopt;
    std::int64_t total = 0;
    for (char c : totalStr) {
        if (c < '0' || c > '9') return std::nullopt;
        if (total > (std::numeric_limits<std::int64_t>::max() - (c - '0')) / 10) {
            return std::nullopt;  // overflow
        }
        total = total * 10 + (c - '0');
    }
    return total;
}

// Parse the range start from a Content-Range header, e.g. "bytes 1024-2047/4096"
// yields 1024. Returns nullopt for non-bytes units or a malformed value.
static std::optional<std::int64_t> parse_content_range_start(std::string_view value) {
    auto space = value.find(' ');
    if (space == std::string_view::npos) return std::nullopt;
    if (!iequals(value.substr(0, space), "bytes")) return std::nullopt;
    auto dash = value.find('-', space + 1);
    if (dash == std::string_view::npos) return std::nullopt;
    std::int64_t start = 0;
    for (char c : value.substr(space + 1, dash - space - 1)) {
        if (c < '0' || c > '9') return std::nullopt;
        if (start > (std::numeric_limits<std::int64_t>::max() - (c - '0')) / 10) {
            return std::nullopt;  // overflow
        }
        start = start * 10 + (c - '0');
    }
    return start;
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
                    contentLength = 0;
                    for (char c : valStr) {
                        if (c >= '0' && c <= '9') {
                            contentLength = contentLength * 10 + (c - '0');
                        }
                    }
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
            }
        }

        // Stream body incrementally, feeding chunks to SseParser
        SseParser parser;
        bool stopped = false;

        auto dispatch = [&](std::string_view data) -> bool {
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

                int chunkSize = parse_hex(sizeLine);
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
        } else {
            // Not chunked — read until connection closes
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

    // Parallel segmented download using HTTP Range (aria2-style). Probes the
    // server for Range support, then fetches non-overlapping segments into a
    // pre-allocated file: split count is maxSegments (or ceil(size /
    // minSegmentBytes)), and concurrency is capped by maxConnectionsPerFile.
    // Falls back to download_to_file() when the server ignores Range or the
    // file is too small to shard. Same progress/cancel semantics as
    // download_to_file().
    DownloadToFileResult download_to_file_parallel(
        const std::string& url,
        const std::filesystem::path& destFile,
        DownloadProgressFn onProgress = nullptr,
        std::function<bool()> isCancelled = nullptr)
    {
        return download_to_file_parallel_impl(url, destFile, std::move(onProgress),
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

    // Establish a fresh TLS connection to `parsed` (proxy-aware). Leaves `sock`
    // invalid on failure. Used by parallel segment workers — each worker gets
    // its own connection and never touches the shared pool_.
    bool connect_fresh(const ParsedUrl& parsed, TlsSocket& sock) {
        bool connected = false;
        if (config_.proxy.has_value()) {
            auto proxyConf = parse_proxy_url(config_.proxy.value());
            auto tunnel = proxy_connect(proxyConf.host, proxyConf.port,
                                       parsed.host, parsed.port,
                                       config_.connectTimeoutMs);
            if (tunnel.is_valid()) {
                connected = sock.connect_over(std::move(tunnel),
                                              parsed.host.c_str(),
                                              config_.verifySsl);
            }
        } else {
            connected = sock.connect(parsed.host.c_str(), parsed.port,
                                     config_.connectTimeoutMs, config_.verifySsl);
        }
        return connected;
    }

    DownloadToFileResult download_to_file_parallel_impl(
        const std::string& url,
        const std::filesystem::path& destFile,
        DownloadProgressFn onProgress,
        std::function<bool()> isCancelled,
        int redirectCount)
    {
        DownloadToFileResult result;

        // Parallelism disabled — identical behavior to the sequential path.
        if (config_.maxConnectionsPerFile <= 1) {
            return download_to_file_impl(url, destFile, std::move(onProgress),
                                         std::move(isCancelled), redirectCount);
        }

        auto parsed = parse_url(url);
        if (parsed.scheme != "https") {
            result.error = "Only HTTPS is supported";
            return result;
        }

        // Probe: can the server honor Range?
        TlsSocket probeSock;
        if (!connect_fresh(parsed, probeSock)) {
            result.error = "Connection failed";
            return result;
        }

        std::string probeReq = "GET " + parsed.path + " HTTP/1.1\r\nHost: " + parsed.host;
        if (parsed.port != 443) probeReq += ":" + std::to_string(parsed.port);
        probeReq += "\r\nUser-Agent: tinyhttps/1.0\r\nAccept: */*\r\nRange: bytes=0-0\r\nConnection: close\r\n\r\n";

        if (!write_all(probeSock, probeReq)) {
            result.error = "Write failed";
            return result;
        }

        std::string statusLine = read_line(probeSock, config_.readTimeoutMs);
        if (statusLine.empty()) {
            result.error = "No response";
            return result;
        }
        int statusCode = parse_status_code(statusLine);

        std::string location;
        std::string contentRange;
        std::string etag;
        std::string lastModified;
        bool chunked = false;
        std::int64_t contentLength = -1;
        while (true) {
            std::string line = read_line(probeSock, config_.readTimeoutMs);
            if (line.empty()) break;
            auto colon = line.find(':');
            if (colon == std::string::npos) continue;
            std::string key = line.substr(0, colon);
            std::string_view val = std::string_view(line).substr(colon + 1);
            while (!val.empty() && val[0] == ' ') val = val.substr(1);
            std::string valStr(val);
            if (iequals(key, "Location")) location = valStr;
            if (iequals(key, "Content-Range")) contentRange = valStr;
            if (iequals(key, "ETag")) etag = valStr;
            if (iequals(key, "Last-Modified")) lastModified = valStr;
            if (iequals(key, "Transfer-Encoding") && iequals(valStr, "chunked")) chunked = true;
            if (iequals(key, "Content-Length")) {
                contentLength = 0;
                for (char c : valStr) {
                    if (c >= '0' && c <= '9') contentLength = contentLength * 10 + (c - '0');
                }
            }
        }

        // Follow redirects up front so every segment worker targets the final
        // URL directly instead of following the chain itself.
        if (statusCode >= 300 && statusCode < 400 &&
            !location.empty() && redirectCount < config_.maxRedirects) {
            probeSock.close();
            if (location.starts_with("/")) {
                location = parsed.scheme + "://" + parsed.host +
                           (parsed.port != 443 ? ":" + std::to_string(parsed.port) : "") +
                           location;
            }
            return download_to_file_parallel_impl(location, destFile,
                                                  std::move(onProgress),
                                                  std::move(isCancelled),
                                                  redirectCount + 1);
        }

        // 200 — server ignored Range; the probe response body is the whole
        // file, so write it out directly (no second round-trip).
        if (statusCode == 200) {
            std::error_code ec;
            std::filesystem::create_directories(destFile.parent_path(), ec);
            std::ofstream ofs(destFile, std::ios::binary);
            if (!ofs) {
                result.error = "Cannot open file: " + destFile.string();
                return result;
            }
            std::int64_t written = 0;
            auto cancelled = [&]() -> bool {
                if (isCancelled && isCancelled()) {
                    result.error = "cancelled";
                    result.bytesWritten = written;
                    return true;
                }
                return false;
            };
            if (chunked) {
                while (true) {
                    if (cancelled()) return result;
                    std::string sizeLine = read_line(probeSock, config_.readTimeoutMs);
                    auto semi = sizeLine.find(';');
                    if (semi != std::string::npos) sizeLine = sizeLine.substr(0, semi);
                    while (!sizeLine.empty() && (sizeLine.back() == ' ' || sizeLine.back() == '\t'))
                        sizeLine.pop_back();
                    int chunkSize = parse_hex(sizeLine);
                    if (chunkSize == 0) break;
                    char buf[8192];
                    int remaining = chunkSize;
                    while (remaining > 0) {
                        if (cancelled()) return result;
                        int toRead = remaining > static_cast<int>(sizeof(buf))
                                   ? static_cast<int>(sizeof(buf)) : remaining;
                        if (!read_exact(probeSock, buf, toRead, config_.readTimeoutMs)) {
                            result.error = "Read error during fallback download";
                            result.bytesWritten = written;
                            return result;
                        }
                        ofs.write(buf, toRead);
                        written += toRead;
                        remaining -= toRead;
                        if (onProgress) onProgress(0, written);
                    }
                    read_line(probeSock, config_.readTimeoutMs);  // trailing CRLF
                }
            } else if (contentLength >= 0) {
                char buf[8192];
                std::int64_t remaining = contentLength;
                while (remaining > 0) {
                    if (cancelled()) return result;
                    int toRead = remaining > static_cast<std::int64_t>(sizeof(buf))
                               ? static_cast<int>(sizeof(buf))
                               : static_cast<int>(remaining);
                    if (!read_exact(probeSock, buf, toRead, config_.readTimeoutMs)) {
                        result.error = "Read error during fallback download";
                        result.bytesWritten = written;
                        return result;
                    }
                    ofs.write(buf, toRead);
                    written += toRead;
                    remaining -= toRead;
                    if (onProgress) onProgress(contentLength, written);
                }
            } else {
                char buf[8192];
                while (true) {
                    if (cancelled()) return result;
                    if (!probeSock.wait_readable(config_.readTimeoutMs)) break;
                    int ret = probeSock.read(buf, sizeof(buf));
                    if (ret <= 0) break;
                    ofs.write(buf, ret);
                    written += ret;
                    if (onProgress) onProgress(0, written);
                }
            }
            ofs.close();
            result.statusCode = 200;
            result.finalUrl = url;
            result.etag = std::move(etag);
            result.lastModified = std::move(lastModified);
            if (contentLength >= 0) result.expectedBytes = contentLength;
            result.bytesWritten = written;
            return result;
        }

        probeSock.close();

        // 416 — resource is empty; write a zero-byte file and succeed.
        if (statusCode == 416) {
            std::error_code ec;
            std::filesystem::create_directories(destFile.parent_path(), ec);
            {
                std::ofstream ofs(destFile, std::ios::binary);
                if (!ofs) {
                    result.error = "Cannot create file: " + destFile.string();
                    return result;
                }
            }
            result.statusCode = 200;
            result.finalUrl = url;
            result.expectedBytes = 0;
            result.bytesWritten = 0;
            return result;
        }

        if (statusCode != 206) {
            result.error = "HTTP " + std::to_string(statusCode);
            return result;
        }

        auto totalOpt = parse_content_range_total(contentRange);
        if (!totalOpt || *totalOpt == 0) {
            // Total unknown or empty — sequential path.
            return download_to_file_impl(url, destFile, std::move(onProgress),
                                         std::move(isCancelled), redirectCount);
        }
        std::int64_t totalBytes = *totalOpt;

        // Segment. Split into ceil(total / minSegmentBytes) pieces, capped by
        // maxSegments when set; with maxSegments == 0 (legacy default) the
        // split count is tied to the connection count.
        constexpr int MAX_SEGMENTS = 2048;  // hard cap against pathological configs
        std::int64_t minSeg = config_.minSegmentBytes > 0
                              ? config_.minSegmentBytes : (1 << 20);
        int nSegs = static_cast<int>((totalBytes + minSeg - 1) / minSeg);
        if (config_.maxSegments > 0) {
            nSegs = std::min(nSegs, config_.maxSegments);
        } else {
            nSegs = std::min(nSegs, config_.maxConnectionsPerFile);
        }
        nSegs = std::min(nSegs, MAX_SEGMENTS);
        if (nSegs <= 1) {
            // Too small to split — sequential path.
            return download_to_file_impl(url, destFile, std::move(onProgress),
                                         std::move(isCancelled), redirectCount);
        }
        const int nWorkers = std::min(config_.maxConnectionsPerFile, nSegs);

        // Pre-allocate the file so each segment can write into place.
        std::error_code ec;
        std::filesystem::create_directories(destFile.parent_path(), ec);
        std::ofstream create(destFile, std::ios::binary);
        if (!create) {
            result.error = "Cannot create file: " + destFile.string();
            return result;
        }
        create.close();
        std::error_code resizeEc;
        std::filesystem::resize_file(destFile, totalBytes, resizeEc);
        if (resizeEc) {
            result.error = "Cannot resize file: " + destFile.string();
            return result;
        }

        // Non-overlapping segment boundaries.
        std::vector<std::pair<std::int64_t, std::int64_t>> segments;
        segments.reserve(nSegs);
        std::int64_t segSize = (totalBytes + nSegs - 1) / nSegs;
        for (int i = 0; i < nSegs; ++i) {
            std::int64_t s = i * segSize;
            std::int64_t e = std::min(s + segSize - 1, totalBytes - 1);
            if (s > e) break;
            segments.emplace_back(s, e);
        }

        // Shared worker state.
        std::atomic<std::int64_t> globalWritten{0};
        std::atomic<bool> userCancelled{false};
        std::atomic<bool> anyFailed{false};
        std::atomic<int> nextSegment{0};
        std::mutex stateMutex;  // serializes onProgress + firstError
        std::string firstError;
        std::int64_t reportedMax = 0;  // guarded by stateMutex: keeps onProgress monotonic

        auto fail = [&](std::string msg) {
            std::lock_guard<std::mutex> lock(stateMutex);
            if (firstError.empty()) firstError = std::move(msg);
            anyFailed.store(true);
        };

        // Workers pull segments from a shared index until exhausted, so
        // maxSegments can exceed maxConnectionsPerFile (aria2 -s vs -x).
        auto worker = [&]() {
            // Open once per worker; Windows CRT sharing allows concurrent
            // in-place writes at disjoint offsets.
            std::fstream file(destFile, std::ios::binary | std::ios::in | std::ios::out);
            if (!file) {
                fail("Cannot open file: " + destFile.string());
                return;
            }

            constexpr int MAX_RETRIES = 2;
            const int totalSegs = static_cast<int>(segments.size());

            for (;;) {
                if (userCancelled.load() || anyFailed.load()) return;
                const int idx = nextSegment.fetch_add(1);
                if (idx >= totalSegs) return;  // queue exhausted

                const std::int64_t segStart = segments[idx].first;
                const std::int64_t segEnd = segments[idx].second;
                const std::int64_t segLen = segEnd - segStart + 1;
                std::int64_t segWritten = 0;

                for (int attempt = 0; attempt <= MAX_RETRIES; ++attempt) {
                    if (userCancelled.load() || anyFailed.load()) return;

                    TlsSocket sock;
                    if (!connect_fresh(parsed, sock)) {
                        if (attempt == MAX_RETRIES) {
                            fail("Connection failed for segment " +
                                 std::to_string(segStart) + "-" + std::to_string(segEnd));
                            return;
                        }
                        continue;
                    }

                    // Request only the not-yet-downloaded remainder (natural resume).
                    std::int64_t chunkStart = segStart + segWritten;
                    std::string req = "GET " + parsed.path + " HTTP/1.1\r\nHost: " + parsed.host;
                    if (parsed.port != 443) req += ":" + std::to_string(parsed.port);
                    req += "\r\nUser-Agent: tinyhttps/1.0\r\nAccept: */*\r\n"
                           "Range: bytes=" + std::to_string(chunkStart) + "-" +
                           std::to_string(segEnd) +
                           "\r\nConnection: close\r\n\r\n";

                    if (!write_all(sock, req)) {
                        sock.close();
                        if (attempt == MAX_RETRIES) {
                            fail("Write failed for segment " + std::to_string(segStart) +
                                 "-" + std::to_string(segEnd));
                            return;
                        }
                        continue;
                    }

                    std::string statusLine = read_line(sock, config_.readTimeoutMs);
                    int statusCode = parse_status_code(statusLine);
                    if (statusCode != 206) {
                        // Retry; a persistent non-206 is a segment failure.
                        sock.close();
                        if (attempt == MAX_RETRIES) {
                            fail("Unexpected status " + std::to_string(statusCode) +
                                 " for segment " + std::to_string(segStart) + "-" +
                                 std::to_string(segEnd));
                            return;
                        }
                        continue;
                    }

                    // Read response headers, keeping Content-Range for validation.
                    bool segChunked = false;
                    std::string segContentRange;
                    while (true) {
                        std::string line = read_line(sock, config_.readTimeoutMs);
                        if (line.empty()) break;
                        auto colon = line.find(':');
                        if (colon == std::string::npos) continue;
                        std::string key = line.substr(0, colon);
                        std::string_view val = std::string_view(line).substr(colon + 1);
                        while (!val.empty() && val[0] == ' ') val = val.substr(1);
                        std::string valStr(val);
                        if (iequals(key, "Transfer-Encoding") && iequals(valStr, "chunked"))
                            segChunked = true;
                        if (iequals(key, "Content-Range"))
                            segContentRange = valStr;
                    }

                    // A chunked 206 would write raw framing bytes into the
                    // pre-allocated file, and a mismatched Content-Range would
                    // write the wrong bytes — neither is retryable, so fail.
                    bool rangeOk = !segChunked;
                    if (rangeOk && !segContentRange.empty()) {
                        auto rangeStart = parse_content_range_start(segContentRange);
                        rangeOk = rangeStart && *rangeStart == chunkStart &&
                                  parse_content_range_total(segContentRange) == totalBytes;
                    }
                    if (!rangeOk) {
                        sock.close();
                        fail(segChunked
                             ? "Chunked 206 response for segment " +
                               std::to_string(segStart) + "-" + std::to_string(segEnd)
                             : "Mismatched Content-Range for segment " +
                               std::to_string(segStart) + "-" + std::to_string(segEnd));
                        return;
                    }

                    file.seekp(segStart + segWritten);

                    bool ok = true;
                    std::int64_t remaining = segLen - segWritten;
                    char buf[8192];
                    while (remaining > 0) {
                        if (userCancelled.load() || anyFailed.load()) {
                            ok = false;
                            break;
                        }
                        if (isCancelled && isCancelled()) {
                            userCancelled.store(true);
                            ok = false;
                            break;
                        }
                        int toRead = remaining > static_cast<std::int64_t>(sizeof(buf))
                                   ? static_cast<int>(sizeof(buf)) : static_cast<int>(remaining);
                        if (!read_exact(sock, buf, toRead, config_.readTimeoutMs)) {
                            ok = false;
                            break;  // connection dropped — retry the remaining range
                        }
                        file.write(buf, toRead);
                        if (!file) {
                            ok = false;
                            break;
                        }
                        segWritten += toRead;
                        remaining -= toRead;
                        std::int64_t g = globalWritten.fetch_add(toRead) + toRead;
                        std::lock_guard<std::mutex> lock(stateMutex);
                        if (onProgress && g > reportedMax) {
                            reportedMax = g;
                            onProgress(totalBytes, g);
                        }
                    }

                    sock.close();
                    if (!ok) {
                        if (userCancelled.load() || anyFailed.load()) return;
                        if (attempt == MAX_RETRIES) {
                            fail("Read error for segment " + std::to_string(segStart) +
                                 "-" + std::to_string(segEnd));
                            return;
                        }
                        continue;  // retry the remainder of this segment
                    }
                    break;  // this segment done — grab the next one
                }
            }
        };

        // Exceptions escaping a thread call std::terminate — surface them as
        // download failures instead (e.g. a throwing onProgress callback).
        auto workerGuarded = [&]() {
            try {
                worker();
            } catch (const std::exception& e) {
                fail(std::string("Worker exception: ") + e.what());
            } catch (...) {
                fail("Worker exception");
            }
        };

        std::vector<std::thread> threads;
        threads.reserve(nWorkers);
        for (int i = 0; i < nWorkers; ++i) {
            threads.emplace_back(workerGuarded);
        }
        for (auto& t : threads) t.join();

        if (userCancelled.load()) {
            result.statusCode = 0;
            result.error = "cancelled";
            result.bytesWritten = globalWritten.load();
            return result;
        }
        if (anyFailed.load()) {
            std::string err;
            {
                std::lock_guard<std::mutex> lock(stateMutex);
                err = firstError;
            }
            std::error_code rmEc;
            std::filesystem::remove(destFile, rmEc);
            result.statusCode = 0;
            result.error = err.empty() ? "Download failed" : err;
            result.bytesWritten = globalWritten.load();
            return result;
        }

        result.statusCode = 206;
        result.finalUrl = url;
        result.etag = std::move(etag);
        result.lastModified = std::move(lastModified);
        result.expectedBytes = totalBytes;
        result.bytesWritten = totalBytes;
        return result;
    }

    HttpClientConfig config_;
    std::map<std::string, TlsSocket> pool_;
};

} // namespace mcpplibs::tinyhttps
