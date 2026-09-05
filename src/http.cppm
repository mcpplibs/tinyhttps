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

    // FALSE WHEN THE BODY ENDED BEFORE ITS FRAMING SAID IT WOULD — a read that
    // timed out, an end of stream mid-body, a chunk header that did not parse,
    // or a streaming callback that asked to stop.
    //
    // The status line and the headers are still what the server sent; `body` is
    // a prefix of what it promised. Before this field a truncated 200 and a
    // complete 200 were indistinguishable to the caller: `DownloadToFileResult`
    // has carried `error` throughout, and `send`/`send_stream` had no way to say
    // it at all.
    //
    // `ok()` deliberately does NOT consult this. `ok()` answers "what did the
    // server say", which is a question about the status code, and making it also
    // answer "did I receive all of it" would change what existing code means
    // without changing what it says.
    bool bodyComplete { true };

    // Why the body is incomplete, when it is. Empty whenever `bodyComplete`.
    //
    // Separate from `statusText`, which used to be overwritten with the reason —
    // so a caller logging `statusText` on a 200 that broke mid-body saw
    // "Invalid chunk size: zz" where the server had said "OK".
    std::string bodyError;

    bool ok() const { return statusCode >= 200 && statusCode < 300; }
};

export struct HttpClientConfig {
    std::optional<std::string> proxy;
    int connectTimeoutMs { 10000 };
    int readTimeoutMs { 60000 };
    bool verifySsl { true };
    bool keepAlive { true };
    int maxRedirects { 10 };   // 0 = don't follow redirects

    // The most `send()` will accumulate in `HttpResponse::body` before treating
    // the response as unreadable.
    //
    // It bounds one specific hazard: `send()` is the entry point that holds the
    // whole body in memory, and the size it was about to allocate came from a
    // header. A server answering `Content-Length: 9223372036854775807` used to
    // reach `std::string::resize` with it — and this library documents no
    // exception, so a caller had no reason to have caught the `length_error`
    // that followed.
    //
    // It does NOT bound `download_to_file` (which streams to disk) or
    // `send_stream` (which streams to a callback); a download larger than this
    // is an ordinary thing to want.
    std::int64_t maxResponseBodyBytes { 64ll * 1024 * 1024 };

    // Whether to reconnect and send once more when a connection taken from the
    // pool turns out to have been closed by the server.
    //
    // A server closing an idle keep-alive connection is routine, and the client
    // cannot see it until it writes: the write lands in a local buffer and
    // succeeds, and the read that follows returns nothing. Without a retry that
    // becomes `statusCode = 0, statusText = "No response"` — for a request the
    // server never saw. curl (`Curl_retry_request`), Go's `net/http`
    // (`shouldRetryRequest`) and requests all send again in this window.
    //
    // The window is narrow by construction: only a connection that came from the
    // pool, only before a single response byte has arrived, and only once. In
    // that state the server has already sent its FIN, so nothing above its
    // transport layer saw the request. Unlike Go, this is not restricted to
    // idempotent methods — this library's traffic is predominantly POST to API
    // endpoints, and restricting it there would make the retry inapplicable to
    // nearly every request it exists to rescue. Set false to opt out.
    bool retryOnStaleConnection { true };
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

// Check if user headers contain a key (case-insensitive)
static bool has_header(const std::map<std::string, std::string>& headers, std::string_view key) {
    for (const auto& [k, v] : headers) {
        if (iequals(k, key)) return true;
    }
    return false;
}

// The value of a header, whatever case the server spelled it in. Empty when
// absent — which the three callers here can all treat as "not set".
static std::string find_header(const std::map<std::string, std::string>& headers,
                               std::string_view key) {
    for (const auto& [k, v] : headers) {
        if (iequals(k, key)) return v;
    }
    return {};
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

// ─────────────────────────────────────────────────────────────────────────────
// Framing primitives — the half of HTTP that can be examined without a server.
// ─────────────────────────────────────────────────────────────────────────────

// A status line is `HTTP-version SP status-code [SP reason]` (RFC 9112 §4.1),
// and anything else is not one.
//
// ALL THREE READERS USED TO EXTRACT THE CODE BY KEEPING THE DIGITS AND SKIPPING
// EVERYTHING ELSE, with no check that the line was a status line at all. That is
// where issue #15's `statusCode = 999` came from: a socket returned to the pool
// with a previous response's bytes still on it, and the next request read
//
//     BBBB…B 999 XHTTP/1.1 200 OK
//
// as a perfectly ordinary 999. `X9Y9Z9` would have been 999 too.
//
// Exported for the same reason as `parse_chunk_size_line` and
// `parse_content_length`: it is testable without a network.
export struct StatusLine {
    int code { 0 };
    std::string text;
};

export std::optional<StatusLine> parse_status_line(std::string_view line) {
    if (!line.starts_with("HTTP/")) return std::nullopt;

    auto sp = line.find(' ');
    if (sp == std::string_view::npos) return std::nullopt;
    auto rest = line.substr(sp + 1);

    auto sp2 = rest.find(' ');
    auto codeStr = (sp2 == std::string_view::npos) ? rest : rest.substr(0, sp2);

    // Exactly three digits — the grammar says three, and accepting two or four
    // is how a fragment of a body starts looking like a status code.
    if (codeStr.size() != 3) return std::nullopt;
    int code {};
    auto [end, error] = std::from_chars(
        codeStr.data(), codeStr.data() + codeStr.size(), code);
    if (error != std::errc{} || end != codeStr.data() + codeStr.size()) {
        return std::nullopt;
    }
    if (code < 100 || code > 599) return std::nullopt;

    return StatusLine{ code,
                       sp2 == std::string_view::npos
                           ? std::string{}
                           : std::string(rest.substr(sp2 + 1)) };
}

// `Content-Length`, rejected rather than salvaged.
//
// Both readers parsed this by walking the characters and keeping the digits, so
// `12abc` was 12, `abc` was 0 — indistinguishable from a genuine `0` — and a
// value past the width of the accumulator wrapped in silence. A length is the
// number of bytes the reader will then trust, so a wrong one is not a cosmetic
// error: too small leaves the next response's bytes in the stream, and too
// large waits for bytes that are not coming.
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

// ─────────────────────────────────────────────────────────────────────────────
// Transport
// ─────────────────────────────────────────────────────────────────────────────

// A header line or a chunk header past this length is a server that is not
// speaking HTTP. Without a bound, one such line grows a std::string until the
// process runs out of memory.
inline constexpr std::size_t max_line_length = 8192;

// And a bound on how MANY such lines, which is a separate hazard from how long
// each one is. A header block is accumulated into a map, so a server sending an
// endless supply of distinct header lines — each one short and well formed —
// grows the client's memory without limit. A trailer section is discarded
// rather than kept, but an endless supply of trailers holds the caller's thread
// just as long, and every line resets the read timeout so nothing else stops
// it. Well past what any real response carries: a large one has forty.
inline constexpr int max_head_lines = 200;

// Reads one CRLF-terminated line, distinguishing the three things an empty
// return used to mean.
//
// The older `read_line` returned `""` on a timeout, on an end of stream, AND on
// a genuine empty line — the blank line that ends a header block. So a header
// block that was cut short by a timeout read as a header block that had ended,
// and the reader went on to the body with half the headers and no idea it had
// done so. That is root cause R2 behind issue #15.
//
// `sawBytes`, when given, is set as soon as any byte of this line has arrived.
// A connection the server closed while it was idle produces none, which is the
// one condition under which resending the request is safe.
static std::expected<std::string, std::string>
read_complete_line(TlsSocket& sock, int timeoutMs, bool* sawBytes = nullptr) {
    std::string line;
    char c {};
    while (true) {
        if (!sock.wait_readable(timeoutMs)) {
            return std::unexpected("timed out before CRLF");
        }
        auto r = sock.read_some(&c, 1);
        if (r.status == ReadStatus::WouldBlock) {
            // The transport had nothing decrypted yet. Wait once more; the
            // socket is blocking after the handshake, so this is rare.
            if (!sock.wait_readable(timeoutMs)) {
                return std::unexpected("timed out before CRLF");
            }
            r = sock.read_some(&c, 1);
        }
        if (r.status == ReadStatus::Eof) {
            return std::unexpected("connection closed before CRLF");
        }
        if (r.status != ReadStatus::Data) {
            return std::unexpected("read error before CRLF");
        }
        if (sawBytes) *sawBytes = true;

        line += c;
        if (line.size() >= 2
            && line[line.size() - 2] == '\r'
            && line[line.size() - 1] == '\n') {
            line.resize(line.size() - 2);
            return line;
        }
        if (line.size() > max_line_length) {
            return std::unexpected("line exceeds " + std::to_string(max_line_length)
                                   + " bytes without a CRLF");
        }
    }
}

// Writes the whole buffer, waiting when the TLS record layer cannot flush.
//
// `TlsSocket::write` reports back-pressure as 0. This used to answer that by
// retrying immediately once and giving up if the second attempt also returned 0
// — so a slow peer reached the caller as an unexplained "Write failed". Waiting
// on the socket is what the 0 was asking for; the total wait is bounded by
// `timeoutMs` so a peer that never drains cannot stall the call.
static bool write_all(TlsSocket& sock, const std::string& data, int timeoutMs) {
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(timeoutMs);
    std::size_t total = 0;
    while (total < data.size()) {
        int ret = sock.write(data.data() + total,
                             static_cast<int>(data.size() - total));
        if (ret < 0) return false;
        if (ret == 0) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0) return false;
            if (!sock.wait_writable(static_cast<int>(left))) return false;
            continue;
        }
        total += static_cast<std::size_t>(ret);
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// One reader, used by all three entry points.
//
// There used to be three: `send`, `send_stream` and `download_to_file` each
// carried a near-copy of the status-line parse, the header loop and the body
// loop. Every hardening landed on one or two of them — strict `Content-Length`
// on two, strict chunk sizes on two, CRLF-after-chunk validation on one, pool
// clean-up on none — and the matrix of which fix reached which copy is the
// whole of issue #15's cause. `#14`, the most recent change to touch them, added
// a branch to one copy and introduced two regressions doing it.
//
// Below there is one status-line parse, one header loop and one body loop.
// ─────────────────────────────────────────────────────────────────────────────

struct ResponseHead {
    int statusCode { 0 };
    std::string statusText;
    std::map<std::string, std::string> headers;
    bool chunked { false };
    std::int64_t contentLength { -1 };
    bool connectionClose { false };
};

struct HeadError {
    std::string message;
    // Whether any byte of the response had arrived when this failed. False means
    // the server never answered, which is what a connection closed while idle
    // looks like from here.
    bool sawBytes { false };
};

static std::expected<ResponseHead, HeadError>
read_response_head(TlsSocket& sock, int timeoutMs) {
    ResponseHead head;
    bool sawBytes = false;

    // AN INTERIM RESPONSE IS NOT THE ANSWER, AND STOPPING AT ONE POISONS THE
    // POOL. RFC 9112 §2.1 requires a client to be able to read one or more 1xx
    // responses before the final one, and each is a complete status line and
    // header block of its own.
    //
    // Returning the 1xx as if it were the answer would report `103 Early Hints`
    // (or `100 Continue`, which any server sends for a request carrying
    // `Expect: 100-continue`) to the caller, and — because a 1xx carries no
    // body — mark the connection clean while the REAL response sat unread on
    // it. The next request through the same client would then read that
    // response as its own, which is issue #15 arriving by another door.
    //
    // The `max_head_lines` cap below applies per interim response; the loop
    // itself is bounded by the same count, so a server sending nothing but 1xx
    // cannot hold the call open forever either.
    for (int interim = 0; ; ++interim) {
        if (interim >= max_head_lines) {
            return std::unexpected(HeadError{
                "More than " + std::to_string(max_head_lines)
                    + " interim responses", true });
        }
        auto statusLine = read_complete_line(sock, timeoutMs, &sawBytes);
        if (!statusLine) {
            return std::unexpected(HeadError{ "No response", sawBytes });
        }
        auto status = parse_status_line(*statusLine);
        if (!status) {
            return std::unexpected(HeadError{ "Invalid status line", true });
        }
        head.statusCode = status->code;
        head.statusText = std::move(status->text);

        if (head.statusCode >= 200) break;

        // Discard the interim response's own header block and read the next
        // status line. Its fields describe the interim response, not the
        // answer, so keeping them would misreport the final one's headers.
        for (int lines = 0; ; ++lines) {
            if (lines >= max_head_lines) {
                return std::unexpected(HeadError{
                    "Interim header block exceeds "
                        + std::to_string(max_head_lines) + " lines", true });
            }
            auto line = read_complete_line(sock, timeoutMs);
            if (!line) {
                return std::unexpected(HeadError{
                    "Incomplete interim headers: " + line.error(), true });
            }
            if (line->empty()) break;
        }
    }

    for (int lines = 0; ; ++lines) {
        if (lines >= max_head_lines) {
            return std::unexpected(HeadError{
                "Header block exceeds " + std::to_string(max_head_lines)
                    + " lines", true });
        }
        auto line = read_complete_line(sock, timeoutMs);
        if (!line) {
            return std::unexpected(HeadError{
                "Incomplete headers: " + line.error(), true });
        }
        if (line->empty()) break;   // the blank line that ends the block

        auto colon = line->find(':');
        if (colon == std::string::npos) continue;
        std::string key = line->substr(0, colon);
        std::string_view value = std::string_view(*line).substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value.remove_prefix(1);
        }
        std::string valStr(value);

        if (iequals(key, "Transfer-Encoding") && iequals(valStr, "chunked")) {
            head.chunked = true;
        }
        if (iequals(key, "Content-Length")) {
            // Rejected rather than salvaged. A malformed value leaves this at
            // -1, which is the same state as an absent header and is a framing
            // this reader already handles.
            head.contentLength = parse_content_length(valStr).value_or(-1);
        }
        if (iequals(key, "Connection") && iequals(valStr, "close")) {
            head.connectionClose = true;
        }
        head.headers[std::move(key)] = std::move(valStr);
    }

    return head;
}

// Whether a response of this shape carries a body at all (RFC 9112 §6.3).
//
// A HEAD response, a 1xx, a 204 and a 304 carry none even when they declare a
// Content-Length — the field describes what a GET would have returned. Reading
// that many bytes would consume the next response instead; only HEAD was
// handled before.
static bool response_has_body(Method method, int statusCode) {
    if (method == Method::HEAD) return false;
    if (statusCode >= 100 && statusCode < 200) return false;
    return statusCode != 204 && statusCode != 304;
}

// WHERE A BODY ENDED, WHICH IS THE SAME QUESTION AS "IS THIS CONNECTION STILL
// USABLE".
//
// `Complete` is the only answer that leaves bytes owed to nobody. Every other
// answer means the stream is at an unknown offset, so the connection cannot be
// handed to the next request whatever its headers said.
enum class BodyEnd {
    Complete,      // read to the end its framing declared
    Truncated,     // the framing was broken or the body stopped short
    ClosedByPeer,  // no framing at all; the body ended when the connection did
    Stopped,       // the sink asked to stop, so bytes are still owed
};

struct BodyOutcome {
    BodyEnd end { BodyEnd::Truncated };
    std::string error;
    std::int64_t bytes { 0 };
};

using BodySink = std::function<bool(std::string_view)>;

// Reads a body according to the framing its head declared, handing each slice to
// `sink`. Returning false from `sink` stops the read (`BodyEnd::Stopped`).
//
// `maxBytes` bounds what will be read. It exists because the size this function
// was about to trust came from the server: a `Content-Length` near INT64_MAX, or
// a single `7fffffff` chunk header, used to reach an allocation of that size.
// Nothing is allocated per chunk here — the body is read in fixed slices — so
// the bound is on the total handed to the sink rather than on any one buffer.
static BodyOutcome read_body(TlsSocket& sock, const ResponseHead& head,
                             int timeoutMs, std::int64_t maxBytes,
                             const BodySink& sink) {
    BodyOutcome out;
    char buf[8192];

    // Reads at least one byte. A timeout on the wait, and a transport that stays
    // unready across two waits, are both reported as `WouldBlock` — at that
    // point bytes are still owed and the framing is broken either way.
    auto pull = [&](std::size_t want) -> ReadResult {
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (!sock.wait_readable(timeoutMs)) return { ReadStatus::WouldBlock, 0 };
            auto r = sock.read_some(buf, static_cast<int>(want));
            if (r.status != ReadStatus::WouldBlock) return r;
        }
        return { ReadStatus::WouldBlock, 0 };
    };

    auto emit = [&](int n) -> bool {
        out.bytes += n;
        return sink(std::string_view(buf, static_cast<std::size_t>(n)));
    };

    auto too_large = [&] {
        out.end = BodyEnd::Truncated;
        out.error = "Body exceeds the configured limit of "
                  + std::to_string(maxBytes) + " bytes";
    };

    if (head.chunked) {
        while (true) {
            auto sizeResult = read_complete_line(sock, timeoutMs);
            if (!sizeResult) {
                out.end = BodyEnd::Truncated;
                out.error = "Invalid chunk size line: " + sizeResult.error();
                return out;
            }
            std::string sizeLine = std::move(*sizeResult);
            if (auto semi = sizeLine.find(';'); semi != std::string::npos) {
                sizeLine.resize(semi);
            }
            while (!sizeLine.empty()
                   && (sizeLine.back() == ' ' || sizeLine.back() == '\t')) {
                sizeLine.pop_back();
            }

            // A CHUNK HEADER THAT DOES NOT PARSE IS NOT A TERMINAL CHUNK. The
            // older `parse_hex` returned what it had accumulated when it met a
            // character it did not recognise, and 0 for an empty line — and the
            // older `read_line` returned an empty line on a timeout. So a stream
            // that was cut short read as one that had ended cleanly, and the
            // socket went back into the pool with the rest of the body owed.
            auto chunkSize = parse_chunk_size_line(sizeLine);
            if (!chunkSize) {
                out.end = BodyEnd::Truncated;
                out.error = "Invalid chunk size: " + sizeLine;
                return out;
            }

            if (*chunkSize == 0) {
                // The trailer section, then the blank line that ends it.
                // Bounded for the reason `max_head_lines` gives: every line
                // resets the read timeout, so an endless supply of them holds
                // this call open with nothing else to stop it.
                for (int lines = 0; ; ++lines) {
                    if (lines >= max_head_lines) {
                        out.end = BodyEnd::Truncated;
                        out.error = "Trailer section exceeds "
                                  + std::to_string(max_head_lines) + " lines";
                        return out;
                    }
                    auto trailer = read_complete_line(sock, timeoutMs);
                    if (!trailer) {
                        out.end = BodyEnd::Truncated;
                        out.error = "Invalid chunk trailer: " + trailer.error();
                        return out;
                    }
                    if (trailer->empty()) break;
                }
                out.end = BodyEnd::Complete;
                return out;
            }

            if (out.bytes + *chunkSize > maxBytes) {
                too_large();
                return out;
            }

            std::int64_t remaining = *chunkSize;
            while (remaining > 0) {
                const auto want = static_cast<std::size_t>(
                    remaining < static_cast<std::int64_t>(sizeof buf)
                        ? remaining : static_cast<std::int64_t>(sizeof buf));
                auto r = pull(want);
                if (r.status != ReadStatus::Data) {
                    out.end = BodyEnd::Truncated;
                    out.error = r.status == ReadStatus::Eof
                              ? "Connection closed in the middle of a chunk"
                              : "Read error in the middle of a chunk";
                    return out;
                }
                remaining -= r.bytes;
                if (!emit(r.bytes)) { out.end = BodyEnd::Stopped; return out; }
            }

            // The CRLF that follows the data. Discarding it lets a wrong chunk
            // length slide into the next chunk header without a word.
            auto delimiter = read_complete_line(sock, timeoutMs);
            if (!delimiter || !delimiter->empty()) {
                out.end = BodyEnd::Truncated;
                out.error = "Missing CRLF after chunk data";
                return out;
            }
        }
    }

    if (head.contentLength >= 0) {
        if (head.contentLength > maxBytes) {
            too_large();
            return out;
        }
        std::int64_t remaining = head.contentLength;
        while (remaining > 0) {
            const auto want = static_cast<std::size_t>(
                remaining < static_cast<std::int64_t>(sizeof buf)
                    ? remaining : static_cast<std::int64_t>(sizeof buf));
            auto r = pull(want);
            if (r.status != ReadStatus::Data) {
                out.end = BodyEnd::Truncated;
                out.error = r.status == ReadStatus::Eof
                          ? "Connection closed before the declared length"
                          : "Read timed out before the declared length";
                return out;
            }
            remaining -= r.bytes;
            if (!emit(r.bytes)) { out.end = BodyEnd::Stopped; return out; }
        }
        out.end = BodyEnd::Complete;
        return out;
    }

    // Neither chunked nor a declared length: the body ends when the connection
    // does, so there is nothing left to reuse afterwards.
    while (true) {
        auto r = pull(sizeof buf);
        if (r.status == ReadStatus::Eof) {
            out.end = BodyEnd::ClosedByPeer;
            return out;
        }
        if (r.status != ReadStatus::Data) {
            out.end = BodyEnd::Truncated;
            out.error = "Read timed out before the connection closed";
            return out;
        }
        if (out.bytes + r.bytes > maxBytes) {
            too_large();
            return out;
        }
        if (!emit(r.bytes)) { out.end = BodyEnd::Stopped; return out; }
    }
}

// Consumes a body the caller is not going to be given, so that the connection
// stays usable. Returns false when it could not be consumed in full — then the
// connection must be dropped.
//
// Bounded: past the cap, reconnecting is cheaper than reading, and a body with
// no declared end must not be able to stall the call. A response with no framing
// of its own ends at the close, so there is nothing to salvage and this refuses
// without reading.
static bool drain_body(TlsSocket& sock, const ResponseHead& head,
                       int timeoutMs, std::int64_t cap = 64 * 1024) {
    if (head.connectionClose) return false;
    if (!head.chunked && head.contentLength < 0) return false;
    if (!head.chunked && head.contentLength == 0) return true;
    if (head.contentLength > cap) return false;

    auto outcome = read_body(sock, head, timeoutMs, cap,
                             [](std::string_view) { return true; });
    return outcome.end == BodyEnd::Complete;
}

// THE POOL'S INVARIANT, MADE THE DEFAULT.
//
// A connection may be reused when it owes no bytes and its peer is still there.
// `TlsSocket::is_valid()` cannot check that — it answers "is the descriptor
// open" — so the condition was maintained by ten early-return paths each
// remembering to set a flag, and issue #15 is the list of the ones that did not.
// Every defect in it has the same shape: a path that did nothing, where doing
// nothing left a dirty socket in the pool for the next request to pick up.
//
// So dropping is what doing nothing means here. A path that leaves without
// calling `keep()` drops the connection, and a path added tomorrow is safe
// before anyone reviews it.
//
// ⚠️ Ordering: `drop()` destroys a `TlsSocket`, which sends `close_notify`,
// which writes to a socket whose peer may be gone. That write is why P0 —
// `MSG_NOSIGNAL` in `Socket::write` — had to land before this class existed;
// without it, making the drop path more common would have made issue #16 more
// common too.
class PooledConnection {
public:
    PooledConnection(std::map<std::string, TlsSocket>& pool, std::string key)
        : pool_(pool), key_(std::move(key)) {}

    ~PooledConnection() { drop(); }

    PooledConnection(const PooledConnection&) = delete;
    PooledConnection& operator=(const PooledConnection&) = delete;

    // Call only where the body was read to the end its framing declared and the
    // response did not ask for the connection to close.
    void keep() noexcept { armed_ = false; }

    // Drop now rather than at the end of the scope. Idempotent, and a no-op
    // after `keep()`.
    //
    // ⚠️ Callers that recurse — the redirect paths — MUST settle the guard
    // before recursing. The inner call puts its own connection into the pool
    // under the same key when the redirect is to the same host, and a guard
    // still armed when the outer scope ends would then delete it.
    void drop() {
        if (!armed_) return;
        armed_ = false;
        if (auto it = pool_.find(key_); it != pool_.end()) {
            it->second.close();
            pool_.erase(it);
        }
    }

    // Drop what is there and arm again for what replaces it. The stale-connection
    // retry is the one place where a guard outlives the socket it was made for.
    void reset() { drop(); armed_ = true; }

private:
    std::map<std::string, TlsSocket>& pool_;
    std::string key_;
    bool armed_ { true };
};

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

    // Streaming SSE request — reads the response body incrementally, feeding
    // chunks through SseParser to the caller's callback. The callback receives
    // each SseEvent and returns true to continue or false to stop.
    HttpResponse send_stream(const HttpRequest& request, SseCallbackFn callback) {
        HttpResponse response;

        auto parsed = parse_url(request.url);
        if (parsed.scheme != "https") {
            response.statusCode = 0;
            response.statusText = "Only HTTPS is supported";
            return response;
        }

        const std::string poolKey = parsed.host + ":" + std::to_string(parsed.port);
        PooledConnection guard(pool_, poolKey);

        auto exchange = perform_exchange(parsed, poolKey,
                                         build_request(request, parsed), guard);
        if (!exchange.error.empty()) {
            response.statusCode = 0;
            response.statusText = exchange.error;
            response.bodyComplete = false;
            response.bodyError = exchange.error;
            return response;
        }

        response.statusCode = exchange.head.statusCode;
        response.statusText = exchange.head.statusText;
        response.headers = exchange.head.headers;

        // A failed streaming request is answered with an error document rather
        // than an event stream, so the parser finds nothing in it. Keeping the
        // bytes is the only way a caller learns the reason.
        const bool captureBody = !response.ok();
        SseParser parser;

        auto sink = [&](std::string_view data) -> bool {
            if (captureBody) {
                append_within_limit(response.body, data, stream_error_body_limit);
            }
            for (const auto& event : parser.feed(data)) {
                if (!callback(event)) return false;
            }
            return true;
        };

        finish_body(response, exchange, request.method,
                    /*maxBytes=*/std::numeric_limits<std::int64_t>::max(),
                    sink, guard);
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
    // What one request/response head exchange produced. `error` empty means
    // `sock` and `head` are usable.
    struct Exchange {
        TlsSocket* sock { nullptr };
        ResponseHead head;
        std::string error;
    };

    std::string build_request(const HttpRequest& request, const ParsedUrl& parsed) const {
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
            reqStr += config_.keepAlive ? "Connection: keep-alive\r\n"
                                        : "Connection: close\r\n";
        }
        reqStr += "\r\n";
        reqStr += request.body;
        return reqStr;
    }

    bool open_connection(TlsSocket& sock, const ParsedUrl& parsed) {
        if (config_.proxy.has_value()) {
            auto proxyConf = parse_proxy_url(config_.proxy.value());
            auto tunnel = proxy_connect(proxyConf.host, proxyConf.port,
                                        parsed.host, parsed.port,
                                        config_.connectTimeoutMs);
            if (!tunnel.is_valid()) return false;
            return sock.connect_over(std::move(tunnel), parsed.host.c_str(),
                                     config_.verifySsl);
        }
        return sock.connect(parsed.host.c_str(), parsed.port,
                            config_.connectTimeoutMs, config_.verifySsl);
    }

    // Acquires a connection for `poolKey`, sends `reqStr` and reads the response
    // head, leaving `guard` armed for whatever is in the pool.
    //
    // A connection the server closed while it was idle fails here and nowhere
    // else: the write lands in a local buffer and succeeds, and the read that
    // follows sees the FIN. Nothing above the server's transport layer saw the
    // request, so sending it again on a fresh connection is safe — once, and
    // only when no response byte has arrived. See `retryOnStaleConnection`.
    Exchange perform_exchange(const ParsedUrl& parsed, const std::string& poolKey,
                              const std::string& reqStr, PooledConnection& guard) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            bool reused = false;
            TlsSocket* sock = nullptr;

            auto it = pool_.find(poolKey);
            if (it != pool_.end() && it->second.is_valid()) {
                sock = &it->second;
                reused = true;
            } else {
                if (it != pool_.end()) pool_.erase(it);
                auto [inserted, ok] = pool_.emplace(poolKey, TlsSocket{});
                sock = &inserted->second;
                if (!open_connection(*sock, parsed)) {
                    guard.drop();
                    return { nullptr, {}, "Connection failed" };
                }
            }

            const bool mayRetry = reused && attempt == 0
                               && config_.retryOnStaleConnection;

            // A failed write needs no `sawBytes` test, and the asymmetry with
            // the read below is not an oversight. `write_all` returns true only
            // when every byte went out, so a false here means an INCOMPLETE
            // request reached the server — and a conforming server cannot act on
            // one: it is still waiting for the blank line, or for the
            // Content-Length bytes it was promised. Resending on a fresh
            // connection therefore yields exactly one execution.
            if (!write_all(*sock, reqStr, config_.readTimeoutMs)) {
                if (mayRetry) { guard.reset(); continue; }
                guard.drop();
                return { nullptr, {}, "Write failed" };
            }

            auto head = read_response_head(*sock, config_.readTimeoutMs);
            if (head) return { sock, std::move(*head), {} };

            // Only a silent connection is safe to resend on. Once a byte has
            // arrived the server has seen the request, and repeating it could
            // repeat its effect.
            if (mayRetry && !head.error().sawBytes) { guard.reset(); continue; }
            guard.drop();
            return { nullptr, {}, head.error().message };
        }
        guard.drop();
        return { nullptr, {}, "No response" };
    }

    // Reads the body into `sink` and settles the pool guard by what the read
    // found. The single place that decides whether a connection is reusable.
    void finish_body(HttpResponse& response, Exchange& exchange, Method method,
                     std::int64_t maxBytes, const BodySink& sink,
                     PooledConnection& guard) {
        if (!response_has_body(method, exchange.head.statusCode)) {
            if (config_.keepAlive && !exchange.head.connectionClose) guard.keep();
            return;
        }

        auto outcome = read_body(*exchange.sock, exchange.head,
                                 config_.readTimeoutMs, maxBytes, sink);
        switch (outcome.end) {
            case BodyEnd::Complete:
                if (config_.keepAlive && !exchange.head.connectionClose) guard.keep();
                break;
            case BodyEnd::Stopped:
                // Not an error, but bytes are still owed on the socket.
                response.bodyComplete = false;
                response.bodyError = "stopped by callback";
                break;
            case BodyEnd::ClosedByPeer:
                // The body ended where it said it would; the connection did too.
                break;
            case BodyEnd::Truncated:
                response.bodyComplete = false;
                response.bodyError = outcome.error;
                break;
        }
    }

    HttpResponse send_impl(const HttpRequest& request, int redirectCount) {
        HttpResponse response;

        auto parsed = parse_url(request.url);
        if (parsed.scheme != "https") {
            response.statusCode = 0;
            response.statusText = "Only HTTPS is supported";
            return response;
        }

        const std::string poolKey = parsed.host + ":" + std::to_string(parsed.port);
        PooledConnection guard(pool_, poolKey);

        auto exchange = perform_exchange(parsed, poolKey,
                                         build_request(request, parsed), guard);
        if (!exchange.error.empty()) {
            response.statusCode = 0;
            response.statusText = exchange.error;
            response.bodyComplete = false;
            response.bodyError = exchange.error;
            return response;
        }

        response.statusCode = exchange.head.statusCode;
        response.statusText = exchange.head.statusText;
        response.headers = exchange.head.headers;

        // Reserving the declared length would let a server ask for an allocation
        // by writing a header. Reserve a modest amount and let the string grow;
        // `maxResponseBodyBytes` is what actually bounds the total.
        if (exchange.head.contentLength > 0) {
            constexpr std::int64_t reserveCap = 1024 * 1024;
            response.body.reserve(static_cast<std::size_t>(
                exchange.head.contentLength < reserveCap
                    ? exchange.head.contentLength : reserveCap));
        }

        finish_body(response, exchange, request.method,
                    config_.maxResponseBodyBytes,
                    [&](std::string_view data) {
                        response.body.append(data);
                        return true;
                    },
                    guard);

        // Follow 3xx redirects if configured.
        if (config_.maxRedirects > 0 &&
            response.statusCode >= 300 && response.statusCode < 400 &&
            redirectCount < config_.maxRedirects) {
            std::string location = find_header(response.headers, "Location");
            if (!location.empty()) {
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
                // Settle before recursing: the inner call may put its own
                // connection into the pool under this same key, and a guard
                // still armed would delete it when this scope ends.
                guard.drop();
                return send_impl(redirectReq, redirectCount + 1);
            }
        }

        return response;
    }

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

        const std::string poolKey = parsed.host + ":" + std::to_string(parsed.port);
        PooledConnection guard(pool_, poolKey);

        HttpRequest request;
        request.method = Method::GET;
        request.url = url;
        request.headers = { {"User-Agent", "tinyhttps/1.0"}, {"Accept", "*/*"} };

        auto exchange = perform_exchange(parsed, poolKey,
                                         build_request(request, parsed), guard);
        if (!exchange.error.empty()) {
            result.error = exchange.error;
            return result;
        }

        result.statusCode = exchange.head.statusCode;
        const bool hasBody = response_has_body(Method::GET, exchange.head.statusCode);

        // Follow redirects.
        if (result.statusCode >= 300 && result.statusCode < 400 &&
            redirectCount < config_.maxRedirects) {
            std::string location = find_header(exchange.head.headers, "Location");
            if (!location.empty()) {
                // A 3xx normally carries a short explanatory body, and the code
                // here promised in a comment to "drain any body to keep the
                // connection clean" without ever draining one. The socket went
                // back into the pool with those bytes owed, and the recursive
                // call below picked it up for the very next request — issue #15's
                // failure mode, on a path with no timeout and no truncation.
                const bool clean = !hasBody
                    || drain_body(*exchange.sock, exchange.head, config_.readTimeoutMs);
                if (clean && config_.keepAlive && !exchange.head.connectionClose) {
                    guard.keep();
                } else {
                    guard.drop();
                }

                if (location.starts_with("/")) {
                    location = parsed.scheme + "://" + parsed.host +
                               (parsed.port != 443 ? ":" + std::to_string(parsed.port) : "") +
                               location;
                }
                return download_to_file_impl(location, destFile, std::move(onProgress),
                                             std::move(isCancelled), redirectCount + 1);
            }
        }

        // A non-2xx carries an error document that nobody is going to read.
        // Draining it is what keeps the connection usable for the next request.
        if (result.statusCode < 200 || result.statusCode >= 300) {
            result.error = "HTTP " + std::to_string(result.statusCode);
            settle_without_body(exchange, hasBody, guard);
            return result;
        }

        result.finalUrl = url;
        result.etag = find_header(exchange.head.headers, "ETag");
        result.lastModified = find_header(exchange.head.headers, "Last-Modified");
        if (exchange.head.contentLength >= 0) {
            result.expectedBytes = exchange.head.contentLength;
        }

        std::error_code ec;
        std::filesystem::create_directories(destFile.parent_path(), ec);
        std::ofstream ofs(destFile, std::ios::binary);
        if (!ofs) {
            result.error = "Cannot open file: " + destFile.string();
            settle_without_body(exchange, hasBody, guard);
            return result;
        }

        if (!hasBody) {
            ofs.close();
            if (config_.keepAlive && !exchange.head.connectionClose) guard.keep();
            return result;
        }

        const std::int64_t totalBytes =
            exchange.head.contentLength > 0 ? exchange.head.contentLength : 0;
        std::int64_t downloaded = 0;
        bool cancelled = false;

        auto outcome = read_body(
            *exchange.sock, exchange.head, config_.readTimeoutMs,
            std::numeric_limits<std::int64_t>::max(),
            [&](std::string_view data) -> bool {
                ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
                downloaded += static_cast<std::int64_t>(data.size());
                if (onProgress) onProgress(totalBytes, downloaded);
                if (isCancelled && isCancelled()) { cancelled = true; return false; }
                return true;
            });

        ofs.close();
        result.bytesWritten = downloaded;

        switch (outcome.end) {
            case BodyEnd::Complete:
                if (config_.keepAlive && !exchange.head.connectionClose) guard.keep();
                break;
            case BodyEnd::ClosedByPeer:
                break;   // the body ended where it said it would
            case BodyEnd::Stopped:
                result.error = cancelled ? "cancelled" : "stopped";
                break;
            case BodyEnd::Truncated:
                result.error = outcome.error;
                break;
        }
        return result;
    }

    // Settles the guard for a response whose body the caller will not be given:
    // drain it if it is short enough, and drop the connection otherwise.
    void settle_without_body(Exchange& exchange, bool hasBody, PooledConnection& guard) {
        const bool clean = !hasBody
            || drain_body(*exchange.sock, exchange.head, config_.readTimeoutMs);
        if (clean && config_.keepAlive && !exchange.head.connectionClose) {
            guard.keep();
        } else {
            guard.drop();
        }
    }

    HttpClientConfig config_;
    std::map<std::string, TlsSocket> pool_;
};

} // namespace mcpplibs::tinyhttps
