// tinyhttps above openkal — a smoke test that runs the whole stack.
//
// WHAT THIS PROVES THAT COMPILING DOES NOT. A build only shows that the headers
// were found. This binary is statically linked, contains openkal's own
// `kal_net_connect` and `kal_stream_read`, and makes a real HTTPS request
// through them: name resolution, TCP, a TLS 1.2 handshake against a public
// certificate chain, and the HTTP framing this library was rewritten around.
//
// Run it with `mcpp run` from this directory. It needs the network; when there
// is none it says so and exits 0, because a CI job without egress should report
// "not run" rather than "broken". A certificate the client refused is not an
// absence of network, and exits 1.
// The listener below is made with the C library's sockets, which openkal-musl
// provides on every target this example runs on. C headers only: they declare
// nothing `import std` also declares.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import mcpplibs.tinyhttps;
import std;

namespace https = mcpplibs::tinyhttps;

namespace {

// CANCELLATION ABOVE openkal, WITH NO NETWORK.
//
// A listener that never accepts: the connection completes in the backlog, the
// client sends its ClientHello and waits for an answer that is not coming. That
// wait is a `poll` in slices of 50 ms, and above openkal each slice is a bounded
// read (`kal_timeout_read`) rather than a readiness query, which is the part of
// the stack this checks. The read timeout is 30 s, so returning promptly can
// only be the token's doing.
bool cancellation_works() {
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { std::println("cancellation: no socket"); return false; }
    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    socklen_t len = sizeof addr;
    if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0
        || ::listen(listener, 4) != 0
        || ::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        std::println("cancellation: no listener");
        ::close(listener);
        return false;
    }
    const std::string url = "https://127.0.0.1:" + std::to_string(ntohs(addr.sin_port)) + "/";

    https::HttpClientConfig config;
    config.verifySsl = false;
    config.connectTimeoutMs = 5000;
    config.readTimeoutMs = 30000;
    https::HttpClient client(config);
    https::HttpRequest request;
    request.method = https::Method::GET;
    request.url = url;

    // A token stopped before the call: nothing is sent.
    std::stop_source early;
    early.request_stop();
    auto before = client.send(request, early.get_token());

    // A token stopped while the handshake waits.
    std::stop_source source;
    std::jthread stopper([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        source.request_stop();
    });
    const auto start = std::chrono::steady_clock::now();
    auto during = client.send(request, source.get_token());
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    ::close(listener);

    const bool ok = before.cancelled && before.statusCode == 0
                 && during.cancelled && during.statusCode == 0
                 && ms >= 150 && ms < 2000;
    std::println("cancellation: {} (stopped at 200 ms, returned after {} ms)",
                 ok ? "ok" : "WRONG", ms);
    return ok;
}

} // namespace

int main() {
    https::Socket::platform_init();

    // The parsers first: they need no network, and reaching them at all means
    // every module of the library compiled and linked on this stack.
    auto status = https::parse_status_line("HTTP/1.1 200 OK");
    auto length = https::parse_content_length("4294967296");   // past 32 bits
    auto chunk  = https::parse_chunk_size_line("1a");
    if (!status || status->code != 200 || !length || *length != 4294967296LL
        || !chunk || *chunk != 26) {
        std::println("framing parsers gave the wrong answers");
        return 1;
    }
    std::println("framing parsers: ok");

    if (!cancellation_works()) return 1;

    https::HttpClientConfig config;
    config.connectTimeoutMs = 15000;
    config.readTimeoutMs = 20000;
    https::HttpClient client(config);

    https::HttpRequest request;
    request.method = https::Method::GET;
    request.url = "https://httpbin.org/bytes/64";

    auto response = client.send(request);
    if (response.statusCode == 0) {
        // A certificate the client refused is a verdict about this stack, not
        // an absence of network, and is reported as one. Read as "no network",
        // a CA bundle this stack cannot find would pass here unnoticed.
        constexpr std::string_view refusals[] = {
            "certificate verification failed",
            "no CA certificate bundle",
            "cannot parse the CA certificate bundle",
            "TLS handshake failed",
        };
        for (auto refusal : refusals) {
            if (response.statusText.starts_with(refusal)) {
                std::println("TLS refused: {}", response.statusText);
                return 1;
            }
        }
        std::println("no network ({}) — the build and the parsers are still verified",
                     response.statusText);
        return 0;
    }

    std::println("GET {} -> {} {} ({} bytes, complete={})",
                 request.url, response.statusCode, response.statusText,
                 response.body.size(), response.bodyComplete);

    const bool ok = response.statusCode == 200
                 && response.bodyComplete
                 && response.body.size() == 64;
    std::println("{}", ok ? "tinyhttps above openkal: ok" : "tinyhttps above openkal: WRONG");
    return ok ? 0 : 1;
}
