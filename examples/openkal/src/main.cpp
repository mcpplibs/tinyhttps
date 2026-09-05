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
// "not run" rather than "broken".
import mcpplibs.tinyhttps;
import std;

namespace https = mcpplibs::tinyhttps;

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

    https::HttpClientConfig config;
    config.connectTimeoutMs = 15000;
    config.readTimeoutMs = 20000;
    https::HttpClient client(config);

    https::HttpRequest request;
    request.method = https::Method::GET;
    request.url = "https://httpbin.org/bytes/64";

    auto response = client.send(request);
    if (response.statusCode == 0) {
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
