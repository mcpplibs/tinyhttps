// What the client does when it is told to go through a proxy.
//
// Each test stands up a proxy that behaves as the test scripts it and the TLS
// server from tls_test_server.hpp as the target, and asserts both what the
// caller got and what the proxy was sent. The second is the half a mock-free
// test cannot see: whether the CONNECT line named the right target, and what
// the Proxy-Authorization header said.
#include <gtest/gtest.h>
#include "proxy_test_server.hpp"
#include "tls_test_server.hpp"

import mcpplibs.tinyhttps;
import std;

namespace https = mcpplibs::tinyhttps;

namespace {

class ProxyTest : public ::testing::Test {
protected:
    void SetUp() override { https::Socket::platform_init(); }
};

https::HttpClientConfig proxied(const std::string& proxyUrl) {
    https::HttpClientConfig cfg;
    cfg.verifySsl = false;          // the test certificate authenticates nothing
    cfg.connectTimeoutMs = 4000;
    cfg.readTimeoutMs = 2000;
    cfg.proxy = proxyUrl;
    return cfg;
}

https::HttpRequest get(const std::string& url) {
    https::HttpRequest req;
    req.url = url;
    return req;
}

tls_test::Server hello_server() {
    return tls_test::Server([](tls_test::Conn& conn, int) {
        conn.write(tls_test::ok_response("hello"));
        return true;
    });
}

// The value of a header in a request head, or "" when absent.
std::string header_of(const std::string& head, std::string_view name) {
    std::string lower, key = std::string(name) + ":";
    for (char c : head) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (char& c : key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto pos = lower.find(key);
    if (pos == std::string::npos) return {};
    pos += key.size();
    while (pos < head.size() && head[pos] == ' ') ++pos;
    return head.substr(pos, head.find("\r\n", pos) - pos);
}

constexpr std::string_view kEstablished = "HTTP/1.1 200 Connection established\r\n\r\n";

// A CONNECT proxy. With `expectAuth` set it answers 407 unless the request
// carries exactly that Proxy-Authorization value. Either way it records the
// request head, so the test can read back what the client sent.
proxy_test::Server::Handler connect_handler(int targetPort, std::string expectAuth = {}) {
    return [=](proxy_test::Peer& peer) {
        auto head = peer.read_head();
        peer.note(head);
        if (head.empty()) return;
        if (!expectAuth.empty() && header_of(head, "Proxy-Authorization") != expectAuth) {
            peer.write("HTTP/1.1 407 Proxy Authentication Required\r\n"
                       "Proxy-Authenticate: Basic realm=\"test\"\r\n"
                       "Content-Length: 0\r\n\r\n");
            return;
        }
        peer.write(kEstablished);
        peer.relay_to(targetPort);
    };
}

std::string proxy_url(const proxy_test::Server& proxy, std::string_view userinfo = {}) {
    std::string url = "http://";
    if (!userinfo.empty()) { url += userinfo; url += "@"; }
    return url + "127.0.0.1:" + std::to_string(proxy.port());
}

} // namespace

// ── parse_proxy_url ──────────────────────────────────────────────────────────

TEST(ProxyUrl, BareHostAndPortIsAnHttpProxy) {
    auto p = https::parse_proxy_url("proxy.example:3128");
    EXPECT_EQ(p.scheme, "http");
    EXPECT_EQ(p.host, "proxy.example");
    EXPECT_EQ(p.port, 3128);
    EXPECT_FALSE(p.hasCredentials);
}

TEST(ProxyUrl, ThePortDefaultsAsItAlwaysHas) {
    EXPECT_EQ(https::parse_proxy_url("http://proxy.example").port, 8080);
}

TEST(ProxyUrl, APathQueryOrFragmentAfterTheAuthorityIsIgnored) {
    auto p = https::parse_proxy_url("http://proxy.example:3128/some/path?x=1#f");
    EXPECT_EQ(p.host, "proxy.example");
    EXPECT_EQ(p.port, 3128);
}

TEST(ProxyUrl, UserAndPasswordAreSplitAndPercentDecoded) {
    auto p = https::parse_proxy_url("http://al%40ice:p%3Ass%20w@proxy.example:3128");
    EXPECT_TRUE(p.hasCredentials);
    EXPECT_EQ(p.user, "al@ice");
    EXPECT_EQ(p.password, "p:ss w");
    EXPECT_EQ(p.host, "proxy.example");
    EXPECT_EQ(p.port, 3128);
}

TEST(ProxyUrl, OnlyTheFirstColonSplitsUserFromPassword) {
    auto p = https::parse_proxy_url("http://u:a:b@proxy.example:1");
    EXPECT_EQ(p.user, "u");
    EXPECT_EQ(p.password, "a:b");
}

TEST(ProxyUrl, AnUnencodedAtSignInThePasswordStaysInThePassword) {
    auto p = https::parse_proxy_url("http://u:p@ss@proxy.example:1");
    EXPECT_EQ(p.password, "p@ss");
    EXPECT_EQ(p.host, "proxy.example");
}

TEST(ProxyUrl, AUserWithNoPasswordStillHasCredentials) {
    auto p = https::parse_proxy_url("http://token@proxy.example:1");
    EXPECT_TRUE(p.hasCredentials);
    EXPECT_EQ(p.user, "token");
    EXPECT_EQ(p.password, "");
}

TEST(ProxyUrl, ABadPercentEscapeIsLeftAsWritten) {
    auto p = https::parse_proxy_url("http://u:50%@proxy.example:1");
    EXPECT_EQ(p.password, "50%");
}

TEST(ProxyUrl, AnIpv6LiteralKeepsItsColons) {
    auto p = https::parse_proxy_url("http://[::1]:3128");
    EXPECT_EQ(p.host, "::1");
    EXPECT_EQ(p.port, 3128);
}

TEST(ProxyUrl, TheSchemeIsLowerCased) {
    EXPECT_EQ(https::parse_proxy_url("HTTP://proxy.example:1").scheme, "http");
}

TEST(ProxyUrl, APortOutOfRangeIsZeroRatherThanTruncated) {
    EXPECT_EQ(https::parse_proxy_url("http://proxy.example:99999").port, 0);
    EXPECT_EQ(https::parse_proxy_url("http://proxy.example:80x").port, 0);
}

// ── CONNECT ──────────────────────────────────────────────────────────────────

TEST_F(ProxyTest, ARequestGoesThroughAProxyThatAsksForNothing) {
    auto target = hello_server();
    proxy_test::Server proxy(connect_handler(target.port()));
    ASSERT_FALSE(proxy.failed());

    https::HttpClient client(proxied(proxy_url(proxy)));
    auto resp = client.send(get(target.url("/")));

    EXPECT_EQ(resp.statusCode, 200);
    EXPECT_EQ(resp.body, "hello");
    auto notes = proxy.notes();
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_TRUE(notes[0].starts_with("CONNECT 127.0.0.1:" + std::to_string(target.port()) + " HTTP/1.1\r\n"));
    EXPECT_EQ(header_of(notes[0], "Proxy-Authorization"), "");
}

TEST_F(ProxyTest, CredentialsInTheUrlBecomeABasicProxyAuthorization) {
    auto target = hello_server();
    // base64("alice:s3cret")
    proxy_test::Server proxy(connect_handler(target.port(), "Basic YWxpY2U6czNjcmV0"));

    https::HttpClient client(proxied(proxy_url(proxy, "alice:s3cret")));
    auto resp = client.send(get(target.url("/")));

    EXPECT_EQ(resp.statusCode, 200);
    EXPECT_EQ(resp.body, "hello");
}

TEST_F(ProxyTest, CredentialsArePercentDecodedBeforeTheyAreEncoded) {
    auto target = hello_server();
    // base64("al@ice:p:ss w")
    proxy_test::Server proxy(connect_handler(target.port(), "Basic YWxAaWNlOnA6c3Mgdw=="));

    https::HttpClient client(proxied(proxy_url(proxy, "al%40ice:p%3Ass%20w")));
    EXPECT_EQ(client.send(get(target.url("/"))).statusCode, 200);
}

TEST_F(ProxyTest, WrongCredentialsAreReportedAsThatAndNotAsAFailedConnection) {
    auto target = hello_server();
    proxy_test::Server proxy(connect_handler(target.port(), "Basic YWxpY2U6czNjcmV0"));

    https::HttpClient client(proxied(proxy_url(proxy, "alice:wrong")));
    auto resp = client.send(get(target.url("/")));

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_NE(resp.statusText.find("rejected the credentials"), std::string::npos);
    EXPECT_NE(resp.statusText.find("407"), std::string::npos);
    EXPECT_EQ(target.accepts(), 0);   // the tunnel was never opened
}

TEST_F(ProxyTest, AProxyThatWantsCredentialsWeDidNotGiveSaysSo) {
    auto target = hello_server();
    proxy_test::Server proxy(connect_handler(target.port(), "Basic YWxpY2U6czNjcmV0"));

    https::HttpClient client(proxied(proxy_url(proxy)));
    auto resp = client.send(get(target.url("/")));

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_NE(resp.statusText.find("requires credentials"), std::string::npos);
}

TEST_F(ProxyTest, AnyOtherRefusalCarriesTheProxysStatus) {
    proxy_test::Server proxy([](proxy_test::Peer& peer) {
        peer.read_head();
        peer.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
    });

    https::HttpClient client(proxied(proxy_url(proxy)));
    auto resp = client.send(get("https://127.0.0.1:9/"));

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_NE(resp.statusText.find("refused CONNECT: 403 Forbidden"), std::string::npos);
}

TEST_F(ProxyTest, AProxyThatHangsUpWithoutAnsweringIsAnError) {
    proxy_test::Server proxy([](proxy_test::Peer& peer) { peer.read_head(); });

    https::HttpClient client(proxied(proxy_url(proxy)));
    auto resp = client.send(get("https://127.0.0.1:9/"));

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_NE(resp.statusText.find("no HTTP response"), std::string::npos);
}

TEST_F(ProxyTest, AnyTwoHundredSeriesAnswerOpensTheTunnel) {
    auto target = hello_server();
    proxy_test::Server proxy([&](proxy_test::Peer& peer) {
        peer.read_head();
        peer.write("HTTP/1.0 204 No Content\r\nX-Note: a header or two\r\n\r\n");
        peer.relay_to(target.port());
    });

    https::HttpClient client(proxied(proxy_url(proxy)));
    EXPECT_EQ(client.send(get(target.url("/"))).statusCode, 200);
}

TEST_F(ProxyTest, TwoRequestsShareOneTunnel) {
    auto target = hello_server();
    proxy_test::Server proxy(connect_handler(target.port()));

    https::HttpClient client(proxied(proxy_url(proxy)));
    EXPECT_EQ(client.send(get(target.url("/a"))).statusCode, 200);
    EXPECT_EQ(client.send(get(target.url("/b"))).statusCode, 200);

    EXPECT_EQ(proxy.accepts(), 1);
    EXPECT_EQ(target.accepts(), 1);
}

TEST_F(ProxyTest, ASchemeThisLibraryDoesNotSpeakIsNotQuietlyTreatedAsHttp) {
    https::HttpClient client(proxied("socks4://127.0.0.1:9"));
    auto resp = client.send(get("https://127.0.0.1:9/"));

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_NE(resp.statusText.find("unsupported scheme 'socks4'"), std::string::npos);
}

TEST_F(ProxyTest, TheOriginalProxyConnectStillReturnsATunnel) {
    auto target = hello_server();
    proxy_test::Server proxy(connect_handler(target.port()));

    auto tunnel = https::proxy_connect("127.0.0.1", proxy.port(), "127.0.0.1",
                                       target.port(), 4000);
    EXPECT_TRUE(tunnel.is_valid());
}

// ── an https:// proxy ────────────────────────────────────────────────────────
//
// The proxy here is the TLS test server: the client opens TLS to it, sends
// CONNECT inside that, and then opens a second TLS session to the target inside
// the tunnel. Two sessions on one descriptor is what these tests exist to
// exercise, and the cases that matter are the ones where the two disagree about
// what is readable: a body larger than a record, and a second request that has
// to find the tunnel already open.

namespace {

// A recorder for what the TLS proxy saw. The handler runs on the server's
// threads; the test reads it after the response is in.
struct Seen {
    std::mutex mutex;
    std::vector<std::string> heads;
    void add(std::string head) {
        std::lock_guard<std::mutex> lock(mutex);
        heads.push_back(std::move(head));
    }
    std::vector<std::string> get() {
        std::lock_guard<std::mutex> lock(mutex);
        return heads;
    }
};

tls_test::Server tls_connect_proxy(Seen& seen, int targetPort, std::string expectAuth = {},
                                   std::chrono::milliseconds gather = std::chrono::milliseconds::zero()) {
    return tls_test::Server([&seen, targetPort, expectAuth, gather](tls_test::Conn& conn, int) {
        seen.add(conn.request());
        if (!expectAuth.empty()
            && header_of(conn.request(), "Proxy-Authorization") != expectAuth) {
            conn.write("HTTP/1.1 407 Proxy Authentication Required\r\n"
                       "Proxy-Authenticate: Basic realm=\"test\"\r\n"
                       "Content-Length: 0\r\n\r\n");
            return false;
        }
        conn.write(kEstablished);
        conn.relay_to(targetPort, gather);
        return false;
    });
}

} // namespace

TEST(ProxyUrl, AnHttpsProxyDefaultsToPort443) {
    auto p = https::parse_proxy_url("https://proxy.example");
    EXPECT_EQ(p.scheme, "https");
    EXPECT_EQ(p.port, 443);
    EXPECT_EQ(https::parse_proxy_url("https://proxy.example:8443").port, 8443);
}

TEST_F(ProxyTest, ARequestGoesThroughAnHttpsProxy) {
    auto target = hello_server();
    Seen seen;
    auto proxy = tls_connect_proxy(seen, target.port());
    ASSERT_FALSE(proxy.failed());

    https::HttpClient client(proxied("https://127.0.0.1:" + std::to_string(proxy.port())));
    auto resp = client.send(get(target.url("/")));

    EXPECT_EQ(resp.statusCode, 200);
    EXPECT_EQ(resp.body, "hello");
    auto heads = seen.get();
    ASSERT_EQ(heads.size(), 1u);
    EXPECT_TRUE(heads[0].starts_with("CONNECT 127.0.0.1:" + std::to_string(target.port()) + " HTTP/1.1\r\n"));
}

TEST_F(ProxyTest, CredentialsGoToAnHttpsProxyInsideItsTlsSession) {
    auto target = hello_server();
    Seen seen;
    auto proxy = tls_connect_proxy(seen, target.port(), "Basic YWxpY2U6czNjcmV0");

    https::HttpClient ok(proxied("https://alice:s3cret@127.0.0.1:" + std::to_string(proxy.port())));
    EXPECT_EQ(ok.send(get(target.url("/"))).statusCode, 200);

    https::HttpClient bad(proxied("https://alice:nope@127.0.0.1:" + std::to_string(proxy.port())));
    auto resp = bad.send(get(target.url("/")));
    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_NE(resp.statusText.find("rejected the credentials"), std::string::npos);
}

TEST_F(ProxyTest, ABodyLargerThanARecordCrossesBothSessions) {
    std::string big(300 * 1024, 'x');
    for (std::size_t i = 0; i < big.size(); i += 97) big[i] = static_cast<char>('a' + i % 26);
    tls_test::Server target([&](tls_test::Conn& conn, int) {
        conn.write(tls_test::ok_response(big));
        return true;
    });
    Seen seen;
    auto proxy = tls_connect_proxy(seen, target.port());

    https::HttpClient client(proxied("https://127.0.0.1:" + std::to_string(proxy.port())));
    auto resp = client.send(get(target.url("/")));

    EXPECT_EQ(resp.statusCode, 200);
    EXPECT_TRUE(resp.bodyComplete);
    EXPECT_TRUE(resp.body == big);
}

TEST_F(ProxyTest, TwoRequestsShareOneTunnelThroughAnHttpsProxy) {
    auto target = hello_server();
    Seen seen;
    auto proxy = tls_connect_proxy(seen, target.port());

    https::HttpClient client(proxied("https://127.0.0.1:" + std::to_string(proxy.port())));
    EXPECT_EQ(client.send(get(target.url("/a"))).statusCode, 200);
    EXPECT_EQ(client.send(get(target.url("/b"))).statusCode, 200);

    EXPECT_EQ(proxy.accepts(), 1);
    EXPECT_EQ(target.accepts(), 1);
}

// The target writes the head and the body as two records and the proxy hands
// them on as one, so both arrive in a single record of the proxy session. The
// client reads the first through the proxy session and the descriptor is then
// empty while the second sits decrypted in that session: waiting on the
// descriptor, rather than on the session, would time out on a response that has
// already arrived.
TEST_F(ProxyTest, ABodyAlreadyDecryptedInTheProxySessionIsNotWaitedFor) {
    tls_test::Server target([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
        conn.write("hello");
        return true;
    });
    Seen seen;
    auto proxy = tls_connect_proxy(seen, target.port(), {}, std::chrono::milliseconds(150));

    https::HttpClient client(proxied("https://127.0.0.1:" + std::to_string(proxy.port())));
    auto resp = client.send(get(target.url("/")));

    EXPECT_EQ(resp.statusCode, 200);
    EXPECT_EQ(resp.body, "hello");
}

TEST_F(ProxyTest, AStreamingRequestWorksThroughAnHttpsProxy) {
    tls_test::Server target([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                   "Connection: close\r\n\r\ndata: one\n\ndata: two\n\n");
        return false;
    });
    Seen seen;
    auto proxy = tls_connect_proxy(seen, target.port());

    https::HttpClient client(proxied("https://127.0.0.1:" + std::to_string(proxy.port())));
    std::vector<std::string> events;
    auto resp = client.send_stream(get(target.url("/")), [&](const https::SseEvent& ev) {
        events.push_back(ev.data);
        return true;
    });

    EXPECT_EQ(resp.statusCode, 200);
    ASSERT_EQ(events.size(), 2u);
    EXPECT_EQ(events[0], "one");
    EXPECT_EQ(events[1], "two");
}

// The handshake has no timeout of its own, so the proxy ends it the way a real
// HTTP proxy does when it is sent something that is not HTTP: it reads the first
// bytes and hangs up.
TEST_F(ProxyTest, AnHttpsUrlToAPlainProxyFailsAtTheHandshake) {
    auto target = hello_server();
    proxy_test::Server proxy([](proxy_test::Peer& peer) { peer.read_some(); });

    https::HttpClient client(proxied("https://127.0.0.1:" + std::to_string(proxy.port())));
    auto resp = client.send(get(target.url("/")));

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_NE(resp.statusText.find("TLS connection"), std::string::npos);
}

TEST_F(ProxyTest, AnHttpUrlToATlsProxyIsAnErrorAndNotAHang) {
    auto target = hello_server();
    Seen seen;
    auto proxy = tls_connect_proxy(seen, target.port());

    https::HttpClient client(proxied("http://127.0.0.1:" + std::to_string(proxy.port())));
    auto resp = client.send(get(target.url("/")));

    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.statusText.empty());
}
