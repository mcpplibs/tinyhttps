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
