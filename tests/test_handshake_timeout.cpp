// The TLS handshake is bounded by connectTimeoutMs.
//
// Each case gives the client a peer that completes the TCP connection and then
// never answers the ClientHello, with no stop token to end the wait. The peer
// holds the connection for at most 5 s and then drops it, so a handshake that
// has no deadline fails the case (by the message and by the time it took)
// instead of hanging the suite.

// As in test_cancel.cpp, `import std` goes first with libc++ because of the
// stop token in one of the cases, and after the includes otherwise.
#include <version>
#ifdef _LIBCPP_VERSION
import std;
#endif
#include <gtest/gtest.h>
#include "proxy_test_server.hpp"
#include "tls_test_server.hpp"

import mcpplibs.tinyhttps;
#ifndef _LIBCPP_VERSION
import std;
#endif

namespace https = mcpplibs::tinyhttps;

namespace {

using Clock = std::chrono::steady_clock;

// Far below the 5 s the peers hold on for, far above the 300 ms timeout.
constexpr long long kPromptMs = 3000;

https::HttpClientConfig test_config() {
    https::HttpClientConfig cfg;
    cfg.verifySsl = false;          // the test certificate authenticates nothing
    cfg.connectTimeoutMs = 300;
    cfg.readTimeoutMs = 30000;
    return cfg;
}

https::HttpRequest get(const std::string& url) {
    https::HttpRequest req;
    req.method = https::Method::GET;
    req.url = url;
    return req;
}

long long since_ms(Clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
}

// Holds a connection for up to 5 s or until `done`.
void hold(const std::atomic<bool>& done) {
    for (int i = 0; i < 500 && !done.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// A TCP listener that never speaks TLS: it reads the ClientHello and says nothing.
class Silent {
public:
    Silent() : server_([this](proxy_test::Peer& peer) {
        peer.read_some();
        hold(done_);
    }) {}
    ~Silent() { done_ = true; }

    [[nodiscard]] bool failed() const { return server_.failed(); }
    [[nodiscard]] std::string url() const {
        return "https://127.0.0.1:" + std::to_string(server_.port()) + "/";
    }
    [[nodiscard]] std::string proxy_url(const char* scheme) const {
        return std::string(scheme) + "://127.0.0.1:" + std::to_string(server_.port());
    }

private:
    std::atomic<bool> done_ { false };
    proxy_test::Server server_;
};

class HandshakeTimeoutTest : public ::testing::Test {
protected:
    void SetUp() override { https::Socket::platform_init(); }
};

} // namespace

TEST_F(HandshakeTimeoutTest, SendGivesUpOnAHandshakeThatNeverAnswers) {
    Silent peer;
    ASSERT_FALSE(peer.failed());

    https::HttpClient client(test_config());
    const auto start = Clock::now();
    auto res = client.send(get(peer.url()));

    EXPECT_EQ(res.statusCode, 0);
    EXPECT_EQ(res.statusText, "TLS handshake timed out");
    EXPECT_LT(since_ms(start), kPromptMs);
}

TEST_F(HandshakeTimeoutTest, SendStreamGivesUpOnAHandshakeThatNeverAnswers) {
    Silent peer;
    ASSERT_FALSE(peer.failed());

    https::HttpClient client(test_config());
    const auto start = Clock::now();
    auto res = client.send_stream(get(peer.url()), [](const https::SseEvent&) { return true; });

    EXPECT_EQ(res.statusCode, 0);
    EXPECT_EQ(res.statusText, "TLS handshake timed out");
    EXPECT_LT(since_ms(start), kPromptMs);
}

// A stop token that is never stopped takes the waits in slices; the deadline
// has to hold there as well.
TEST_F(HandshakeTimeoutTest, TheDeadlineHoldsWithAStopTokenAttached) {
    Silent peer;
    ASSERT_FALSE(peer.failed());

    https::HttpClient client(test_config());
    std::stop_source never;
    const auto start = Clock::now();
    auto res = client.send(get(peer.url()), never.get_token());

    EXPECT_FALSE(res.cancelled);
    EXPECT_EQ(res.statusText, "TLS handshake timed out");
    EXPECT_LT(since_ms(start), kPromptMs);
}

TEST_F(HandshakeTimeoutTest, TheHandshakeWithAnHttpsProxyIsBounded) {
    Silent proxy;
    ASSERT_FALSE(proxy.failed());

    auto cfg = test_config();
    cfg.proxy = proxy.proxy_url("https");
    https::HttpClient client(cfg);
    const auto start = Clock::now();
    auto res = client.send(get("https://127.0.0.1:9/"));

    EXPECT_EQ(res.statusCode, 0);
    EXPECT_NE(res.statusText.find("proxy: could not open a TLS connection"), std::string::npos)
        << res.statusText;
    EXPECT_NE(res.statusText.find("TLS handshake timed out"), std::string::npos)
        << res.statusText;
    EXPECT_LT(since_ms(start), kPromptMs);
}

// The session to the target runs inside the one to the proxy, which answered
// the CONNECT and is now silent.
TEST_F(HandshakeTimeoutTest, TheHandshakeInsideAnHttpsProxyTunnelIsBounded) {
    tls_test::Server proxy([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 Connection established\r\n\r\n");
        conn.wait_peer_close(std::chrono::seconds(5));
        return false;
    });
    ASSERT_FALSE(proxy.failed());

    // The proxy's own handshake is real and has to fit in the timeout too.
    auto cfg = test_config();
    cfg.connectTimeoutMs = 1000;
    cfg.proxy = "https://127.0.0.1:" + std::to_string(proxy.port());
    https::HttpClient client(cfg);
    const auto start = Clock::now();
    auto res = client.send(get("https://127.0.0.1:9/"));

    EXPECT_EQ(res.statusCode, 0);
    EXPECT_EQ(res.statusText, "TLS handshake timed out");
    EXPECT_LT(since_ms(start), kPromptMs);
}

TEST_F(HandshakeTimeoutTest, TheHandshakeInsideAnHttpProxyTunnelIsBounded) {
    std::atomic<bool> done { false };
    proxy_test::Server proxy([&](proxy_test::Peer& peer) {
        peer.read_head();
        peer.write("HTTP/1.1 200 Connection established\r\n\r\n");
        peer.read_some();
        hold(done);
    });
    ASSERT_FALSE(proxy.failed());

    auto cfg = test_config();
    cfg.proxy = "http://127.0.0.1:" + std::to_string(proxy.port());
    https::HttpClient client(cfg);
    const auto start = Clock::now();
    auto res = client.send(get("https://127.0.0.1:9/"));
    done = true;

    EXPECT_EQ(res.statusCode, 0);
    EXPECT_EQ(res.statusText, "TLS handshake timed out");
    EXPECT_LT(since_ms(start), kPromptMs);
}

// A peer that sends a byte at a time keeps every read short, so only a limit on
// the handshake as a whole ends it: the record header promises 64 bytes and the
// peer sends fewer than that, one per 100 ms.
TEST_F(HandshakeTimeoutTest, ABytePerReadDoesNotHoldTheHandshakeOpen) {
    std::atomic<bool> done { false };
    proxy_test::Server peerServer([&](proxy_test::Peer& peer) {
        peer.read_some();
        if (!peer.write(std::string("\x16\x03\x03\x00\x40", 5))) return;
        for (int i = 0; i < 50 && !done.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (!peer.write("\x01")) return;
        }
    });
    ASSERT_FALSE(peerServer.failed());

    https::HttpClient client(test_config());
    const auto start = Clock::now();
    auto res = client.send(get("https://127.0.0.1:" + std::to_string(peerServer.port()) + "/"));
    done = true;

    EXPECT_EQ(res.statusCode, 0);
    EXPECT_EQ(res.statusText, "TLS handshake timed out");
    EXPECT_LT(since_ms(start), kPromptMs);
}

// connectTimeoutMs is for establishing the connection. Once the handshake is
// done a read waits as long as it always did: here 1600 ms of silence after a
// 1000 ms timeout, and then the bytes arrive. The timeout leaves room for a
// real handshake on a slow machine.
TEST_F(HandshakeTimeoutTest, TheDeadlineIsLiftedOnceTheHandshakeIsDone) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1600));
        conn.write("x");
        conn.wait_peer_close(std::chrono::seconds(5));
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::TlsSocket tls;
    ASSERT_TRUE(tls.connect("127.0.0.1", server.port(), 1000, /*verifySsl=*/false)) << tls.error();
    const std::string request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    ASSERT_EQ(tls.write(request.data(), static_cast<int>(request.size())),
              static_cast<int>(request.size()));
    char byte = 0;
    auto r = tls.read_some(&byte, 1);

    EXPECT_EQ(r.status, https::ReadStatus::Data);
    EXPECT_EQ(byte, 'x');
}
