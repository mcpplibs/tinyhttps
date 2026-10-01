// Abandoning a request from another thread through a std::stop_token.
//
// Every wait here is far longer than the test should take (readTimeoutMs is
// 30 s), so a request that returns promptly with `cancelled` set can only have
// been ended by the token, never by a timeout.

// WHERE `import std` GOES DEPENDS ON THE STANDARD LIBRARY, AND ONLY HERE.
//
// Every other test file includes its headers and then imports std, which is the
// order libstdc++ needs: the other way round, gcc 16 rejects the headers as
// redefinitions of what the module already declared. This file is the one that
// calls `std::stop_source::request_stop()`, and libc++ 20 and 22 compile that
// call, after a textual <thread> or <condition_variable> (gtest and the test
// servers include both), into a reference to an inline helper that nothing then
// emits: the link fails on `__atomic_unique_lock<...>::__set_locked_bit`. With
// the import first it links, and libc++ 23 links either way. Measured with the
// toolchains mcpp installs; see .agents/docs/design-cancel-stop-token.md §6.2.
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

// Well above the 50 ms slice and still far below any timeout in play.
constexpr long long kPromptMs = 500;

https::HttpClientConfig test_config(int readTimeoutMs = 30000) {
    https::HttpClientConfig cfg;
    cfg.verifySsl = false;          // the test certificate authenticates nothing
    cfg.connectTimeoutMs = 4000;
    cfg.readTimeoutMs = readTimeoutMs;
    return cfg;
}

https::HttpRequest get(const std::string& url) {
    https::HttpRequest req;
    req.method = https::Method::GET;
    req.url = url;
    return req;
}

long long ms_between(Clock::time_point from, Clock::time_point to) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(to - from).count();
}

// Requests a stop `delay` after `ready` first holds (at once when it is not
// given) and remembers when it did, so a test can measure from the stop to the
// return of the call. Waiting for the server to have seen the request keeps a
// slow machine from stopping a request that was never sent.
class Stopper {
public:
    explicit Stopper(std::chrono::milliseconds delay,
                     std::function<bool()> ready = {})
        : thread_([this, delay, ready = std::move(ready)] {
              for (int i = 0; ready && !ready() && i < 1000 && !quit_.load(); ++i) {
                  std::this_thread::sleep_for(std::chrono::milliseconds(5));
              }
              for (auto end = Clock::now() + delay;
                   Clock::now() < end && !quit_.load();) {
                  std::this_thread::sleep_for(std::chrono::milliseconds(5));
              }
              if (quit_.load()) return;
              stoppedAt_.store(Clock::now().time_since_epoch().count());
              source.request_stop();
          }) {}
    // A stop that has not come yet is abandoned, so a long delay costs nothing
    // when the call it was meant to end has already returned.
    ~Stopper() {
        quit_ = true;
        if (thread_.joinable()) thread_.join();
    }

    long long since_stop_ms(Clock::time_point returned) {
        thread_.join();
        return ms_between(Clock::time_point(Clock::duration(stoppedAt_.load())), returned);
    }

    std::stop_source source;

private:
    std::atomic<Clock::rep> stoppedAt_ { 0 };
    std::atomic<bool> quit_ { false };
    std::thread thread_;
};

// A TCP listener that never speaks TLS: it accepts, reads and discards, so a
// client's handshake waits for a ServerHello that is not coming.
class SilentListener {
public:
    SilentListener() {
        mbedtls_net_init(&listener_);
        if (mbedtls_net_bind(&listener_, "127.0.0.1", "0", MBEDTLS_NET_PROTO_TCP) != 0) {
            failed_ = true;
            return;
        }
        sockaddr_in addr {};
        socklen_t len = sizeof addr;
        if (::getsockname(listener_.fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            failed_ = true;
            return;
        }
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { run(); });
    }

    ~SilentListener() {
        release();
        if (thread_.joinable()) thread_.join();
        mbedtls_net_free(&listener_);
    }

    [[nodiscard]] bool failed() const { return failed_; }
    [[nodiscard]] std::string url() const {
        return "https://127.0.0.1:" + std::to_string(port_) + "/";
    }
    [[nodiscard]] bool peer_closed() const { return peerClosed_.load(); }
    [[nodiscard]] bool received() const { return received_.load(); }

    // Lets go of the accepted connection and stops listening.
    void release() { released_.store(true); }

private:
    void run() {
        while (!released_.load()) {
            const int ready = mbedtls_net_poll(&listener_, MBEDTLS_NET_POLL_READ, 50);
            if (ready < 0) return;
            if (ready == 0) continue;
            mbedtls_net_context client {};
            mbedtls_net_init(&client);
            if (mbedtls_net_accept(&listener_, &client, nullptr, 0, nullptr) != 0) {
                mbedtls_net_free(&client);
                continue;
            }
            unsigned char buf[512];
            while (!released_.load()) {
                const int r = mbedtls_net_poll(&client, MBEDTLS_NET_POLL_READ, 50);
                if (r < 0) break;
                if (r == 0) continue;
                if (mbedtls_net_recv(&client, buf, sizeof buf) <= 0) {
                    peerClosed_.store(true);
                    break;
                }
                received_.store(true);
            }
            mbedtls_net_free(&client);
            return;
        }
    }

    mbedtls_net_context listener_ {};
    int port_ { 0 };
    bool failed_ { false };
    std::atomic<bool> released_ { false };
    std::atomic<bool> peerClosed_ { false };
    std::atomic<bool> received_ { false };
    std::thread thread_;
};

// Waits up to `limit` for `predicate`, which is how a test learns that the server
// saw the connection end.
bool becomes_true(const std::function<bool()>& predicate,
                  std::chrono::milliseconds limit = std::chrono::seconds(2)) {
    const auto deadline = Clock::now() + limit;
    while (!predicate() && Clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return predicate();
}

class CancelTest : public ::testing::Test {
protected:
    void SetUp() override { https::Socket::platform_init(); }
};

} // namespace

// The case that motivates all of this: the request is written and the server
// has not answered. The server also records that the connection ended, which is
// what makes it stop working on a request nobody is waiting for.
TEST_F(CancelTest, ARequestWaitingForTheHeadersIsAbandoned) {
    std::atomic<bool> peerClosed { false };
    tls_test::Server server([&](tls_test::Conn& conn, int) {
        peerClosed = conn.wait_peer_close();
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    Stopper stopper(std::chrono::milliseconds(200), [&] { return server.requests() >= 1; });

    auto res = client.send(get(server.url("/")), stopper.source.get_token());
    const auto returned = Clock::now();
    const auto latency = stopper.since_stop_ms(returned);
    std::cout << "[ latency  ] headers: " << latency << " ms after the stop" << std::endl;

    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.statusCode, 0);
    EXPECT_FALSE(res.bodyComplete);
    EXPECT_LT(latency, kPromptMs);
    EXPECT_TRUE(becomes_true([&] { return peerClosed.load(); }))
        << "the connection was not closed";
}

TEST_F(CancelTest, AStreamWaitingForTheNextChunkIsAbandoned) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        conn.write("b\r\ndata: one\n\n\r\n");
        conn.park();
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    std::atomic<int> events { 0 };
    Stopper stopper(std::chrono::milliseconds(100), [&] { return events.load() > 0; });

    auto res = client.send_stream(get(server.url("/")),
                                  [&](const https::SseEvent&) { ++events; return true; },
                                  stopper.source.get_token());
    const auto latency = stopper.since_stop_ms(Clock::now());
    std::cout << "[ latency  ] stream: " << latency << " ms after the stop" << std::endl;

    EXPECT_EQ(res.statusCode, 200);
    EXPECT_TRUE(res.cancelled);
    EXPECT_FALSE(res.bodyComplete);
    EXPECT_EQ(res.bodyError, "cancelled");
    EXPECT_EQ(events.load(), 1);
    EXPECT_LT(latency, kPromptMs);
}

// The handshake has no timeout of its own, so a server that accepts and says
// nothing holds the call for good unless the token ends it. The watchdog keeps
// a regression from hanging the suite: it lets go of the connection after 5 s.
TEST_F(CancelTest, AHandshakeThatNeverAnswersIsAbandoned) {
    SilentListener listener;
    ASSERT_FALSE(listener.failed());

    https::HttpClient client(test_config());
    Stopper stopper(std::chrono::milliseconds(200), [&] { return listener.received(); });

    std::atomic<bool> done { false };
    std::atomic<bool> watchdogFired { false };
    std::thread watchdog([&] {
        for (int i = 0; i < 500 && !done.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (!done.load()) { watchdogFired = true; listener.release(); }
    });

    auto res = client.send(get(listener.url()), stopper.source.get_token());
    const auto returned = Clock::now();
    done = true;
    watchdog.join();
    const auto latency = stopper.since_stop_ms(returned);
    std::cout << "[ latency  ] handshake: " << latency << " ms after the stop" << std::endl;

    EXPECT_FALSE(watchdogFired.load()) << "the handshake was not interrupted";
    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.statusCode, 0);
    EXPECT_LT(latency, kPromptMs);
    EXPECT_TRUE(becomes_true([&] { return listener.peer_closed(); }))
        << "the connection was not closed";
}

TEST_F(CancelTest, ATokenAlreadyStoppedSendsNothing) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write(tls_test::ok_response("hello"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    std::stop_source source;
    source.request_stop();
    https::HttpClient client(test_config());

    auto res = client.send(get(server.url("/")), source.get_token());
    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.statusCode, 0);

    auto streamed = client.send_stream(get(server.url("/")),
                                       [](const https::SseEvent&) { return true; },
                                       source.get_token());
    EXPECT_TRUE(streamed.cancelled);
    EXPECT_EQ(server.accepts(), 0);
}

// The slices must not shorten or lengthen the timeout a token-carrying call
// already had. The token is stopped after 5 s, so a timeout that never comes
// fails the test rather than hanging the suite.
TEST_F(CancelTest, ATokenThatIsNeverStoppedLeavesTheTimeoutAlone) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.park();
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config(/*readTimeoutMs=*/300));
    Stopper backstop(std::chrono::seconds(5));

    const auto started = Clock::now();
    auto res = client.send(get(server.url("/")), backstop.source.get_token());
    const auto elapsed = ms_between(started, Clock::now());

    EXPECT_FALSE(res.cancelled);
    EXPECT_EQ(res.statusCode, 0);
    EXPECT_EQ(res.statusText, "No response");
    EXPECT_GT(elapsed, 250);
    EXPECT_LT(elapsed, 1500);
}

// A cancelled connection has an unknown amount of the response still on it, so
// it must not be handed to the next request.
TEST_F(CancelTest, ACancelledConnectionIsNotReused) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.wait_peer_close();
            return false;
        }
        conn.write(tls_test::ok_response("second"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    Stopper stopper(std::chrono::milliseconds(100), [&] { return server.requests() >= 1; });
    auto first = client.send(get(server.url("/")), stopper.source.get_token());
    EXPECT_TRUE(first.cancelled);

    auto second = client.send(get(server.url("/")));
    EXPECT_EQ(second.statusCode, 200) << "status text was: " << second.statusText;
    EXPECT_EQ(second.body, "second");
    EXPECT_FALSE(second.cancelled);
    EXPECT_EQ(server.accepts(), 2);
}

// A pooled connection that fails before any response byte is normally retried
// on a new one. A request the caller has abandoned must not be sent again.
TEST_F(CancelTest, ACancelledRequestIsNotRetriedOnAFreshConnection) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write(tls_test::ok_response("first"));
            return true;
        }
        conn.wait_peer_close();
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    EXPECT_EQ(client.send(get(server.url("/"))).statusCode, 200);

    Stopper stopper(std::chrono::milliseconds(100), [&] { return server.requests() >= 2; });
    auto res = client.send(get(server.url("/")), stopper.source.get_token());
    EXPECT_TRUE(res.cancelled);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(server.requests(), 2);
    EXPECT_EQ(server.accepts(), 1);
}

namespace {

int open_fds() {
    std::error_code ec;
    for (const char* dir : { "/proc/self/fd", "/dev/fd" }) {
        if (!std::filesystem::exists(dir, ec)) continue;
        int n = 0;
        for (auto it = std::filesystem::directory_iterator(dir, ec);
             !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
            ++n;
        }
        return n;
    }
    return -1;
}

void cancel_stuck_requests(int times) {
    std::atomic<int> closed { 0 };
    tls_test::Server server([&](tls_test::Conn& conn, int) {
        if (conn.wait_peer_close()) ++closed;
        return false;
    });
    https::HttpClient client(test_config());
    for (int i = 0; i < times; ++i) {
        const int seen = server.requests();
        Stopper stopper(std::chrono::milliseconds(50), [&] { return server.requests() > seen; });
        client.send(get(server.url("/")), stopper.source.get_token());
    }
    // The server's side of each connection is done before its descriptors are
    // counted as gone.
    for (int i = 0; i < 200 && closed.load() < times; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    server.stop();
}

} // namespace

TEST_F(CancelTest, CancelledRequestsDoNotLeakDescriptors) {
    if (open_fds() < 0) GTEST_SKIP() << "no /proc/self/fd or /dev/fd";

    cancel_stuck_requests(1);   // anything the first request opens and keeps
    const int before = open_fds();
    cancel_stuck_requests(20);
    EXPECT_EQ(open_fds(), before);
}

// A redirect whose body is still arriving when the stop comes has to be reported
// as it is, not followed: the next request would be one the caller abandoned.
TEST_F(CancelTest, ARedirectIsNotFollowedOnceTheRequestIsCancelled) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 100\r\n\r\npartial");
        conn.park();
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    Stopper stopper(std::chrono::milliseconds(100), [&] { return server.requests() >= 1; });
    auto res = client.send(get(server.url("/")), stopper.source.get_token());

    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.statusCode, 302);
    EXPECT_EQ(res.bodyError, "cancelled");
    EXPECT_EQ(server.requests(), 1);
}

// Connecting is a wait too, and nothing may be sent to an address once the stop
// has been asked for. The listener only has to exist: the kernel completes the
// connection for it, so an attempt shows as an accept.
TEST_F(CancelTest, AConnectAfterTheStopSendsNoSyn) {
    tls_test::Server server([](tls_test::Conn&, int) { return false; });
    ASSERT_FALSE(server.failed());

    std::stop_source source;
    source.request_stop();
    https::Socket sock;
    sock.set_stop(source.get_token());

    EXPECT_FALSE(sock.connect("127.0.0.1", server.port(), 4000));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(server.accepts(), 0);
}

// ── through a proxy ──────────────────────────────────────────────────────────

namespace {

https::HttpClientConfig proxied_config(const std::string& proxyUrl) {
    auto cfg = test_config();
    cfg.proxy = proxyUrl;
    return cfg;
}

// Holds a connection for up to 5 s or until `done`, so a test whose cancellation
// fails sees the connection dropped (and an assertion fail) rather than a hang.
void hold(const std::atomic<bool>& done) {
    for (int i = 0; i < 500 && !done.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

} // namespace

TEST_F(CancelTest, AProxyThatNeverAnswersConnectIsAbandoned) {
    std::atomic<bool> sawConnect { false };
    std::atomic<bool> done { false };
    proxy_test::Server proxy([&](proxy_test::Peer& peer) {
        peer.read_head();
        sawConnect = true;
        hold(done);
    });
    ASSERT_FALSE(proxy.failed());

    https::HttpClient client(proxied_config("http://127.0.0.1:" + std::to_string(proxy.port())));
    Stopper stopper(std::chrono::milliseconds(100), [&] { return sawConnect.load(); });
    auto res = client.send(get("https://127.0.0.1:9/"), stopper.source.get_token());
    const auto returned = Clock::now();
    done = true;

    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.statusCode, 0);
    EXPECT_EQ(res.statusText, "Cancelled");
    EXPECT_LT(stopper.since_stop_ms(returned), kPromptMs);
}

TEST_F(CancelTest, AnHttpsProxyThatNeverCompletesItsHandshakeIsAbandoned) {
    std::atomic<bool> sawHello { false };
    std::atomic<bool> done { false };
    proxy_test::Server proxy([&](proxy_test::Peer& peer) {
        peer.read_some();
        sawHello = true;
        hold(done);
    });
    ASSERT_FALSE(proxy.failed());

    https::HttpClient client(proxied_config("https://127.0.0.1:" + std::to_string(proxy.port())));
    Stopper stopper(std::chrono::milliseconds(100), [&] { return sawHello.load(); });
    auto res = client.send(get("https://127.0.0.1:9/"), stopper.source.get_token());
    const auto returned = Clock::now();
    done = true;

    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.statusCode, 0);
    EXPECT_LT(stopper.since_stop_ms(returned), kPromptMs);
}

// The session to the target runs inside the one to the proxy, and the stop has
// to reach the proxy's session for the inner handshake to be interruptible.
TEST_F(CancelTest, AHandshakeInsideAnHttpsProxyTunnelIsAbandoned) {
    std::atomic<bool> tunnelOpen { false };
    tls_test::Server proxy([&](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 Connection established\r\n\r\n");
        tunnelOpen = true;
        conn.wait_peer_close(std::chrono::seconds(5));
        return false;
    });
    ASSERT_FALSE(proxy.failed());

    https::HttpClient client(proxied_config("https://127.0.0.1:" + std::to_string(proxy.port())));
    Stopper stopper(std::chrono::milliseconds(200), [&] { return tunnelOpen.load(); });
    auto res = client.send(get("https://127.0.0.1:9/"), stopper.source.get_token());
    const auto returned = Clock::now();

    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.statusCode, 0);
    EXPECT_LT(stopper.since_stop_ms(returned), kPromptMs);
}

// ── a reused connection carries the current call's token ─────────────────────
//
// The token is set on a connection for one call and taken off when it goes back
// to the pool. Through an https:// proxy the waits happen in the session beneath
// the one the pool holds, and it was that session's token, set by the call that
// opened the tunnel, that every later call waited on.

namespace {

enum class Route { Direct, HttpProxy, HttpsProxy };

std::string route_name(const ::testing::TestParamInfo<Route>& info) {
    switch (info.param) {
        case Route::Direct:     return "Direct";
        case Route::HttpProxy:  return "HttpProxy";
        case Route::HttpsProxy: return "HttpsProxy";
    }
    return "Unknown";
}

// The proxy in front of a target, when the route has one, and the client
// configuration that reaches the target through it.
class Path {
public:
    Path(Route route, int targetPort) {
        if (route == Route::HttpProxy) {
            http_ = std::make_unique<proxy_test::Server>([targetPort](proxy_test::Peer& peer) {
                if (peer.read_head().empty()) return;
                peer.write("HTTP/1.1 200 Connection established\r\n\r\n");
                peer.relay_to(targetPort);
            });
        } else if (route == Route::HttpsProxy) {
            https_ = std::make_unique<tls_test::Server>([targetPort](tls_test::Conn& conn, int) {
                conn.write("HTTP/1.1 200 Connection established\r\n\r\n");
                conn.relay_to(targetPort);
                return false;
            });
        }
    }

    [[nodiscard]] bool failed() const {
        return (http_ && http_->failed()) || (https_ && https_->failed());
    }

    [[nodiscard]] https::HttpClientConfig config() const {
        auto cfg = test_config();
        if (http_)  cfg.proxy = "http://127.0.0.1:" + std::to_string(http_->port());
        if (https_) cfg.proxy = "https://127.0.0.1:" + std::to_string(https_->port());
        return cfg;
    }

    // Connections the proxy accepted; the target's count when there is none.
    [[nodiscard]] int proxy_accepts(const tls_test::Server& target) const {
        if (http_)  return http_->accepts();
        if (https_) return https_->accepts();
        return target.accepts();
    }

private:
    std::unique_ptr<proxy_test::Server> http_;
    std::unique_ptr<tls_test::Server> https_;
};

https::HttpRequest post(const std::string& url) {
    https::HttpRequest req;
    req.method = https::Method::POST;
    req.url = url;
    req.body = "{}";
    return req;
}

class ReuseTest : public CancelTest, public ::testing::WithParamInterface<Route> {};

} // namespace

// THE README'S OWN PATTERN. A jthread requests a stop in its destructor, after
// the call it ran has returned and its connection is back in the pool. That stop
// must not reach the next call: through an https:// proxy it made every wait on
// the tunnel fail at once, and the stale-connection retry then sent a POST the
// target had already received a second time.
TEST_P(ReuseTest, AStopAfterTheCallReturnedDoesNotReachTheNextCall) {
    tls_test::Server target([](tls_test::Conn& conn, int) {
        conn.write(tls_test::ok_response("done"));
        return true;
    });
    ASSERT_FALSE(target.failed());
    Path path(GetParam(), target.port());
    ASSERT_FALSE(path.failed());

    https::HttpClient client(path.config());
    {
        std::atomic<bool> returned { false };
        std::jthread worker([&](std::stop_token stop) {
            auto first = client.send(post(target.url("/first")), stop);
            EXPECT_EQ(first.statusCode, 200) << first.statusText;
            EXPECT_FALSE(first.cancelled);
            returned = true;
        });
        while (!returned.load()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }   // ~jthread: request_stop(), then join

    auto second = client.send(post(target.url("/second")));
    EXPECT_EQ(second.statusCode, 200) << second.statusText;
    EXPECT_FALSE(second.cancelled);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(target.requests(), 2) << "the second POST reached the target more than once";
    EXPECT_EQ(target.accepts(), 1) << "the pooled connection was not reused";
    EXPECT_EQ(path.proxy_accepts(target), 1);
}

// The other half: the second call's own token has to reach the connection it
// reuses, whatever the first call's token is doing.
TEST_P(ReuseTest, TheSecondCallsTokenReachesTheReusedConnection) {
    tls_test::Server target([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write(tls_test::ok_response("first"));
            return true;
        }
        conn.wait_peer_close();
        return false;
    });
    ASSERT_FALSE(target.failed());
    Path path(GetParam(), target.port());
    ASSERT_FALSE(path.failed());

    https::HttpClient client(path.config());
    std::stop_source first;   // never stopped, and alive throughout
    EXPECT_EQ(client.send(get(target.url("/a")), first.get_token()).statusCode, 200);

    Stopper stopper(std::chrono::milliseconds(100), [&] { return target.requests() >= 2; });
    auto res = client.send(get(target.url("/b")), stopper.source.get_token());
    const auto returned = Clock::now();

    EXPECT_TRUE(res.cancelled) << res.statusText;
    EXPECT_LT(stopper.since_stop_ms(returned), kPromptMs);
    EXPECT_EQ(target.accepts(), 1) << "the second call did not reuse the connection";
}

INSTANTIATE_TEST_SUITE_P(Routes, ReuseTest,
                         ::testing::Values(Route::Direct, Route::HttpProxy, Route::HttpsProxy),
                         route_name);

TEST_F(CancelTest, ASocks5ProxyThatNeverAnswersTheGreetingIsAbandoned) {
    std::atomic<bool> sawGreeting { false };
    std::atomic<bool> done { false };
    proxy_test::Server proxy([&](proxy_test::Peer& peer) {
        peer.read_some();
        sawGreeting = true;
        hold(done);
    });
    ASSERT_FALSE(proxy.failed());

    https::HttpClient client(proxied_config("socks5://127.0.0.1:" + std::to_string(proxy.port())));
    Stopper stopper(std::chrono::milliseconds(100), [&] { return sawGreeting.load(); });
    auto res = client.send(get("https://127.0.0.1:9/"), stopper.source.get_token());
    const auto returned = Clock::now();
    done = true;

    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.statusCode, 0);
    EXPECT_LT(stopper.since_stop_ms(returned), kPromptMs);
}

// ── download_to_file ─────────────────────────────────────────────────────────

namespace {

std::filesystem::path scratch_file(std::string_view name) {
    auto path = std::filesystem::temp_directory_path()
              / ("tinyhttps-cancel-" + std::string(name));
    std::error_code ec;
    std::filesystem::remove(path, ec);
    return path;
}

} // namespace

TEST_F(CancelTest, ADownloadWaitingForTheHeadersIsAbandoned) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.wait_peer_close();
        return false;
    });
    ASSERT_FALSE(server.failed());

    const auto file = scratch_file("head");
    https::HttpClient client(test_config());
    Stopper stopper(std::chrono::milliseconds(100), [&] { return server.requests() >= 1; });
    auto res = client.download_to_file(server.url("/file"), file, nullptr, nullptr,
                                       stopper.source.get_token());
    const auto returned = Clock::now();

    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.statusCode, 0);
    EXPECT_EQ(res.error, "Cancelled");
    EXPECT_FALSE(res.ok());
    EXPECT_FALSE(std::filesystem::exists(file)) << "no file before a status line";
    EXPECT_LT(stopper.since_stop_ms(returned), kPromptMs);
}

TEST_F(CancelTest, ADownloadWaitingForTheRestOfTheBodyIsAbandoned) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n");
        conn.write(std::string(1000, 'x'));
        conn.wait_peer_close();
        return false;
    });
    ASSERT_FALSE(server.failed());

    const auto file = scratch_file("body");
    std::atomic<std::int64_t> written { 0 };
    https::HttpClient client(test_config());
    Stopper stopper(std::chrono::milliseconds(100), [&] { return written.load() >= 1000; });
    auto res = client.download_to_file(server.url("/file"), file,
                                       [&](std::int64_t, std::int64_t now) { written = now; },
                                       nullptr, stopper.source.get_token());
    const auto returned = Clock::now();

    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.statusCode, 200);
    EXPECT_EQ(res.error, "cancelled");
    EXPECT_FALSE(res.writeFailed);
    EXPECT_EQ(res.bytesWritten, 1000);
    EXPECT_LT(stopper.since_stop_ms(returned), kPromptMs);

    std::error_code ec;
    std::filesystem::remove(file, ec);
}

TEST_F(CancelTest, ADownloadWithATokenAlreadyStoppedSendsNothing) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write(tls_test::ok_response("never"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    std::stop_source source;
    source.request_stop();
    https::HttpClient client(test_config());
    auto res = client.download_to_file(server.url("/file"), scratch_file("none"),
                                       nullptr, nullptr, source.get_token());

    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.error, "Cancelled");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(server.accepts(), 0);
}

// `isCancelled` and the token are two ways to say the same thing, and the result
// says it the same way for both.
TEST_F(CancelTest, IsCancelledSetsCancelledAsTheTokenDoes) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n");
        conn.write(std::string(1000, 'x'));
        conn.wait_peer_close();
        return false;
    });
    ASSERT_FALSE(server.failed());

    const auto file = scratch_file("predicate");
    https::HttpClient client(test_config());
    auto res = client.download_to_file(server.url("/file"), file, nullptr,
                                       [] { return true; });

    EXPECT_TRUE(res.cancelled);
    EXPECT_EQ(res.error, "cancelled");
    EXPECT_EQ(res.statusCode, 200);

    std::error_code ec;
    std::filesystem::remove(file, ec);
}
