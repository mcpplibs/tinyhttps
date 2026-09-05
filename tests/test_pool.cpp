// What the connection pool does with a response that went wrong.
//
// `tests/` had no keep-alive coverage at all, which is the direct reason the
// regression `#14` introduced (a `Content-Length` branch in `send_stream` that
// stopped marking the connection unusable) went in green. Every test here scripts
// a server, makes two requests through one `HttpClient`, and asserts BOTH what
// the second request received AND **how many TCP connections the server saw**.
//
// The connection count is the assertion that matters. Issue #15's own report
// contains a case whose output is byte-for-byte identical to a correct client's;
// the only observable difference was that the server logged one connection where
// it should have logged two.
#include <gtest/gtest.h>
#include "tls_test_server.hpp"

#ifndef _WIN32
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

import mcpplibs.tinyhttps;
import std;

namespace https = mcpplibs::tinyhttps;

namespace {

https::HttpClientConfig test_config(int readTimeoutMs = 700) {
    https::HttpClientConfig cfg;
    cfg.verifySsl = false;          // the test certificate authenticates nothing
    cfg.connectTimeoutMs = 4000;
    cfg.readTimeoutMs = readTimeoutMs;
    cfg.keepAlive = true;           // the configuration under test
    return cfg;
}

https::HttpRequest get(const std::string& url) {
    https::HttpRequest req;
    req.method = https::Method::GET;
    req.url = url;
    return req;
}

class PoolTest : public ::testing::Test {
protected:
    void SetUp() override { https::Socket::platform_init(); }
};

} // namespace

// ── issue #15 · a declared length that stops halfway ─────────────────────────

// The first response promises 100 bytes, delivers 50, and sends the rest AFTER
// the client has given up on it — which is what a server that is merely slow
// does. The read times out with 50 bytes still owed, and those 50 bytes then
// arrive on a socket nobody is reading.
//
// ⚠️ THE LATE SECOND HALF IS WHAT MAKES THIS A TEST. An earlier form of this
// server stalled and never sent the rest; the connection was then silent rather
// than dirty, and the stale-connection retry rescued the second request whether
// or not the pool guard worked. Verified by mutation: with the guard's
// destructor emptied, that form still passed and this one fails.
TEST_F(PoolTest, AShortContentLengthBodyDoesNotPoisonTheNextRequest) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
            conn.write(std::string(50, 'B'));
            std::this_thread::sleep_for(std::chrono::milliseconds(1300));
            conn.write(std::string(50, 'B'));   // arrives after the read timeout
            return true;
        }
        conn.write(tls_test::ok_response("second"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());

    auto first = client.send(get(server.url("/one")));
    EXPECT_EQ(first.statusCode, 200);
    EXPECT_EQ(first.body, std::string(50, 'B'));
    EXPECT_FALSE(first.bodyComplete)
        << "50 of 100 bytes arrived; the caller has no other way to learn that";
    EXPECT_FALSE(first.bodyError.empty());

    auto second = client.send(get(server.url("/two")));
    EXPECT_EQ(second.statusCode, 200) << "status text was: " << second.statusText;
    EXPECT_EQ(second.body, "second");
    EXPECT_TRUE(second.bodyComplete);

    // THE ASSERTION THE BYTES CANNOT MAKE.
    EXPECT_EQ(server.accepts(), 2)
        << "the truncated connection was reused instead of being dropped";
}

TEST_F(PoolTest, AChunkedBodyThatStopsMidChunkDoesNotPoisonTheNextRequest) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            conn.write("10\r\n");          // 16 bytes announced
            conn.write("0123456");         // 7 delivered now
            std::this_thread::sleep_for(std::chrono::milliseconds(1300));
            conn.write("789abcdef\r\n0\r\n\r\n");   // the rest, too late
            return true;
        }
        conn.write(tls_test::ok_response("second"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());

    auto first = client.send(get(server.url("/one")));
    EXPECT_EQ(first.statusCode, 200);
    EXPECT_FALSE(first.bodyComplete);

    auto second = client.send(get(server.url("/two")));
    EXPECT_EQ(second.statusCode, 200) << "status text was: " << second.statusText;
    EXPECT_EQ(second.body, "second");
    EXPECT_EQ(server.accepts(), 2);
}

// A chunk header that does not parse is not a terminal chunk. `parse_hex`
// returned 0 for `zz` — the same value a real `0\r\n` gives — so the reader
// declared the body finished and returned the socket with the rest still on it.
TEST_F(PoolTest, AnUnparsableChunkHeaderIsAnErrorAndNotAnEndOfBody) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            conn.write("4\r\nabcd\r\n");
            conn.write("zz\r\n");
            // Whatever follows a header the client could not parse is still on
            // the wire, and a reused connection would read it as a status line.
            conn.write("4\r\nefgh\r\n0\r\n\r\n");
            return true;
        }
        conn.write(tls_test::ok_response("second"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());

    auto first = client.send(get(server.url("/one")));
    EXPECT_EQ(first.statusCode, 200);
    EXPECT_EQ(first.body, "abcd");
    EXPECT_FALSE(first.bodyComplete) << "`zz` was accepted as a terminal chunk";
    EXPECT_NE(first.bodyError.find("zz"), std::string::npos);
    // The server's real reason phrase survives; it used to be overwritten with
    // the parse error, so a caller logging statusText on a 200 saw the error.
    EXPECT_EQ(first.statusText, "OK");

    auto second = client.send(get(server.url("/two")));
    EXPECT_EQ(second.statusCode, 200);
    EXPECT_EQ(server.accepts(), 2);
}

// A `Content-Length` past the width of an `int`. This was the one pool defect a
// server could trigger with a single header and no timing at all: the value was
// assigned to an `int`, 2^32 truncated to 0, the reader took that for an empty
// body and returned a socket with four gigabytes owed on it.
TEST_F(PoolTest, AContentLengthPastThirtyTwoBitsIsNotSilentlyZero) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 200 OK\r\nContent-Length: 4294967296\r\n\r\n");
            conn.write("0123456789");
            std::this_thread::sleep_for(std::chrono::milliseconds(1300));
            conn.write("late-and-unread");   // still owed, and still arriving
            return true;
        }
        conn.write(tls_test::ok_response("second"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    // The size cap is lifted here on purpose. With the default 64 MiB it would
    // refuse this response before reading a byte — correct, and a different
    // mechanism from the one under test. Lifting it puts the reader back on the
    // path where the truncation used to happen, so what this test observes is
    // the width of the field and nothing else.
    // (`ABodyLargerThanTheConfiguredLimitIsRefused` covers the cap.)
    auto cfg = test_config();
    cfg.maxResponseBodyBytes = std::numeric_limits<std::int64_t>::max();
    https::HttpClient client(cfg);

    auto first = client.send(get(server.url("/one")));
    EXPECT_EQ(first.statusCode, 200);
    EXPECT_EQ(first.body, "0123456789")
        << "the length truncated to zero, so the reader took the body for empty";
    EXPECT_FALSE(first.bodyComplete);

    auto second = client.send(get(server.url("/two")));
    EXPECT_EQ(second.statusCode, 200) << "status text was: " << second.statusText;
    EXPECT_EQ(second.body, "second");
    EXPECT_EQ(server.accepts(), 2);
}

// Leftover bytes must not be readable as a status line. This is the exact input
// from issue #15, where `BBBB…` produced `statusCode = 999`: the parser took the
// first run of digits it found and never checked that the line began with
// `HTTP/`.
TEST_F(PoolTest, AStatusLineThatIsNotOneIsRejectedRatherThanMined) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("BBBB 999 XHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    auto response = client.send(get(server.url("/")));
    EXPECT_EQ(response.statusCode, 0) << "a body fragment was read as a status code";
    EXPECT_EQ(response.statusText, "Invalid status line");
}

// ── the other half: a clean connection must still be reused ──────────────────
//
// Without this, "drop everything, always" would pass every test above. The two
// assertions are a pair.
TEST_F(PoolTest, TwoCleanRequestsShareOneConnection) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        conn.write(tls_test::ok_response(index == 0 ? "first" : "second"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());

    auto first = client.send(get(server.url("/one")));
    EXPECT_EQ(first.body, "first");
    EXPECT_TRUE(first.bodyComplete);

    auto second = client.send(get(server.url("/two")));
    EXPECT_EQ(second.body, "second");
    EXPECT_TRUE(second.bodyComplete);

    EXPECT_EQ(server.accepts(), 1) << "keep-alive stopped reusing connections";
}

TEST_F(PoolTest, KeepAliveOffDoesNotLeaveAConnectionInThePool) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        conn.write(tls_test::ok_response(index == 0 ? "first" : "second"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    auto cfg = test_config();
    cfg.keepAlive = false;
    https::HttpClient client(cfg);

    EXPECT_EQ(client.send(get(server.url("/one"))).body, "first");
    EXPECT_EQ(client.send(get(server.url("/two"))).body, "second");
    // The request said `Connection: close`; a server that answers without
    // echoing it used to leave the socket pooled anyway.
    EXPECT_EQ(server.accepts(), 2);
}

// ── redirects and error bodies: the paths with no timeout and no truncation ──

// A 302 that carries a body — which is what nearly every server sends — and
// keep-alive. The code here promised in a comment to "drain any body to keep
// connection clean" and drained nothing, so the recursive call below picked up a
// socket with the redirect's own HTML still on it.
TEST_F(PoolTest, ARedirectBodyIsConsumedBeforeTheConnectionIsReused) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 302 Found\r\nLocation: /final\r\n"
                       "Content-Length: 27\r\n\r\n"
                       "<html>moved, see you</html>");   // 27 bytes exactly
            return true;
        }
        conn.write(tls_test::ok_response("REDIRECTED-CONTENT"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    auto response = client.send(get(server.url("/start")));

    EXPECT_EQ(response.statusCode, 200) << "status text was: " << response.statusText;
    EXPECT_EQ(response.body, "REDIRECTED-CONTENT")
        << "the redirect's own body was read as the final response";
    EXPECT_TRUE(response.bodyComplete);
}

TEST_F(PoolTest, ARedirectedDownloadReusesTheConnectionAfterDrainingTheBody) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 302 Found\r\nLocation: /final\r\n"
                       "Content-Length: 12\r\n\r\n"
                       "moved-along\n");
            return true;
        }
        conn.write(tls_test::ok_response("REDIRECTED-FILE"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    auto dir = std::filesystem::temp_directory_path() / "tinyhttps_pool_test";
    std::filesystem::create_directories(dir);
    auto dest = dir / "redirected.bin";

    https::HttpClient client(test_config());
    auto result = client.download_to_file(server.url("/start"), dest);

    ASSERT_TRUE(result.ok()) << "error: " << result.error;
    std::ifstream in(dest, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    EXPECT_EQ(content, "REDIRECTED-FILE");

    // A short 3xx body is drained rather than thrown away with the connection,
    // so the redirect costs no second handshake. Correctness above does not
    // depend on this number; reuse does.
    EXPECT_EQ(server.accepts(), 1);

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// A 404's body is never handed to the caller of download_to_file, and used to be
// left on the socket for whatever asked next.
TEST_F(PoolTest, AnErrorBodyIsConsumedBeforeTheConnectionIsReused) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\n"
                       "not found");
            return true;
        }
        conn.write(tls_test::ok_response("after-404"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    auto dir = std::filesystem::temp_directory_path() / "tinyhttps_pool_404";
    std::filesystem::create_directories(dir);

    https::HttpClient client(test_config());
    auto failed = client.download_to_file(server.url("/missing"), dir / "x.bin");
    EXPECT_FALSE(failed.ok());
    EXPECT_EQ(failed.statusCode, 404);
    EXPECT_EQ(failed.error, "HTTP 404");

    auto next = client.send(get(server.url("/present")));
    EXPECT_EQ(next.statusCode, 200) << "status text was: " << next.statusText;
    EXPECT_EQ(next.body, "after-404")
        << "the 404's body was read as the next response";
    EXPECT_EQ(server.accepts(), 1);

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// ── a pooled connection the server has since closed ──────────────────────────

// The scenario issue #15 mentions in passing and that none of the fixes above
// address: the server closes an idle keep-alive connection, which is routine.
// The client cannot see that until it writes, and the write succeeds into a
// local buffer. Without a retry the caller gets `statusCode = 0` /
// "No response" for a request the server never saw.
TEST_F(PoolTest, AConnectionClosedWhileIdleIsRetriedRatherThanReported) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        conn.write(tls_test::ok_response(index == 0 ? "first" : "second"));
        return false;   // answer, then close — as an idle-timeout would
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());

    auto first = client.send(get(server.url("/one")));
    EXPECT_EQ(first.statusCode, 200);
    EXPECT_EQ(first.body, "first");

    // Let the close reach us, so the pooled socket is genuinely dead.
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    auto second = client.send(get(server.url("/two")));
    EXPECT_EQ(second.statusCode, 200)
        << "status text was: " << second.statusText
        << " — a dead pooled connection was reported instead of replaced";
    EXPECT_EQ(second.body, "second");
    EXPECT_EQ(server.accepts(), 2);
}

// THE OTHER HALF OF THE RETRY, AND THE ONE THAT KEEPS IT SAFE.
//
// The window closes the moment a byte arrives: past that the server has seen the
// request, and sending it again could repeat whatever it did. Here the server
// answers with a status line it never finishes and then closes — a failure, but
// one that must NOT be retried.
TEST_F(PoolTest, ARequestTheServerHasBegunAnsweringIsNotResent) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200");   // a head that never completes
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    auto response = client.send(get(server.url("/once")));

    EXPECT_EQ(response.statusCode, 0);
    EXPECT_EQ(server.requests(), 1)
        << "a request the server had begun answering was sent a second time";
    EXPECT_EQ(server.accepts(), 1);
}

TEST_F(PoolTest, TheRetryCanBeTurnedOff) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        conn.write(tls_test::ok_response(index == 0 ? "first" : "second"));
        return false;
    });
    ASSERT_FALSE(server.failed());

    auto cfg = test_config();
    cfg.retryOnStaleConnection = false;
    https::HttpClient client(cfg);

    EXPECT_EQ(client.send(get(server.url("/one"))).statusCode, 200);
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    auto second = client.send(get(server.url("/two")));
    EXPECT_EQ(second.statusCode, 0)
        << "opting out of the retry must actually opt out";
}

// ── streaming ────────────────────────────────────────────────────────────────

// The regression `#14` introduced. `send_stream` gained a `Content-Length`
// branch whose two exits — a read timeout and an end of stream — left the
// connection marked reusable, which the branch they replaced never did.
TEST_F(PoolTest, AStreamCutShortDoesNotPoisonTheNextRequest) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                       "Content-Length: 200\r\n\r\n");
            conn.write("data: one\n\n");
            conn.park();
            return false;
        }
        conn.write(tls_test::ok_response("second"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());

    int events = 0;
    auto first = client.send_stream(get(server.url("/stream")),
                                    [&](const https::SseEvent&) { ++events; return true; });
    EXPECT_EQ(first.statusCode, 200);
    EXPECT_EQ(events, 1);
    EXPECT_FALSE(first.bodyComplete);

    auto second = client.send(get(server.url("/two")));
    EXPECT_EQ(second.statusCode, 200) << "status text was: " << second.statusText;
    EXPECT_EQ(second.body, "second");
    EXPECT_EQ(server.accepts(), 2);
}

// A callback that stops early leaves bytes owed, so the connection cannot be
// reused either — but it is not an error, and the status line is untouched.
TEST_F(PoolTest, AStreamStoppedByItsCallbackReleasesTheConnection) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            for (int i = 0; i < 20; ++i) conn.write("9\r\ndata: x\n\n\r\n");
            conn.park();
            return false;
        }
        conn.write(tls_test::ok_response("second"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());

    int events = 0;
    auto first = client.send_stream(get(server.url("/stream")),
                                    [&](const https::SseEvent&) { ++events; return false; });
    EXPECT_EQ(first.statusCode, 200);
    EXPECT_EQ(first.statusText, "OK");
    EXPECT_EQ(events, 1);
    EXPECT_FALSE(first.bodyComplete);

    auto second = client.send(get(server.url("/two")));
    EXPECT_EQ(second.statusCode, 200) << "status text was: " << second.statusText;
    EXPECT_EQ(server.accepts(), 2);
}

// ── allocation bounded by configuration rather than by a header ──────────────

TEST_F(PoolTest, ABodyLargerThanTheConfiguredLimitIsRefused) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n");
        conn.park();
        return false;
    });
    ASSERT_FALSE(server.failed());

    auto cfg = test_config();
    cfg.maxResponseBodyBytes = 1024;
    https::HttpClient client(cfg);

    auto response = client.send(get(server.url("/big")));
    EXPECT_EQ(response.statusCode, 200);
    EXPECT_TRUE(response.body.empty()) << "refused before reading, not after";
    EXPECT_FALSE(response.bodyComplete);
    EXPECT_NE(response.bodyError.find("limit"), std::string::npos);
}

// ── a body a HEAD response does not have ─────────────────────────────────────

TEST_F(PoolTest, AHeadResponseDoesNotConsumeTheDeclaredLength) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            // A HEAD answer carries the length a GET would have returned, and
            // no body. Reading it would consume the next response instead.
            conn.write("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n");
            return true;
        }
        conn.write(tls_test::ok_response("after-head"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());

    https::HttpRequest head;
    head.method = https::Method::HEAD;
    head.url = server.url("/thing");
    auto headResponse = client.send(head);
    EXPECT_EQ(headResponse.statusCode, 200);
    EXPECT_TRUE(headResponse.body.empty());
    EXPECT_TRUE(headResponse.bodyComplete);

    auto next = client.send(get(server.url("/thing")));
    EXPECT_EQ(next.body, "after-head");
    EXPECT_EQ(server.accepts(), 1);
}

TEST_F(PoolTest, A204CarriesNoBodyWhateverItsHeadersSay) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 204 No Content\r\nContent-Length: 42\r\n\r\n");
            return true;
        }
        conn.write(tls_test::ok_response("after-204"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    auto empty = client.send(get(server.url("/nothing")));
    EXPECT_EQ(empty.statusCode, 204);
    EXPECT_TRUE(empty.body.empty());
    EXPECT_TRUE(empty.bodyComplete);

    EXPECT_EQ(client.send(get(server.url("/next"))).body, "after-204");
    EXPECT_EQ(server.accepts(), 1);
}

// ── a body whose framing is the close, ended the way servers actually end it ─

// No Content-Length and no chunked encoding: the body ends when the connection
// does (RFC 9112 §6.3). The server then closes WITHOUT a TLS `close_notify`,
// which is what most servers do.
//
// The BIO under this client used to answer that FIN with
// MBEDTLS_ERR_NET_CONN_RESET — mbedtls's own BIO passes the zero through, and
// `ssl_fetch_input` tests for exactly that zero to produce SSL_CONN_EOF — so an
// orderly end of stream reached the reader as an error and a complete body read
// as truncated.
TEST_F(PoolTest, ABodyDelimitedByTheCloseIsCompleteWithoutACloseNotify) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
        conn.write("connection-delimited-body");
        conn.close_hard();
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    auto response = client.send(get(server.url("/")));

    EXPECT_EQ(response.statusCode, 200);
    EXPECT_EQ(response.body, "connection-delimited-body");
    EXPECT_TRUE(response.bodyComplete) << "bodyError was: " << response.bodyError;
    EXPECT_TRUE(response.bodyError.empty());
}

// The same framing through `download_to_file`, where mistaking the close for an
// error is worse than cosmetic: it sets `result.error`, and `ok()` consults it.
TEST_F(PoolTest, ADownloadDelimitedByTheCloseReportsSuccess) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n");
        conn.write("0123456789abcdef");
        conn.close_hard();
        return false;
    });
    ASSERT_FALSE(server.failed());

    auto dir = std::filesystem::temp_directory_path() / "tinyhttps_pool_close";
    std::filesystem::create_directories(dir);
    auto dest = dir / "closed.bin";

    https::HttpClient client(test_config());
    auto result = client.download_to_file(server.url("/blob"), dest);

    EXPECT_TRUE(result.ok())
        << "a file that arrived complete was reported as failed: " << result.error;
    EXPECT_EQ(result.bytesWritten, 16);
    EXPECT_EQ(std::filesystem::file_size(dest), 16u);

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// ── interim responses ────────────────────────────────────────────────────────

// A 1xx is not the answer. RFC 9112 §2.1 requires a client to read past one or
// more of them; stopping at one reports `103 Early Hints` as the result AND —
// because a 1xx carries no body — marks the connection clean while the real
// response is still sitting on it, for the next request to read as its own.
TEST_F(PoolTest, AnInterimResponseIsNotMistakenForTheAnswer) {
    tls_test::Server server([](tls_test::Conn& conn, int index) {
        if (index == 0) {
            conn.write("HTTP/1.1 103 Early Hints\r\n"
                       "Link: </style.css>; rel=preload\r\n\r\n");
            conn.write(tls_test::ok_response("the-real-answer"));
            return true;
        }
        conn.write(tls_test::ok_response("second"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());

    auto first = client.send(get(server.url("/one")));
    EXPECT_EQ(first.statusCode, 200) << "statusText was: " << first.statusText;
    EXPECT_EQ(first.body, "the-real-answer");
    EXPECT_TRUE(first.bodyComplete);
    // The interim response's fields describe the interim response, not this one.
    EXPECT_EQ(first.headers.count("Link"), 0u);

    auto second = client.send(get(server.url("/two")));
    EXPECT_EQ(second.statusCode, 200) << "statusText was: " << second.statusText;
    EXPECT_EQ(second.body, "second")
        << "the real response was left on the socket and read by the next request";
    EXPECT_EQ(server.accepts(), 1);
}

// More than one, which the grammar allows and the loop has to survive. A
// `100 Continue` is what any server sends for a request carrying
// `Expect: 100-continue`, so a caller can provoke this with one header.
TEST_F(PoolTest, SeveralInterimResponsesInARowAreAllSkipped) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 100 Continue\r\n\r\n");
        conn.write("HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n");
        conn.write("HTTP/1.1 103 Early Hints\r\nLink: </b.css>; rel=preload\r\n\r\n");
        conn.write(tls_test::ok_response("finally"));
        return true;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    auto response = client.send(get(server.url("/")));
    EXPECT_EQ(response.statusCode, 200) << "statusText was: " << response.statusText;
    EXPECT_EQ(response.body, "finally");
    EXPECT_TRUE(response.bodyComplete);
}

// ── how many lines, which is a different bound from how long each one is ─────

// A header block is accumulated into a map, so an endless supply of short,
// well-formed header lines grows the client's memory without limit — and every
// line resets the read timeout, so nothing else stops it.
TEST_F(PoolTest, AnEndlessHeaderBlockIsRefusedRatherThanAccumulated) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 OK\r\n");
        for (int i = 0; i < 400; ++i) {
            conn.write("X-Filler-" + std::to_string(i) + ": aaaaaaaaaaaaaaaa\r\n");
        }
        conn.write("\r\n");
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    auto response = client.send(get(server.url("/")));
    EXPECT_EQ(response.statusCode, 0);
    EXPECT_NE(response.statusText.find("Header block"), std::string::npos)
        << "statusText was: " << response.statusText;
}

// The trailer section is discarded rather than kept, so it costs no memory —
// but an endless supply of trailers holds the call open just as long.
TEST_F(PoolTest, AnEndlessTrailerSectionIsRefused) {
    tls_test::Server server([](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        conn.write("4\r\nabcd\r\n");
        conn.write("0\r\n");
        for (int i = 0; i < 400; ++i) {
            conn.write("X-Trailer-" + std::to_string(i) + ": v\r\n");
        }
        conn.write("\r\n");
        return false;
    });
    ASSERT_FALSE(server.failed());

    https::HttpClient client(test_config());
    auto response = client.send(get(server.url("/")));
    EXPECT_EQ(response.statusCode, 200);
    EXPECT_EQ(response.body, "abcd") << "the body itself was well formed";
    EXPECT_FALSE(response.bodyComplete);
    EXPECT_NE(response.bodyError.find("Trailer"), std::string::npos)
        << "bodyError was: " << response.bodyError;
}

// ── issue #16 · SIGPIPE ──────────────────────────────────────────────────────

#ifndef _WIN32
// THE TEST HAS TO FORK, AND THE REASON IS ITSELF EVIDENCE.
//
// `mbedtls_net_bind` calls `net_prepare`, which does `signal(SIGPIPE, SIG_IGN)`
// (net_sockets.c:114) — so merely having a test server in this binary disarms
// the signal for the whole process, and an in-process check would pass whether
// or not the library was fixed. That process-wide disarming is also precisely
// what tinyhttps loses by replacing mbedtls's network layer with its own BIO,
// which is why issue #16 exists at all.
//
// The child restores the default disposition, connects, and writes to a peer
// that has gone away. Unfixed, it dies with signal 13 and exit status 141 —
// which is what the reporter saw.
TEST(SigPipe, WritingToADepartedPeerReturnsInsteadOfKillingTheProcess) {
    int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listener, 0);
    int reuse = 1;
    ::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof addr), 0);
    ASSERT_EQ(::listen(listener, 4), 0);

    socklen_t len = sizeof addr;
    ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len), 0);
    const int port = ntohs(addr.sin_port);

    const pid_t child = ::fork();
    ASSERT_GE(child, 0);

    if (child == 0) {
        ::close(listener);
        // Undo whatever else in this binary disarmed it. This is the disposition
        // a program that has never thought about SIGPIPE has.
        ::signal(SIGPIPE, SIG_DFL);

        mcpplibs::tinyhttps::Socket sock;
        if (!sock.connect("127.0.0.1", port, 4000)) _exit(3);

        // Give the parent time to accept and slam the connection shut.
        ::usleep(300 * 1000);

        // THE LOOP DOES NOT STOP AT THE FIRST FAILURE, AND THAT IS THE WHOLE
        // POINT. A write to a socket that has just received an RST returns
        // ECONNRESET and raises nothing; it is the write AFTER that one which
        // gets EPIPE, and EPIPE is what SIGPIPE accompanies. A loop that broke
        // on the first non-positive return would exit cleanly whether or not
        // MSG_NOSIGNAL was there — measured: it did.
        const std::string payload(4096, 'x');
        int last = 1;
        for (int i = 0; i < 8; ++i) {
            last = sock.write(payload.data(), static_cast<int>(payload.size()));
            ::usleep(20 * 1000);
        }
        _exit(last <= 0 ? 0 : 4);   // 0 = the write reported failure, as it must
    }

    sockaddr_in peer {};
    socklen_t peerLen = sizeof peer;
    const int accepted = ::accept(listener, reinterpret_cast<sockaddr*>(&peer), &peerLen);
    if (accepted >= 0) {
        // Zero linger turns the close into an RST, so the child's next write
        // meets a connection that is not merely half-closed but gone.
        struct linger lg { 1, 0 };
        ::setsockopt(accepted, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        ::close(accepted);
    }
    ::close(listener);

    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);

    ASSERT_FALSE(WIFSIGNALED(status))
        << "the child was killed by signal " << WTERMSIG(status)
        << " (13 is SIGPIPE, which reaches a shell as exit status 141) — "
           "Socket::write is sending without MSG_NOSIGNAL";
    EXPECT_EQ(WEXITSTATUS(status), 0)
        << "child exit code 3 = could not connect, 4 = the write never failed";
}
#endif // !_WIN32
