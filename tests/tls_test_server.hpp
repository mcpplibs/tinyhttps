// A TLS server, in this process, that answers exactly what a test tells it to.
//
// WHY A TEST SERVER AND NOT AN ENDPOINT ON THE INTERNET. The defects in issue
// #15 are all about what the library does with a connection AFTER a response
// went wrong — a body that stops halfway, a chunk header that does not parse, a
// 302 whose body is never read. No public endpoint produces those on demand,
// and the assertion that matters most is not about a response at all: it is
// **how many TCP connections the server saw**. A socket returned to the pool
// dirty is invisible in the bytes a caller receives (issue #15's own report has
// a case whose output is byte-for-byte correct) and unmissable in the
// connection count.
//
// WHY TLS AND NOT PLAIN HTTP. All three entry points begin with
// `if (parsed.scheme != "https") return "Only HTTPS is supported"`, so a plain
// listener cannot be reached by the code under test at all. mbedtls is already a
// dependency and its server side is compiled in (MBEDTLS_SSL_SRV_C), so the
// server costs a certificate and about two hundred lines.
//
// The certificate below is self-signed and its private key is in this file on
// purpose: it authenticates nothing, exists only for 127.0.0.1, and the tests
// connect with `verifySsl = false`. It is not a secret and must never be used
// for anything.
#pragma once

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace tls_test {

// Self-signed, CN=localhost, valid for a century. See the file comment.
inline constexpr const char* kCertPem = R"PEM(-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIUexXC6epWFGkwN5tQmE6z/veNad0wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkwNTE4NDUxN1oYDzIxMjYw
ODEyMTg0NTE3WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDU5o+tqAgr2GUZc607VbubYhGNStjM2BIcADu8MZeZ
/pyclKaVlCQ5aCF0MyQBZWPBxOPCYblDHjZG0qZ5Hp4cw115yH5di2aa7U9BVQ9C
gPiH1xdX7fNECu8TqTGL7PaKgF2MguWSB05MQy1MrSKBwGf4r03tJkdxCR2wzEUN
Jswo6DrS2NzD61Xzs5djF+pOjNpnc/SpvTZ+axptbenm6UDziCnvCQXBFTsUvJVK
Cdb9ZPNdkoijtEsv625HXeNDvjwW02J5I9JxooSeCkBDMpr406toqMPq+C2sqTMO
kyNUD9LnwFLDkhy5+JcH7MlCGMZChpAUCU+k1hEdgAxfAgMBAAGjbzBtMB0GA1Ud
DgQWBBRqeelsU+P58i5W+sj/fEfOqBJ7hjAfBgNVHSMEGDAWgBRqeelsU+P58i5W
+sj/fEfOqBJ7hjAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQTMBGCCWxvY2FsaG9z
dIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAFwgEVRw4Rqic7iXDSIF6SCofHTLL
7WlUEEgc6yOd6A3Z0KKSgnh1ty/4UwAWxWpcHNCpSI+A6YJaPwM9OJ0z3BOjhRHQ
p/vnAABJhoNBPUESUQyLRRkWMnhrAXaKiGughFkc1+oVqZwEvislcqxswBNxeCiM
kvQ7w1spMHf5bKLxg4hrjK+yj+M9YF8eZEtIQ9uZwV/AgQldt7K/6RMqb1LMcU3d
g47eY4vrNfyNPED6RSR6UwbatLzlotDSHmyQA0fme015Lxv0s511ZUSTvWbEm8rH
8/M9s4fhALVinK2IMktVEgFruo651BCUBNL17ki60uB29BGNhNu5zvprag==
-----END CERTIFICATE-----
)PEM";

inline constexpr const char* kKeyPem = R"PEM(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDU5o+tqAgr2GUZ
c607VbubYhGNStjM2BIcADu8MZeZ/pyclKaVlCQ5aCF0MyQBZWPBxOPCYblDHjZG
0qZ5Hp4cw115yH5di2aa7U9BVQ9CgPiH1xdX7fNECu8TqTGL7PaKgF2MguWSB05M
Qy1MrSKBwGf4r03tJkdxCR2wzEUNJswo6DrS2NzD61Xzs5djF+pOjNpnc/SpvTZ+
axptbenm6UDziCnvCQXBFTsUvJVKCdb9ZPNdkoijtEsv625HXeNDvjwW02J5I9Jx
ooSeCkBDMpr406toqMPq+C2sqTMOkyNUD9LnwFLDkhy5+JcH7MlCGMZChpAUCU+k
1hEdgAxfAgMBAAECggEAPnGZdp+wNdv0WzC4gIy2x+5No5luWTaOqTPQUXRiOMKb
ALoA2iJnNYc7OK+/QcGRLsYm3152Th9QYBlsxl2almkew5dwqNM4NvyfoFPoc+MM
AhuuNxYNoclrMeMQKzBHZ3wa9Bl4aApIhsm1QaYOVuwuEpyoSIRPs/GuiaqAHkjX
3i+GK+kQHZc4p9pWaxRSXjxveLJ43SKpGbr0Wd3RrvcOiVJJxIHylH7CVw49SW8q
Pqp4fTHyIpAi+TaUcwcHPN+KdPSQCeii4qGHdGbAOoO4CBEr6R8mj8Yd0UbhMB9t
EuQkJyF+CUz/kL1wl1SObkxFOtrMQmAk2pnoqcHxcQKBgQDvkUsGSJyI4yNA64D0
FzxI2OAVokFqrgA/OW4fAvGdSvaZcrLO682UCMMYGYwPypOmCoqXTCUa+Z6eXL6P
Wn+KdAGpHigMmHVUxRKoHqqKAfPY2wlwfRPa52GbDomPbB5IXofvrq1Wzez6KLzb
jGnXvWuhDAGW6YVkTSRN2Yj01QKBgQDjgQISUe/hriDiP80EcjRBqy0bAMiBn/TR
mcwGFgv0OFGealCc9AAH9/ahX0fMAhROwbn0Z5bvuM+TLtYRbsDbb7rFksyQauoJ
7FLIkxvIB+zD0u0mg1ceWpl0cm5XwvHDTU6vlcyfY2zr1WHAREeMSh7qJUkUle76
8QB7fErmYwKBgGqj/YaVigCxQz8h1ixRr4cp604WBRKs0/VQ5kEtuUnwVadm1Euh
0chEwjuXG67n2SO/a4P/5ECGv2H1HOqJOV7zVs3mW6OHtir+8tgdloKKbfapQiFt
vAnkl6FDLl7GnRBP7Cj4U7bhQcz1l2QPtAnSCvgMdSStXLCSWkfBPuLlAoGAYPyn
iG3b6QcVx75RRZr2QiSadw+PawtpEE4Tl2igsf2sde927GJs/Pit8L+w2Pzt8WFP
SC09QHc2LtXhts7Tcvkf04iwosShf5d69z0Xs+AFBLqQFUIayrru/qCl/84AyTTU
3a/r6us1DRkLsi6pndofccxxalA88Ef736juOWcCgYEAsD22JvgmQJwNB0VOtPdh
5TEXjnyBsw4DCIkk13ADPm9TqrxBKE4zbF2E7tMrg8McKk09rPGgCrAkZXkAG3Kt
kXIBxmXf9BwXX0U27Owr6xpm75nNan4LZ9CxzXtK9jkLq9peAcphWYu7TRJK8G02
VQKaSq3Gef7/KLR3YARmm5A=
-----END PRIVATE KEY-----
)PEM";

class Server;

// One accepted connection, after its handshake. Handed to the test's handler.
class Conn {
public:
    explicit Conn(Server& server) : server_(server) {}

    // Writes bytes verbatim. A test scripts a response by calling this, so a
    // malformed status line or a body shorter than its Content-Length is as
    // easy to produce as a correct one — which is the point.
    bool write(std::string_view data) {
        std::size_t sent = 0;
        while (sent < data.size()) {
            int ret = mbedtls_ssl_write(
                &ssl_, reinterpret_cast<const unsigned char*>(data.data() + sent),
                data.size() - sent);
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (ret <= 0) return false;
            sent += static_cast<std::size_t>(ret);
        }
        return true;
    }

    // Stops answering while leaving the connection open, which is what a server
    // that stalls mid-body looks like from the client. Returns when the server
    // is stopped or after `limit`.
    void park(std::chrono::milliseconds limit = std::chrono::seconds(20));

    // Ends the connection at the TLS layer, then at the transport.
    void shutdown() {
        if (closed_) return;
        closed_ = true;
        mbedtls_ssl_close_notify(&ssl_);
        mbedtls_net_free(&net_);
    }

    // Ends it at the transport only — a FIN with no `close_notify` first.
    //
    // THIS IS THE COMMON CASE, NOT THE EXOTIC ONE. The two-way TLS shutdown
    // handshake is what the specification asks for and what few servers
    // bother with; most simply close the socket. A client must read that as an
    // end of stream, because for a body whose framing IS the close it is the
    // only thing marking the end.
    void close_hard() {
        if (closed_) return;
        closed_ = true;
        mbedtls_net_free(&net_);
    }

    // The request head this connection last read, for a handler that wants to
    // answer differently per path.
    const std::string& request() const { return request_; }

private:
    friend class Server;

    // Waits for a readable byte while staying responsive to `Server::stop`.
    //
    // A plain blocking read would be simpler and would hang the test binary:
    // several tests leave a connection open with no further request on it, and
    // the connection thread has to notice the server shutting down. The
    // buffered-bytes check first is the same one `TlsSocket::wait_readable`
    // makes — decrypted data can be waiting where the socket has nothing.
    bool wait_readable();

    // Reads one request: the head through its blank line, then as many body
    // bytes as its Content-Length declares, so the stream stays aligned for the
    // next request on a keep-alive connection.
    bool read_request() {
        request_.clear();
        unsigned char c {};
        while (request_.find("\r\n\r\n") == std::string::npos) {
            if (!wait_readable()) return false;
            int ret = mbedtls_ssl_read(&ssl_, &c, 1);
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (ret <= 0) return false;
            request_.push_back(static_cast<char>(c));
            if (request_.size() > 65536) return false;
        }
        std::size_t bodyLen = declared_body_length(request_);
        std::string sink;
        while (sink.size() < bodyLen) {
            if (!wait_readable()) return false;
            unsigned char buf[4096];
            std::size_t want = bodyLen - sink.size();
            if (want > sizeof buf) want = sizeof buf;
            int ret = mbedtls_ssl_read(&ssl_, buf, want);
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (ret <= 0) return false;
            sink.append(reinterpret_cast<char*>(buf), static_cast<std::size_t>(ret));
        }
        return true;
    }

    static std::size_t declared_body_length(const std::string& head) {
        // Case-insensitive search for the one header a test request may carry.
        std::string lower;
        lower.reserve(head.size());
        for (char c : head) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        auto pos = lower.find("content-length:");
        if (pos == std::string::npos) return 0;
        pos += std::strlen("content-length:");
        std::size_t value = 0;
        while (pos < head.size() && (head[pos] == ' ' || head[pos] == '\t')) ++pos;
        while (pos < head.size() && head[pos] >= '0' && head[pos] <= '9') {
            value = value * 10 + static_cast<std::size_t>(head[pos] - '0');
            ++pos;
        }
        return value;
    }

    Server& server_;
    mbedtls_net_context net_ {};
    mbedtls_ssl_context ssl_ {};
    std::string request_;
    bool closed_ { false };
};

class Server {
public:
    // Answers one request. `index` counts requests across all connections, so a
    // handler can script "the first request stalls, the second succeeds".
    // Return true to serve another request on the same connection.
    using Handler = std::function<bool(Conn&, int index)>;

    explicit Server(Handler handler) : handler_(std::move(handler)) {
        mbedtls_net_init(&listener_);
        // Port 0: the OS picks a free one, which is what lets tests run
        // concurrently and on a machine where anything might already be bound.
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
        acceptor_ = std::thread([this] { accept_loop(); });
    }

    ~Server() { stop(); }

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // The acceptor is joined before the listener is closed, and the connection
    // threads before anything they touch is freed. Closing a descriptor another
    // thread is blocked on is a race that mostly works, which is the worst kind
    // to put in a test suite — so the accept loop polls instead.
    void stop() {
        if (stopping_.exchange(true)) return;
        if (acceptor_.joinable()) acceptor_.join();
        for (auto& t : connections_) {
            if (t.joinable()) t.join();
        }
        connections_.clear();
        mbedtls_net_free(&listener_);
    }

    [[nodiscard]] bool failed() const { return failed_; }
    [[nodiscard]] int port() const { return port_; }
    [[nodiscard]] std::string url(std::string_view path) const {
        return "https://127.0.0.1:" + std::to_string(port_) + std::string(path);
    }

    // THE ASSERTION THAT CATCHES WHAT THE BYTES DO NOT. A connection returned to
    // the pool with a previous response still on it produces a correct-looking
    // result and one fewer accept than a correct client would make.
    [[nodiscard]] int accepts() const { return accepts_.load(); }
    [[nodiscard]] int requests() const { return requests_.load(); }
    [[nodiscard]] bool stopping() const { return stopping_.load(); }

private:
    void accept_loop() {
        while (!stopping_.load()) {
            int ready = mbedtls_net_poll(&listener_, MBEDTLS_NET_POLL_READ, 50);
            if (ready < 0) break;
            if (ready == 0) continue;

            mbedtls_net_context client {};
            mbedtls_net_init(&client);
            if (mbedtls_net_accept(&listener_, &client, nullptr, 0, nullptr) != 0) {
                mbedtls_net_free(&client);
                continue;
            }
            accepts_.fetch_add(1);
            connections_.emplace_back([this, client]() mutable { serve(client); });
        }
    }

    // Each connection carries its own TLS state. Sharing one `mbedtls_ssl_config`
    // would mean sharing one CTR_DRBG across threads, and this build of mbedtls
    // has no threading layer compiled in — so the isolation is a correctness
    // requirement rather than tidiness.
    void serve(mbedtls_net_context client) {
        Conn conn(*this);
        conn.net_ = client;

        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context drbg;
        mbedtls_ssl_config conf;
        mbedtls_x509_crt cert;
        mbedtls_pk_context key;

        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cert);
        mbedtls_pk_init(&key);
        mbedtls_ssl_init(&conn.ssl_);

        auto cleanup = [&] {
            mbedtls_ssl_free(&conn.ssl_);
            mbedtls_pk_free(&key);
            mbedtls_x509_crt_free(&cert);
            mbedtls_ssl_config_free(&conf);
            mbedtls_ctr_drbg_free(&drbg);
            mbedtls_entropy_free(&entropy);
            mbedtls_net_free(&conn.net_);
        };

        if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, nullptr, 0) != 0
            || mbedtls_x509_crt_parse(&cert,
                   reinterpret_cast<const unsigned char*>(kCertPem),
                   std::strlen(kCertPem) + 1) != 0
            || mbedtls_pk_parse_key(&key,
                   reinterpret_cast<const unsigned char*>(kKeyPem),
                   std::strlen(kKeyPem) + 1, nullptr, 0,
                   mbedtls_ctr_drbg_random, &drbg) != 0
            || mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                   MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
            cleanup();
            return;
        }

        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
        // The client caps itself at TLS 1.2 (tls.cppm), so this is the version
        // that will be negotiated; saying so keeps the handshake off the 1.3
        // path entirely.
        mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
        if (mbedtls_ssl_conf_own_cert(&conf, &cert, &key) != 0
            || mbedtls_ssl_setup(&conn.ssl_, &conf) != 0) {
            cleanup();
            return;
        }
        mbedtls_ssl_set_bio(&conn.ssl_, &conn.net_, mbedtls_net_send,
                            mbedtls_net_recv, nullptr);

        int ret = 0;
        while ((ret = mbedtls_ssl_handshake(&conn.ssl_)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                cleanup();
                return;
            }
        }

        while (!stopping_.load()) {
            if (!conn.read_request()) break;
            const int index = requests_.fetch_add(1);
            if (!handler_(conn, index)) break;
        }
        conn.shutdown();
        cleanup();
    }

    Handler handler_;
    mbedtls_net_context listener_ {};
    int port_ { 0 };
    bool failed_ { false };
    std::atomic<bool> stopping_ { false };
    std::atomic<int> accepts_ { 0 };
    std::atomic<int> requests_ { 0 };
    std::thread acceptor_;
    std::vector<std::thread> connections_;
};

inline bool Conn::wait_readable() {
    if (mbedtls_ssl_get_bytes_avail(&ssl_) > 0) return true;
    for (int waited = 0; waited < 20000; waited += 50) {
        if (server_.stopping()) return false;
        int ready = mbedtls_net_poll(&net_, MBEDTLS_NET_POLL_READ, 50);
        if (ready > 0) return true;
        if (ready < 0) return false;
    }
    return false;
}

inline void Conn::park(std::chrono::milliseconds limit) {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (!server_.stopping() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// A response with a declared length and a body of exactly that length.
inline std::string ok_response(std::string_view body,
                               std::string_view extraHeaders = {}) {
    std::string out = "HTTP/1.1 200 OK\r\nContent-Length: ";
    out += std::to_string(body.size());
    out += "\r\n";
    out += extraHeaders;
    out += "\r\n";
    out += body;
    return out;
}

} // namespace tls_test
