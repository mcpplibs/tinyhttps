// A proxy, in this process, that does exactly what a test tells it to.
//
// The proxy tests need the three things a real proxy does between accepting a
// connection and relaying bytes: read what the client asked for, answer it, and
// then splice the client to the target. A handler scripts the first two and
// `Peer::relay_to` does the third, so one test can make the proxy refuse, stall
// or hang up, and another can let a request through to the TLS server from
// tls_test_server.hpp and check what arrived.
//
// Plain TCP on 127.0.0.1, port chosen by the OS. It uses mbedtls's net layer
// for the same reason tls_test_server.hpp does: it is already a dependency and
// it is the same on every platform the library builds for.
#pragma once

#include <mbedtls/net_sockets.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// Which socket interface this is built against; see socket.cppm.
#if defined(_WIN32) && !defined(TINYHTTPS_POSIX_SOCKETS)
#define TINYHTTPS_WINSOCK 1
#endif

#ifdef TINYHTTPS_WINSOCK
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

namespace proxy_test {

class Server;

// The accepted connection, as the handler sees it.
class Peer {
public:
    Peer(Server& server, mbedtls_net_context net) : server_(server), net_(net) {}
    ~Peer() { mbedtls_net_free(&net_); }
    Peer(const Peer&) = delete;
    Peer& operator=(const Peer&) = delete;

    // Everything up to and including the blank line that ends an HTTP head,
    // read a byte at a time so nothing past it is taken. Empty on a hang-up.
    std::string read_head();

    // Exactly `n` bytes, or empty when the client hangs up first.
    std::string read_exact(std::size_t n);

    // Whatever arrives first, up to 4 KiB. Empty on a hang-up.
    std::string read_some();

    bool write(std::string_view data) {
        std::size_t sent = 0;
        while (sent < data.size()) {
            int ret = mbedtls_net_send(&net_,
                reinterpret_cast<const unsigned char*>(data.data() + sent),
                data.size() - sent);
            if (ret <= 0) return false;
            sent += static_cast<std::size_t>(ret);
        }
        return true;
    }

    void note(std::string text);

    // Splices this connection to 127.0.0.1:`port` until either side ends.
    void relay_to(int port);

private:
    bool wait_readable(int ms) { return mbedtls_net_poll(&net_, MBEDTLS_NET_POLL_READ, ms) > 0; }

    Server& server_;
    mbedtls_net_context net_;
};

class Server {
public:
    using Handler = std::function<void(Peer&)>;

    explicit Server(Handler handler) : handler_(std::move(handler)) {
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
        acceptor_ = std::thread([this] { accept_loop(); });
    }

    ~Server() { stop(); }
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

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
    [[nodiscard]] bool stopping() const { return stopping_.load(); }
    [[nodiscard]] int accepts() const { return accepts_.load(); }

    // The text a handler stored with `note`, for the test to assert on once the
    // request has completed.
    void note(std::string text) {
        std::lock_guard<std::mutex> lock(mutex_);
        notes_.push_back(std::move(text));
    }
    [[nodiscard]] std::vector<std::string> notes() {
        std::lock_guard<std::mutex> lock(mutex_);
        return notes_;
    }

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
            connections_.emplace_back([this, client] {
                Peer peer(*this, client);
                handler_(peer);
            });
        }
    }

    Handler handler_;
    mbedtls_net_context listener_ {};
    int port_ { 0 };
    bool failed_ { false };
    std::atomic<bool> stopping_ { false };
    std::atomic<int> accepts_ { 0 };
    std::thread acceptor_;
    std::vector<std::thread> connections_;
    std::mutex mutex_;
    std::vector<std::string> notes_;
};

inline void Peer::note(std::string text) { server_.note(std::move(text)); }

inline std::string Peer::read_head() {
    std::string head;
    unsigned char c {};
    while (head.find("\r\n\r\n") == std::string::npos) {
        if (head.size() > 65536) return {};
        // 20 s is far beyond any test; the loop exists so `stop` is noticed.
        bool ready = false;
        for (int waited = 0; waited < 20000 && !ready; waited += 50) {
            if (server_.stopping()) return {};
            ready = wait_readable(50);
        }
        if (!ready) return {};
        if (mbedtls_net_recv(&net_, &c, 1) <= 0) return {};
        head.push_back(static_cast<char>(c));
    }
    return head;
}

inline std::string Peer::read_exact(std::size_t n) {
    std::string out;
    unsigned char c {};
    while (out.size() < n) {
        bool ready = false;
        for (int waited = 0; waited < 20000 && !ready; waited += 50) {
            if (server_.stopping()) return {};
            ready = wait_readable(50);
        }
        if (!ready || mbedtls_net_recv(&net_, &c, 1) <= 0) return {};
        out.push_back(static_cast<char>(c));
    }
    return out;
}

inline std::string Peer::read_some() {
    unsigned char buf[4096];
    for (int waited = 0; waited < 20000; waited += 50) {
        if (server_.stopping()) return {};
        if (!wait_readable(50)) continue;
        int n = mbedtls_net_recv(&net_, buf, sizeof buf);
        return n > 0 ? std::string(reinterpret_cast<char*>(buf), static_cast<std::size_t>(n))
                     : std::string();
    }
    return {};
}

inline void Peer::relay_to(int port) {
    mbedtls_net_context target {};
    mbedtls_net_init(&target);
    if (mbedtls_net_connect(&target, "127.0.0.1", std::to_string(port).c_str(),
                            MBEDTLS_NET_PROTO_TCP) != 0) {
        return;
    }
    // Round-robin over two sockets with a short poll each: slower than a
    // select over both, and portable without a second code path.
    unsigned char buf[4096];
    bool open = true;
    while (open && !server_.stopping()) {
        for (auto [from, to] : {std::pair{&net_, &target}, std::pair{&target, &net_}}) {
            if (mbedtls_net_poll(from, MBEDTLS_NET_POLL_READ, 10) <= 0) continue;
            int n = mbedtls_net_recv(from, buf, sizeof buf);
            if (n <= 0) { open = false; break; }
            for (int sent = 0; sent < n;) {
                int w = mbedtls_net_send(to, buf + sent, static_cast<std::size_t>(n - sent));
                if (w <= 0) { open = false; break; }
                sent += w;
            }
        }
    }
    mbedtls_net_free(&target);
}

} // namespace proxy_test
