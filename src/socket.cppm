module;

// The socket interface is chosen by the C library, not by the operating
// system. On Windows with the platform's own C runtime it is Windows Sockets;
// where the C library is POSIX-shaped (openkal-musl, selected in mcpp.toml by
// `cfg(c-abi = "musl")`) it is the POSIX interface on every system, Windows
// included.
#if defined(_WIN32) && !defined(TINYHTTPS_POSIX_SOCKETS)
#define TINYHTTPS_WINSOCK 1
#endif

#ifdef TINYHTTPS_WINSOCK
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#endif

export module mcpplibs.tinyhttps:socket;

import std;
import :platform;

namespace mcpplibs::tinyhttps {

#ifdef TINYHTTPS_WINSOCK
using SocketHandle = SOCKET;
constexpr SocketHandle INVALID_SOCKET_FD = INVALID_SOCKET;
#else
using SocketHandle = int;
constexpr SocketHandle INVALID_SOCKET_FD = -1;
#endif

export class Socket {
public:
    Socket() = default;

    ~Socket() {
        close();
    }

    // Non-copyable
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    // Move constructor
    Socket(Socket&& other) noexcept
        : fd_(other.fd_), stop_(std::move(other.stop_)), deadline_(other.deadline_) {
        other.fd_ = INVALID_SOCKET_FD;
    }

    // Move assignment
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close();
            fd_ = other.fd_;
            stop_ = std::move(other.stop_);
            deadline_ = other.deadline_;
            other.fd_ = INVALID_SOCKET_FD;
        }
        return *this;
    }

    [[nodiscard]] bool is_valid() const {
        return fd_ != INVALID_SOCKET_FD;
    }

    // Once the token is stopped, every wait on this socket (connect included)
    // ends within 50 ms and reports "not ready".
    void set_stop(std::stop_token stop) { stop_ = std::move(stop); }

    [[nodiscard]] bool stop_possible() const { return stop_.stop_possible(); }

    // Bounds the TLS handshake: until it is cleared, `wait_before_recv` gives up
    // once this time has passed. Cleared once the handshake is over.
    void set_deadline(std::optional<std::chrono::steady_clock::time_point> deadline) {
        deadline_ = deadline;
        deadline_hit_ = false;
    }

    // True once `wait_before_recv` gave up because of the deadline.
    [[nodiscard]] bool deadline_hit() const { return deadline_hit_; }

    // What `bio_recv` calls ahead of a `recv` that would otherwise block. True
    // when a `recv` now will not block. With neither a token nor a deadline it
    // answers true without waiting, so the plain `recv` is as it was.
    bool wait_before_recv() {
        if (!stop_.stop_possible() && !deadline_) return true;
        int wait = -1;
        if (deadline_) {
            const auto left = std::chrono::ceil<std::chrono::milliseconds>(
                *deadline_ - std::chrono::steady_clock::now()).count();
            wait = left > 0 ? static_cast<int>(left) : 0;
        }
        if (wait_readable(wait)) return true;
        if (deadline_ && !stop_.stop_requested()) deadline_hit_ = true;
        return false;
    }

    bool connect(const char* host, int port, int timeoutMs) {
        // Close existing connection if any
        if (is_valid()) {
            close();
        }

        auto portStr = std::to_string(port);

        // Resolve via the system resolver (getaddrinfo). On Termux/Android a
        // musl-static build can't — its nameservers live in $PREFIX/etc/resolv.conf
        // which libc never reads — so fall back to a manual DNS query there.
        auto try_resolved = [&](const char* node, bool numeric) -> bool {
            if (stop_.stop_requested()) return false;
            struct addrinfo hints{};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            if (numeric) hints.ai_flags = AI_NUMERICHOST;

            struct addrinfo* result = nullptr;
            if (::getaddrinfo(node, portStr.c_str(), &hints, &result) != 0 || result == nullptr) {
                return false;
            }
            bool ok = connect_addrinfo(result, timeoutMs);
            ::freeaddrinfo(result);
            return ok;
        };

        if constexpr (platform::uses_winsock) {
            return try_resolved(host, /*numeric=*/false);
        } else {
            // Fall back to a manual DNS query when libc can't resolve (Termux:
            // nameservers live in $PREFIX/etc/resolv.conf, which libc ignores).
            auto try_manual = [&]() -> bool {
                if (stop_.stop_requested()) return false;
                // DNS must be snappy: a UDP query to a working resolver answers
                // in well under a second. Cap it hard (independent of the much
                // larger connect timeout) so an intermittently-dropped packet to
                // 8.8.8.8 can't stall a connect for tens of seconds per host.
                // Plain ternary, not std::min: <winsock2.h> defines a `min`
                // macro that would mangle std::min on the (compiled-but-discarded)
                // Windows branch of this if constexpr.
                constexpr int kDnsTimeoutMs = 2500;
                int dnsTimeout = (timeoutMs > 0 && timeoutMs < kDnsTimeoutMs)
                                     ? timeoutMs : kDnsTimeoutMs;
                for (const auto& ip : platform::resolve_fallback(host, dnsTimeout)) {
                    if (try_resolved(ip.c_str(), /*numeric=*/true)) return true;
                }
                return false;
            };

            // No libc resolver config but a relocatable one exists → resolve
            // manually first to avoid a multi-second stall on a dead 127.0.0.1:53.
            if (!platform::system_resolver_configured()) {
                return try_manual() || try_resolved(host, /*numeric=*/false);
            }
            return try_resolved(host, /*numeric=*/false) || try_manual();
        }
    }

    // The first address `host` resolves to, as network-order bytes: four for
    // IPv4, sixteen for IPv6, none when it does not resolve. IPv4 wins when both
    // exist, which is what a SOCKS5 proxy of any age can be asked for.
    // `numericOnly` accepts an address literal and nothing else, with no lookup.
    static std::vector<unsigned char> resolve_address(const char* host, bool numericOnly = false) {
        struct addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (numericOnly) hints.ai_flags = AI_NUMERICHOST;

        std::vector<unsigned char> bytes;
        struct addrinfo* result = nullptr;
        if (::getaddrinfo(host, nullptr, &hints, &result) == 0 && result != nullptr) {
            for (auto* rp = result; rp != nullptr; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET) {
                    auto* in = reinterpret_cast<unsigned char*>(
                        &reinterpret_cast<struct sockaddr_in*>(rp->ai_addr)->sin_addr);
                    bytes.assign(in, in + 4);
                    break;
                }
                if (rp->ai_family == AF_INET6 && bytes.empty()) {
                    auto* in = reinterpret_cast<unsigned char*>(
                        &reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr)->sin6_addr);
                    bytes.assign(in, in + 16);
                }
            }
            ::freeaddrinfo(result);
        }

        // As in `connect`: where libc has no resolver configuration (Termux),
        // fall back to a manual query.
        if constexpr (!platform::uses_winsock) {
            if (bytes.empty() && !numericOnly) {
                for (const auto& ip : platform::resolve_fallback(host, 2500)) {
                    bytes = resolve_address(ip.c_str(), true);
                    if (!bytes.empty()) break;
                }
            }
        }
        return bytes;
    }

    // Connect to the first reachable address in a resolved list.
    bool connect_addrinfo(struct addrinfo* result, int timeoutMs) {
        for (auto* rp = result; rp != nullptr; rp = rp->ai_next) {
            if (stop_.stop_requested()) return false;
            SocketHandle fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == INVALID_SOCKET_FD) {
                continue;
            }

            // macOS and the BSDs spell "do not raise a signal" as a socket
            // option rather than as a send flag; `write` below carries the flag
            // for the platforms that have one.
            //
            // NOTHING SELECTS THIS AND NOTHING MAY. It is not a feature, not
            // a config field and not a runtime probe: the preprocessor reads the
            // target's own <sys/socket.h> and the answer is already complete.
            // Measured on this machine — glibc: SO_NOSIGPIPE absent,
            // MSG_NOSIGNAL 0x4000; musl (Termux, Alpine, openkal-musl):
            // SO_NOSIGPIPE absent, MSG_NOSIGNAL 0x4000; Darwin/BSD: the reverse;
            // Windows: neither, and no SIGPIPE to raise.
            //
            // Making it selectable would be actively wrong. A consumer who left
            // it off on macOS would get exactly issue #16 — the process killed
            // by a signal it never armed — and would get it silently, on a
            // platform they may not build for themselves. A property that only
            // prevents harm and costs one setsockopt is not a choice worth
            // offering; there is no target where the name exists and setting it
            // is undesirable.
            //
            // This does NOT touch the process's signal disposition, so a program
            // that wants SIGPIPE on its own stdout still gets it. That is the
            // whole reason to prefer this over mbedtls's `signal(SIGPIPE,
            // SIG_IGN)`, which changes it for everything the host does.
            //
            // Best-effort: a failure leaves the socket with the disposition it
            // had before this line.
            //
            // #ifdef, not `if constexpr`: the name does not exist on Linux or
            // Windows, and both arms of an `if constexpr` must compile.
#ifdef SO_NOSIGPIPE
            int nosigpipe = 1;
            ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
                         reinterpret_cast<const char*>(&nosigpipe), sizeof(nosigpipe));
#endif

            // Set non-blocking
            if (!set_non_blocking(fd, true)) {
                close_handle(fd);
                continue;
            }

            int rc = ::connect(fd, rp->ai_addr, static_cast<int>(rp->ai_addrlen));

            bool connected = false;
            if (rc == 0) {
                connected = true;
            } else {
#ifdef TINYHTTPS_WINSOCK
                if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
                if (errno == EINPROGRESS) {
#endif
                    // Wait for connection with timeout
                    if (wait_fd(fd, timeoutMs, false)) {
                        int err = 0;
                        socklen_t len = sizeof(err);
                        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) == 0 && err == 0) {
                            connected = true;
                        }
                    }
                }
            }

            if (connected) {
                // Restore blocking mode
                set_non_blocking(fd, false);
                fd_ = fd;
                return true;
            }

            close_handle(fd);
        }

        return false;
    }

    int read(char* buf, int len) {
        if (!is_valid()) return -1;
        return static_cast<int>(::recv(fd_, buf, len, 0));
    }

    // A WRITE TO A SOCKET WHOSE PEER HAS GONE AWAY RAISES SIGPIPE, AND A
    // PROGRAM THAT HAS NOT DISARMED IT — THE DEFAULT — IS KILLED RATHER THAN
    // TOLD. That is issue #16, and it is this library's defect rather than its
    // caller's: the fd is one this class created, and the write that meets a
    // dead peer is most often the `close_notify` the pool's own clean-up sends.
    //
    // mbedtls guards against this in `net_prepare` (net_sockets.c:114) with a
    // process-wide `signal(SIGPIPE, SIG_IGN)`. This library replaces mbedtls's
    // network layer with its own BIO and never calls `mbedtls_net_init`, so it
    // dropped that guard without putting anything in its place. MSG_NOSIGNAL is
    // the better replacement in any case: a library has no business changing
    // its host's signal disposition.
    //
    // The failure travels along paths that already exist — `bio_send` maps a
    // non-positive return to MBEDTLS_ERR_NET_SEND_FAILED, and `TlsSocket::close`
    // already ignores what close_notify returns — so the successful path is
    // unchanged byte for byte.
    //
    // #ifdef, not `if constexpr`: the macro does not exist on Windows (which has
    // no SIGPIPE either) or on the BSDs (which use SO_NOSIGPIPE, set in
    // `connect_addrinfo`), and both arms of an `if constexpr` must compile. That
    // is the trap 5e7d66f fixed in the resolver stubs.
    //
    // Above openkal the flag is accepted and ignored — openkal has no signals at
    // all (openkal-musl `port/src/okm_net.c:546-550`) — so this compiles and is
    // correct there without a branch of its own.
    int write(const char* buf, int len) {
        if (!is_valid()) return -1;
#ifdef MSG_NOSIGNAL
        return static_cast<int>(::send(fd_, buf, len, MSG_NOSIGNAL));
#else
        return static_cast<int>(::send(fd_, buf, len, 0));
#endif
    }

    bool wait_readable(int timeoutMs) {
        if (!is_valid()) return false;
        return wait_fd(fd_, timeoutMs, true);
    }

    bool wait_writable(int timeoutMs) {
        if (!is_valid()) return false;
        return wait_fd(fd_, timeoutMs, false);
    }

    [[nodiscard]] SocketHandle native_handle() const {
        return fd_;
    }

    void close() {
        if (is_valid()) {
            close_handle(fd_);
            fd_ = INVALID_SOCKET_FD;
        }
    }

    static void platform_init() {
#ifdef TINYHTTPS_WINSOCK
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    }

    static void platform_cleanup() {
#ifdef TINYHTTPS_WINSOCK
        WSACleanup();
#endif
    }

private:
    SocketHandle fd_ = INVALID_SOCKET_FD;
    std::stop_token stop_;
    std::optional<std::chrono::steady_clock::time_point> deadline_;
    bool deadline_hit_ = false;

    // poll_fd in slices while a token is attached. A negative timeout waits
    // without limit. Not std::min: <winsock2.h> defines a `min` macro.
    bool wait_fd(SocketHandle fd, int timeoutMs, bool forRead) const {
        if (!stop_.stop_possible()) return poll_fd(fd, timeoutMs, forRead);
        constexpr int slice = 50;
        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(timeoutMs);
        while (!stop_.stop_requested()) {
            int wait = slice;
            if (timeoutMs >= 0) {
                const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now()).count();
                if (left < slice) wait = left > 0 ? static_cast<int>(left) : 0;
            }
            if (poll_fd(fd, wait, forRead)) return true;
            if (timeoutMs >= 0 && std::chrono::steady_clock::now() >= deadline) return false;
        }
        return false;
    }

    static bool set_non_blocking(SocketHandle fd, bool nonBlocking) {
#ifdef TINYHTTPS_WINSOCK
        u_long mode = nonBlocking ? 1 : 0;
        return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags == -1) return false;
        if (nonBlocking) {
            flags |= O_NONBLOCK;
        } else {
            flags &= ~O_NONBLOCK;
        }
        return ::fcntl(fd, F_SETFL, flags) == 0;
#endif
    }

    static bool poll_fd(SocketHandle fd, int timeoutMs, bool forRead) {
#ifdef TINYHTTPS_WINSOCK
        WSAPOLLFD pfd{};
        pfd.fd = fd;
        pfd.events = forRead ? POLLIN : POLLOUT;
        int ret = WSAPoll(&pfd, 1, timeoutMs);
        return ret > 0 && (pfd.revents & (pfd.events | POLLERR | POLLHUP));
#else
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = forRead ? POLLIN : POLLOUT;
        int ret = ::poll(&pfd, 1, timeoutMs);
        return ret > 0 && (pfd.revents & (pfd.events | POLLERR | POLLHUP));
#endif
    }

    static void close_handle(SocketHandle fd) {
#ifdef TINYHTTPS_WINSOCK
        ::closesocket(fd);
#else
        ::close(fd);
#endif
    }
};

} // namespace mcpplibs::tinyhttps
