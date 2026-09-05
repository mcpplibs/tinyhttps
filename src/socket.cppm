module;

#ifdef _WIN32
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

#ifdef _WIN32
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
        : fd_(other.fd_) {
        other.fd_ = INVALID_SOCKET_FD;
    }

    // Move assignment
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close();
            fd_ = other.fd_;
            other.fd_ = INVALID_SOCKET_FD;
        }
        return *this;
    }

    [[nodiscard]] bool is_valid() const {
        return fd_ != INVALID_SOCKET_FD;
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

        if constexpr (platform::is_windows) {
            return try_resolved(host, /*numeric=*/false);
        } else {
            // Fall back to a manual DNS query when libc can't resolve (Termux:
            // nameservers live in $PREFIX/etc/resolv.conf, which libc ignores).
            auto try_manual = [&]() -> bool {
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

    // Connect to the first reachable address in a resolved list.
    bool connect_addrinfo(struct addrinfo* result, int timeoutMs) {
        for (auto* rp = result; rp != nullptr; rp = rp->ai_next) {
            SocketHandle fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == INVALID_SOCKET_FD) {
                continue;
            }

            // macOS and the BSDs spell "do not raise a signal" as a socket
            // option rather than as a send flag; `write` below carries the flag
            // for the platforms that have one.
            //
            // ⭐ NOTHING SELECTS THIS AND NOTHING MAY. It is not a feature, not
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
#ifdef _WIN32
                if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
                if (errno == EINPROGRESS) {
#endif
                    // Wait for connection with timeout
                    if (poll_fd(fd, timeoutMs, false)) {
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
        return poll_fd(fd_, timeoutMs, true);
    }

    bool wait_writable(int timeoutMs) {
        if (!is_valid()) return false;
        return poll_fd(fd_, timeoutMs, false);
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
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    }

    static void platform_cleanup() {
#ifdef _WIN32
        WSACleanup();
#endif
    }

private:
    SocketHandle fd_ = INVALID_SOCKET_FD;

    static bool set_non_blocking(SocketHandle fd, bool nonBlocking) {
#ifdef _WIN32
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
#ifdef _WIN32
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
#ifdef _WIN32
        ::closesocket(fd);
#else
        ::close(fd);
#endif
    }
};

} // namespace mcpplibs::tinyhttps
