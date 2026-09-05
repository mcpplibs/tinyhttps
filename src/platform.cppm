module;

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#endif

export module mcpplibs.tinyhttps:platform;

import std;

// mcpplibs.tinyhttps:platform — the one place OS-specific networking quirks
// live. Everything else (socket.cppm, http.cppm…) stays portable and branches
// on `platform::is_windows` with `if constexpr`, never raw #ifdef.
//
// ── The platforms this library is known to run on, and what differs ──────────
//
// | platform          | not raising SIGPIPE      | notes                      |
// |-------------------|--------------------------|----------------------------|
// | Linux, Android    | MSG_NOSIGNAL on send()   |                            |
// | Termux            | MSG_NOSIGNAL on send()   | manual DNS, below          |
// | macOS, the BSDs   | SO_NOSIGPIPE on socket() | no MSG_NOSIGNAL            |
// | Windows           | nothing to do            | no SIGPIPE, neither macro  |
// | above openkal     | MSG_NOSIGNAL, and moot   | see below                  |
//
// ⭐ ABOVE openkal there are no signals at all, so the hazard issue #16
// describes cannot arise — and the same code is nevertheless correct there
// without a branch. openkal-musl defines MSG_NOSIGNAL
// (`musl/include/sys/socket.h:344`) and accepts it as a no-op, in its own words:
// "MSG_NOSIGNAL asks that a signal not be raised. There are no signals here, so
// the request is satisfied by there being nothing to raise"
// (`port/src/okm_net.c:546-550`); a flag it does not know it refuses with
// -ENOSYS (`:550`, `:592-593`). SO_NOSIGPIPE is a BSD spelling that musl does
// not define, so `socket.cppm`'s `#ifdef` for it simply does not compile in.
//
// ⚠️ One difference that IS live above openkal: connect() completes before it
// returns even on a non-blocking descriptor, because `kal_net_connect` has no
// form that begins a connection and reports its outcome later
// (`port/src/okm_net.c:454-467`). `Socket::connect_addrinfo` therefore never
// sees EINPROGRESS, never reaches its poll, and `connectTimeoutMs` is not
// enforced for the TCP connect on that stack. Nothing here can fix that — the
// bound would have to come from openkal — and nothing here needs to know it at
// compile time, which is why there is no `is_openkal`.
//
// Sole runtime concern today: hostname resolution on platforms where libc can't
// do it.
// A musl-static binary on Android/Termux can't resolve through getaddrinfo() —
// libc reads /etc/resolv.conf, but Android's /etc is read-only with no
// resolv.conf; Termux keeps its nameservers in $PREFIX/etc/resolv.conf, which
// libc never consults. So getaddrinfo stalls on a dead 127.0.0.1:53 and every
// HTTPS fetch (github, gitcode, anything) ends in "Connection failed". We read
// the relocatable resolv.conf ourselves and run a UDP DNS query. Self-contained:
// no shelling out to curl/getprop, no extra deps.

namespace mcpplibs::tinyhttps::platform {

// Compile-time platform flag for `if constexpr` at call sites.
export inline constexpr bool is_windows =
#ifdef _WIN32
    true;
#else
    false;
#endif

#ifndef _WIN32

namespace {

inline bool is_numeric_host(const char* host) {
    // An IPv4/IPv6 literal is digits, dots, colons and hex letters only. This is
    // a fast pre-filter; getaddrinfo(AI_NUMERICHOST) downstream is the real check.
    if (host == nullptr || host[0] == '\0') return false;
    for (const char* p = host; *p; ++p) {
        char c = *p;
        bool ok = (c >= '0' && c <= '9') || c == '.' || c == ':'
               || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}

// Nameservers from the first readable resolv.conf, $PREFIX (Termux) first.
inline std::vector<std::string> resolv_nameservers() {
    std::vector<std::string> servers;
    std::vector<std::string> paths;
    if (const char* prefix = std::getenv("PREFIX"); prefix && *prefix) {
        paths.emplace_back(std::string(prefix) + "/etc/resolv.conf");
    }
    paths.emplace_back("/data/data/com.termux/files/usr/etc/resolv.conf");
    paths.emplace_back("/etc/resolv.conf");
    for (const auto& path : paths) {
        std::ifstream f(path);
        if (!f) continue;
        std::string line;
        while (std::getline(f, line)) {
            if (auto hash = line.find('#'); hash != std::string::npos) line.erase(hash);
            std::istringstream is(line);
            std::string kw, val;
            if ((is >> kw >> val) && kw == "nameserver" && !val.empty()) {
                servers.push_back(val);
            }
        }
        if (!servers.empty()) break;
    }
    return servers;
}

// Query one nameserver for A records of `host`. Returns dotted-quad IPv4s.
inline std::vector<std::string> dns_query_a(const std::string& server, const char* host, int timeoutMs) {
    std::vector<std::string> ips;

    unsigned char q[512];
    size_t n = 0;
    q[n++] = 0x12; q[n++] = 0x34;   // id
    q[n++] = 0x01; q[n++] = 0x00;   // flags: recursion desired
    q[n++] = 0x00; q[n++] = 0x01;   // qdcount = 1
    q[n++] = 0x00; q[n++] = 0x00;   // ancount
    q[n++] = 0x00; q[n++] = 0x00;   // nscount
    q[n++] = 0x00; q[n++] = 0x00;   // arcount
    for (const char* p = host; *p; ) {                 // qname: length-prefixed labels
        const char* dot = p;
        while (*dot && *dot != '.') ++dot;
        size_t len = static_cast<size_t>(dot - p);
        if (len == 0 || len > 63 || n + len + 1 >= sizeof(q)) return ips;
        q[n++] = static_cast<unsigned char>(len);
        for (size_t i = 0; i < len; ++i) q[n++] = static_cast<unsigned char>(p[i]);
        p = (*dot == '.') ? dot + 1 : dot;
    }
    q[n++] = 0x00;                  // root label
    q[n++] = 0x00; q[n++] = 0x01;   // qtype A
    q[n++] = 0x00; q[n++] = 0x01;   // qclass IN

    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST;
    struct addrinfo* sres = nullptr;
    if (::getaddrinfo(server.c_str(), "53", &hints, &sres) != 0 || sres == nullptr) return ips;

    int fd = ::socket(sres->ai_family, sres->ai_socktype, sres->ai_protocol);
    if (fd < 0) { ::freeaddrinfo(sres); return ips; }
    bool sent = ::sendto(fd, q, n, 0, sres->ai_addr, sres->ai_addrlen) == static_cast<ssize_t>(n);
    ::freeaddrinfo(sres);
    if (!sent) { ::close(fd); return ips; }

    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    if (::poll(&pfd, 1, timeoutMs) <= 0) { ::close(fd); return ips; }

    unsigned char resp[1024];
    ssize_t rn = ::recv(fd, resp, sizeof(resp), 0);
    ::close(fd);
    if (rn < 12) return ips;
    auto R = static_cast<size_t>(rn);

    unsigned ancount = (static_cast<unsigned>(resp[6]) << 8) | resp[7];
    size_t off = 12;
    while (off < R && resp[off] != 0) off += resp[off] + 1;   // question qname (no compression)
    off += 1 + 4;                                             // root label + qtype + qclass

    for (unsigned a = 0; a < ancount && off + 12 <= R; ++a) {
        if ((resp[off] & 0xc0) == 0xc0) {                     // compressed name pointer
            off += 2;
        } else {
            while (off < R && resp[off] != 0) off += resp[off] + 1;
            off += 1;
        }
        if (off + 10 > R) break;
        unsigned type  = (static_cast<unsigned>(resp[off]) << 8) | resp[off + 1];
        unsigned rdlen = (static_cast<unsigned>(resp[off + 8]) << 8) | resp[off + 9];
        off += 10;
        if (off + rdlen > R) break;
        if (type == 1 && rdlen == 4) {
            ips.push_back(std::format("{}.{}.{}.{}",
                resp[off], resp[off + 1], resp[off + 2], resp[off + 3]));
        }
        off += rdlen;
    }
    return ips;
}

} // anonymous namespace

#endif // !_WIN32

// True when libc's own resolver has a usable config (/etc/resolv.conf). When
// false, callers should prefer resolve_fallback() to avoid a multi-second stall
// on a dead 127.0.0.1:53. Always true on Windows (the OS resolver is reliable).
//
// Note: the bodies branch with #ifdef, not `if constexpr` — a non-template
// `if constexpr` still compiles its discarded branch, which would reference the
// POSIX-only helpers above that don't exist on Windows. Concentrating that
// preprocessor divergence here is exactly why this platform module exists; call
// sites elsewhere branch on `is_windows` with `if constexpr`.
export bool system_resolver_configured() {
#ifdef _WIN32
    return true;
#else
    std::error_code ec;
    return std::filesystem::exists("/etc/resolv.conf", ec);
#endif
}

// Resolve a hostname to IPv4 literals WITHOUT relying on libc's resolver, by
// reading the system nameservers ($PREFIX/etc/resolv.conf on Termux) and doing
// a UDP DNS query. Returns {} on Windows, when no nameserver is configured, or
// on query failure. A numeric host is returned unchanged.
export std::vector<std::string> resolve_fallback([[maybe_unused]] const char* host,
                                                 [[maybe_unused]] int timeoutMs) {
#ifdef _WIN32
    return {};
#else
    if (is_numeric_host(host)) return { std::string(host) };

    // Process-wide cache of successful resolutions. A single download performs
    // several connects to the same host (HEAD probe, GET, redirect targets); on
    // Termux each would otherwise re-run a UDP query to 8.8.8.8, and one dropped
    // packet stalls the whole transfer. Cache once, reuse for the process.
    static std::mutex cache_mutex;
    static std::map<std::string, std::vector<std::string>> cache;
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        if (auto it = cache.find(host); it != cache.end()) return it->second;
    }

    for (const auto& ns : resolv_nameservers()) {
        auto got = dns_query_a(ns, host, timeoutMs);
        if (!got.empty()) {
            std::lock_guard<std::mutex> lock(cache_mutex);
            cache.emplace(std::string(host), got);
            return got;
        }
    }
    return {};
#endif
}

} // namespace mcpplibs::tinyhttps::platform
