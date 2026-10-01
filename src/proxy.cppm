export module mcpplibs.tinyhttps:proxy;

import :socket;
import :tls;
import std;

namespace mcpplibs::tinyhttps {

// A parsed proxy URL: where the proxy is, how to talk to it, and the credentials
// to send. `parse_proxy_url` fills it in; nothing validates it until
// `proxy_tunnel` tries to use it.
export struct ProxyConfig {
    std::string host;
    int port { 8080 };

    // Lower case: "http", "https" for a proxy that is itself reached over TLS,
    // "socks5" or "socks5h". "http" when the URL has no scheme, which is how a
    // bare `host:port` has always been read. With "socks5" this library
    // resolves the target's name and gives the proxy an address; with "socks5h"
    // it gives the proxy the name.
    std::string scheme { "http" };

    // From `user:password@` in the URL, percent-decoded. A URL with `@` and no
    // password still has credentials; `hasCredentials` is what says so, because
    // an empty user or an empty password is a legitimate value.
    bool hasCredentials { false };
    std::string user;
    std::string password;
};

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// "%40" is "@". A '%' that is not followed by two hex digits stays as written.
static std::string percent_decode(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size() && hex_digit(in[i + 1]) >= 0
            && hex_digit(in[i + 2]) >= 0) {
            out += static_cast<char>(hex_digit(in[i + 1]) * 16 + hex_digit(in[i + 2]));
            i += 2;
        } else {
            out += in[i];
        }
    }
    return out;
}

// Parse "[scheme://][user[:password]@]host[:port]". A path, query or fragment
// after the authority is ignored. IPv6 literals are written in brackets. The
// port defaults to 443 for https, 1080 for socks5 and socks5h, and 8080
// otherwise.
export ProxyConfig parse_proxy_url(std::string_view url) {
    ProxyConfig config;

    auto schemeEnd = url.find("://");
    if (schemeEnd != std::string_view::npos) {
        config.scheme.clear();
        for (char c : url.substr(0, schemeEnd)) {
            config.scheme += (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
        }
        url = url.substr(schemeEnd + 3);
    }

    url = url.substr(0, url.find_first_of("/?#"));

    // The last '@' separates the userinfo, so an unencoded '@' in a password
    // still parses the way curl reads it.
    if (auto at = url.rfind('@'); at != std::string_view::npos) {
        auto userinfo = url.substr(0, at);
        url = url.substr(at + 1);
        auto colon = userinfo.find(':');
        config.hasCredentials = true;
        config.user = percent_decode(userinfo.substr(0, colon));
        if (colon != std::string_view::npos) {
            config.password = percent_decode(userinfo.substr(colon + 1));
        }
    }

    std::string_view portStr;
    bool hasPort = false;
    if (!url.empty() && url.front() == '[') {
        auto close = url.find(']');
        config.host = std::string(url.substr(1, close == std::string_view::npos
                                                  ? std::string_view::npos : close - 1));
        if (close != std::string_view::npos && close + 1 < url.size() && url[close + 1] == ':') {
            portStr = url.substr(close + 2);
            hasPort = true;
        }
    } else if (auto colon = url.find(':'); colon != std::string_view::npos) {
        config.host = std::string(url.substr(0, colon));
        portStr = url.substr(colon + 1);
        hasPort = true;
    } else {
        config.host = std::string(url);
    }

    if (config.scheme == "https") config.port = 443;
    if (config.scheme.starts_with("socks")) config.port = 1080;

    if (hasPort && !portStr.empty()) {
        // Anything but 1..65535 becomes 0, which no connect will accept.
        long port = 0;
        for (char c : portStr) {
            if (c < '0' || c > '9' || (port = port * 10 + (c - '0')) > 65535) { port = 0; break; }
        }
        config.port = static_cast<int>(port);
    }

    return config;
}

static std::string base64_encode(std::string_view in) {
    constexpr std::string_view table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < in.size(); i += 3) {
        unsigned v = static_cast<unsigned char>(in[i]) << 16;
        if (i + 1 < in.size()) v |= static_cast<unsigned char>(in[i + 1]) << 8;
        if (i + 2 < in.size()) v |= static_cast<unsigned char>(in[i + 2]);
        out += table[(v >> 18) & 63];
        out += table[(v >> 12) & 63];
        out += i + 1 < in.size() ? table[(v >> 6) & 63] : '=';
        out += i + 2 < in.size() ? table[v & 63] : '=';
    }
    return out;
}

// One line without its CRLF. nullopt on a timeout, an end of stream, or a line
// longer than any proxy sends. Reads a byte at a time on purpose: whatever
// follows the blank line belongs to the tunnel and must not be consumed.
template <typename Stream>
static std::optional<std::string> read_line(Stream& sock, int timeoutMs) {
    std::string line;
    char c;
    while (line.size() < 8192) {
        if (!sock.wait_readable(timeoutMs)) return std::nullopt;
        int ret = sock.read(&c, 1);
        if (ret == 0) {
            if (!sock.wait_readable(timeoutMs)) return std::nullopt;
            ret = sock.read(&c, 1);
        }
        if (ret <= 0) return std::nullopt;
        line += c;
        if (line.size() >= 2 && line[line.size() - 2] == '\r' && line.back() == '\n') {
            line.resize(line.size() - 2);
            return line;
        }
    }
    return std::nullopt;
}

template <typename Stream>
static bool write_all(Stream& sock, std::string_view data, int timeoutMs) {
    std::size_t total = 0;
    while (total < data.size()) {
        int ret = sock.write(data.data() + total, static_cast<int>(data.size() - total));
        if (ret < 0) return false;
        if (ret == 0 && !sock.wait_writable(timeoutMs)) return false;
        total += static_cast<std::size_t>(ret);
    }
    return true;
}

// "HTTP/1.1 407 Proxy Authentication Required" -> 407, or 0 when the line is
// not a status line.
static int status_code_of(std::string_view line) {
    if (!line.starts_with("HTTP/1.") || line.size() < 12 || line[8] != ' ') return 0;
    int code = 0;
    for (char c : line.substr(9, 3)) {
        if (c < '0' || c > '9') return 0;
        code = code * 10 + (c - '0');
    }
    return code;
}

// Ask an HTTP proxy to open a tunnel to host:port. Returns an error message, or
// an empty string once the proxy has answered 2xx and the stream is the tunnel.
template <typename Stream>
static std::string http_connect(Stream& sock, const ProxyConfig& proxy,
                                std::string_view host, int port, int timeoutMs) {
    // An IPv6 literal needs its brackets back in the request target.
    std::string authority = host.contains(':') ? "[" + std::string(host) + "]" : std::string(host);
    authority += ":" + std::to_string(port);

    std::string request = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n";
    if (proxy.hasCredentials) {
        request += "Proxy-Authorization: Basic "
                 + base64_encode(proxy.user + ":" + proxy.password) + "\r\n";
    }
    request += "\r\n";

    if (!write_all(sock, request, timeoutMs)) return "proxy: could not send CONNECT";

    auto statusLine = read_line(sock, timeoutMs);
    int code = statusLine ? status_code_of(*statusLine) : 0;
    if (code == 0) return "proxy: no HTTP response to CONNECT";
    if (code == 407) {
        return std::string(proxy.hasCredentials ? "proxy rejected the credentials: "
                                                : "proxy requires credentials: ")
             + statusLine->substr(9);
    }
    if (code < 200 || code > 299) return "proxy refused CONNECT: " + statusLine->substr(9);

    // The rest of the head. A 2xx answer to CONNECT carries no body.
    for (int i = 0; i < 100; ++i) {
        auto header = read_line(sock, timeoutMs);
        if (!header) return "proxy: response to CONNECT was cut short";
        if (header->empty()) return {};
    }
    return "proxy: response to CONNECT has too many headers";
}

// SOCKS5 (RFC 1928), with the username/password method of RFC 1929.

static bool read_exact(Socket& sock, unsigned char* buf, std::size_t n, int timeoutMs) {
    std::size_t got = 0;
    while (got < n) {
        if (!sock.wait_readable(timeoutMs)) return false;
        int ret = sock.read(reinterpret_cast<char*>(buf) + got, static_cast<int>(n - got));
        if (ret <= 0) return false;   // 0 is the proxy closing the connection
        got += static_cast<std::size_t>(ret);
    }
    return true;
}

static std::string_view socks5_reply_text(unsigned char code) {
    switch (code) {
        case 1: return "general failure";
        case 2: return "connection not allowed by ruleset";
        case 3: return "network unreachable";
        case 4: return "host unreachable";
        case 5: return "connection refused";
        case 6: return "TTL expired";
        case 7: return "command not supported";
        case 8: return "address type not supported";
    }
    return "unknown error";
}

// Returns an error message, or an empty string once the proxy has connected to
// the target and the stream is the tunnel.
static std::string socks5_connect(Socket& sock, const ProxyConfig& proxy,
                                  std::string_view host, int port, int timeoutMs) {
    const bool remoteDns = proxy.scheme == "socks5h";
    const std::string hostStr(host);

    // Everything that can be refused before a byte is sent is refused first.
    if (proxy.hasCredentials && (proxy.user.size() > 255 || proxy.password.size() > 255)) {
        return "proxy: SOCKS5 credentials are limited to 255 bytes each";
    }
    // An address literal is always sent as an address; a name is sent as a name
    // for socks5h and resolved here for socks5.
    auto address = Socket::resolve_address(hostStr.c_str(), /*numericOnly=*/true);
    if (address.empty() && remoteDns) {
        if (host.empty() || host.size() > 255) return "proxy: host name does not fit a SOCKS5 request";
    } else if (address.empty()) {
        address = Socket::resolve_address(hostStr.c_str());
        if (address.empty()) return "proxy: could not resolve " + hostStr;
    }

    std::string greeting = proxy.hasCredentials ? std::string("\x05\x02\x00\x02", 4)
                                                : std::string("\x05\x01\x00", 3);
    if (!write_all(sock, greeting, timeoutMs)) return "proxy: could not send the SOCKS5 greeting";

    unsigned char choice[2];
    if (!read_exact(sock, choice, 2, timeoutMs)) return "proxy: no SOCKS5 response";
    if (choice[0] != 5) return "proxy: not a SOCKS5 proxy";
    if (choice[1] == 0xFF) {
        return proxy.hasCredentials
            ? "proxy: SOCKS5 proxy accepts neither no authentication nor a username and password"
            : "proxy requires credentials: no acceptable SOCKS5 authentication method";
    }
    if (choice[1] == 2 && proxy.hasCredentials) {
        std::string auth = "\x01";
        auth += static_cast<char>(proxy.user.size());
        auth += proxy.user;
        auth += static_cast<char>(proxy.password.size());
        auth += proxy.password;
        unsigned char status[2];
        if (!write_all(sock, auth, timeoutMs) || !read_exact(sock, status, 2, timeoutMs)) {
            return "proxy: no response to the SOCKS5 username and password";
        }
        if (status[1] != 0) return "proxy rejected the credentials (SOCKS5 status " + std::to_string(status[1]) + ")";
    } else if (choice[1] != 0) {
        return "proxy: SOCKS5 proxy chose an authentication method that was not offered";
    }

    std::string request("\x05\x01\x00", 3);
    if (address.empty()) {
        request += '\x03';
        request += static_cast<char>(host.size());
        request += host;
    } else {
        request += address.size() == 4 ? '\x01' : '\x04';
        request.append(reinterpret_cast<const char*>(address.data()), address.size());
    }
    request += static_cast<char>(port >> 8);
    request += static_cast<char>(port & 0xFF);
    if (!write_all(sock, request, timeoutMs)) return "proxy: could not send the SOCKS5 request";

    unsigned char reply[4];
    if (!read_exact(sock, reply, 4, timeoutMs)) return "proxy: no SOCKS5 reply to the request";
    if (reply[0] != 5) return "proxy: not a SOCKS5 proxy";
    if (reply[1] != 0) {
        return "proxy refused CONNECT: " + std::string(socks5_reply_text(reply[1]))
             + " (SOCKS5 reply " + std::to_string(reply[1]) + ")";
    }

    // The bound address and port: nothing to use, but they are on the stream
    // ahead of the tunnel and have to be read off it.
    std::size_t bound = 0;
    if (reply[3] == 1) {
        bound = 4;
    } else if (reply[3] == 4) {
        bound = 16;
    } else if (reply[3] == 3) {
        unsigned char len;
        if (!read_exact(sock, &len, 1, timeoutMs)) return "proxy: SOCKS5 reply was cut short";
        bound = len;
    } else {
        return "proxy: SOCKS5 reply has an unknown address type";
    }
    unsigned char rest[258];
    if (!read_exact(sock, rest, bound + 2, timeoutMs)) return "proxy: SOCKS5 reply was cut short";
    return {};
}

// A connection to the target through a proxy. `error` is empty exactly when the
// tunnel is open; otherwise it says what the proxy did, in words fit for a
// caller to log.
//
// The tunnel is `socket`, except for an https:// proxy, where it is the TLS
// session to the proxy, `proxyTls`, and `socket` is unused.
export struct ProxyTunnel {
    Socket socket;
    std::unique_ptr<TlsSocket> proxyTls;
    std::string error;

    [[nodiscard]] bool ok() const {
        return error.empty() && (proxyTls ? proxyTls->is_valid() : socket.is_valid());
    }
};

// `verifySsl` is for the connection to an https:// proxy, and is the same
// setting that governs the connection to the target.
export ProxyTunnel proxy_tunnel(const ProxyConfig& proxy,
                                std::string_view targetHost, int targetPort,
                                int timeoutMs, bool verifySsl = true,
                                std::stop_token stop = {}) {
    ProxyTunnel tunnel;
    tunnel.socket.set_stop(stop);
    const std::string where = proxy.host + ":" + std::to_string(proxy.port);

    if (proxy.scheme == "http" || proxy.scheme == "socks5" || proxy.scheme == "socks5h") {
        if (!tunnel.socket.connect(proxy.host.c_str(), proxy.port, timeoutMs)) {
            tunnel.error = "proxy: could not connect to " + where;
            return tunnel;
        }
        tunnel.error = proxy.scheme == "http"
            ? http_connect(tunnel.socket, proxy, targetHost, targetPort, timeoutMs)
            : socks5_connect(tunnel.socket, proxy, targetHost, targetPort, timeoutMs);
        if (!tunnel.error.empty()) tunnel.socket.close();
    } else if (proxy.scheme == "https") {
        auto tls = std::make_unique<TlsSocket>();
        tls->set_stop(stop);
        if (!tls->connect(proxy.host.c_str(), proxy.port, timeoutMs, verifySsl)) {
            // The session says why when the TCP connection was up, which is
            // where a proxy certificate that does not verify is refused.
            tunnel.error = "proxy: could not open a TLS connection to " + where;
            if (!tls->error().empty()) tunnel.error += ": " + tls->error();
            return tunnel;
        }
        tunnel.error = http_connect(*tls, proxy, targetHost, targetPort, timeoutMs);
        if (tunnel.error.empty()) tunnel.proxyTls = std::move(tls);
    } else {
        tunnel.error = "proxy: unsupported scheme '" + proxy.scheme + "'";
    }
    return tunnel;
}

// The original entry point, kept for callers outside this repository. It cannot
// say why it failed; `proxy_tunnel` can.
export Socket proxy_connect(std::string_view proxyHost, int proxyPort,
                            std::string_view targetHost, int targetPort,
                            int timeoutMs, std::stop_token stop = {}) {
    ProxyConfig proxy;
    proxy.host = std::string(proxyHost);
    proxy.port = proxyPort;
    auto tunnel = proxy_tunnel(proxy, targetHost, targetPort, timeoutMs, true, stop);
    return std::move(tunnel.socket);
}

} // namespace mcpplibs::tinyhttps
