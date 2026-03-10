export module mcpplibs.tinyhttps:proxy;

import :socket;
import std;

namespace mcpplibs::tinyhttps {

export struct ProxyConfig {
    std::string host;
    int port { 8080 };
};

// Parse "http://host:port" proxy URL
export ProxyConfig parse_proxy_url(std::string_view url) {
    ProxyConfig config;

    // Strip scheme if present
    auto schemeEnd = url.find("://");
    if (schemeEnd != std::string_view::npos) {
        url = url.substr(schemeEnd + 3);
    }

    // Strip trailing path if present
    auto pathStart = url.find('/');
    if (pathStart != std::string_view::npos) {
        url = url.substr(0, pathStart);
    }

    // Check for port
    auto colonPos = url.find(':');
    if (colonPos != std::string_view::npos) {
        config.host = std::string(url.substr(0, colonPos));
        auto portStr = url.substr(colonPos + 1);
        config.port = 0;
        for (char c : portStr) {
            if (c >= '0' && c <= '9') {
                config.port = config.port * 10 + (c - '0');
            }
        }
    } else {
        config.host = std::string(url);
        config.port = 8080;
    }

    return config;
}

// Read a line (ending with \r\n) from a plain Socket
static std::string read_line_plain(Socket& sock, int timeoutMs) {
    std::string line;
    char c;
    while (true) {
        if (!sock.wait_readable(timeoutMs)) {
            break;
        }
        int ret = sock.read(&c, 1);
        if (ret < 0) break;
        if (ret == 0) {
            if (!sock.wait_readable(timeoutMs)) break;
            ret = sock.read(&c, 1);
            if (ret <= 0) break;
        }
        line += c;
        if (line.size() >= 2 && line[line.size() - 2] == '\r' && line[line.size() - 1] == '\n') {
            line.resize(line.size() - 2);
            break;
        }
    }
    return line;
}

// Write all data to a plain Socket
static bool write_all_plain(Socket& sock, const std::string& data) {
    int total = 0;
    int len = static_cast<int>(data.size());
    while (total < len) {
        int ret = sock.write(data.c_str() + total, len - total);
        if (ret < 0) return false;
        if (ret == 0) {
            ret = sock.write(data.c_str() + total, len - total);
            if (ret <= 0) return false;
        }
        total += ret;
    }
    return true;
}

// Connect through HTTP CONNECT proxy, returning a Socket connected to target through tunnel.
// On failure, returns an invalid (closed) Socket.
export Socket proxy_connect(std::string_view proxyHost, int proxyPort,
                            std::string_view targetHost, int targetPort,
                            int timeoutMs) {
    Socket sock;

    // Step 1: Connect to proxy
    std::string proxyHostStr(proxyHost);
    if (!sock.connect(proxyHostStr.c_str(), proxyPort, timeoutMs)) {
        return sock;
    }

    // Step 2: Send CONNECT request
    std::string request = "CONNECT ";
    request += targetHost;
    request += ":";
    request += std::to_string(targetPort);
    request += " HTTP/1.1\r\nHost: ";
    request += targetHost;
    request += ":";
    request += std::to_string(targetPort);
    request += "\r\n\r\n";

    if (!write_all_plain(sock, request)) {
        sock.close();
        return sock;
    }

    // Step 3: Read response status line
    std::string statusLine = read_line_plain(sock, timeoutMs);
    if (statusLine.empty()) {
        sock.close();
        return sock;
    }

    // Parse status code from "HTTP/1.x 200 ..."
    int statusCode = 0;
    auto spacePos = statusLine.find(' ');
    if (spacePos != std::string::npos) {
        auto rest = std::string_view(statusLine).substr(spacePos + 1);
        for (char c : rest) {
            if (c >= '0' && c <= '9') {
                statusCode = statusCode * 10 + (c - '0');
            } else {
                break;
            }
        }
    }

    if (statusCode != 200) {
        sock.close();
        return sock;
    }

    // Step 4: Read remaining response headers until empty line
    while (true) {
        std::string headerLine = read_line_plain(sock, timeoutMs);
        if (headerLine.empty()) {
            break;
        }
    }

    // Socket is now tunneled to the target
    return sock;
}

} // namespace mcpplibs::tinyhttps
