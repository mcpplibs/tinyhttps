module;

#include <cstdio>

export module mcpplibs.tinyhttps:ca_bundle;

import std;

namespace mcpplibs::tinyhttps {

namespace {

auto read_file(const char* path) -> std::string {
    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
        return {};
    }
    std::string result;
    char buf[4096];
    while (auto n = std::fread(buf, 1, sizeof(buf), f)) {
        result.append(buf, n);
    }
    std::fclose(f);
    return result;
}

} // anonymous namespace

export auto load_ca_certs() -> std::string {
    // Try known system CA paths
    static constexpr const char* ca_paths[] = {
        "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/CentOS
        "/etc/ssl/cert.pem",                   // macOS / general
    };

    for (auto* path : ca_paths) {
        auto pem = read_file(path);
        if (!pem.empty()) {
            return pem;
        }
    }

    // No system certs found — return empty.
    // A production build could embed a Mozilla CA root bundle here.
    return {};
}

} // namespace mcpplibs::tinyhttps
