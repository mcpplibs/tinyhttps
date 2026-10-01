module;

#include <cstdio>

// The same switch as socket.cppm. The store is read through the Win32 API, whose
// headers a build on the POSIX socket interface does not have.
#if defined(_WIN32) && !defined(TINYHTTPS_POSIX_SOCKETS)
#define TINYHTTPS_WINSOCK 1
#endif

#ifdef TINYHTTPS_WINSOCK
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#endif

export module mcpplibs.tinyhttps:ca_bundle;

import std;
import :platform;

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

#ifdef TINYHTTPS_WINSOCK
// Whether the root may be used to authenticate a server: no usage restriction at
// all, or serverAuth listed. Windows marks roots it no longer trusts for TLS
// servers through this restriction, and the store still holds them.
auto trusted_for_servers(const CERT_CONTEXT* c) -> bool {
    DWORD n = 0;
    if (!::CertGetEnhancedKeyUsage(c, 0, nullptr, &n)) {
        return false;
    }
    std::vector<std::byte> buf(n);
    auto* usage = reinterpret_cast<CERT_ENHKEY_USAGE*>(buf.data());
    if (!::CertGetEnhancedKeyUsage(c, 0, usage, &n)) {
        return false;
    }
    if (usage->cUsageIdentifier == 0) {
        // CRYPT_E_NOT_FOUND means no restriction; otherwise the root allows no use.
        return ::GetLastError() == CRYPT_E_NOT_FOUND;
    }
    for (DWORD i = 0; i < usage->cUsageIdentifier; ++i) {
        if (std::strcmp(usage->rgpszUsageIdentifier[i], szOID_PKIX_KP_SERVER_AUTH) == 0) {
            return true;
        }
    }
    return false;
}
#endif

// The Windows ROOT store as one PEM string; empty elsewhere or on failure.
auto system_store_pem() -> std::string {
    std::string pem;
#ifdef TINYHTTPS_WINSOCK
    if (HCERTSTORE store = ::CertOpenSystemStoreW(0, L"ROOT")) {
        for (const CERT_CONTEXT* c = nullptr; (c = ::CertEnumCertificatesInStore(store, c));) {
            if (!trusted_for_servers(c)) {
                continue;
            }
            DWORD n = 0;
            if (!::CryptBinaryToStringA(c->pbCertEncoded, c->cbCertEncoded,
                                        CRYPT_STRING_BASE64HEADER, nullptr, &n)) {
                continue;
            }
            std::string one(n, '\0');
            if (::CryptBinaryToStringA(c->pbCertEncoded, c->cbCertEncoded,
                                       CRYPT_STRING_BASE64HEADER, one.data(), &n)) {
                pem.append(one, 0, n);
            }
        }
        ::CertCloseStore(store, 0);
    }
#endif
    return pem;
}

} // anonymous namespace

export auto load_ca_certs() -> std::string {
    // 1. SSL_CERT_FILE — the OpenSSL/curl convention and an explicit escape
    //    hatch. Relocatable distros (Termux, Nix, conda) set it because their
    //    bundle isn't under /etc.
    if (const char* env = std::getenv("SSL_CERT_FILE"); env && *env) {
        auto pem = read_file(env);
        if (!pem.empty()) {
            return pem;
        }
    }

    // Windows has no bundle file; read the system's trusted roots instead.
    if constexpr (platform::uses_winsock) {
        if (auto pem = system_store_pem(); !pem.empty()) {
            return pem;
        }
    }

    std::vector<std::string> ca_paths;

    // 2. Non-FHS prefixes (Termux et al. ship the bundle under $PREFIX). Probed
    //    before /etc so a Termux session — where /etc/ssl doesn't exist and TLS
    //    otherwise fails with "Connection failed" on every HTTPS fetch — works.
    if (const char* prefix = std::getenv("PREFIX"); prefix && *prefix) {
        ca_paths.emplace_back(std::string(prefix) + "/etc/tls/cert.pem");
        ca_paths.emplace_back(std::string(prefix) + "/etc/ssl/cert.pem");
    }
    // Default Termux prefix, in case PREFIX is unset (e.g. under su / cron).
    ca_paths.emplace_back("/data/data/com.termux/files/usr/etc/tls/cert.pem");

    // 3. Known system CA bundle locations.
    ca_paths.emplace_back("/etc/ssl/certs/ca-certificates.crt"); // Debian/Ubuntu
    ca_paths.emplace_back("/etc/pki/tls/certs/ca-bundle.crt");   // RHEL/CentOS
    ca_paths.emplace_back("/etc/ssl/cert.pem");                  // macOS / Alpine

    for (auto& path : ca_paths) {
        auto pem = read_file(path.c_str());
        if (!pem.empty()) {
            return pem;
        }
    }

    // No system certs found — return empty.
    // A production build could embed a Mozilla CA root bundle here.
    return {};
}

} // namespace mcpplibs::tinyhttps
