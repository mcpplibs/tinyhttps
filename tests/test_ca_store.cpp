// The trust store the platform supplies is found with nothing configured, and a
// public certificate chain verifies against it.
//
// On a Windows Sockets build the store is the system's ROOT store, read through
// the Win32 API; elsewhere it is a bundle file at one of the known locations.
// Either way a default-constructed client verifies a public server. A host that
// cannot be reached is a skip, so a runner without egress reports "not run"; a
// certificate the client refused is a failure.
#include <gtest/gtest.h>

#include <cstdlib>

import mcpplibs.tinyhttps;
import std;

namespace https = mcpplibs::tinyhttps;

TEST(SystemStore, IsFoundWithNothingConfigured) {
    if (const char* file = std::getenv("SSL_CERT_FILE"); file && *file) {
        GTEST_SKIP() << "SSL_CERT_FILE is set, so the system store is not consulted";
    }
    const auto pem = https::load_ca_certs();
    EXPECT_FALSE(pem.empty());
    EXPECT_NE(pem.find("-----BEGIN CERTIFICATE-----"), std::string::npos);
}

TEST(SystemStore, APublicChainVerifiesAgainstIt) {
    https::Socket::platform_init();
    https::HttpClientConfig config;
    config.connectTimeoutMs = 15000;
    config.readTimeoutMs = 20000;
    https::HttpClient client{config};

    https::HttpRequest request;
    request.url = "https://one.one.one.one/";
    const auto response = client.send(request);

    if (response.statusCode == 0 && response.statusText == "Connection failed") {
        GTEST_SKIP() << "one.one.one.one is not reachable from this runner";
    }
    EXPECT_NE(response.statusCode, 0) << response.statusText;
}
