// A client with `verifySsl = true` refuses a server certificate it cannot trust.
//
// Each test serves one certificate from the in-process TLS server and trusts it
// (or not) by pointing SSL_CERT_FILE at a bundle written for the test, so the
// machine's own CA store never enters into it and nothing leaves 127.0.0.1.
// The certificates in tls_test_server.hpp are self-signed, which lets a trusted
// one be its own bundle and lets the expired and wrong-name ones differ from it
// in that one respect only.
#include <gtest/gtest.h>
#include "tls_test_server.hpp"

#include <cstdlib>

import mcpplibs.tinyhttps;
import std;

namespace https = mcpplibs::tinyhttps;

namespace {

void set_env(const char* name, const char* value) {
#ifdef TINYHTTPS_WINSOCK
    _putenv_s(name, value);
#else
    ::setenv(name, value, 1);
#endif
}

class TlsVerifyTest : public ::testing::Test {
protected:
    void SetUp() override {
        https::Socket::platform_init();
        const char* old = std::getenv("SSL_CERT_FILE");
        hadOld_ = old != nullptr;
        if (hadOld_) old_ = old;
        bundle_ = std::filesystem::temp_directory_path()
                / ("tinyhttps-verify-"
                   + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
                   + ".pem");
    }

    void TearDown() override {
        set_env("SSL_CERT_FILE", hadOld_ ? old_.c_str() : "");
        std::error_code ec;
        std::filesystem::remove(bundle_, ec);
    }

    // Makes `content` the only CA bundle the client will read.
    void trust(std::string_view content) {
        std::ofstream(bundle_, std::ios::binary) << content;
        set_env("SSL_CERT_FILE", bundle_.string().c_str());
    }

    https::HttpResponse get(const tls_test::Server& server) {
        https::HttpClientConfig cfg;   // verifySsl is true by default
        cfg.connectTimeoutMs = 4000;
        cfg.readTimeoutMs = 2000;
        https::HttpClient client(cfg);
        https::HttpRequest req;
        req.url = server.url("/");
        return client.send(req);
    }

private:
    std::filesystem::path bundle_;
    std::string old_;
    bool hadOld_ { false };
};

bool answer_ok(tls_test::Conn& conn, int) {
    conn.write(tls_test::ok_response("ok"));
    return true;
}

} // namespace

TEST_F(TlsVerifyTest, ACertificateIssuedByATrustedCaIsAccepted) {
    tls_test::Server server(answer_ok);
    ASSERT_FALSE(server.failed());
    trust(tls_test::kCertPem);

    auto r = get(server);
    EXPECT_EQ(r.statusCode, 200) << r.statusText;
    EXPECT_EQ(r.body, "ok");
}

TEST_F(TlsVerifyTest, ACertificateNoTrustedCaIssuedIsRefused) {
    tls_test::Server server(answer_ok);
    ASSERT_FALSE(server.failed());
    trust(tls_test::kWrongNameCertPem);   // a bundle that does not contain the server's

    auto r = get(server);
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_NE(r.statusText.find("certificate verification failed"), std::string::npos)
        << r.statusText;
    EXPECT_NE(r.statusText.find("not correctly signed by the trusted CA"), std::string::npos)
        << r.statusText;
}

TEST_F(TlsVerifyTest, AnExpiredCertificateIsRefused) {
    tls_test::Server server(answer_ok, tls_test::kExpiredCertPem, tls_test::kExpiredKeyPem);
    ASSERT_FALSE(server.failed());
    trust(tls_test::kExpiredCertPem);

    auto r = get(server);
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_NE(r.statusText.find("expired"), std::string::npos) << r.statusText;
}

TEST_F(TlsVerifyTest, ACertificateForAnotherHostnameIsRefused) {
    tls_test::Server server(answer_ok, tls_test::kWrongNameCertPem, tls_test::kWrongNameKeyPem);
    ASSERT_FALSE(server.failed());
    trust(tls_test::kWrongNameCertPem);

    auto r = get(server);
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_NE(r.statusText.find("does not match"), std::string::npos) << r.statusText;
}

TEST_F(TlsVerifyTest, ABundleThatCannotBeParsedIsReportedAsSuch) {
    tls_test::Server server(answer_ok);
    ASSERT_FALSE(server.failed());
    trust("this is not a certificate\n");

    auto r = get(server);
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_NE(r.statusText.find("cannot parse the CA certificate bundle"), std::string::npos)
        << r.statusText;
}

TEST_F(TlsVerifyTest, VerificationCanStillBeTurnedOff) {
    tls_test::Server server(answer_ok, tls_test::kExpiredCertPem, tls_test::kExpiredKeyPem);
    ASSERT_FALSE(server.failed());
    trust(tls_test::kWrongNameCertPem);

    https::HttpClientConfig cfg;
    cfg.verifySsl = false;
    cfg.connectTimeoutMs = 4000;
    https::HttpClient client(cfg);
    https::HttpRequest req;
    req.url = server.url("/");
    EXPECT_EQ(client.send(req).statusCode, 200);
}
