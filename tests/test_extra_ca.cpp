// `HttpClientConfig::extraCaFile` adds roots to the default trust store.
//
// The default store is whatever SSL_CERT_FILE names, so each test writes the
// bundles it needs to temp files and the machine's own store never enters into
// it. The servers present leaves signed by two private CAs (extra_ca_certs.hpp);
// nothing leaves 127.0.0.1.
#include <gtest/gtest.h>
#include "extra_ca_certs.hpp"
#include "tls_test_server.hpp"

#include <cstdlib>

import mcpplibs.tinyhttps;
import std;

namespace https = mcpplibs::tinyhttps;
namespace pki = extra_ca_test;

namespace {

void set_env(const char* name, const char* value) {
#ifdef TINYHTTPS_WINSOCK
    _putenv_s(name, value);
#else
    ::setenv(name, value, 1);
#endif
}

class ExtraCaTest : public ::testing::Test {
protected:
    void SetUp() override {
        https::Socket::platform_init();
        const char* old = std::getenv("SSL_CERT_FILE");
        hadOld_ = old != nullptr;
        if (hadOld_) old_ = old;
    }

    void TearDown() override {
        set_env("SSL_CERT_FILE", hadOld_ ? old_.c_str() : "");
        std::error_code ec;
        for (auto& path : files_) std::filesystem::remove(path, ec);
    }

    // Writes `content` to a new temp file and returns its path.
    std::string write_file(std::string_view content) {
        auto path = std::filesystem::temp_directory_path()
                  / ("tinyhttps-extra-ca-"
                     + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
                     + "-" + std::to_string(files_.size()) + ".pem");
        std::ofstream(path, std::ios::binary) << content;
        files_.push_back(path);
        return path.string();
    }

    // Makes `content` the whole default store.
    void default_store(std::string_view content) {
        set_env("SSL_CERT_FILE", write_file(content).c_str());
    }

    static https::HttpClientConfig config(std::string extraCaFile = {}) {
        https::HttpClientConfig cfg;   // verifySsl is true by default
        cfg.connectTimeoutMs = 4000;
        cfg.readTimeoutMs = 2000;
        cfg.extraCaFile = std::move(extraCaFile);
        return cfg;
    }

    static https::HttpResponse get(const https::HttpClientConfig& cfg, const std::string& url) {
        https::HttpClient client(cfg);
        https::HttpRequest req;
        req.url = url;
        return client.send(req);
    }

private:
    std::vector<std::filesystem::path> files_;
    std::string old_;
    bool hadOld_ { false };
};

bool answer_ok(tls_test::Conn& conn, int) {
    conn.write(tls_test::ok_response("ok"));
    return true;
}

tls_test::Server server_of_ca1() {
    return tls_test::Server(answer_ok, pki::kLeaf1Pem, pki::kLeaf1KeyPem);
}

tls_test::Server server_of_ca2() {
    return tls_test::Server(answer_ok, pki::kLeaf2Pem, pki::kLeaf2KeyPem);
}

} // namespace

TEST_F(ExtraCaTest, APrivateCaIsNotTrustedWithoutTheFile) {
    auto server = server_of_ca1();
    ASSERT_FALSE(server.failed());
    default_store(tls_test::kCertPem);   // a store that does not contain CA 1

    auto r = get(config(), server.url("/"));
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_NE(r.statusText.find("not correctly signed by the trusted CA"), std::string::npos)
        << r.statusText;
}

TEST_F(ExtraCaTest, APrivateCaIsTrustedWithTheFile) {
    auto server = server_of_ca1();
    ASSERT_FALSE(server.failed());
    default_store(tls_test::kCertPem);

    auto r = get(config(write_file(pki::kCa1Pem)), server.url("/"));
    EXPECT_EQ(r.statusCode, 200) << r.statusText;
    EXPECT_EQ(r.body, "ok");
}

// The file adds to the default store; it does not replace it.
TEST_F(ExtraCaTest, TheDefaultStoreStaysInEffect) {
    auto fromDefault = server_of_ca1();
    auto fromExtra = server_of_ca2();
    auto neither = tls_test::Server(answer_ok);   // self-signed, in no store
    ASSERT_FALSE(fromDefault.failed());
    ASSERT_FALSE(fromExtra.failed());
    ASSERT_FALSE(neither.failed());
    default_store(pki::kCa1Pem);
    auto cfg = config(write_file(pki::kCa2Pem));

    EXPECT_EQ(get(cfg, fromDefault.url("/")).statusCode, 200);
    EXPECT_EQ(get(cfg, fromExtra.url("/")).statusCode, 200);
    EXPECT_EQ(get(cfg, neither.url("/")).statusCode, 0);
}

TEST_F(ExtraCaTest, AFileHoldingSeveralCertificatesTrustsAllOfThem) {
    auto a = server_of_ca1();
    auto b = server_of_ca2();
    ASSERT_FALSE(a.failed());
    ASSERT_FALSE(b.failed());
    default_store(tls_test::kCertPem);
    auto cfg = config(write_file(std::string(pki::kCa1Pem) + pki::kCa2Pem));

    EXPECT_EQ(get(cfg, a.url("/")).statusCode, 200);
    EXPECT_EQ(get(cfg, b.url("/")).statusCode, 200);
}

// Both hops of a request through an https:// proxy use the file: the proxy's
// certificate comes from CA 2, which only the file names, and the target's from
// CA 1, which only the default store names.
TEST_F(ExtraCaTest, TheHopToAnHttpsProxyUsesTheFileToo) {
    auto target = server_of_ca1();
    ASSERT_FALSE(target.failed());
    const int targetPort = target.port();
    auto proxy = tls_test::Server([targetPort](tls_test::Conn& conn, int) {
        conn.write("HTTP/1.1 200 Connection established\r\n\r\n");
        conn.relay_to(targetPort);
        return false;
    }, pki::kLeaf2Pem, pki::kLeaf2KeyPem);
    ASSERT_FALSE(proxy.failed());
    default_store(pki::kCa1Pem);

    auto cfg = config(write_file(pki::kCa2Pem));
    cfg.proxy = "https://127.0.0.1:" + std::to_string(proxy.port());
    auto r = get(cfg, target.url("/"));
    EXPECT_EQ(r.statusCode, 200) << r.statusText;

    cfg.extraCaFile.clear();
    r = get(cfg, target.url("/"));
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_TRUE(r.statusText.starts_with("proxy: could not open a TLS connection to 127.0.0.1:"))
        << r.statusText;
    EXPECT_NE(r.statusText.find("certificate verification failed"), std::string::npos)
        << r.statusText;
}

TEST_F(ExtraCaTest, AFileThatDoesNotExistIsReportedWithItsPath) {
    auto server = server_of_ca1();
    ASSERT_FALSE(server.failed());
    default_store(pki::kCa1Pem);   // the server would verify without the file
    const auto missing = (std::filesystem::temp_directory_path() / "tinyhttps-no-such-ca.pem").string();

    auto r = get(config(missing), server.url("/"));
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_NE(r.statusText.find("cannot read extra CA file '" + missing + "'"), std::string::npos)
        << r.statusText;
}

TEST_F(ExtraCaTest, AFileThatIsNotPemIsReportedWithItsPath) {
    auto server = server_of_ca1();
    ASSERT_FALSE(server.failed());
    default_store(pki::kCa1Pem);
    const auto path = write_file("this is not a certificate\n");

    auto r = get(config(path), server.url("/"));
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_NE(r.statusText.find("extra CA file '" + path + "'"), std::string::npos)
        << r.statusText;
}

TEST_F(ExtraCaTest, AFileWhoseCertificateCannotBeParsedIsReportedWithItsPath) {
    auto server = server_of_ca1();
    ASSERT_FALSE(server.failed());
    default_store(pki::kCa1Pem);
    const auto path = write_file("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");

    auto r = get(config(path), server.url("/"));
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_NE(r.statusText.find("extra CA file '" + path + "'"), std::string::npos)
        << r.statusText;
}

TEST_F(ExtraCaTest, AnEmptyFileIsReportedWithItsPath) {
    auto server = server_of_ca1();
    ASSERT_FALSE(server.failed());
    default_store(pki::kCa1Pem);
    const auto path = write_file("");

    auto r = get(config(path), server.url("/"));
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_NE(r.statusText.find("extra CA file '" + path + "'"), std::string::npos)
        << r.statusText;
}

// The file is checked whether or not the server would be verified.
TEST_F(ExtraCaTest, AFileThatCannotBeUsedFailsEvenWithoutVerification) {
    auto server = server_of_ca1();
    ASSERT_FALSE(server.failed());
    default_store(pki::kCa1Pem);
    const auto path = write_file("not a certificate\n");

    auto cfg = config(path);
    cfg.verifySsl = false;
    auto r = get(cfg, server.url("/"));
    EXPECT_EQ(r.statusCode, 0);
    EXPECT_NE(r.statusText.find("extra CA file '" + path + "'"), std::string::npos)
        << r.statusText;
}

// SSL_CERT_FILE keeps its meaning when the field is unset.
TEST_F(ExtraCaTest, WithoutTheFieldNothingChanges) {
    auto server = server_of_ca1();
    ASSERT_FALSE(server.failed());
    default_store(pki::kCa1Pem);
    EXPECT_EQ(get(config(), server.url("/")).statusCode, 200);
}
