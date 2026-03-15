// Test must include gtest before import std to avoid GCC module redefinition errors
#include <gtest/gtest.h>

import mcpplibs.tinyhttps;
import std;

namespace https = mcpplibs::tinyhttps;

// Test download_to_file against a real HTTPS endpoint.
// Uses httpbin.org which returns known-size responses.

class DownloadToFileTest : public ::testing::Test {
protected:
    std::filesystem::path tmpDir;

    void SetUp() override {
        https::Socket::platform_init();
        tmpDir = std::filesystem::temp_directory_path() / "tinyhttps_test";
        std::filesystem::create_directories(tmpDir);
    }
    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
    }
};

TEST_F(DownloadToFileTest, BasicDownloadWithProgress) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.keepAlive = false;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "test_100bytes.bin";
    std::int64_t lastTotal = -1;
    std::int64_t lastDownloaded = -1;
    int callCount = 0;

    auto result = client.download_to_file(
        "https://httpbin.org/bytes/100",
        dest,
        [&](std::int64_t total, std::int64_t downloaded) {
            lastTotal = total;
            lastDownloaded = downloaded;
            ++callCount;
        }
    );

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    EXPECT_EQ(result.statusCode, 200);
    EXPECT_EQ(result.bytesWritten, 100);
    EXPECT_TRUE(std::filesystem::exists(dest));
    EXPECT_EQ(std::filesystem::file_size(dest), 100u);
    EXPECT_GT(callCount, 0) << "Progress callback should be called at least once";
    EXPECT_EQ(lastDownloaded, 100);
    EXPECT_EQ(lastTotal, 100);
}

TEST_F(DownloadToFileTest, ProgressIncrementsMonotonically) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 60000;
    cfg.keepAlive = false;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "test_50k.bin";
    std::vector<std::int64_t> downloadedValues;

    auto result = client.download_to_file(
        "https://httpbin.org/bytes/51200",
        dest,
        [&](std::int64_t total, std::int64_t downloaded) {
            (void)total;
            downloadedValues.push_back(downloaded);
        }
    );

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    EXPECT_EQ(result.bytesWritten, 51200);

    // Progress must be monotonically increasing
    for (std::size_t i = 1; i < downloadedValues.size(); ++i) {
        EXPECT_GT(downloadedValues[i], downloadedValues[i - 1])
            << "Progress not monotonic at index " << i;
    }

    // Must have multiple progress calls for 50KB
    EXPECT_GT(downloadedValues.size(), 1u)
        << "50KB download should report progress more than once";
}

TEST_F(DownloadToFileTest, FollowsRedirects) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.keepAlive = false;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "redirected.bin";

    // httpbin /redirect-to redirects to the given URL
    auto result = client.download_to_file(
        "https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fbytes%2F50",
        dest
    );

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    EXPECT_EQ(result.bytesWritten, 50);
    EXPECT_TRUE(std::filesystem::exists(dest));
}

TEST_F(DownloadToFileTest, NoProgressCallbackStillWorks) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.keepAlive = false;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "no_progress.bin";

    auto result = client.download_to_file(
        "https://httpbin.org/bytes/200",
        dest
    );

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    EXPECT_EQ(result.bytesWritten, 200);
}

TEST_F(DownloadToFileTest, Http404ReturnsError) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.keepAlive = false;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "not_found.bin";

    auto result = client.download_to_file(
        "https://httpbin.org/status/404",
        dest
    );

    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.statusCode, 404);
}

TEST_F(DownloadToFileTest, TotalBytesKnownForContentLength) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.keepAlive = false;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "known_size.bin";
    std::int64_t reportedTotal = -1;

    auto result = client.download_to_file(
        "https://httpbin.org/bytes/1024",
        dest,
        [&](std::int64_t total, [[maybe_unused]] std::int64_t downloaded) {
            if (reportedTotal < 0) reportedTotal = total;
        }
    );

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    // httpbin /bytes/N returns Content-Length: N
    EXPECT_EQ(reportedTotal, 1024);
}
