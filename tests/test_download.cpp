// Test must include gtest before import std to avoid GCC module redefinition errors
#include <gtest/gtest.h>

import mcpplibs.tinyhttps;
import std;

namespace https = mcpplibs::tinyhttps;

TEST(ChunkedProtocol, RejectsEmptyInvalidAndOverflowSizeLines) {
    EXPECT_FALSE(https::parse_chunk_size_line("").has_value());
    EXPECT_FALSE(https::parse_chunk_size_line("xyz").has_value());
    EXPECT_FALSE(https::parse_chunk_size_line("1g").has_value());
    EXPECT_FALSE(https::parse_chunk_size_line("FFFFFFFFFFFFFFFF").has_value());
}

TEST(ChunkedProtocol, AcceptsValidSizeAndTerminalChunk) {
    ASSERT_TRUE(https::parse_chunk_size_line("1a").has_value());
    EXPECT_EQ(*https::parse_chunk_size_line("1a"), 26);
    ASSERT_TRUE(https::parse_chunk_size_line("0").has_value());
    EXPECT_EQ(*https::parse_chunk_size_line("0"), 0);
}

TEST(DownloadResultContract, CarriesTransferAndResponseMetadata) {
    https::DownloadToFileResult result;
    result.bytesWritten = 42;
    result.expectedBytes = 42;
    result.finalUrl = "https://example.test/final";
    result.etag = "\"abc\"";
    result.lastModified = "Wed, 21 Oct 2015 07:28:00 GMT";

    EXPECT_EQ(result.bytesWritten, 42);
    ASSERT_TRUE(result.expectedBytes.has_value());
    EXPECT_EQ(*result.expectedBytes, 42);
    EXPECT_EQ(result.finalUrl, "https://example.test/final");
    EXPECT_EQ(result.etag, "\"abc\"");
    EXPECT_FALSE(result.lastModified.empty());
}

// Test download_to_file against a real HTTPS endpoint.
// Uses httpbingo.org (a maintained httpbin work-alike) which returns known-size responses.

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
        "https://httpbingo.org/bytes/100",
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
        "https://httpbingo.org/bytes/51200",
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

    // httpbingo /redirect-to redirects to the given URL
    auto result = client.download_to_file(
        "https://httpbingo.org/redirect-to?url=https%3A%2F%2Fhttpbingo.org%2Fbytes%2F50",
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
        "https://httpbingo.org/bytes/200",
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
        "https://httpbingo.org/status/404",
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
        "https://httpbingo.org/bytes/1024",
        dest,
        [&](std::int64_t total, [[maybe_unused]] std::int64_t downloaded) {
            if (reportedTotal < 0) reportedTotal = total;
        }
    );

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    // httpbingo /bytes/N returns Content-Length: N
    EXPECT_EQ(reportedTotal, 1024);
}

// Test download_to_file_parallel against endpoints with known Range behavior.
// httpbingo.org /range/N honors Range (206) with deterministic content;
// /bytes/N ignores Range (200), which exercises the fallback path.

class ParallelDownloadTest : public ::testing::Test {
protected:
    std::filesystem::path tmpDir;

    void SetUp() override {
        https::Socket::platform_init();
        tmpDir = std::filesystem::temp_directory_path() / "tinyhttps_parallel_test";
        std::filesystem::create_directories(tmpDir);
    }
    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
    }
};

TEST_F(ParallelDownloadTest, SegmentedResultMatchesSequential) {
    const std::string url = "https://httpbingo.org/range/65536";

    https::HttpClient seqClient({});
    auto seqDest = tmpDir / "seq.bin";
    auto seq = seqClient.download_to_file(url, seqDest);
    ASSERT_TRUE(seq.ok()) << "Sequential error: " << seq.error;

    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.maxConnectionsPerFile = 4;
    cfg.minSegmentBytes = 1024;  // small so test files actually split
    https::HttpClient parClient(cfg);

    auto parDest = tmpDir / "par.bin";
    auto par = parClient.download_to_file_parallel(url, parDest);
    ASSERT_TRUE(par.ok()) << "Parallel error: " << par.error;

    EXPECT_EQ(par.bytesWritten, 65536);
    ASSERT_TRUE(par.expectedBytes.has_value());
    EXPECT_EQ(*par.expectedBytes, 65536);
    EXPECT_EQ(std::filesystem::file_size(parDest), 65536u);

    std::ifstream seqFile(seqDest, std::ios::binary);
    std::ifstream parFile(parDest, std::ios::binary);
    std::string seqContent{ std::istreambuf_iterator<char>(seqFile),
                            std::istreambuf_iterator<char>() };
    std::string parContent{ std::istreambuf_iterator<char>(parFile),
                            std::istreambuf_iterator<char>() };
    EXPECT_EQ(parContent, seqContent)
        << "Segmented download content differs from sequential";
}

TEST_F(ParallelDownloadTest, MoreSegmentsThanConnections) {
    // maxSegments decoupled from connection count (aria2 -s): 16 segments
    // pulled by only 2 workers.
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.maxConnectionsPerFile = 2;
    cfg.maxSegments = 16;
    cfg.minSegmentBytes = 1024;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "decoupled.bin";
    auto result = client.download_to_file_parallel(
        "https://httpbingo.org/range/32768", dest);

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    EXPECT_EQ(result.bytesWritten, 32768);
    EXPECT_EQ(std::filesystem::file_size(dest), 32768u);
}

TEST_F(ParallelDownloadTest, ProgressIsMonotonic) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.maxConnectionsPerFile = 4;
    cfg.minSegmentBytes = 1024;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "monotonic.bin";
    std::vector<std::int64_t> values;
    std::int64_t reportedTotal = -1;

    auto result = client.download_to_file_parallel(
        "https://httpbingo.org/range/131072",
        dest,
        [&](std::int64_t total, std::int64_t downloaded) {
            reportedTotal = total;
            values.push_back(downloaded);
        }
    );

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    EXPECT_EQ(reportedTotal, 131072);
    ASSERT_FALSE(values.empty());
    EXPECT_EQ(values.back(), 131072);
    for (std::size_t i = 1; i < values.size(); ++i) {
        EXPECT_GT(values[i], values[i - 1])
            << "Parallel progress not monotonic at index " << i;
    }
}

TEST_F(ParallelDownloadTest, FallsBackWhenServerIgnoresRange) {
    // /bytes/N does not honor Range — probe gets 200 and the body is
    // streamed out over the single probe connection.
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.maxConnectionsPerFile = 4;
    cfg.minSegmentBytes = 1024;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "fallback.bin";
    auto result = client.download_to_file_parallel(
        "https://httpbingo.org/bytes/4096", dest);

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    EXPECT_EQ(result.statusCode, 200);
    EXPECT_EQ(result.bytesWritten, 4096);
    EXPECT_EQ(std::filesystem::file_size(dest), 4096u);
}

TEST_F(ParallelDownloadTest, SmallFileFallsBackToSequential) {
    // File smaller than minSegmentBytes — not worth splitting.
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.maxConnectionsPerFile = 4;
    cfg.minSegmentBytes = 1 << 20;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "small.bin";
    auto result = client.download_to_file_parallel(
        "https://httpbingo.org/range/2048", dest);

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    EXPECT_EQ(result.statusCode, 200);
    EXPECT_EQ(result.bytesWritten, 2048);
}

TEST_F(ParallelDownloadTest, FollowsRedirectBeforeSegmenting) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.maxConnectionsPerFile = 4;
    cfg.minSegmentBytes = 1024;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "redirected.bin";
    auto result = client.download_to_file_parallel(
        "https://httpbingo.org/redirect-to?url=https%3A%2F%2Fhttpbingo.org%2Frange%2F8192",
        dest);

    ASSERT_TRUE(result.ok()) << "Error: " << result.error;
    EXPECT_EQ(result.bytesWritten, 8192);
    EXPECT_EQ(result.finalUrl, "https://httpbingo.org/range/8192");
}

TEST_F(ParallelDownloadTest, CancellationAbortsWorkers) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    cfg.maxConnectionsPerFile = 4;
    cfg.minSegmentBytes = 1024;
    https::HttpClient client(cfg);

    auto dest = tmpDir / "cancelled.bin";
    auto result = client.download_to_file_parallel(
        "https://httpbingo.org/range/524288",  // httpbingo /range caps at 512KiB
        dest,
        nullptr,
        [] { return true; }  // cancel immediately
    );

    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.error, "cancelled");
}
