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

// `Content-Length` decides how many bytes a reader will trust, so a wrong
// answer is not cosmetic: too small leaves the next response's bytes in the
// stream and too large waits for bytes that are not coming.
//
// Both readers used to keep the digits and discard everything else. Measured,
// by compiling that parser on its own:
//
//     "135"                  -> 135
//     "0"                    -> 0
//     "abc"                  -> 0                     <- a refusal read as a real zero
//     "12abc"                -> 12                    <- stops twelve bytes in
//     ""                     -> 0
//     "-1"                   -> 1                     <- the sign is discarded
//     "99999999999999999999" -> 7766279631452241919   <- wraps, in silence
//
// The last two are the ones no amount of care at the call site could recover
// from, because the value it receives is a plausible number.
TEST(ContentLength, AcceptsAWellFormedValue) {
    ASSERT_TRUE(https::parse_content_length("135").has_value());
    EXPECT_EQ(*https::parse_content_length("135"), 135);
    // A field value may carry optional whitespace on either side.
    ASSERT_TRUE(https::parse_content_length("  135\t").has_value());
    EXPECT_EQ(*https::parse_content_length("  135\t"), 135);
}

// The one a salvaging parser cannot express. `abc` used to yield 0, which is
// indistinguishable from a server that genuinely declared an empty body — and
// the two call for opposite behaviour.
TEST(ContentLength, AZeroIsDistinguishableFromARefusal) {
    ASSERT_TRUE(https::parse_content_length("0").has_value());
    EXPECT_EQ(*https::parse_content_length("0"), 0);
    EXPECT_FALSE(https::parse_content_length("abc").has_value());
}

TEST(ContentLength, RejectsEmptyTrailingGarbageAndOverflow) {
    EXPECT_FALSE(https::parse_content_length("").has_value());
    EXPECT_FALSE(https::parse_content_length("   ").has_value());
    // `12abc` used to be 12: the reader would then stop twelve bytes in and
    // leave the rest of the body to be read as the next response.
    EXPECT_FALSE(https::parse_content_length("12abc").has_value());
    EXPECT_FALSE(https::parse_content_length("-1").has_value());
    EXPECT_FALSE(https::parse_content_length("+1").has_value());
    // Past the width of the accumulator, which used to wrap in silence.
    EXPECT_FALSE(https::parse_content_length("99999999999999999999").has_value());
}

TEST(StreamErrorBody, KeepsEverythingWhileUnderLimit) {
    std::string buffer;
    EXPECT_TRUE(https::append_within_limit(buffer, "abc", 8));
    EXPECT_TRUE(https::append_within_limit(buffer, "de", 8));
    EXPECT_EQ(buffer, "abcde");
}

TEST(StreamErrorBody, TruncatesTheChunkThatCrossesTheLimit) {
    std::string buffer = "abc";
    EXPECT_FALSE(https::append_within_limit(buffer, "defgh", 5));
    EXPECT_EQ(buffer, "abcde");
}

TEST(StreamErrorBody, RefusesFurtherDataOnceFull) {
    std::string buffer = "abcde";
    EXPECT_FALSE(https::append_within_limit(buffer, "f", 5));
    EXPECT_EQ(buffer, "abcde");
    // A zero limit must not append anything, not even an empty append.
    std::string empty;
    EXPECT_FALSE(https::append_within_limit(empty, "a", 0));
    EXPECT_TRUE(empty.empty());
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

// Test that a failed streaming request carries its error body, against a real
// HTTPS endpoint. httpbin's /status/418 answers non-2xx with a body, which is
// exactly the shape SseParser cannot turn into events.

class StreamErrorBodyLiveTest : public ::testing::Test {
protected:
    void SetUp() override { https::Socket::platform_init(); }
};

// ON THE LIBRARY'S OWN DEFAULTS, AND THE READ TIMEOUT IS PART OF THE
// OBSERVATION RATHER THAN A SAFETY NET.
//
// The first form of this test set `keepAlive = false`, "so the server closes
// and the read loop ends". That comment was the defect: `send_stream` had no
// branch for a declared `Content-Length`, so a response that was not chunked
// was read until the connection closed — and on the defaults the server does
// not close. The body arrived, one full `readTimeoutMs` late.
//
//     keepAlive = false   status=418 body=135   elapsed  1370 ms
//     keepAlive = true    status=418 body=135   elapsed  9379 ms   (timeout 8000)
//
// So the configuration under test is the default one, and the elapsed time is
// asserted. A test that closed the connection to make the loop end would be
// examining the one arrangement in which the defect does not appear.
TEST_F(StreamErrorBodyLiveTest, FailedStreamKeepsTheErrorBody) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    // keepAlive is left at its default, which is true.
    https::HttpClient client(cfg);

    https::HttpRequest req;
    req.method = https::Method::GET;
    req.url = "https://httpbin.org/status/418";

    int events = 0;
    const auto started = std::chrono::steady_clock::now();
    auto res = client.send_stream(req, [&](const https::SseEvent&) {
        ++events;
        return true;
    });
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();

    EXPECT_EQ(res.statusCode, 418);
    EXPECT_EQ(events, 0) << "an error document is not an event stream";
    EXPECT_FALSE(res.body.empty()) << "error body was dropped";
    EXPECT_NE(res.body.find("teapot"), std::string::npos);
    // Generous against a slow runner and still an order of magnitude below the
    // read timeout, which is what the defect consumed.
    EXPECT_LT(elapsed, 15000)
        << "the body arrived after " << elapsed
        << " ms; a declared Content-Length was not honoured and the reader "
           "waited for a close that keep-alive was never going to bring";
}

// The success path, on the framing an event stream actually uses. A 2xx is not
// captured, so `body` stays empty and the bytes reach the parser — and it must
// still return promptly, since the chunked branch is the one this change did
// not restructure.
TEST_F(StreamErrorBodyLiveTest, AChunkedSuccessIsUnchangedAndPrompt) {
    https::HttpClientConfig cfg;
    cfg.connectTimeoutMs = 15000;
    cfg.readTimeoutMs = 30000;
    https::HttpClient client(cfg);

    https::HttpRequest req;
    req.method = https::Method::GET;
    req.url = "https://httpbin.org/stream/3";

    const auto started = std::chrono::steady_clock::now();
    auto res = client.send_stream(req, [](const https::SseEvent&) { return true; });
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();

    EXPECT_EQ(res.statusCode, 200);
    EXPECT_TRUE(res.body.empty()) << "a 2xx body is not captured; it is the caller's stream";
    EXPECT_LT(elapsed, 15000) << "the chunked reader did not terminate promptly";
}

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
