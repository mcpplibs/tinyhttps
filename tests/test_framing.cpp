// The half of HTTP framing that can be examined without a server.
//
// `parse_chunk_size_line` and `parse_content_length` are exported so they can be
// tested here rather than through a network; `parse_status_line` joins them for
// the same reason. Every case below is a string a server can send.
#include <gtest/gtest.h>

import mcpplibs.tinyhttps;
import std;

namespace https = mcpplibs::tinyhttps;

// ── the status line ──────────────────────────────────────────────────────────

TEST(StatusLine, AcceptsTheOrdinaryShape) {
    auto parsed = https::parse_status_line("HTTP/1.1 200 OK");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->code, 200);
    EXPECT_EQ(parsed->text, "OK");
}

TEST(StatusLine, AReasonPhraseIsOptionalAndMayContainSpaces) {
    auto none = https::parse_status_line("HTTP/1.1 204");
    ASSERT_TRUE(none.has_value());
    EXPECT_EQ(none->code, 204);
    EXPECT_TRUE(none->text.empty());

    auto phrase = https::parse_status_line("HTTP/1.0 404 Not Found Here");
    ASSERT_TRUE(phrase.has_value());
    EXPECT_EQ(phrase->code, 404);
    EXPECT_EQ(phrase->text, "Not Found Here");
}

// THE ONE FROM ISSUE #15.
//
// A socket returned to the pool with the previous response's body still on it
// gave the next request this to read. The older parser looked for the first
// space, then the second, then kept whatever digits it found between them:
//
//     "BBBB 999 XHTTP/1.1 200 OK"
//          ^ first space          -> rest = "999 XHTTP/1.1 200 OK"
//              ^ second space     -> code = "999"
//
// and reported a perfectly ordinary-looking 999 to the caller.
TEST(StatusLine, RejectsALineThatDoesNotBeginWithTheVersion) {
    EXPECT_FALSE(https::parse_status_line("BBBB 999 XHTTP/1.1 200 OK").has_value());
    EXPECT_FALSE(https::parse_status_line("").has_value());
    EXPECT_FALSE(https::parse_status_line("200 OK").has_value());
    EXPECT_FALSE(https::parse_status_line("<html><body>").has_value());
    // A run of digits with letters around it used to become 999 as well.
    EXPECT_FALSE(https::parse_status_line("X9Y9Z9 999 OK").has_value());
}

TEST(StatusLine, RejectsAStatusCodeThatIsNotThreeDigits) {
    EXPECT_FALSE(https::parse_status_line("HTTP/1.1 20 OK").has_value());
    EXPECT_FALSE(https::parse_status_line("HTTP/1.1 2000 OK").has_value());
    EXPECT_FALSE(https::parse_status_line("HTTP/1.1 20a OK").has_value());
    EXPECT_FALSE(https::parse_status_line("HTTP/1.1 +20 OK").has_value());
    EXPECT_FALSE(https::parse_status_line("HTTP/1.1").has_value());
    // Outside the range the grammar defines. 999 is what issue #15 reported,
    // and it is not a status code either.
    EXPECT_FALSE(https::parse_status_line("HTTP/1.1 099 OK").has_value());
    EXPECT_FALSE(https::parse_status_line("HTTP/1.1 999 OK").has_value());
}

TEST(StatusLine, AcceptsEveryClassTheGrammarDefines) {
    for (int code : {100, 200, 204, 301, 302, 404, 418, 500, 599}) {
        auto line = "HTTP/1.1 " + std::to_string(code) + " X";
        auto parsed = https::parse_status_line(line);
        ASSERT_TRUE(parsed.has_value()) << line;
        EXPECT_EQ(parsed->code, code);
    }
}

// ── chunk sizes ──────────────────────────────────────────────────────────────

TEST(ChunkedProtocol, RejectsEmptyInvalidAndOverflowSizeLines) {
    EXPECT_FALSE(https::parse_chunk_size_line("").has_value());
    EXPECT_FALSE(https::parse_chunk_size_line("xyz").has_value());
    EXPECT_FALSE(https::parse_chunk_size_line("1g").has_value());
    EXPECT_FALSE(https::parse_chunk_size_line("FFFFFFFFFFFFFFFF").has_value());
    // The two the older `parse_hex` turned into a terminal chunk: an empty line
    // (what a timed-out read produced) and a line of letters.
    EXPECT_FALSE(https::parse_chunk_size_line("zz").has_value());
}

TEST(ChunkedProtocol, AcceptsValidSizeAndTerminalChunk) {
    ASSERT_TRUE(https::parse_chunk_size_line("1a").has_value());
    EXPECT_EQ(*https::parse_chunk_size_line("1a"), 26);
    ASSERT_TRUE(https::parse_chunk_size_line("0").has_value());
    EXPECT_EQ(*https::parse_chunk_size_line("0"), 0);
}

// ── content length ───────────────────────────────────────────────────────────

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

// A value that fits in 64 bits but not in 32. `send_impl` held this in an `int`
// and truncated 2^32 to 0 in silence, which read as "the body is empty".
TEST(ContentLength, KeepsAValuePastThirtyTwoBits) {
    auto parsed = https::parse_content_length("4294967296");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, 4294967296LL);
}

// ── the bounded error-body buffer ────────────────────────────────────────────

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

// ── the response contract ────────────────────────────────────────────────────

// `bodyComplete` defaults to true, so code that never looks at it behaves as it
// did. That default is the whole of the compatibility claim for this field.
TEST(ResponseContract, ABodyIsCompleteUntilSomethingSaysOtherwise) {
    https::HttpResponse response;
    EXPECT_TRUE(response.bodyComplete);
    EXPECT_TRUE(response.bodyError.empty());
}

// `ok()` answers what the server said, and deliberately does not consult
// `bodyComplete`. Making it stricter would change what existing `if (res.ok())`
// means without changing what it says.
TEST(ResponseContract, OkReportsTheStatusCodeAndNotTheTransfer) {
    https::HttpResponse response;
    response.statusCode = 200;
    response.bodyComplete = false;
    response.bodyError = "Connection closed before the declared length";
    EXPECT_TRUE(response.ok());
    EXPECT_FALSE(response.bodyComplete);
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
