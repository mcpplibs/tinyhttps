module;

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>

// mbedTLS draws its entropy from BCryptGenRandom on Windows. Its package asks
// for the library as `-lbcrypt`, which link.exe does not read, so the request is
// made here in the form every linker for this target reads, as socket.cppm does
// for ws2_32.
#if defined(_WIN32) && !defined(TINYHTTPS_POSIX_SOCKETS)
#pragma comment(lib, "bcrypt.lib")
#endif

// WHERE THE C LIBRARY IS musl, THE ENTROPY IS THE C LIBRARY'S.
//
// mbedTLS's own platform source asks the kernel through `getrandom` only where
// it recognises glibc (`entropy_poll.c`: `__linux__ && __GLIBC__`); with musl it
// opens `/dev/urandom`. Above openkal that file is not a thing the C library can
// promise — openkal reaches entropy through its own `openkal.random` interface,
// and openkal-musl answers `getrandom` with it — so on x86_64-windows-musl every
// handshake failed before it began, with "CTR_DRBG - The entropy source failed".
// musl's `getentropy` is `getrandom` underneath on every system it runs on,
// which is the source mbedTLS would have chosen had it known. The macro comes
// from mcpp.toml's `cfg(c-abi = "musl")`, because musl defines none of its own.
#ifdef TINYHTTPS_GETENTROPY
#include <unistd.h>
#endif

export module mcpplibs.tinyhttps:tls;

import :socket;
import :ca_bundle;
import std;

namespace mcpplibs::tinyhttps {

struct TlsState {
    mbedtls_ssl_context     ssl;
    mbedtls_ssl_config      conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context  entropy;
    mbedtls_x509_crt        ca_cert;

    TlsState() {
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);
        mbedtls_x509_crt_init(&ca_cert);
    }

    ~TlsState() {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_x509_crt_free(&ca_cert);
    }

    TlsState(const TlsState&) = delete;
    TlsState& operator=(const TlsState&) = delete;
};

// BIO callbacks for mbedtls — forward to Socket read/write
static int bio_send(void* ctx, const unsigned char* buf, size_t len) {
    auto* sock = static_cast<Socket*>(ctx);
    int ret = sock->write(reinterpret_cast<const char*>(buf), static_cast<int>(len));
    if (ret <= 0) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
}

// A ZERO IS PASSED THROUGH, AND THAT IS THE WHOLE CONTRACT.
//
// This used to answer a `recv` of 0 — a peer that sent FIN, which is how nearly
// every server ends a connection-close-delimited response — with
// MBEDTLS_ERR_NET_CONN_RESET. mbedtls's own BIO does not: `mbedtls_net_recv`
// returns `read()`'s result unchanged and reserves CONN_RESET for an actual
// ECONNRESET/EPIPE (net_sockets.c). The distinction is not cosmetic, because
// `mbedtls_ssl_fetch_input` tests for exactly this zero —
//
//     if (ret == 0) { return MBEDTLS_ERR_SSL_CONN_EOF; }   ssl_msg.c:2251, :2320
//
// — and passes any negative value straight through. So the old mapping made an
// orderly end of stream indistinguishable from a transport error, one layer
// below `TlsSocket::read_some`, which then had to call it `Error`. A body whose
// framing IS the close then read as truncated: `download_to_file` set
// `result.error` and `ok()` returned false for a file that had arrived
// complete and correct.
static int bio_recv(void* ctx, unsigned char* buf, size_t len) {
    auto* sock = static_cast<Socket*>(ctx);
    // With a stop token or a handshake deadline, wait here so the recv below
    // cannot block past a stop or the deadline.
    if (!sock->wait_before_recv()) {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    int ret = sock->read(reinterpret_cast<char*>(buf), static_cast<int>(len));
    if (ret < 0) {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return ret;   // 0 means end of stream; mbedtls turns it into SSL_CONN_EOF
}

#ifdef TINYHTTPS_GETENTROPY
// `getentropy` gives at most 256 bytes a call.
static int c_library_entropy(void*, unsigned char* out, size_t len) {
    while (len > 0) {
        const size_t n = len < 256 ? len : 256;
        if (::getentropy(out, n) != 0) return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        out += n;
        len -= n;
    }
    return 0;
}
#endif

static std::string mbedtls_message(int ret) {
    char buf[200];
    mbedtls_strerror(ret, buf, sizeof buf);
    return buf;
}

// verify_info ends every reason with a newline; join them with "; ".
static std::string one_line(std::string text) {
    while (!text.empty() && text.back() == '\n') text.pop_back();
    for (std::size_t pos = 0; (pos = text.find('\n', pos)) != std::string::npos;) {
        text.replace(pos, 1, "; ");
    }
    return text;
}

// WHAT A READ ENDED IN, WHICH `int` COULD NOT SAY.
//
// `TlsSocket::read` returned 0 for a peer that had closed AND for a transport
// that had no bytes ready yet, so every caller had to guess. They all guessed
// the same way — wait once more and try again — and a reader that cannot tell
// "the body ended here" from "nothing yet" cannot decide whether the connection
// is still reusable. That is root cause R3 behind issue #15.
//
// `Eof` is a fact about the stream and `WouldBlock` is a fact about this
// instant; naming them apart is what lets `read_body` below return `Complete`
// rather than a guess.
export enum class ReadStatus { Data, WouldBlock, Eof, Error };

export struct ReadResult {
    ReadStatus status { ReadStatus::Error };
    int bytes { 0 };   // meaningful only when status == Data
};

export class TlsSocket {
public:
    TlsSocket() = default;
    ~TlsSocket() { close(); }

    // Non-copyable
    TlsSocket(const TlsSocket&) = delete;
    TlsSocket& operator=(const TlsSocket&) = delete;

    // Move constructor
    TlsSocket(TlsSocket&& other) noexcept
        : socket_(std::move(other.socket_))
        , lower_(std::move(other.lower_))
        , state_(std::move(other.state_))
        , error_(std::move(other.error_))
        , extraCaFile_(std::move(other.extraCaFile_)) {
        // Re-bind BIO to point to our socket_ (not the moved-from one)
        bind_bio();
    }

    // Move assignment
    TlsSocket& operator=(TlsSocket&& other) noexcept {
        if (this != &other) {
            close();
            socket_ = std::move(other.socket_);
            lower_ = std::move(other.lower_);
            state_ = std::move(other.state_);
            error_ = std::move(other.error_);
            extraCaFile_ = std::move(other.extraCaFile_);
            // Re-bind BIO to point to our socket_
            bind_bio();
        }
        return *this;
    }

    [[nodiscard]] bool is_valid() const {
        return state_ != nullptr && (lower_ ? lower_->is_valid() : socket_.is_valid());
    }

    // Why the last connect_over/connect failed once the TCP connection was up;
    // empty if it failed earlier or has not failed.
    [[nodiscard]] const std::string& error() const { return error_; }

    // Call before connect(); it covers the handshake and every later wait.
    //
    // THE TOKEN BELONGS TO THE SOCKET AT THE BOTTOM, AND ONLY THERE. Every wait
    // ends in a `Socket` — this session's own, or, inside an https:// proxy's
    // tunnel, the one beneath `lower_` — so that is where it is set. Setting
    // only `socket_` left a reused tunnel holding the token of the call that
    // opened it: a later call could not be cancelled, and once that first
    // token was stopped every wait failed at once and the stale-connection
    // retry sent a POST that had already arrived a second time.
    void set_stop(std::stop_token stop) {
        if (lower_) lower_->set_stop(stop);
        socket_.set_stop(std::move(stop));
    }

    // A PEM file of roots to trust in addition to the default store. Call before
    // connect(); setup fails if the file cannot be read or holds no certificate.
    void set_extra_ca_file(std::string path) { extraCaFile_ = std::move(path); }

    // Connect over an already-established Socket (e.g. a proxy tunnel).
    // Takes ownership of the socket and performs TLS handshake on top of it.
    // The handshake gives up after `handshakeTimeoutMs`; a negative value waits
    // without limit.
    bool connect_over(Socket&& socket, const char* host, bool verifySsl,
                      int handshakeTimeoutMs = -1) {
        error_.clear();
        socket_ = std::move(socket);
        return setup_tls(host, verifySsl, handshakeTimeoutMs);
    }

    // Run the handshake inside another TLS session, which is how a client
    // reaches a target through an https:// proxy: TLS to the proxy, CONNECT
    // inside it, then this session to the target inside the tunnel. Takes
    // ownership of `lower`, which must already be past its CONNECT.
    bool connect_over(std::unique_ptr<TlsSocket> lower, const char* host, bool verifySsl,
                      int handshakeTimeoutMs = -1) {
        error_.clear();
        lower_ = std::move(lower);
        return setup_tls(host, verifySsl, handshakeTimeoutMs);
    }

    bool connect(const char* host, int port, int timeoutMs, bool verifySsl) {
        error_.clear();
        // Step 1: TCP connect via Socket
        if (!socket_.connect(host, port, timeoutMs)) {
            return false;
        }

        return setup_tls(host, verifySsl, timeoutMs);
    }

    // The read that says which of the four things happened. Prefer it over
    // `read` below wherever the answer changes what the caller does.
    ReadResult read_some(char* buf, int len) {
        if (!is_valid()) return { ReadStatus::Error, 0 };
        int ret = mbedtls_ssl_read(&state_->ssl,
            reinterpret_cast<unsigned char*>(buf), static_cast<size_t>(len));
        // Three spellings of "there is nothing more coming", and all three are
        // an end of stream rather than a failure: the peer shut the session
        // down politely, the transport reached its end (what `bio_recv`'s zero
        // becomes), or mbedtls had nothing left to hand back. Most servers do
        // NOT send close_notify before closing, so the middle one is the common
        // case rather than the exotic one.
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
            || ret == MBEDTLS_ERR_SSL_CONN_EOF
            || ret == 0) {
            return { ReadStatus::Eof, 0 };
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return { ReadStatus::WouldBlock, 0 };
        }
        if (ret < 0) return { ReadStatus::Error, 0 };
        return { ReadStatus::Data, ret };
    }

    // The older shape, kept because it is exported and callers outside this
    // repository use it. It collapses Eof and WouldBlock back into 0, which is
    // the ambiguity `read_some` exists to remove.
    int read(char* buf, int len) {
        auto r = read_some(buf, len);
        switch (r.status) {
            case ReadStatus::Data:       return r.bytes;
            case ReadStatus::Eof:
            case ReadStatus::WouldBlock: return 0;
            case ReadStatus::Error:      return -1;
        }
        return -1;
    }

    // Returns 0 for "the transport is not ready", which `write_all` answers by
    // waiting on the socket rather than by retrying immediately.
    int write(const char* buf, int len) {
        if (!is_valid()) return -1;
        int ret = mbedtls_ssl_write(&state_->ssl,
            reinterpret_cast<const unsigned char*>(buf), static_cast<size_t>(len));
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                return 0;
            }
            return -1;
        }
        return ret;
    }

    void close() {
        if (state_) {
            mbedtls_ssl_close_notify(&state_->ssl);
            state_.reset();
        }
        // Only after the close_notify above, which travels through it.
        lower_.reset();
        socket_.close();
    }

    bool wait_readable(int timeoutMs) {
        // Check if mbedtls has already buffered decrypted data
        if (state_ && mbedtls_ssl_get_bytes_avail(&state_->ssl) > 0) {
            return true;
        }
        // Under another session the bytes may be decrypted and waiting there
        // while the descriptor has nothing, so ask that session, not the fd.
        return lower_ ? lower_->wait_readable(timeoutMs) : socket_.wait_readable(timeoutMs);
    }

    // TLS back-pressure is a wait, not a failure. `mbedtls_ssl_write` reports
    // WANT_WRITE when the record layer cannot flush, and `write` above turns
    // that into 0; without something to wait on, `write_all` could only retry
    // at once and then give up, which reached the caller as "Write failed".
    bool wait_writable(int timeoutMs) {
        return lower_ ? lower_->wait_writable(timeoutMs) : socket_.wait_writable(timeoutMs);
    }

private:
    Socket socket_;
    // The session this one runs inside, when there is one; `socket_` is unused
    // then. Declared before `state_` so it is destroyed after it: the BIO of
    // `state_` points at it.
    std::unique_ptr<TlsSocket> lower_;
    std::unique_ptr<TlsState> state_;
    std::string error_;
    std::string extraCaFile_;

    // The session beneath this one, when there is one, is closed as well: a
    // failed handshake to the target leaves nothing of the tunnel open.
    bool fail(std::string message) {
        error_ = std::move(message);
        state_.reset();
        drop_transport();
        return false;
    }

    // The BIO of a session that runs inside another is that session, which stays
    // put when this object moves; the BIO of one on a socket is `socket_`, which
    // moves with it.
    void bind_bio() {
        if (!state_) return;
        if (lower_) {
            mbedtls_ssl_set_bio(&state_->ssl, lower_.get(), send_over_tls, recv_over_tls, nullptr);
        } else {
            mbedtls_ssl_set_bio(&state_->ssl, &socket_, bio_send, bio_recv, nullptr);
        }
    }

    static int send_over_tls(void* ctx, const unsigned char* buf, size_t len) {
        int ret = static_cast<TlsSocket*>(ctx)->write(reinterpret_cast<const char*>(buf),
                                                      static_cast<int>(len));
        if (ret < 0) return MBEDTLS_ERR_NET_SEND_FAILED;
        if (ret == 0) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return ret;
    }

    // As `bio_recv`: an end of stream is passed on as a zero.
    static int recv_over_tls(void* ctx, unsigned char* buf, size_t len) {
        auto r = static_cast<TlsSocket*>(ctx)->read_some(reinterpret_cast<char*>(buf),
                                                         static_cast<int>(len));
        switch (r.status) {
            case ReadStatus::Data:       return r.bytes;
            case ReadStatus::Eof:        return 0;
            case ReadStatus::WouldBlock: return MBEDTLS_ERR_SSL_WANT_READ;
            case ReadStatus::Error:      break;
        }
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    void drop_transport() {
        lower_.reset();
        socket_.close();
    }

    // As `set_stop`, the deadline belongs to the socket at the bottom, which
    // inside a tunnel is the one beneath `lower_`.
    void set_deadline(std::optional<std::chrono::steady_clock::time_point> deadline) {
        if (lower_) lower_->set_deadline(deadline);
        else socket_.set_deadline(deadline);
    }

    bool deadline_hit() const { return lower_ ? lower_->deadline_hit() : socket_.deadline_hit(); }

    bool setup_tls(const char* host, bool verifySsl, int handshakeTimeoutMs) {
        state_ = std::make_unique<TlsState>();

        int ret = mbedtls_ctr_drbg_seed(
#ifdef TINYHTTPS_GETENTROPY
            &state_->ctr_drbg, c_library_entropy, nullptr,
#else
            &state_->ctr_drbg, mbedtls_entropy_func, &state_->entropy,
#endif
            nullptr, 0);
        if (ret != 0) return fail(mbedtls_message(ret));

        ret = mbedtls_ssl_config_defaults(
            &state_->conf,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) return fail(mbedtls_message(ret));

        mbedtls_ssl_conf_rng(&state_->conf, mbedtls_ctr_drbg_random, &state_->ctr_drbg);

        // mbedTLS 3.6 TLS 1.3 key derivation can fail in statically-linked
        // builds; cap at TLS 1.2 which works reliably everywhere.
        mbedtls_ssl_conf_max_tls_version(&state_->conf, MBEDTLS_SSL_VERSION_TLS1_2);

        // Load CA certs
        auto ca_pem = load_ca_certs();
        if (ca_pem.empty() && verifySsl) {
            return fail("no CA certificate bundle found; set SSL_CERT_FILE to a PEM "
                        "file of trusted roots, or set verifySsl to false");
        }
        if (!ca_pem.empty()) {
            ret = mbedtls_x509_crt_parse(
                &state_->ca_cert,
                reinterpret_cast<const unsigned char*>(ca_pem.c_str()),
                ca_pem.size() + 1); // +1 for null terminator required by mbedtls
            // ret > 0 means some certs failed to parse but others succeeded — acceptable
            if (ret < 0) {
                return fail("cannot parse the CA certificate bundle: " + mbedtls_message(ret));
            }
        }
        // Roots the caller adds to the above. A file that cannot be used is an
        // error, not something to skip: the caller named it because a server
        // needs it, and skipping would surface later as a verification failure
        // that does not mention the file.
        if (!extraCaFile_.empty()) {
            std::ifstream in(extraCaFile_, std::ios::binary);
            if (!in) return fail("cannot read extra CA file '" + extraCaFile_ + "'");
            std::string extra((std::istreambuf_iterator<char>(in)), {});
            ret = mbedtls_x509_crt_parse(
                &state_->ca_cert,
                reinterpret_cast<const unsigned char*>(extra.c_str()), extra.size() + 1);
            if (ret < 0) {
                return fail("cannot parse extra CA file '" + extraCaFile_ + "': "
                            + mbedtls_message(ret));
            }
        }
        if (!ca_pem.empty() || !extraCaFile_.empty()) {
            mbedtls_ssl_conf_ca_chain(&state_->conf, &state_->ca_cert, nullptr);
        }

        // Certificate verification. REQUIRED makes the handshake fail on a bad
        // chain, an expired certificate or a name that is not `host`.
        mbedtls_ssl_conf_authmode(&state_->conf,
            verifySsl ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);

        ret = mbedtls_ssl_setup(&state_->ssl, &state_->conf);
        if (ret != 0) return fail(mbedtls_message(ret));

        // Set hostname for SNI
        ret = mbedtls_ssl_set_hostname(&state_->ssl, host);
        if (ret != 0) return fail(mbedtls_message(ret));

        // Set BIO callbacks using our Socket, or the session beneath this one
        bind_bio();

        // Perform TLS handshake. The socket is blocking, so `bio_recv` waits
        // against the deadline before it reads, and the deadline is taken off
        // again before the connection is used.
        std::optional<std::chrono::steady_clock::time_point> deadline;
        if (handshakeTimeoutMs >= 0) {
            deadline = std::chrono::steady_clock::now()
                     + std::chrono::milliseconds(handshakeTimeoutMs);
        }
        set_deadline(deadline);
        while ((ret = mbedtls_ssl_handshake(&state_->ssl)) == MBEDTLS_ERR_SSL_WANT_READ
               || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {}
        const bool timedOut = deadline_hit();
        set_deadline({});
        if (ret != 0) {
            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                char info[512] = {};
                mbedtls_x509_crt_verify_info(info, sizeof info, "",
                    mbedtls_ssl_get_verify_result(&state_->ssl));
                return fail("certificate verification failed: " + one_line(info));
            }
            if (ret == MBEDTLS_ERR_NET_RECV_FAILED && timedOut) {
                return fail("TLS handshake timed out");
            }
            return fail("TLS handshake failed: " + mbedtls_message(ret));
        }

        return true;
    }
};

} // namespace mcpplibs::tinyhttps
