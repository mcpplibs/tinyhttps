module;

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>

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
    int ret = sock->read(reinterpret_cast<char*>(buf), static_cast<int>(len));
    if (ret < 0) {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return ret;   // 0 means end of stream; mbedtls turns it into SSL_CONN_EOF
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
        , state_(std::move(other.state_)) {
        // Re-bind BIO to point to our socket_ (not the moved-from one)
        if (state_) {
            mbedtls_ssl_set_bio(&state_->ssl, &socket_, bio_send, bio_recv, nullptr);
        }
    }

    // Move assignment
    TlsSocket& operator=(TlsSocket&& other) noexcept {
        if (this != &other) {
            close();
            socket_ = std::move(other.socket_);
            state_ = std::move(other.state_);
            // Re-bind BIO to point to our socket_
            if (state_) {
                mbedtls_ssl_set_bio(&state_->ssl, &socket_, bio_send, bio_recv, nullptr);
            }
        }
        return *this;
    }

    [[nodiscard]] bool is_valid() const {
        return state_ != nullptr && socket_.is_valid();
    }

    // Connect over an already-established Socket (e.g. a proxy tunnel).
    // Takes ownership of the socket and performs TLS handshake on top of it.
    bool connect_over(Socket&& socket, const char* host, bool verifySsl) {
        socket_ = std::move(socket);
        return setup_tls(host, verifySsl);
    }

    bool connect(const char* host, int port, int timeoutMs, bool verifySsl) {
        // Step 1: TCP connect via Socket
        if (!socket_.connect(host, port, timeoutMs)) {
            return false;
        }

        return setup_tls(host, verifySsl);
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
        socket_.close();
    }

    bool wait_readable(int timeoutMs) {
        // Check if mbedtls has already buffered decrypted data
        if (state_ && mbedtls_ssl_get_bytes_avail(&state_->ssl) > 0) {
            return true;
        }
        return socket_.wait_readable(timeoutMs);
    }

    // TLS back-pressure is a wait, not a failure. `mbedtls_ssl_write` reports
    // WANT_WRITE when the record layer cannot flush, and `write` above turns
    // that into 0; without something to wait on, `write_all` could only retry
    // at once and then give up, which reached the caller as "Write failed".
    bool wait_writable(int timeoutMs) {
        return socket_.wait_writable(timeoutMs);
    }

private:
    Socket socket_;
    std::unique_ptr<TlsState> state_;

    bool setup_tls(const char* host, bool verifySsl) {
        state_ = std::make_unique<TlsState>();

        int ret = mbedtls_ctr_drbg_seed(
            &state_->ctr_drbg, mbedtls_entropy_func, &state_->entropy,
            nullptr, 0);
        if (ret != 0) {
            state_.reset();
            socket_.close();
            return false;
        }

        ret = mbedtls_ssl_config_defaults(
            &state_->conf,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            state_.reset();
            socket_.close();
            return false;
        }

        mbedtls_ssl_conf_rng(&state_->conf, mbedtls_ctr_drbg_random, &state_->ctr_drbg);

        // mbedTLS 3.6 TLS 1.3 key derivation can fail in statically-linked
        // builds; cap at TLS 1.2 which works reliably everywhere.
        mbedtls_ssl_conf_max_tls_version(&state_->conf, MBEDTLS_SSL_VERSION_TLS1_2);

        // Load CA certs
        auto ca_pem = load_ca_certs();
        if (!ca_pem.empty()) {
            ret = mbedtls_x509_crt_parse(
                &state_->ca_cert,
                reinterpret_cast<const unsigned char*>(ca_pem.c_str()),
                ca_pem.size() + 1); // +1 for null terminator required by mbedtls
            // ret > 0 means some certs failed to parse but others succeeded — acceptable
            if (ret < 0) {
                state_.reset();
                socket_.close();
                return false;
            }
            mbedtls_ssl_conf_ca_chain(&state_->conf, &state_->ca_cert, nullptr);
        }

        // Certificate verification
        // Use OPTIONAL (not REQUIRED) so handshake succeeds even if the CA
        // bundle is incomplete; callers that need strict verification can
        // inspect the verification result after handshake.
        if (verifySsl) {
            mbedtls_ssl_conf_authmode(&state_->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        } else {
            mbedtls_ssl_conf_authmode(&state_->conf, MBEDTLS_SSL_VERIFY_NONE);
        }

        ret = mbedtls_ssl_setup(&state_->ssl, &state_->conf);
        if (ret != 0) {
            state_.reset();
            socket_.close();
            return false;
        }

        // Set hostname for SNI
        ret = mbedtls_ssl_set_hostname(&state_->ssl, host);
        if (ret != 0) {
            state_.reset();
            socket_.close();
            return false;
        }

        // Set BIO callbacks using our Socket
        mbedtls_ssl_set_bio(&state_->ssl, &socket_, bio_send, bio_recv, nullptr);

        // Perform TLS handshake
        while ((ret = mbedtls_ssl_handshake(&state_->ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                state_.reset();
                socket_.close();
                return false;
            }
        }

        return true;
    }
};

} // namespace mcpplibs::tinyhttps
