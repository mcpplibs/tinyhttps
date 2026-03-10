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

static int bio_recv(void* ctx, unsigned char* buf, size_t len) {
    auto* sock = static_cast<Socket*>(ctx);
    int ret = sock->read(reinterpret_cast<char*>(buf), static_cast<int>(len));
    if (ret < 0) {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (ret == 0) {
        return MBEDTLS_ERR_NET_CONN_RESET;
    }
    return ret;
}

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

    int read(char* buf, int len) {
        if (!is_valid()) return -1;
        int ret = mbedtls_ssl_read(&state_->ssl,
            reinterpret_cast<unsigned char*>(buf), static_cast<size_t>(len));
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) {
            return 0; // Connection closed
        }
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                return 0; // Would block, treat as no data yet
            }
            return -1;
        }
        return ret;
    }

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
        if (verifySsl) {
            mbedtls_ssl_conf_authmode(&state_->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
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
