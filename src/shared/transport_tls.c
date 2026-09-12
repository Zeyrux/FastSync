#include "transport_tls.h"
#include "log.h"
#include "protocol.h"
#include "transport_tcp.h"
#include "utils.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

bool tls_global_init(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
#endif
  return true;
}

static void log_ssl_errors(void) {
  unsigned long err;
  char buf[256];
  while ((err = ERR_get_error()) != 0) {
    ERR_error_string_n(err, buf, sizeof(buf));
    log_message(LOG_LEVEL_ERROR, "SSL error: %s", buf);
  }
}

static SSL_CTX* create_ssl_ctx(bool is_server, const char* cert, const char* key,
                               const char* ca_path) {
  if (!is_server && !ca_path) {
    log_message(LOG_LEVEL_ERROR, "TLS clients require a CA certificate path");
    return NULL;
  }
  const SSL_METHOD* method = is_server ? TLS_server_method() : TLS_client_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) {
    log_message(LOG_LEVEL_ERROR, "Unable to create SSL context");
    log_ssl_errors();
    return NULL;
  }

  /* Harden the context: never negotiate TLS compression (the CRIME attack
   * vector) and never honour a post-handshake renegotiation request.
   * SSL_OP_NO_RENEGOTIATION is only available from OpenSSL 1.1.1, so it is
   * guarded to keep older headers building. */
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#ifdef SSL_OP_NO_RENEGOTIATION
  SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
#endif

  if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
    SSL_CTX_free(ctx);
    return NULL;
  }
  if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES") != 1) {
    SSL_CTX_free(ctx);
    return NULL;
  }

  if (cert && key) {
    struct stat key_stat;
    if (stat(key, &key_stat) != 0 || !S_ISREG(key_stat.st_mode) || key_stat.st_uid != geteuid() ||
        (key_stat.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH))) {
      log_message(LOG_LEVEL_ERROR, "TLS private key must be owned by the current user and private");
      SSL_CTX_free(ctx);
      return NULL;
    }
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
      char* escaped = output_escape(cert, false);
      log_message(LOG_LEVEL_ERROR, "Failed to load certificate: %s",
                  escaped ? escaped : "<allocation failed>");
      free(escaped);
      log_ssl_errors();
      SSL_CTX_free(ctx);
      return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
      char* escaped = output_escape(key, false);
      log_message(LOG_LEVEL_ERROR, "Failed to load private key: %s",
                  escaped ? escaped : "<allocation failed>");
      free(escaped);
      log_ssl_errors();
      SSL_CTX_free(ctx);
      return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
      log_message(LOG_LEVEL_ERROR, "Private key does not match certificate");
      SSL_CTX_free(ctx);
      return NULL;
    }
  }

  if (ca_path) {
    if (!SSL_CTX_load_verify_locations(ctx, ca_path, NULL)) {
      char* escaped = output_escape(ca_path, false);
      log_message(LOG_LEVEL_ERROR, "Failed to load CA: %s",
                  escaped ? escaped : "<allocation failed>");
      free(escaped);
      log_ssl_errors();
      SSL_CTX_free(ctx);
      return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
  } else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  }

  return ctx;
}

static SSL* wrap_fd_with_ssl(int fd, SSL_CTX* ctx, bool is_server, const char* hostname) {
  SSL* ssl = SSL_new(ctx);
  if (!ssl) {
    log_message(LOG_LEVEL_ERROR, "Failed to create SSL object");
    return NULL;
  }
  if (SSL_set_fd(ssl, fd) != 1) {
    SSL_free(ssl);
    return NULL;
  }

  // Enable hostname verification for client connections when a hostname is provided.
  // Must be done before SSL_connect to take effect during the handshake.
  if (!is_server && hostname) {
    if (SSL_set1_host(ssl, hostname) != 1) {
      SSL_free(ssl);
      return NULL;
    }
  }

  // Retry SSL_accept/SSL_connect on WANT_READ/WANT_WRITE (non-blocking handshake)
  time_t deadline = time(NULL) + (is_server ? tcp_get_timeout_sec() : tcp_get_contimeout_sec());
  int ret;
  do {
    if (is_server)
      ret = SSL_accept(ssl);
    else
      ret = SSL_connect(ssl);

    if (ret <= 0) {
      int ssl_err = SSL_get_error(ssl, ret);
      if ((ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) &&
          time(NULL) < deadline)
        continue;
      log_message(LOG_LEVEL_ERROR, "SSL %s failed", is_server ? "accept" : "connect");
      log_ssl_errors();
      SSL_free(ssl);
      return NULL;
    }
  } while (ret <= 0);
  return ssl;
}

bool server_create_tls(Server* server, const char* cert_path, const char* key_path,
                       const char* ca_path) {
  SSL_CTX* ctx = create_ssl_ctx(true, cert_path, key_path, ca_path);
  if (!ctx)
    return false;
  server->ssl_ctx = ctx;
  return true;
}

struct tls_child_ctx {
  void (*handler)(int);
  SSL_CTX* ssl_ctx;
};

static void tls_child_fn(int fd, void* arg) {
  struct tls_child_ctx* ctx = (struct tls_child_ctx*)arg;
  SSL* ssl = wrap_fd_with_ssl(fd, ctx->ssl_ctx, true, NULL);
  if (!ssl) {
    io_set_ssl(NULL);
    return;
  }
  io_set_ssl(ssl);
  ctx->handler(fd);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  io_set_ssl(NULL);
}

bool server_listen_tls(Server* server, void (*handler)(int file_descriptor)) {
  struct tls_child_ctx ctx = {handler, (SSL_CTX*)server->ssl_ctx};
  server_accept_loop(server, tls_child_fn, &ctx, "Received TLS Connection");
  return true;
}

bool client_connect_tls_ex(Client* client, const char* host, int port, const char* cert_path,
                           const char* key_path, const char* ca_path,
                           const TcpConnectOptions* opts) {
  if (!tcp_connect_socket_ex(client, host, port, opts)) {
    if (client->file_descriptor >= 0)
      close(client->file_descriptor);
    client->file_descriptor = -1;
    return false;
  }

  SSL_CTX* ctx = create_ssl_ctx(false, cert_path, key_path, ca_path);
  if (!ctx) {
    close(client->file_descriptor);
    client->file_descriptor = -1;
    return false;
  }
  client->ssl_ctx = ctx;

  // Pass the server hostname for TLS hostname verification (SSL_set1_host
  // is called inside wrap_fd_with_ssl before the handshake when ca_path is set).
  const char* verify_host = ca_path ? host : NULL;
  SSL* ssl = wrap_fd_with_ssl(client->file_descriptor, ctx, false, verify_host);
  if (!ssl) {
    SSL_CTX_free(ctx);
    client->ssl_ctx = NULL;
    close(client->file_descriptor);
    client->file_descriptor = -1;
    return false;
  }

  client->ssl = ssl;
  io_set_ssl(ssl);
  return true;
}

bool client_connect_tls(Client* client, const char* host, int port, const char* cert_path,
                        const char* key_path, const char* ca_path) {
  return client_connect_tls_ex(client, host, port, cert_path, key_path, ca_path, NULL);
}
