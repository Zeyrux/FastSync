#include "transport_tls.h"
#include "log.h"
#include "protocol.h"
#include "transport_tcp.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
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
  const SSL_METHOD* method = is_server ? TLS_server_method() : TLS_client_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) {
    log_message(LOG_LEVEL_ERROR, "Unable to create SSL context");
    log_ssl_errors();
    return NULL;
  }

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

  if (cert && key) {
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
      log_message(LOG_LEVEL_ERROR, "Failed to load certificate: %s", cert);
      log_ssl_errors();
      SSL_CTX_free(ctx);
      return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
      log_message(LOG_LEVEL_ERROR, "Failed to load private key: %s", key);
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
      log_message(LOG_LEVEL_ERROR, "Failed to load CA: %s", ca_path);
      log_ssl_errors();
      SSL_CTX_free(ctx);
      return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
  } else {
    if (!is_server) {
      log_message(LOG_LEVEL_WARNING,
                  "No CA path provided — TLS server certificate will not be verified");
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  }

  return ctx;
}

static SSL* wrap_fd_with_ssl(int fd, SSL_CTX* ctx, bool is_server) {
  SSL* ssl = SSL_new(ctx);
  if (!ssl) {
    log_message(LOG_LEVEL_ERROR, "Failed to create SSL object");
    return NULL;
  }
  SSL_set_fd(ssl, fd);

  int ret;
  if (is_server)
    ret = SSL_accept(ssl);
  else
    ret = SSL_connect(ssl);

  if (ret <= 0) {
    log_message(LOG_LEVEL_ERROR, "SSL %s failed", is_server ? "accept" : "connect");
    log_ssl_errors();
    SSL_free(ssl);
    return NULL;
  }

  // In client mode, check verification result if peer verification was requested
  if (!is_server) {
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
      log_message(LOG_LEVEL_ERROR, "TLS certificate verification failed: %ld", verify_result);
      SSL_free(ssl);
      return NULL;
    }
  }

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
  SSL* ssl = wrap_fd_with_ssl(fd, ctx->ssl_ctx, true);
  if (!ssl)
    return;
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

bool client_connect_tls(Client* client, char* host, int port, const char* cert_path,
                        const char* key_path, const char* ca_path) {
  // Use the common TCP connection logic (with IPv6 support)
  if (!client_connect(client, host, port))
    return false;

  SSL_CTX* ctx = create_ssl_ctx(false, cert_path, key_path, ca_path);
  if (!ctx)
    return false;
  client->ssl_ctx = ctx;

  SSL* ssl = wrap_fd_with_ssl(client->file_descriptor, ctx, false);
  if (!ssl) {
    SSL_CTX_free(ctx);
    client->ssl_ctx = NULL;
    return false;
  }
  client->ssl = ssl;
  io_set_ssl(ssl);
  return true;
}
