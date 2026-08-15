#include "transport_tls.h"
#include "log.h"
#include "protocol.h"
#include "transport_tcp.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
  SSL_set_fd(ssl, fd);

  // Enable hostname verification for client connections when a hostname is provided.
  // Must be done before SSL_connect to take effect during the handshake.
  if (!is_server && hostname) {
    SSL_set1_host(ssl, hostname);
  }

  // Retry SSL_accept/SSL_connect on WANT_READ/WANT_WRITE (non-blocking handshake)
  int ret;
  do {
    if (is_server)
      ret = SSL_accept(ssl);
    else
      ret = SSL_connect(ssl);

    if (ret <= 0) {
      int ssl_err = SSL_get_error(ssl, ret);
      if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
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
  struct addrinfo hints;
  struct addrinfo* result;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  int err = getaddrinfo(host, port_str, &hints, &result);
  if (err != 0 || result == NULL) {
    fprintf(stderr, "Could not resolve host: %s (%s)\n", host, gai_strerror(err));
    return false;
  }

  struct addrinfo* rp;
  bool connected = false;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    if (client->file_descriptor >= 0)
      close(client->file_descriptor);

    client->file_descriptor = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (client->file_descriptor < 0)
      continue;

    struct timeval ct;
    ct.tv_sec = tcp_get_contimeout_sec();
    ct.tv_usec = 0;
    setsockopt(client->file_descriptor, SOL_SOCKET, SO_RCVTIMEO, &ct, sizeof(ct));
    setsockopt(client->file_descriptor, SOL_SOCKET, SO_SNDTIMEO, &ct, sizeof(ct));

    memcpy(&client->address, rp->ai_addr, rp->ai_addrlen);
    client->address_length = rp->ai_addrlen;

    if (connect(client->file_descriptor, (struct sockaddr*)&client->address,
                client->address_length) == 0) {
      connected = true;
      break;
    }
  }
  freeaddrinfo(result);

  if (!connected) {
    perror("Could not connect to Server!");
    return false;
  }

  SSL_CTX* ctx = create_ssl_ctx(false, cert_path, key_path, ca_path);
  if (!ctx)
    return false;
  client->ssl_ctx = ctx;

  // Pass the server hostname for TLS hostname verification (SSL_set1_host
  // is called inside wrap_fd_with_ssl before the handshake when ca_path is set).
  const char* verify_host = ca_path ? host : NULL;
  SSL* ssl = wrap_fd_with_ssl(client->file_descriptor, ctx, false, verify_host);
  if (!ssl) {
    SSL_CTX_free(ctx);
    client->ssl_ctx = NULL;
    return false;
  }

  client->ssl = ssl;
  io_set_ssl(ssl);
  return true;
}
