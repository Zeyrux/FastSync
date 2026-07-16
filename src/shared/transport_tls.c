#include "transport_tls.h"
#include "log.h"
#include "protocol.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static SSL_CTX *g_ssl_ctx = NULL;

bool tls_global_init(void) {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  return true;
}

void tls_global_cleanup(void) {
  if (g_ssl_ctx) {
    SSL_CTX_free(g_ssl_ctx);
    g_ssl_ctx = NULL;
  }
  EVP_cleanup();
}

static SSL_CTX *create_ssl_ctx(bool is_server, const char *cert, const char *key) {
  const SSL_METHOD *method = is_server ? TLS_server_method() : TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    log_message(LOG_LEVEL_ERROR, "Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  if (cert && key) {
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
      log_message(LOG_LEVEL_ERROR, "Failed to load certificate: %s", cert);
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(ctx);
      return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
      log_message(LOG_LEVEL_ERROR, "Failed to load private key: %s", key);
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(ctx);
      return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
      log_message(LOG_LEVEL_ERROR, "Private key does not match certificate");
      SSL_CTX_free(ctx);
      return NULL;
    }
  }

  return ctx;
}

static SSL *wrap_fd_with_ssl(int fd, SSL_CTX *ctx, bool is_server) {
  SSL *ssl = SSL_new(ctx);
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
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    return NULL;
  }
  return ssl;
}

bool server_create_tls(Server *server, const char *cert_path, const char *key_path) {
  SSL_CTX *ctx = create_ssl_ctx(true, cert_path, key_path);
  if (!ctx) return false;
  server->ssl_ctx = ctx;
  return true;
}

bool server_listen_tls(Server *server, void (*handler)(int file_descriptor)) {
  log_message(LOG_LEVEL_INFO, "Start TLS Listening on Port: %d",
              ntohs(server->address.sin_port));
  if (listen(server->file_descriptor, SOMAXCONN) < 0) {
    perror("Could not listen on port!");
    return false;
  }

  signal(SIGCHLD, SIG_IGN);

  while (1) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int file_descriptor =
        accept(server->file_descriptor, (struct sockaddr *)&client_addr,
               &client_len);
    if (file_descriptor < 0) {
      perror("Could not accept the connection");
      continue;
    }
    log_message(LOG_LEVEL_INFO, "Received TLS Connection");
    pid_t pid = fork();
    if (pid == 0) {
      close(server->file_descriptor);

      SSL *ssl = wrap_fd_with_ssl(file_descriptor, (SSL_CTX *)server->ssl_ctx, true);
      if (!ssl) {
        close(file_descriptor);
        _exit(1);
      }
      io_set_ssl(ssl);
      handler(file_descriptor);
      SSL_shutdown(ssl);
      SSL_free(ssl);
      io_set_ssl(NULL);
      close(file_descriptor);
      _exit(0);
    }
    close(file_descriptor);
  }
  return true;
}

bool client_connect_tls(Client *client, char *host, int port,
                        const char *cert_path, const char *key_path) {
  client->address.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &client->address.sin_addr) <= 0) {
    perror("Could not convert host address!");
    return false;
  }
  if (connect(client->file_descriptor, (struct sockaddr *)&client->address,
              client->address_length) < 0) {
    perror("Could not connect to Server!");
    return false;
  }

  SSL_CTX *ctx = create_ssl_ctx(false, cert_path, key_path);
  if (!ctx) return false;
  client->ssl_ctx = ctx;

  SSL *ssl = wrap_fd_with_ssl(client->file_descriptor, ctx, false);
  if (!ssl) {
    SSL_CTX_free(ctx);
    client->ssl_ctx = NULL;
    return false;
  }
  client->ssl = ssl;
  io_set_ssl(ssl);
  return true;
}
