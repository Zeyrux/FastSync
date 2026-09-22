#include "test_transport_tls.h"
#include "protocol.h"
#include "test_utils.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include <dirent.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void test_tls_global_init() {
  bool ok = tls_global_init();
  EXPECT_TRUE(ok);
}

static void test_server_create_tls_without_certs() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  bool ok = server_create_tls(s, NULL, NULL, NULL);
  EXPECT_TRUE(ok);
  EXPECT_NOT_NULL(s->ssl_ctx);
  /* The context must disable TLS compression (CRIME) and renegotiation. */
  SSL_CTX* ctx = (SSL_CTX*)s->ssl_ctx;
  EXPECT_TRUE((SSL_CTX_get_options(ctx) & SSL_OP_NO_COMPRESSION) != 0);
#ifdef SSL_OP_NO_RENEGOTIATION
  EXPECT_TRUE((SSL_CTX_get_options(ctx) & SSL_OP_NO_RENEGOTIATION) != 0);
#endif
  /* C5: the server's preference order decides the cipher and the TLS 1.2 list is
   * AEAD-only (no CBC/RC4/3DES legacy suites). */
  EXPECT_TRUE((SSL_CTX_get_options(ctx) & SSL_OP_CIPHER_SERVER_PREFERENCE) != 0);
  STACK_OF(SSL_CIPHER)* ciphers = SSL_CTX_get_ciphers(ctx);
  EXPECT_NOT_NULL(ciphers);
  for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
    const char* name = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, i));
    EXPECT_TRUE(name != NULL && strstr(name, "CBC") == NULL);
    EXPECT_TRUE(name != NULL && strstr(name, "RC4") == NULL);
    EXPECT_TRUE(name != NULL && strstr(name, "3DES") == NULL);
  }
  server_delete(&s);
  EXPECT_NULL(s);
}

/* Test client_connect_tls with no server listening (should fail gracefully) */
static void test_client_connect_tls_fail() {
  /* Create a client to localhost on a high port with no server */
  Client* c = client_create();
  EXPECT_NOT_NULL(c);

  /* connect to localhost:1 (no server) - should fail as connect() fails first */
  bool ok = client_connect_tls(c, "127.0.0.1", 1, NULL, NULL, NULL);
  EXPECT_FALSE(ok);

  /* Note: client_connect_tls internally calls connect() which sets up the socket.
   * On failure it returns false but does NOT close the socket - we need to
   * disconnect/delete the client. The socket fd may be in an undefined state
   * after a failed connect, so we just call client_delete which closes it. */
  client_disconnect(c);
  client_delete(c);
}

/* Test server_create_tls with missing cert file paths (should still create ctx without certs) */
static void test_server_create_tls_empty_certs() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);

  /* Empty string paths - SSL_CTX_use_certificate_file will fail, but function returns false */
  bool ok = server_create_tls(s, "", "", NULL);
  EXPECT_FALSE(ok);
  EXPECT_NULL(s->ssl_ctx);

  server_delete(&s);
  EXPECT_NULL(s);
}

/* Count the process's open descriptors via /proc/self/fd (see the TCP tests). */
static int tls_count_open_fds(void) {
  DIR* dir = opendir("/proc/self/fd");
  if (!dir)
    return -1;
  int count = 0;
  const struct dirent* ent;
  while ((ent = readdir(dir)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
      continue;
    count++;
  }
  closedir(dir);
  return count;
}

/* #219 AC3: client_connect_tls_ex() reuses the shared tcp_connect_socket_ex()
 * for the TCP connect, and a later TLS-setup failure must release that
 * descriptor.  Passing no CA path makes create_ssl_ctx() fail deterministically
 * AFTER a successful TCP connect, so the cleanup path is exercised without a
 * TLS handshake or a certificate.  (The multi-address fallback itself is covered
 * by the shared tcp_connect_socket_ex() tests in test_transport_tcp.c, which the
 * TLS entry point calls.) */
static void test_client_connect_tls_releases_fd_on_setup_failure() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  EXPECT_EQ_INT(listen(s->file_descriptor, 1), 0);
  struct sockaddr_in bound;
  socklen_t bound_len = sizeof(bound);
  EXPECT_EQ_INT(getsockname(s->file_descriptor, (struct sockaddr*)&bound, &bound_len), 0);
  int port = ntohs(bound.sin_port);

  int before = tls_count_open_fds();
  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  EXPECT_FALSE(client_connect_tls(c, "127.0.0.1", port, NULL, NULL, NULL));
  EXPECT_TRUE(c->file_descriptor == -1);
  if (before >= 0)
    EXPECT_EQ_INT(tls_count_open_fds(), before);
  client_delete(c);
  server_delete(&s);
}

void test_transport_tls() {
  test_tls_global_init();
  test_server_create_tls_without_certs();
  test_client_connect_tls_fail();
  test_client_connect_tls_releases_fd_on_setup_failure();
  test_server_create_tls_empty_certs();
}
