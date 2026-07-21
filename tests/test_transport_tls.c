#include "test_transport_tls.h"
#include "transport_tls.h"
#include "transport_tcp.h"
#include "test_utils.h"
#include <stdlib.h>
#include <unistd.h>

/* Test tls_global_init succeeds */
static void test_tls_global_init() {
  bool ok = tls_global_init();
  EXPECT_TRUE(ok);
}

/* Test tls_global_init can be called multiple times */
static void test_tls_global_init_twice() {
  bool ok1 = tls_global_init();
  bool ok2 = tls_global_init();
  EXPECT_TRUE(ok1);
  EXPECT_TRUE(ok2);
}

/* Test client_connect_tls with bad certificate path.
 * The function will create a socket, try to connect to localhost,
 * fail to connect (since nothing is listening), and return false.
 * We don't need a server to verify the error path. */
static void test_tls_connect_bad_cert() {
  /* First, init TLS globally */
  tls_global_init();

  Client* client = client_create();
  EXPECT_NOT_NULL(client);

  /* Attempt to connect to a non-existent server with bad cert paths.
   * client_connect_tls will try to connect first, fail, and return false.
   * Note: we use an invalid host to ensure connection failure,
   * which exercises the error path before cert loading. */
  bool ok = client_connect_tls(client, "127.0.0.1", 1, "/nonexistent/cert.pem",
                               "/nonexistent/key.pem", "/nonexistent/ca.pem");
  EXPECT_FALSE(ok);

  client_delete(client);
}

/* Test client_connect_tls with NULL cert paths (should still attempt connection).
 * Cert/key/ca being NULL is valid — the function will attempt to create an
 * SSL context without client certificates. */
static void test_tls_connect_null_paths() {
  tls_global_init();

  Client* client = client_create();
  EXPECT_NOT_NULL(client);

  /* Connect to invalid address — will fail at connect() step */
  bool ok = client_connect_tls(client, "127.0.0.1", 1, NULL, NULL, NULL);
  EXPECT_FALSE(ok);

  client_delete(client);
}

/* Test server_create_tls with bad cert paths.
 * The function should fail gracefully. */
static void test_tls_server_bad_cert() {
  tls_global_init();

  Server* server = server_create(0);
  EXPECT_NOT_NULL(server);

  /* Load bad cert paths — should fail and return false */
  bool ok = server_create_tls(server, "/nonexistent/cert.pem", "/nonexistent/key.pem", NULL);
  EXPECT_FALSE(ok);

  server_delete(&server);
}

void test_transport_tls() {
  test_tls_global_init();
  test_tls_global_init_twice();
  test_tls_connect_bad_cert();
  test_tls_connect_null_paths();
  test_tls_server_bad_cert();
}
