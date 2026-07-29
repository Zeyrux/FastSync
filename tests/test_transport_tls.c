#include "test_transport_tls.h"
#include "protocol.h"
#include "test_utils.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include <string.h>
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
  server_delete(&s);
  EXPECT_NULL(s);
}

/* Test client_connect_tls with no server listening (should fail gracefully) */
static void test_client_connect_tls_fail() {
  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  bool ok = client_connect_tls(c, "127.0.0.1", 1, NULL, NULL, NULL);
  EXPECT_FALSE(ok);
  client_disconnect(c);
  client_delete(c);
}

/* Test server_create_tls with empty cert paths (should fail gracefully) */
static void test_server_create_tls_empty_certs() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  bool ok = server_create_tls(s, "", "", NULL);
  EXPECT_FALSE(ok);
  EXPECT_NULL(s->ssl_ctx);
  server_delete(&s);
  EXPECT_NULL(s);
}

void test_transport_tls() {
  test_tls_global_init();
  test_server_create_tls_without_certs();
  test_client_connect_tls_fail();
  test_server_create_tls_empty_certs();
}
