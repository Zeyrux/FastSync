#include "test_transport_tls.h"
#include "test_utils.h"
#include "transport_tcp.h"
#include "transport_tls.h"

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

void test_transport_tls() {
  test_tls_global_init();
  test_server_create_tls_without_certs();
}
