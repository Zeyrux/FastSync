#include "test_transport_tcp.h"
#include "test_utils.h"
#include "transport_tcp.h"
#include <unistd.h>

static void test_server_create_ephemeral() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  EXPECT_TRUE(s->file_descriptor >= 0);
  EXPECT_EQ_INT(s->address.sin_family, AF_INET);
  server_delete(&s);
  EXPECT_NULL(s);
}

static void test_server_delete_null() {
  Server* s = NULL;
  server_delete(&s);
  EXPECT_NULL(s);
}

static void test_client_create() {
  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  EXPECT_TRUE(c->file_descriptor >= 0);
  EXPECT_EQ_INT(c->address.sin_family, AF_INET);
  EXPECT_EQ_INT(c->ssh_child_pid, -1);
  EXPECT_NULL(c->ssl);
  EXPECT_NULL(c->ssl_ctx);
  client_disconnect(c);
  client_delete(c);
}

static void test_client_delete_null() {
  Client* c = NULL;
  client_delete(c);
}

void test_transport_tcp() {
  test_server_create_ephemeral();
  test_server_delete_null();
  test_client_create();
  test_client_delete_null();
}
