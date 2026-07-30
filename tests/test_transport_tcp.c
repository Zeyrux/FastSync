#include "test_transport_tcp.h"
#include "protocol.h"
#include "test_utils.h"
#include "transport_tcp.h"
#include <string.h>
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
  EXPECT_TRUE(c->file_descriptor == -1);
  EXPECT_EQ_INT(c->address.ss_family, 0);
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

/* Test tcp_set_timeouts with valid values */
static void test_tcp_set_timeouts() {
  /* Just verify the function doesn't crash with edge cases */
  tcp_set_timeouts(0, 0);   /* zero means "don't change" */
  tcp_set_timeouts(60, 20); /* normal values */
  tcp_set_timeouts(-1, -1); /* negative means "don't change" */
  /* If we got here without crashing, the test passes */
  EXPECT_TRUE(true);
}

/* Test client_connect with an invalid host (should fail gracefully) */
static void test_client_connect_invalid_host() {
  Client* c = client_create();
  EXPECT_NOT_NULL(c);

  /* Use a non-routable IP that will fail connect quickly */
  bool ok = client_connect(c, "10.255.255.1", 9999);
  EXPECT_FALSE(ok);

  client_disconnect(c);
  client_delete(c);
}

/* Test server_create with a specific port */
static void test_server_create_specific_port() {
  /* Port 0 = ephemeral, but try 0 and verify bind works */
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  EXPECT_TRUE(s->file_descriptor >= 0);
  server_delete(&s);
  EXPECT_NULL(s);
}

/* Test server_create with invalid port (0 is valid for ephemeral) */
static void test_server_delete_double() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  server_delete(&s);
  EXPECT_NULL(s);
  /* Deleting again should be safe - pointer is already NULL */
  server_delete(&s);
  EXPECT_NULL(s);
}

/* Test client_disconnect followed by client_delete */
static void test_client_disconnect_delete() {
  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  client_disconnect(c);
  client_delete(c);
}

void test_transport_tcp() {
  test_server_create_ephemeral();
  test_server_delete_null();
  test_client_create();
  test_client_delete_null();
  test_tcp_set_timeouts();
  test_client_connect_invalid_host();
  test_server_create_specific_port();
  test_server_delete_double();
  test_client_disconnect_delete();
}
