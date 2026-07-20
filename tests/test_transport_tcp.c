#include "test_transport_tcp.h"
#include "transport_tcp.h"
#include "test_utils.h"
#include <stdlib.h>
#include <unistd.h>

/* Test client_create and client_delete lifecycle */
static void test_client_create_delete() {
  Client* client = client_create();
  EXPECT_NOT_NULL(client);
  EXPECT_TRUE(client->file_descriptor >= 0);
  EXPECT_EQ_INT(client->address.sin_family, AF_INET);
  EXPECT_EQ_INT(client->ssh_child_pid, -1);
  EXPECT_NULL(client->ssl);
  EXPECT_NULL(client->ssl_ctx);

  /* Delete should clean up without error */
  client_delete(client);
}

/* Test client_delete with NULL (safety) */
static void test_client_delete_null() {
  client_delete(NULL);
  EXPECT_TRUE(true);
}

/* Test server_create and server_delete lifecycle */
static void test_server_create_delete() {
  /* Use port 0 to let the OS assign a port */
  Server* server = server_create(0);
  EXPECT_NOT_NULL(server);
  EXPECT_TRUE(server->file_descriptor >= 0);
  EXPECT_EQ_INT(server->address.sin_family, AF_INET);
  EXPECT_NULL(server->ssl_ctx);

  /* Clean up */
  server_delete(&server);
  EXPECT_NULL(server);
}

/* Test server_delete with NULL pointer */
static void test_server_delete_null_ptr() {
  server_delete(NULL);
  EXPECT_TRUE(true);
}

/* Test server_delete with NULL server */
static void test_server_delete_null_server() {
  Server* s = NULL;
  server_delete(&s);
  EXPECT_NULL(s);
}

/* Test client_create can be called multiple times */
static void test_client_create_multiple() {
  Client* c1 = client_create();
  Client* c2 = client_create();
  EXPECT_NOT_NULL(c1);
  EXPECT_NOT_NULL(c2);
  EXPECT_TRUE(c1->file_descriptor >= 0);
  EXPECT_TRUE(c2->file_descriptor >= 0);
  EXPECT_TRUE(c1->file_descriptor != c2->file_descriptor);

  client_delete(c1);
  client_delete(c2);
}

/* Test client_disconnect on a fresh client (should close socket) */
static void test_client_disconnect_fresh() {
  Client* client = client_create();
  EXPECT_NOT_NULL(client);

  /* Disconnect should close the file descriptor */
  client_disconnect(client);
  /* The fd should now be invalid */
  /* Verify by trying to use close() on it - should fail */
  EXPECT_EQ_INT(close(client->file_descriptor), -1);

  client_delete(client);
}

void test_transport_tcp() {
  test_client_create_delete();
  test_client_delete_null();
  test_server_create_delete();
  test_server_delete_null_ptr();
  test_server_delete_null_server();
  test_client_create_multiple();
  test_client_disconnect_fresh();
}
