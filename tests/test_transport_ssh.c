#include "test_transport_ssh.h"
#include "transport_ssh.h"
#include "test_utils.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

/* Test client_connect_ssh with invalid destination (missing colon) */
static void test_ssh_connect_invalid_dest() {
  /* Missing colon — parse_remote_dest should fail and return NULL */
  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh("invalid-destination-no-colon", 22);
  EXPECT_NULL(client);
}

/* Test client_connect_ssh with empty destination */
static void test_ssh_connect_empty_dest() {
  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh("", 22);
  EXPECT_NULL(client);
}

/* Test client_connect_ssh with malformed destination (just a colon).
 * parse_remote_dest succeeds, ssh is exec'd and fails, but the function
 * creates a Client that must be cleaned up. */
static void test_ssh_connect_malformed() {
  Client* client = client_connect_ssh(":", 22);
  /* ssh binary exists, so exec succeeds; the function returns a Client.
   * We just verify it doesn't crash and clean up properly. */
  if (client != NULL) {
    client_disconnect(client);
    client_delete(client);
  }
  EXPECT_TRUE(true);
}

/* Test client_connect_ssh with valid format but unreachable host.
 * The function launches ssh which will fail to connect, returns a Client. */
static void test_ssh_connect_unreachable() {
  Client* client = client_connect_ssh("nonexistent.invalid:/remote/path", 22);
  if (client != NULL) {
    client_disconnect(client);
    client_delete(client);
  }
  EXPECT_TRUE(true);
}

void test_transport_ssh() {
  test_ssh_connect_invalid_dest();
  test_ssh_connect_empty_dest();
  test_ssh_connect_malformed();
  test_ssh_connect_unreachable();
}
