#include "test_transport_ssh.h"
#include "test_utils.h"
#include "transport_ssh.h"

static void test_ssh_connect_invalid_dest_no_colon() {
  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh("invalid-destination-no-colon", 22, NULL, false);
  EXPECT_NULL(client);
}

static void test_ssh_connect_invalid_dest_empty() {
  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh("", 22, NULL, false);
  EXPECT_NULL(client);
}

/* Test client_connect_ssh with malformed destination (just a colon).
 * parse_remote_dest succeeds, ssh is exec'd and fails, but the function
 * creates a Client that must be cleaned up. */
static void test_ssh_connect_malformed() {
  Client* client = client_connect_ssh(":", 22, NULL, false);
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
  Client* client = client_connect_ssh("nonexistent.invalid:/remote/path", 22, NULL, false);
  if (client != NULL) {
    client_disconnect(client);
    client_delete(client);
  }
  EXPECT_TRUE(true);
}

static void test_ssh_remote_command_argument_modes() {
  char* command = ssh_build_remote_command("fast sync; touch /tmp/pwned", false);
  EXPECT_EQ_STR(command, "'fast sync; touch /tmp/pwned' --stdio");
  free(command);

  command = ssh_build_remote_command("fast'sync", false);
  EXPECT_EQ_STR(command, "'fast'\\''sync' --stdio");
  free(command);

  command = ssh_build_remote_command("fast sync; touch /tmp/pwned", true);
  EXPECT_EQ_STR(command, "fast sync; touch /tmp/pwned --stdio");
  free(command);
}

void test_transport_ssh() {
  test_ssh_connect_invalid_dest_no_colon();
  test_ssh_connect_invalid_dest_empty();
  test_ssh_connect_malformed();
  test_ssh_connect_unreachable();
  test_ssh_remote_command_argument_modes();
}
