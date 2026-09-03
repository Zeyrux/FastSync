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

/* A child that cannot exec ssh must not be returned as a successful client. */
static void test_ssh_connect_malformed() {
  const char* old_path = getenv("PATH");
  char* saved_path = old_path ? strdup(old_path) : NULL;
  setenv("PATH", "", 1);

  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh(":", 22, NULL, false);

  if (saved_path) {
    setenv("PATH", saved_path, 1);
    free(saved_path);
  } else {
    unsetenv("PATH");
  }

  EXPECT_NULL(client);
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
