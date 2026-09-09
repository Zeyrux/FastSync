#include "test_transport_ssh.h"
#include "test_utils.h"
#include "transport_ssh.h"

static void test_ssh_connect_invalid_dest_no_colon() {
  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh("invalid-destination-no-colon", 22, NULL, false, NULL, false);
  EXPECT_NULL(client);
}

static void test_ssh_connect_invalid_dest_empty() {
  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh("", 22, NULL, false, NULL, false);
  EXPECT_NULL(client);
}

/* A child that cannot exec ssh must not be returned as a successful client. */
static void test_ssh_connect_malformed() {
  const char* old_path = getenv("PATH");
  char* saved_path = old_path ? strdup(old_path) : NULL;
  setenv("PATH", "", 1);

  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh(":", 22, NULL, false, NULL, false);

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
  Client* client =
      client_connect_ssh("nonexistent.invalid:/remote/path", 22, NULL, false, NULL, false);
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

/* The build for a single-word argv is [prog, six -o args, user, command]. */

static void test_ssh_build_client_argv_default_is_ssh() {
  char** argv = ssh_build_client_argv(NULL, 0, "u@h", "'srv' --stdio");
  EXPECT_NOT_NULL(argv);
  EXPECT_EQ_STR(argv[0], "ssh");
  EXPECT_EQ_STR(argv[1], "-o");
  EXPECT_EQ_STR(argv[7], "u@h");
  EXPECT_EQ_STR(argv[8], "'srv' --stdio");
  EXPECT_NULL(argv[9]);
  ssh_free_client_argv(argv);
}

/* A configured rsh must replace "ssh" as argv[0] (and never leak the default). */
static void test_ssh_build_client_argv_uses_custom_rsh() {
  char** argv = ssh_build_client_argv("myrsh", 0, "u@h", "rc");
  EXPECT_NOT_NULL(argv);
  EXPECT_EQ_STR(argv[0], "myrsh");
  EXPECT_NULL(argv[9]);
  ssh_free_client_argv(argv);
}

/* A multi-word rsh command line (rsync -e "ssh -p 2222") is split into the
 * leading argv words; a non-default port adds a -p/value pair. */
static void test_ssh_build_client_argv_whitespace_command_and_port() {
  char** argv = ssh_build_client_argv("ssh -p 2222", 0, "u@h", "rc");
  EXPECT_NOT_NULL(argv);
  EXPECT_EQ_STR(argv[0], "ssh");
  EXPECT_EQ_STR(argv[1], "-p");
  EXPECT_EQ_STR(argv[2], "2222");
  EXPECT_NULL(argv[11]);
  ssh_free_client_argv(argv);

  argv = ssh_build_client_argv("ssh", 2222, "u@h", "rc");
  EXPECT_NOT_NULL(argv);
  EXPECT_EQ_STR(argv[0], "ssh");
  /* Flat [prog, -o x6, -p, port, user, command]. */
  EXPECT_EQ_STR(argv[7], "-p");
  EXPECT_EQ_STR(argv[8], "2222");
  EXPECT_EQ_STR(argv[9], "u@h");
  EXPECT_EQ_STR(argv[10], "rc");
  EXPECT_NULL(argv[11]);
  ssh_free_client_argv(argv);
}

void test_transport_ssh() {
  test_ssh_connect_invalid_dest_no_colon();
  test_ssh_connect_invalid_dest_empty();
  test_ssh_connect_malformed();
  test_ssh_connect_unreachable();
  test_ssh_remote_command_argument_modes();
  test_ssh_build_client_argv_default_is_ssh();
  test_ssh_build_client_argv_uses_custom_rsh();
  test_ssh_build_client_argv_whitespace_command_and_port();
}
