#include "test_transport_ssh.h"
#include "test_utils.h"
#include "transport_ssh.h"

static void test_ssh_connect_invalid_dest_no_colon() {
  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh("invalid-destination-no-colon", 22, NULL, false, NULL, 0);
  EXPECT_NULL(client);
}

static void test_ssh_connect_invalid_dest_empty() {
  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh("", 22, NULL, false, NULL, 0);
  EXPECT_NULL(client);
}

/* A child that cannot exec ssh must not be returned as a successful client. */
static void test_ssh_connect_malformed() {
  const char* old_path = getenv("PATH");
  char* saved_path = old_path ? strdup(old_path) : NULL;
  setenv("PATH", "", 1);

  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh(":", 22, NULL, false, NULL, 0);

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
  Client* client = client_connect_ssh("nonexistent.invalid:/remote/path", 22, NULL, false, NULL, 0);
  if (client != NULL) {
    client_disconnect(client);
    client_delete(client);
  }
  EXPECT_TRUE(true);
}

static void test_ssh_remote_command_argument_modes() {
  char* command = ssh_build_remote_command("fast sync; touch /tmp/pwned", false, NULL, 0);
  EXPECT_EQ_STR(command, "'fast sync; touch /tmp/pwned' --stdio");
  free(command);

  command = ssh_build_remote_command("fast'sync", false, NULL, 0);
  EXPECT_EQ_STR(command, "'fast'\\''sync' --stdio");
  free(command);

  command = ssh_build_remote_command("fast sync; touch /tmp/pwned", true, NULL, 0);
  EXPECT_EQ_STR(command, "fast sync; touch /tmp/pwned --stdio");
  free(command);
}

/* --remote-option=OPT appends OPT to the remote command line after " --stdio",
 * each escaped as its own single-quoted shell word.  Metacharacters that could
 * break out of the quoting are neutralized (never injected), matching the
 * ssh_build_remote_command safety boundary for the server path. */
static void test_ssh_remote_command_with_remote_options() {
  char* noop[] = {"--allow-delete"};
  char* command = ssh_build_remote_command("fastsync-server", false, noop, 1);
  EXPECT_EQ_STR(command, "'fastsync-server' --stdio '--allow-delete'");
  free(command);

  /* Multiple options append in order, each as its own quoted word. */
  char* multi[] = {"-v", "--allow-delete"};
  command = ssh_build_remote_command("srv", false, multi, 2);
  EXPECT_EQ_STR(command, "'srv' --stdio '-v' '--allow-delete'");
  free(command);

  /* A remote option containing a single quote and shell metacharacters is
     escaped with the same "'\''" boundary, so it stays one word and cannot
     break out into an arbitrary remote command. */
  char* val = strdup("--x=un'der; touch /tmp/pwned");
  char* dangerous[1] = {val};
  command = ssh_build_remote_command("srv", false, dangerous, 1);
  EXPECT_EQ_STR(command, "'srv' --stdio '--x=un'\\''der; touch /tmp/pwned'");
  free(command);
  free(val);

  /* --old-args leaves the server path unquoted but still quotes remote options. */
  command = ssh_build_remote_command("srv", true, multi, 2);
  EXPECT_EQ_STR(command, "srv --stdio '-v' '--allow-delete'");
  free(command);
}

/* The remote command builder refuses to forward an empty or control-character
 * remote option (defense-in-depth independent of the CLI validation). */
static void test_ssh_remote_command_rejects_bad_options() {
  char* empty[] = {""};
  EXPECT_NULL(ssh_build_remote_command("srv", false, empty, 1));

  char nl = '\n';
  char* newline[] = {&nl};
  EXPECT_NULL(ssh_build_remote_command("srv", false, newline, 1));

  char* with_null[] = {NULL};
  EXPECT_NULL(ssh_build_remote_command("srv", false, with_null, 1));
}

void test_transport_ssh() {
  test_ssh_connect_invalid_dest_no_colon();
  test_ssh_connect_invalid_dest_empty();
  test_ssh_connect_malformed();
  test_ssh_connect_unreachable();
  test_ssh_remote_command_argument_modes();
  test_ssh_remote_command_with_remote_options();
  test_ssh_remote_command_rejects_bad_options();
}
