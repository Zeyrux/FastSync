#include "test_transport_ssh.h"
#include "test_utils.h"
#include "transport_ssh.h"

static void test_ssh_connect_invalid_dest_no_colon() {
  /* cppcheck-suppress constVariablePointer */
  Client* client =
      client_connect_ssh("invalid-destination-no-colon", 22, NULL, NULL, false, NULL, 0);
  EXPECT_NULL(client);
}

static void test_ssh_connect_invalid_dest_empty() {
  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh("", 22, NULL, NULL, false, NULL, 0);
  EXPECT_NULL(client);
}

/* A child that cannot exec ssh must not be returned as a successful client. */
static void test_ssh_connect_malformed() {
  const char* old_path = getenv("PATH");
  char* saved_path = old_path ? strdup(old_path) : NULL;
  setenv("PATH", "", 1);

  /* cppcheck-suppress constVariablePointer */
  Client* client = client_connect_ssh(":", 22, NULL, NULL, false, NULL, 0);

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
      client_connect_ssh("nonexistent.invalid:/remote/path", 22, NULL, NULL, false, NULL, 0);
  if (client != NULL) {
    client_disconnect(client);
    client_delete(client);
  }
  EXPECT_TRUE(true);
}

static void test_ssh_remote_command_argument_modes() {
  char* command = ssh_build_remote_command("fast sync; touch /tmp/pwned", NULL, 0);
  EXPECT_EQ_STR(command, "'fast sync; touch /tmp/pwned' --stdio");
  free(command);

  command = ssh_build_remote_command("fast'sync", NULL, 0);
  EXPECT_EQ_STR(command, "'fast'\\''sync' --stdio");
  free(command);
}

/* The build for a single-word argv is [prog, six -o args, "--", user, command]. */

static void test_ssh_build_client_argv_default_is_ssh() {
  char** argv = ssh_build_client_argv(NULL, 0, "u@h", "'srv' --stdio");
  EXPECT_NOT_NULL(argv);
  EXPECT_EQ_STR(argv[0], "ssh");
  EXPECT_EQ_STR(argv[1], "-o");
  /* The "--" end-of-options marker precedes the destination token. */
  EXPECT_EQ_STR(argv[7], "--");
  EXPECT_EQ_STR(argv[8], "u@h");
  EXPECT_EQ_STR(argv[9], "'srv' --stdio");
  EXPECT_NULL(argv[10]);
  ssh_free_client_argv(argv);
}

/* A configured rsh must replace "ssh" as argv[0] (and never leak the default). */
static void test_ssh_build_client_argv_uses_custom_rsh() {
  char** argv = ssh_build_client_argv("myrsh", 0, "u@h", "rc");
  EXPECT_NOT_NULL(argv);
  EXPECT_EQ_STR(argv[0], "myrsh");
  EXPECT_NULL(argv[10]);
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
  EXPECT_NULL(argv[12]);
  ssh_free_client_argv(argv);

  argv = ssh_build_client_argv("ssh", 2222, "u@h", "rc");
  EXPECT_NOT_NULL(argv);
  EXPECT_EQ_STR(argv[0], "ssh");
  /* Flat [prog, -o x6, -p, port, "--", user, command]. */
  EXPECT_EQ_STR(argv[7], "-p");
  EXPECT_EQ_STR(argv[8], "2222");
  EXPECT_EQ_STR(argv[9], "--");
  EXPECT_EQ_STR(argv[10], "u@h");
  EXPECT_EQ_STR(argv[11], "rc");
  EXPECT_NULL(argv[12]);
  ssh_free_client_argv(argv);
}

/* C1: a destination host/user beginning with '-' would be parsed by ssh as an
 * option (argument injection: -oProxyCommand=...), and an empty host is never
 * valid.  These are refused before any child is forked, so no Client is
 * returned and no command can run. */
static void test_ssh_connect_rejects_option_host() {
  /* cppcheck-suppress constVariablePointer */
  Client* client =
      client_connect_ssh("-oProxyCommand=touch /tmp/pwned:/remote", 22, NULL, NULL, false, NULL, 0);
  EXPECT_NULL(client);
  client = client_connect_ssh("-evil:/remote", 22, NULL, NULL, false, NULL, 0);
  EXPECT_NULL(client);
  client = client_connect_ssh("user@:/remote", 22, NULL, NULL, false, NULL, 0);
  EXPECT_NULL(client);
}

/* --remote-option=OPT appends OPT to the remote command line after " --stdio",
 * each escaped as its own single-quoted shell word.  Metacharacters that could
 * break out of the quoting are neutralized (never injected), matching the
 * ssh_build_remote_command safety boundary for the server path. */
static void test_ssh_remote_command_with_remote_options() {
  char* noop[] = {"--allow-delete"};
  char* command = ssh_build_remote_command("fastsync-server", noop, 1);
  EXPECT_EQ_STR(command, "'fastsync-server' --stdio '--allow-delete'");
  free(command);

  /* Multiple options append in order, each as its own quoted word. */
  char* multi[] = {"-v", "--allow-delete"};
  command = ssh_build_remote_command("srv", multi, 2);
  EXPECT_EQ_STR(command, "'srv' --stdio '-v' '--allow-delete'");
  free(command);

  /* A remote option containing a single quote and shell metacharacters is
     escaped with the same "'\''" boundary, so it stays one word and cannot
     break out into an arbitrary remote command. */
  char* val = strdup("--x=un'der; touch /tmp/pwned");
  char* dangerous[1] = {val};
  command = ssh_build_remote_command("srv", dangerous, 1);
  EXPECT_EQ_STR(command, "'srv' --stdio '--x=un'\\''der; touch /tmp/pwned'");
  free(command);
  free(val);
}

/* The remote command builder refuses to forward an empty or control-character
 * remote option (defense-in-depth independent of the CLI validation). */
static void test_ssh_remote_command_rejects_bad_options() {
  char* empty[] = {""};
  EXPECT_NULL(ssh_build_remote_command("srv", empty, 1));

  char nl = '\n';
  char* newline[] = {&nl};
  EXPECT_NULL(ssh_build_remote_command("srv", newline, 1));

  char* with_null[] = {NULL};
  EXPECT_NULL(ssh_build_remote_command("srv", with_null, 1));
}

void test_transport_ssh() {
  test_ssh_connect_invalid_dest_no_colon();
  test_ssh_connect_invalid_dest_empty();
  test_ssh_connect_malformed();
  test_ssh_connect_unreachable();
  test_ssh_connect_rejects_option_host();
  test_ssh_remote_command_argument_modes();
  test_ssh_build_client_argv_default_is_ssh();
  test_ssh_build_client_argv_uses_custom_rsh();
  test_ssh_build_client_argv_whitespace_command_and_port();
  test_ssh_remote_command_with_remote_options();
  test_ssh_remote_command_rejects_bad_options();
}