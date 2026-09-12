#include "test_server_cli.h"
#include "server_cli.h"
#include "test_utils.h"
#include <string.h>
#include <sys/socket.h>

static int parse_ok(const char* const* args, int count, ServerCliOptions* opts) {
  char err[512];
  int r = server_cli_parse(count, (char**)args, opts, err, sizeof(err));
  if (r == 0)
    return 0;
  if (r < 0)
    return -1;
  return 1;
}

static void test_server_cli_defaults() {
  const char* args[] = {"fastsync-server"};
  ServerCliOptions opts;
  EXPECT_EQ_INT(parse_ok(args, 1, &opts), 0);
  EXPECT_FALSE(opts.stdio_mode);
  EXPECT_FALSE(opts.daemon_mode);
  EXPECT_FALSE(opts.no_detach);
  EXPECT_FALSE(opts.verbose);
  EXPECT_FALSE(opts.use_tls);
  EXPECT_EQ_INT(opts.port, 8080);
  EXPECT_FALSE(opts.port_set);
  EXPECT_EQ_STR(opts.destination_root, ".");
  EXPECT_NULL(opts.config_path);
  EXPECT_EQ_INT(opts.dparam_count, 0);
  EXPECT_EQ_INT(opts.bind_family, AF_UNSPEC);
  EXPECT_FALSE(opts.allow_delete);
  EXPECT_FALSE(opts.allow_unauthenticated);
  EXPECT_FALSE(opts.no_super);
  server_cli_options_free(&opts);
}

/* --no-super is a standalone/SSH operator veto (does not require --daemon):
   it forces SUPER_MODE_OFF for every connection and refuses client --copy-as. */
static void test_server_cli_no_super() {
  const char* args[] = {"fastsync-server", "--no-super", "--destination-root", "/srv"};
  ServerCliOptions opts;
  EXPECT_EQ_INT(parse_ok(args, 4, &opts), 0);
  EXPECT_TRUE(opts.no_super);
  EXPECT_EQ_STR(opts.destination_root, "/srv");
  server_cli_options_free(&opts);

  const char* args2[] = {"fastsync-server", "--daemon", "--config=/tmp/x.conf", "--no-super"};
  ServerCliOptions opts2;
  EXPECT_EQ_INT(parse_ok(args2, 4, &opts2), 0);
  EXPECT_TRUE(opts2.no_super);
  EXPECT_TRUE(opts2.daemon_mode);
  server_cli_options_free(&opts2);
}

static void test_server_cli_daemon_flags() {
  const char* args[] = {"fastsync-server", "--daemon", "--no-detach", "--allow-unauthenticated"};
  ServerCliOptions opts;
  EXPECT_EQ_INT(parse_ok(args, 4, &opts), 0);
  EXPECT_TRUE(opts.daemon_mode);
  EXPECT_TRUE(opts.no_detach);
  EXPECT_TRUE(opts.allow_unauthenticated);
  server_cli_options_free(&opts);
}

static void test_server_cli_config_and_dparam_forms() {
  const char* args[] = {"fastsync-server",    "--daemon", "--config=/tmp/x.conf",
                        "--dparam=port=8734", "--dparam", "address=127.0.0.1"};
  ServerCliOptions opts;
  EXPECT_EQ_INT(parse_ok(args, 6, &opts), 0);
  EXPECT_EQ_STR(opts.config_path, "/tmp/x.conf");
  EXPECT_EQ_INT(opts.dparam_count, 2);
  EXPECT_EQ_STR(opts.dparams[0], "port=8734");
  EXPECT_EQ_STR(opts.dparams[1], "address=127.0.0.1");

  const char* args2[] = {"fastsync-server", "--daemon", "--config", "/tmp/y.conf"};
  ServerCliOptions opts2;
  EXPECT_EQ_INT(parse_ok(args2, 4, &opts2), 0);
  EXPECT_EQ_STR(opts2.config_path, "/tmp/y.conf");
  server_cli_options_free(&opts);
  server_cli_options_free(&opts2);
}

static void test_server_cli_preserves_existing_flags() {
  const char* args[] = {"fastsync-server",
                        "-p",
                        "9000",
                        "--tls",
                        "--cert",
                        "/c",
                        "--key",
                        "/k",
                        "--ca",
                        "/ca",
                        "--client-cn",
                        "cn",
                        "--allow-delete",
                        "--trust-sender",
                        "--address",
                        "127.0.0.1",
                        "-6",
                        "--destination-root",
                        "/srv"};
  ServerCliOptions opts;
  EXPECT_EQ_INT(parse_ok(args, 19, &opts), 0);
  EXPECT_EQ_INT(opts.port, 9000);
  EXPECT_TRUE(opts.port_set);
  EXPECT_TRUE(opts.use_tls);
  EXPECT_EQ_STR(opts.tls_cert, "/c");
  EXPECT_EQ_STR(opts.tls_key, "/k");
  EXPECT_EQ_STR(opts.tls_ca, "/ca");
  EXPECT_EQ_STR(opts.client_cn, "cn");
  EXPECT_TRUE(opts.allow_delete);
  EXPECT_TRUE(opts.trust_sender);
  EXPECT_EQ_STR(opts.bind_address, "127.0.0.1");
  EXPECT_EQ_INT(opts.bind_family, AF_INET6);
  EXPECT_TRUE(opts.destination_root_set);
  EXPECT_EQ_STR(opts.destination_root, "/srv");
  server_cli_options_free(&opts);
}

static void test_server_cli_conflicts() {
  /* server_cli_parse zero-initializes opts (server_cli_options_default) before
   * parsing, so `opts` is still safe to pass to server_cli_options_free even
   * when every parse below returns -1 on failure. */
  char err[256];
  ServerCliOptions opts;
  const char* a1[] = {"s", "--daemon", "--stdio"};
  EXPECT_EQ_INT(server_cli_parse(3, (char**)a1, &opts, err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "mutually exclusive") != NULL);

  const char* a2[] = {"s", "--daemon", "--destination-root", "/x"};
  EXPECT_EQ_INT(server_cli_parse(4, (char**)a2, &opts, err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "module paths") != NULL);

  const char* a3[] = {"s", "--config", "/x.conf"};
  EXPECT_EQ_INT(server_cli_parse(3, (char**)a3, &opts, err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "require --daemon") != NULL);

  const char* a4[] = {"s", "--no-detach"};
  EXPECT_EQ_INT(server_cli_parse(2, (char**)a4, &opts, err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "require --daemon") != NULL);
  server_cli_options_free(&opts);
}

static void test_server_cli_invalid() {
  char err[256];
  ServerCliOptions opts;
  const char* a1[] = {"s", "-p", "notaport"};
  EXPECT_EQ_INT(server_cli_parse(3, (char**)a1, &opts, err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "invalid port") != NULL);

  const char* a2[] = {"s", "-4", "-6"};
  EXPECT_EQ_INT(server_cli_parse(3, (char**)a2, &opts, err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "mutually exclusive") != NULL);

  const char* a3[] = {"s", "--nope"};
  EXPECT_EQ_INT(server_cli_parse(2, (char**)a3, &opts, err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "unknown option") != NULL);

  const char* a4[] = {"s", "--cert"};
  EXPECT_EQ_INT(server_cli_parse(2, (char**)a4, &opts, err, sizeof(err)), -1);
  server_cli_options_free(&opts);
}

static void test_server_cli_password_and_early_input() {
  const char* args[] = {"s", "--daemon", "--password-file=/etc/fast.pw", "--early-input",
                        "/run/secrets"};
  ServerCliOptions opts;
  EXPECT_EQ_INT(parse_ok(args, 5, &opts), 0);
  EXPECT_EQ_STR(opts.password_file, "/etc/fast.pw");
  EXPECT_EQ_STR(opts.early_input_file, "/run/secrets");

  const char* args2[] = {"s", "--daemon", "--password-file", "/etc/fast.pw",
                         "--early-input=/secrets"};
  ServerCliOptions opts2;
  EXPECT_EQ_INT(parse_ok(args2, 5, &opts2), 0);
  EXPECT_EQ_STR(opts2.password_file, "/etc/fast.pw");
  EXPECT_EQ_STR(opts2.early_input_file, "/secrets");
  server_cli_options_free(&opts);
  server_cli_options_free(&opts2);
}

static void test_server_cli_password_requires_daemon() {
  char err[256];
  ServerCliOptions opts;
  const char* a1[] = {"s", "--password-file", "/etc/fast.pw"};
  EXPECT_EQ_INT(server_cli_parse(3, (char**)a1, &opts, err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "require --daemon") != NULL);

  const char* a2[] = {"s", "--early-input", "/secrets"};
  EXPECT_EQ_INT(server_cli_parse(3, (char**)a2, &opts, err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "require --daemon") != NULL);

  const char* a3[] = {"s", "--daemon", "--password-file"};
  EXPECT_EQ_INT(server_cli_parse(3, (char**)a3, &opts, err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "missing argument") != NULL);
  server_cli_options_free(&opts);
}

static void test_server_cli_help() {
  char err[256];
  const char* a1[] = {"s", "--help"};
  ServerCliOptions opts;
  EXPECT_EQ_INT(server_cli_parse(2, (char**)a1, &opts, err, sizeof(err)), 1);
  EXPECT_TRUE(opts.show_help);
  server_cli_options_free(&opts);
}

void test_server_cli() {
  test_server_cli_defaults();
  test_server_cli_daemon_flags();
  test_server_cli_config_and_dparam_forms();
  test_server_cli_preserves_existing_flags();
  test_server_cli_conflicts();
  test_server_cli_invalid();
  test_server_cli_password_and_early_input();
  test_server_cli_password_requires_daemon();
  test_server_cli_no_super();
  test_server_cli_help();
}
