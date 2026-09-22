#include "test_daemon_conf.h"
#include "credentials.h"
#include "daemon_conf.h"
#include "log.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Write a config body into a fresh temp file and return its path in out_path
 * (heap-allocated; caller frees).  Returns 0 on success. */
static int write_conf(const char* body, char** out_path) {
  char tmpl[] = "/tmp/fastsync_daemon_conf_XXXXXX";
  int fd = mkstemp(tmpl);
  if (fd < 0)
    return -1;
  size_t len = strlen(body);
  if (write(fd, body, len) != (ssize_t)len) {
    close(fd);
    unlink(tmpl);
    return -1;
  }
  close(fd);
  *out_path = strdup(tmpl);
  return *out_path ? 0 : -1;
}

static void test_daemon_conf_create_defaults() {
  DaemonConf* conf = daemon_conf_create();
  EXPECT_NOT_NULL(conf);
  EXPECT_EQ_INT(conf->global.port, DAEMON_CONF_DEFAULT_PORT);
  EXPECT_NULL(conf->global.motd_file);
  EXPECT_NULL(conf->global.address);
  /* rsync modules are read-only unless they opt in, so the default must be
   * true. */
  EXPECT_TRUE(conf->global.read_only_default);
  EXPECT_EQ_INT(conf->global.max_connections, DAEMON_CONF_DEFAULT_MAX_CONNECTIONS);
  EXPECT_EQ_INT(conf->global.auth_failure_delay_ms, DAEMON_CONF_DEFAULT_AUTH_FAILURE_DELAY_MS);
  EXPECT_EQ_INT(conf->global.max_connections_per_host,
                DAEMON_CONF_DEFAULT_MAX_CONNECTIONS_PER_HOST);
  EXPECT_EQ_INT(conf->global.auth_lockout_threshold, DAEMON_CONF_DEFAULT_AUTH_LOCKOUT_THRESHOLD);
  EXPECT_EQ_INT(conf->global.auth_lockout_duration_sec,
                DAEMON_CONF_DEFAULT_AUTH_LOCKOUT_DURATION_SEC);
  EXPECT_EQ_INT(conf->global.hosts_allow_count, 0);
  EXPECT_EQ_INT(conf->global.hosts_deny_count, 0);
  EXPECT_EQ_INT(conf->module_count, 0);
  daemon_conf_free(conf);
}

static void test_daemon_conf_full_parse() {
  char* path;
  EXPECT_EQ_INT(write_conf("port = 8734\n"
                           "motd file = /etc/fastsync/motd\n"
                           "address = 127.0.0.1\n"
                           "\n"
                           "[backup]\n"
                           "path = /srv/backup\n"
                           "read only = yes\n"
                           "client owner = yes\n"
                           "auth users = alice, bob\n",
                           &path),
                0);
  char err[256];
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_EQ_INT(conf->global.port, 8734);
  EXPECT_EQ_STR(conf->global.motd_file, "/etc/fastsync/motd");
  EXPECT_EQ_STR(conf->global.address, "127.0.0.1");
  EXPECT_EQ_INT(conf->module_count, 1);
  EXPECT_EQ_STR(conf->modules[0].name, "backup");
  EXPECT_EQ_STR(conf->modules[0].path, "/srv/backup");
  EXPECT_TRUE(conf->modules[0].read_only);
  EXPECT_TRUE(conf->modules[0].client_owner);
  EXPECT_EQ_INT(conf->modules[0].auth_user_count, 2);
  EXPECT_EQ_STR(conf->modules[0].auth_users[0], "alice");
  EXPECT_EQ_STR(conf->modules[0].auth_users[1], "bob");
  daemon_conf_free(conf);
}

static void test_daemon_conf_comments_and_blank_lines() {
  char* path;
  EXPECT_EQ_INT(write_conf("# a full-line comment\n"
                           "; a semicolon comment\n"
                           "   # indented comment\n"
                           "   \n"
                           "\t; another\n"
                           "[alpha]\n"
                           "path = /a\n"
                           "\n"
                           "[beta]\n"
                           "path = /b\n",
                           &path),
                0);
  char err[256];
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_EQ_INT(conf->module_count, 2);
  EXPECT_EQ_STR(conf->modules[0].name, "alpha");
  EXPECT_EQ_STR(conf->modules[1].name, "beta");
  /* `client owner` defaults to off: a module must opt in to client-chosen
     ownership. */
  EXPECT_FALSE(conf->modules[0].client_owner);
  EXPECT_FALSE(conf->modules[1].client_owner);
  daemon_conf_free(conf);
}

static void test_daemon_conf_case_insensitive_and_bool_variants() {
  char* path;
  EXPECT_EQ_INT(write_conf("PORT = 9001\n"
                           "[CaseMod]\n"
                           "PATH = /cm\n"
                           "READ ONLY = True\n",
                           &path),
                0);
  char err[256];
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_EQ_INT(conf->global.port, 9001);
  EXPECT_EQ_INT(conf->module_count, 1);
  EXPECT_EQ_STR(conf->modules[0].name, "CaseMod");
  EXPECT_TRUE(conf->modules[0].read_only);
  daemon_conf_free(conf);

  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nread only = 0\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_FALSE(conf->modules[0].read_only);
  daemon_conf_free(conf);

  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nread only = false\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_FALSE(conf->modules[0].read_only);
  daemon_conf_free(conf);
}

static void test_daemon_conf_quoted_value() {
  char* path;
  EXPECT_EQ_INT(write_conf("[m]\npath = \"/srv/my dir/mod\"\n", &path), 0);
  char err[256];
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_EQ_STR(conf->modules[0].path, "/srv/my dir/mod");
  daemon_conf_free(conf);
}

static void test_daemon_conf_global_defaults_when_absent() {
  char* path;
  EXPECT_EQ_INT(write_conf("[m]\npath = /x\n", &path), 0);
  char err[256];
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_EQ_INT(conf->global.port, DAEMON_CONF_DEFAULT_PORT); /* 873 */
  EXPECT_NULL(conf->global.motd_file);
  EXPECT_NULL(conf->global.address);
  daemon_conf_free(conf);
}

static void test_daemon_conf_unknown_key_rejected() {
  char* path;
  char err[256];
  EXPECT_EQ_INT(write_conf("bogus_key = 1\n", &path), 0);
  const DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "unknown global key") != NULL);

  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nflavor = van\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "unknown key 'flavor'") != NULL);
}

static void test_daemon_conf_malformed_rejected() {
  char* path;
  char err[256];
  const DaemonConf* conf;

  EXPECT_EQ_INT(write_conf("port 8734\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "expected 'key = value'") != NULL);

  EXPECT_EQ_INT(write_conf("[m]\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "no 'path'") != NULL);

  EXPECT_EQ_INT(write_conf("[m\npath = /x\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "unterminated module header") != NULL);

  EXPECT_EQ_INT(write_conf("[m] trailing\npath = /x\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "after module header") != NULL);

  EXPECT_EQ_INT(write_conf("port = notanumber\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "invalid port") != NULL);

  EXPECT_EQ_INT(write_conf("port = 70000\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "invalid port") != NULL);

  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nread only = maybe\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "read only") != NULL);

  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nclient owner = maybe\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "client owner") != NULL);

  EXPECT_EQ_INT(write_conf("= value\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "empty key") != NULL);

  EXPECT_EQ_INT(write_conf("[]\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "invalid module name") != NULL);

  EXPECT_EQ_INT(write_conf("[bad/name]\npath = /x\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);

  EXPECT_EQ_INT(write_conf("[m]\npath = \"/unterminated\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "unterminated quoted value") != NULL);
}

static void test_daemon_conf_duplicate_module_rejected() {
  char* path;
  char err[256];
  EXPECT_EQ_INT(write_conf("[m]\npath = /a\n[m]\npath = /b\n", &path), 0);
  const DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "duplicate module") != NULL);
}

static void test_daemon_conf_long_line_rejected() {
  char* path;
  char err[256];
  char body[4600];
  memset(body, 'a', sizeof(body) - 1);
  memcpy(body, "[m]\npath = /x\nport = ", 21);
  body[sizeof(body) - 1] = '\0';
  EXPECT_EQ_INT(write_conf(body, &path), 0);
  const DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "exceeds the") != NULL);
}

static void test_daemon_conf_missing_file_rejected() {
  char err[256];
  const DaemonConf* conf =
      daemon_conf_load("/nonexistent/fastsync_daemon_conf_zzz", err, sizeof(err));
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "cannot open") != NULL);
}

static void test_daemon_conf_find_module() {
  char* path;
  EXPECT_EQ_INT(write_conf("[known]\npath = /rooted\n[m]\npath = /other\n", &path), 0);
  char err[256];
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  const DaemonModule* found = daemon_conf_find_module(conf, "known");
  EXPECT_NOT_NULL(found);
  EXPECT_EQ_STR(found->path, "/rooted");
  EXPECT_NULL(daemon_conf_find_module(conf, "nope"));
  /* Case-sensitive like rsync module names. */
  EXPECT_NULL(daemon_conf_find_module(conf, "Known"));
  daemon_conf_free(conf);
}

static void test_daemon_conf_dparam_override() {
  DaemonConf* conf = daemon_conf_create();
  EXPECT_NOT_NULL(conf);
  char err[256];

  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "port=8734", err, sizeof(err)), 0);
  EXPECT_EQ_INT(conf->global.port, 8734);

  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "motd file=/tmp/motd", err, sizeof(err)), 0);
  EXPECT_EQ_STR(conf->global.motd_file, "/tmp/motd");

  /* Keys are case-insensitive. */
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "ADDRESS=127.0.0.1", err, sizeof(err)), 0);
  EXPECT_EQ_STR(conf->global.address, "127.0.0.1");

  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "port = 9000", err, sizeof(err)), 0);
  EXPECT_EQ_INT(conf->global.port, 9000);

  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "max connections=7", err, sizeof(err)), 0);
  EXPECT_EQ_INT(conf->global.max_connections, 7);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "max connections per host=3", err, sizeof(err)), 0);
  EXPECT_EQ_INT(conf->global.max_connections_per_host, 3);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "auth lockout threshold=5", err, sizeof(err)), 0);
  EXPECT_EQ_INT(conf->global.auth_lockout_threshold, 5);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "auth lockout duration=120", err, sizeof(err)), 0);
  EXPECT_EQ_INT(conf->global.auth_lockout_duration_sec, 120);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "AUTH FAILURE DELAY=1500", err, sizeof(err)), 0);
  EXPECT_EQ_INT(conf->global.auth_failure_delay_ms, 1500);
  EXPECT_EQ_INT(
      daemon_conf_apply_dparam(conf, "hosts allow=127.0.0.1,10.0.0.0/8", err, sizeof(err)), 0);
  EXPECT_EQ_INT(conf->global.hosts_allow_count, 2);
  /* A later --dparam replaces the list (an override must be able to narrow). */
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "hosts allow=127.0.0.1", err, sizeof(err)), 0);
  EXPECT_EQ_INT(conf->global.hosts_allow_count, 1);
  EXPECT_EQ_STR(conf->global.hosts_allow[0], "127.0.0.1");

  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "port=notaport", err, sizeof(err)), -1);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "bogus=1", err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "unknown global key") != NULL);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "port", err, sizeof(err)), -1);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "=1", err, sizeof(err)), -1);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "port=", err, sizeof(err)), -1);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "", err, sizeof(err)), -1);

  daemon_conf_free(conf);
}

/* Each `auth users` entry is validated with the same username rule as the
 * credential store, so invisible whitespace/control characters can never make
 * an exact strcmp match ambiguous. */
static void test_daemon_conf_auth_users_validated() {
  char* path;
  char err[256];
  const DaemonConf* conf;

  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nauth users = alice, bad user\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "invalid 'auth users' entry") != NULL);

  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nauth users = good\tbad\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "invalid 'auth users' entry") != NULL);

  /* An over-long name exceeds CREDENTIAL_MAX_USER_LEN and is rejected. */
  {
    char body[CREDENTIAL_MAX_USER_LEN + 128];
    int n = snprintf(body, sizeof(body), "[m]\npath = /x\nauth users = ");
    memset(body + n, 'a', CREDENTIAL_MAX_USER_LEN + 1);
    body[n + CREDENTIAL_MAX_USER_LEN + 1] = '\n';
    body[n + CREDENTIAL_MAX_USER_LEN + 2] = '\0';
    EXPECT_EQ_INT(write_conf(body, &path), 0);
    conf = daemon_conf_load(path, err, sizeof(err));
    free(path);
    EXPECT_NULL(conf);
    EXPECT_TRUE(strstr(err, "invalid 'auth users' entry") != NULL);
  }

  /* Empty entries between commas are skipped, not treated as invalid. */
  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nauth users = alice,, bob\n", &path), 0);
  DaemonConf* ok_conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(ok_conf);
  EXPECT_EQ_INT(ok_conf->modules[0].auth_user_count, 2);
  EXPECT_EQ_STR(ok_conf->modules[0].auth_users[0], "alice");
  EXPECT_EQ_STR(ok_conf->modules[0].auth_users[1], "bob");
  daemon_conf_free(ok_conf);

  /* C4: an empty or separator-only `auth users` value is a parse error.  It
   * would otherwise leave the module with a zero-length allow-list, silently
   * disabling the authentication the operator asked for. */
  const char* empty_auth[] = {
      "[m]\npath = /x\nauth users = \n",
      "[m]\npath = /x\nauth users = , ,\n",
      "[m]\npath = /x\nauth users = \t\n",
  };
  for (size_t i = 0; i < sizeof(empty_auth) / sizeof(empty_auth[0]); i++) {
    EXPECT_EQ_INT(write_conf(empty_auth[i], &path), 0);
    const DaemonConf* rejected = daemon_conf_load(path, err, sizeof(err));
    free(path);
    EXPECT_NULL(rejected);
    EXPECT_TRUE(strstr(err, "'auth users' must list at least one user") != NULL);
  }
}

/* Wave 3 daemon hardening: configurable global/per-module connection caps,
 * auth-failure throttle and host access lists parse strictly (valid values are
 * stored, malformed values fail the whole load). */
static void test_daemon_conf_limits_and_hosts_parse() {
  char* path;
  char err[256];
  EXPECT_EQ_INT(write_conf("max connections = 25\n"
                           "auth failure delay = 0\n"
                           "max connections per host = 4\n"
                           "auth lockout threshold = 3\n"
                           "auth lockout duration = 60\n"
                           "hosts allow = 10.0.0.0/8, 192.168.1.0/24\n"
                           "hosts deny = 192.168.0.1 2001:db8::/32\n"
                           "\n"
                           "[m]\n"
                           "path = /x\n"
                           "max connections = 3\n"
                           "hosts allow = 127.0.0.1\n"
                           "hosts deny = *\n",
                           &path),
                0);
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_EQ_INT(conf->global.max_connections, 25);
  EXPECT_EQ_INT(conf->global.auth_failure_delay_ms, 0);
  EXPECT_EQ_INT(conf->global.max_connections_per_host, 4);
  EXPECT_EQ_INT(conf->global.auth_lockout_threshold, 3);
  EXPECT_EQ_INT(conf->global.auth_lockout_duration_sec, 60);
  EXPECT_EQ_INT(conf->global.hosts_allow_count, 2);
  EXPECT_EQ_STR(conf->global.hosts_allow[0], "10.0.0.0/8");
  EXPECT_EQ_STR(conf->global.hosts_allow[1], "192.168.1.0/24");
  EXPECT_EQ_INT(conf->global.hosts_deny_count, 2);
  EXPECT_EQ_STR(conf->global.hosts_deny[0], "192.168.0.1");
  EXPECT_EQ_STR(conf->global.hosts_deny[1], "2001:db8::/32");
  EXPECT_EQ_INT(conf->modules[0].max_connections, 3);
  EXPECT_EQ_INT(conf->modules[0].hosts_allow_count, 1);
  EXPECT_EQ_STR(conf->modules[0].hosts_allow[0], "127.0.0.1");
  EXPECT_EQ_INT(conf->modules[0].hosts_deny_count, 1);
  EXPECT_EQ_STR(conf->modules[0].hosts_deny[0], "*");
  daemon_conf_free(conf);

  const char* bad_values[] = {
      "max connections = 0\n",           "max connections = -1\n",
      "max connections = abc\n",         "auth failure delay = -1\n",
      "auth failure delay = 70000\n",    "auth failure delay = soon\n",
      "max connections per host = -1\n", "max connections per host = lots\n",
      "auth lockout threshold = -2\n",   "auth lockout threshold = many\n",
      "auth lockout duration = -1\n",    "auth lockout duration = forever\n",
      "hosts allow = 10.0.0.0/99\n",     "hosts deny = 2001:db8::/129\n",
      "hosts allow = *.example.com\n",   "hosts deny = not-an-ip\n",
  };
  for (size_t i = 0; i < sizeof(bad_values) / sizeof(bad_values[0]); i++) {
    EXPECT_EQ_INT(write_conf(bad_values[i], &path), 0);
    const DaemonConf* rejected = daemon_conf_load(path, err, sizeof(err));
    free(path);
    EXPECT_NULL(rejected);
  }

  /* The same strictness applies inside a module section. */
  const char* bad_module[] = {
      "[m]\npath = /x\nmax connections = -1\n",
      "[m]\npath = /x\nmax connections = abc\n",
      "[m]\npath = /x\nhosts allow = 10.0.0.0/40\n",
      "[m]\npath = /x\nhosts deny = 999.1.1.1/8\n",
  };
  for (size_t i = 0; i < sizeof(bad_module) / sizeof(bad_module[0]); i++) {
    EXPECT_EQ_INT(write_conf(bad_module[i], &path), 0);
    const DaemonConf* rejected = daemon_conf_load(path, err, sizeof(err));
    free(path);
    EXPECT_NULL(rejected);
    EXPECT_TRUE(strstr(err, "invalid") != NULL);
  }

  /* Module `max connections = 0` is now valid and means unlimited. */
  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nmax connections = 0\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_EQ_INT(conf->modules[0].max_connections, 0);
  daemon_conf_free(conf);

  /* C4: a present hosts key with an empty/separator-only value must not silently
   * install a zero-length (allow-everyone) list. */
  const char* empty_hosts[] = {
      "hosts allow = \n[m]\npath = /x\n",
      "hosts deny = \n[m]\npath = /x\n",
      "hosts allow = , ,\n[m]\npath = /x\n",
      "hosts deny = \t\n[m]\npath = /x\n",
  };
  for (size_t i = 0; i < sizeof(empty_hosts) / sizeof(empty_hosts[0]); i++) {
    EXPECT_EQ_INT(write_conf(empty_hosts[i], &path), 0);
    const DaemonConf* rejected = daemon_conf_load(path, err, sizeof(err));
    free(path);
    EXPECT_NULL(rejected);
    EXPECT_TRUE(strstr(err, "must list at least one host pattern") != NULL);
  }

  const char* empty_module_hosts[] = {
      "[m]\npath = /x\nhosts allow = \n",
      "[m]\npath = /x\nhosts deny = ,\n",
  };
  for (size_t i = 0; i < sizeof(empty_module_hosts) / sizeof(empty_module_hosts[0]); i++) {
    EXPECT_EQ_INT(write_conf(empty_module_hosts[i], &path), 0);
    const DaemonConf* rejected = daemon_conf_load(path, err, sizeof(err));
    free(path);
    EXPECT_NULL(rejected);
    EXPECT_TRUE(strstr(err, "must list at least one host pattern") != NULL);
    /* The diagnostic must name the offending module. */
    EXPECT_TRUE(strstr(err, "module 'm'") != NULL);
  }

  /* Per-module host lists APPEND across lines like the global ones.  (A swapped
   * store_host_list call passed the module name as `replace`, so each line
   * silently replaced the previous one and only the last survived.) */
  EXPECT_EQ_INT(write_conf("[m]\npath = /x\n"
                           "hosts allow = 127.0.0.1\n"
                           "hosts allow = 10.0.0.0/8\n"
                           "hosts deny = 192.168.0.1\n"
                           "hosts deny = 2001:db8::/32\n",
                           &path),
                0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_EQ_INT(conf->modules[0].hosts_allow_count, 2);
  EXPECT_EQ_STR(conf->modules[0].hosts_allow[0], "127.0.0.1");
  EXPECT_EQ_STR(conf->modules[0].hosts_allow[1], "10.0.0.0/8");
  EXPECT_EQ_INT(conf->modules[0].hosts_deny_count, 2);
  EXPECT_EQ_STR(conf->modules[0].hosts_deny[0], "192.168.0.1");
  EXPECT_EQ_STR(conf->modules[0].hosts_deny[1], "2001:db8::/32");
  daemon_conf_free(conf);
}

static void test_daemon_hosts_allowed() {
  /* Pattern forms. */
  EXPECT_TRUE(daemon_host_pattern_match("*", "203.0.113.9"));
  EXPECT_TRUE(daemon_host_pattern_match("10.0.0.1", "10.0.0.1"));
  EXPECT_FALSE(daemon_host_pattern_match("10.0.0.1", "10.0.0.2"));
  EXPECT_TRUE(daemon_host_pattern_match("10.0.0.0/8", "10.255.1.2"));
  EXPECT_FALSE(daemon_host_pattern_match("10.0.0.0/8", "11.0.0.1"));
  EXPECT_TRUE(daemon_host_pattern_match("2001:db8::/32", "2001:db8:1234::5"));
  EXPECT_FALSE(daemon_host_pattern_match("2001:db8::/32", "2001:db9::1"));
  EXPECT_TRUE(daemon_host_pattern_match("::1", "::1"));
  EXPECT_FALSE(daemon_host_pattern_match("::1", "::2"));
  EXPECT_TRUE(daemon_host_pattern_match("*.example.com", "host.example.com"));
  EXPECT_FALSE(daemon_host_pattern_match("*.example.com", "example.org"));
  EXPECT_FALSE(daemon_host_pattern_match(NULL, "10.0.0.1"));
  EXPECT_FALSE(daemon_host_pattern_match("10.0.0.1", NULL));
  EXPECT_FALSE(daemon_host_pattern_match("", "10.0.0.1"));

  char* allow[] = {"10.0.0.0/8"};
  char* deny[] = {"10.0.0.1"};
  /* Deny takes precedence over a matching allow. */
  EXPECT_FALSE(daemon_hosts_allowed("10.0.0.1", allow, 1, deny, 1));
  EXPECT_TRUE(daemon_hosts_allowed("10.0.0.2", allow, 1, deny, 1));
  /* A non-empty allow list rejects a peer that matches none of its entries. */
  EXPECT_FALSE(daemon_hosts_allowed("192.168.1.1", allow, 1, NULL, 0));
  /* With only a deny list, everything not denied is accepted. */
  EXPECT_TRUE(daemon_hosts_allowed("192.168.1.1", NULL, 0, deny, 1));
  EXPECT_FALSE(daemon_hosts_allowed("10.0.0.1", NULL, 0, deny, 1));
  /* No lists at all accepts everyone. */
  EXPECT_TRUE(daemon_hosts_allowed("192.168.1.1", NULL, 0, NULL, 0));
  /* An unprovable peer (NULL) never matches an allow list. */
  EXPECT_FALSE(daemon_hosts_allowed(NULL, allow, 1, NULL, 0));

  EXPECT_FALSE(daemon_hosts_restricted(NULL, 0, NULL, 0));
  EXPECT_TRUE(daemon_hosts_restricted(allow, 1, NULL, 0));
  EXPECT_TRUE(daemon_hosts_restricted(NULL, 0, deny, 1));
}

static void test_daemon_module_name_valid() {
  EXPECT_TRUE(daemon_module_name_valid("backup"));
  EXPECT_TRUE(daemon_module_name_valid("Backup_2"));
  EXPECT_TRUE(daemon_module_name_valid("a.b-c"));
  EXPECT_FALSE(daemon_module_name_valid(""));
  EXPECT_FALSE(daemon_module_name_valid("with space"));
  EXPECT_FALSE(daemon_module_name_valid("with/slash"));
  EXPECT_FALSE(daemon_module_name_valid("with\t\ttab"));
  EXPECT_FALSE(daemon_module_name_valid("bracket]"));
  {
    char long_name[DAEMON_MAX_MODULE_NAME + 2];
    memset(long_name, 'a', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';
    EXPECT_FALSE(daemon_module_name_valid(long_name));
  }
}

static void test_daemon_conf_module_count_capped() {
  size_t cap = DAEMON_CONF_MAX_MODULES;
  size_t len = (cap + 8) * 32;
  char* body = malloc(len);
  EXPECT_NOT_NULL(body);
  size_t used = 0;
  body[0] = '\0';
  for (size_t i = 0; i < cap + 1; i++) {
    char line[48];
    int n = snprintf(line, sizeof(line), "[m%zu]\npath = /x\n", i);
    if (n < 0 || (size_t)n >= sizeof(line) || used + (size_t)n >= len) {
      free(body);
      EXPECT_FAIL("module-count test buffer overflow");
      return;
    }
    memcpy(body + used, line, (size_t)n);
    used += (size_t)n;
    body[used] = '\0';
  }
  char* path;
  EXPECT_EQ_INT(write_conf(body, &path), 0);
  free(body);
  char err[256];
  const DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "too many modules") != NULL);
}

/* rsync rsyncd.conf compatibility: the common GLOBAL keys FastSync does not
 * implement (pid file, log file, use chroot, uid/gid, timeout, ...) are
 * accepted as documented inert keys, while the keys with a FastSync equivalent
 * keep working and the compact rsync --dparam spellings (`pidfile`, `logfile`,
 * `motdfile`) are recognized.  A global `read only` is rsync's module default
 * and must not be silently dropped. */
static void test_daemon_conf_rsync_global_keys() {
  char* path;
  char err[256];
  EXPECT_EQ_INT(write_conf("pid file = /run/fastsyncd.pid\n"
                           "log file = /var/log/fastsyncd.log\n"
                           "socket options = TCP_NODELAY\n"
                           "listen backlog = 10\n"
                           "syslog facility = daemon\n"
                           "syslog tag = fastsyncd\n"
                           "use chroot = no\n"
                           "uid = nobody\n"
                           "gid = nogroup\n"
                           "timeout = 600\n"
                           "max verbosity = 3\n"
                           "lock file = /var/run/fastsyncd.lock\n"
                           "transfer logging = yes\n"
                           "strict modes = yes\n"
                           "reverse lookup = no\n"
                           "dont compress = *.gz\n"
                           "read only = yes\n"
                           "port = 8734\n"
                           "address = 127.0.0.1\n"
                           "pidfile = /run/other.pid\n"
                           "logfile = /var/log/other.log\n"
                           "motdfile = /etc/fastsync/motd.alt\n"
                           "\n"
                           "[pub]\n"
                           "path = /srv/pub\n"
                           "\n"
                           "[explicit]\n"
                           "path = /srv/explicit\n"
                           "read only = no\n",
                           &path),
                0);
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  /* Mapped globals took effect; the compact aliases too. */
  EXPECT_EQ_INT(conf->global.port, 8734);
  EXPECT_EQ_STR(conf->global.address, "127.0.0.1");
  EXPECT_EQ_STR(conf->global.motd_file, "/etc/fastsync/motd.alt");
  /* The global `read only = yes` is the default for modules defined after it. */
  EXPECT_TRUE(conf->global.read_only_default);
  EXPECT_EQ_INT(conf->module_count, 2);
  EXPECT_TRUE(conf->modules[0].read_only);
  /* An explicit per-module value wins over the global default. */
  EXPECT_FALSE(conf->modules[1].read_only);
  daemon_conf_free(conf);
}

/* rsync module keys with no FastSync equivalent load inert; the keys with a
 * FastSync meaning still map onto their native fields. */
static void test_daemon_conf_rsync_module_keys() {
  char* path;
  char err[256];
  EXPECT_EQ_INT(write_conf("[data]\n"
                           "path = /srv/data\n"
                           "comment = Public data\n"
                           "use chroot = yes\n"
                           "uid = nobody\n"
                           "gid = nogroup\n"
                           "exclude = *.tmp\n"
                           "include = keep.tmp\n"
                           "exclude from = /etc/rsync.exclude\n"
                           "max verbosity = 2\n"
                           "lock file = /var/run/rsyncd.lock\n"
                           "transfer logging = yes\n"
                           "timeout = 300\n"
                           "secrets file = /etc/rsyncd.secrets\n"
                           "auth digest = sha256\n"
                           "numeric ids = yes\n"
                           "write only = no\n"
                           "list = yes\n"
                           "dont compress = *.gz\n"
                           "refuse options = delete\n"
                           "read only = yes\n"
                           "max connections = 5\n"
                           "hosts allow = 10.0.0.0/8\n"
                           "auth users = alice\n",
                           &path),
                0);
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_EQ_STR(conf->modules[0].path, "/srv/data");
  EXPECT_TRUE(conf->modules[0].read_only);
  EXPECT_EQ_INT(conf->modules[0].max_connections, 5);
  EXPECT_EQ_INT(conf->modules[0].hosts_allow_count, 1);
  EXPECT_EQ_STR(conf->modules[0].hosts_allow[0], "10.0.0.0/8");
  EXPECT_EQ_INT(conf->modules[0].auth_user_count, 1);
  EXPECT_EQ_STR(conf->modules[0].auth_users[0], "alice");
  daemon_conf_free(conf);
}

/* A genuinely unknown key is still rejected in both contexts, so accepting the
 * rsync subset did not turn typos into silent no-ops. */
static void test_daemon_conf_rsync_unknown_keys_rejected() {
  char* path;
  char err[256];
  EXPECT_EQ_INT(write_conf("bogus rsync key = 1\n", &path), 0);
  const DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "unknown global key") != NULL);

  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nnot a real key = 1\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "unknown key 'not a real key'") != NULL);
}

/* A recognized rsync key with an invalid value is still a clear parse error. */
static void test_daemon_conf_rsync_read_only_invalid() {
  char* path;
  char err[256];
  EXPECT_EQ_INT(write_conf("read only = maybe\n[m]\npath = /x\n", &path), 0);
  const DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "read only") != NULL);

  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nread only = maybe\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "read only") != NULL);
}

/* --dparam reuses the same global dispatch: it accepts the compact rsync
 * spellings and the inert rsync global keys, and `read only` sets the default
 * for modules that did not set their own value. */
static void test_daemon_conf_dparam_rsync_keys() {
  DaemonConf* conf = daemon_conf_create();
  EXPECT_NOT_NULL(conf);
  char err[256];

  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "pidfile=/run/x.pid", err, sizeof(err)), 0);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "pid file=/run/y.pid", err, sizeof(err)), 0);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "logfile=/tmp/x.log", err, sizeof(err)), 0);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "log file=/tmp/y.log", err, sizeof(err)), 0);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "motdfile=/tmp/alt.motd", err, sizeof(err)), 0);
  EXPECT_EQ_STR(conf->global.motd_file, "/tmp/alt.motd");
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "timeout=600", err, sizeof(err)), 0);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "use chroot=no", err, sizeof(err)), 0);

  /* A module already parsed without an explicit `read only` takes the
   * --dparam default; an explicit module value is preserved. */
  {
    char* path;
    EXPECT_EQ_INT(write_conf("[plain]\npath = /p\n[explicit]\npath = /e\nread only = no\n", &path),
                  0);
    DaemonConf* loaded = daemon_conf_load(path, err, sizeof(err));
    free(path);
    EXPECT_NOT_NULL(loaded);
    EXPECT_EQ_INT(daemon_conf_apply_dparam(loaded, "read only=yes", err, sizeof(err)), 0);
    EXPECT_TRUE(loaded->global.read_only_default);
    EXPECT_TRUE(loaded->modules[0].read_only);
    EXPECT_FALSE(loaded->modules[1].read_only);
    daemon_conf_free(loaded);
  }

  /* Invalid values and genuinely unknown keys are still rejected. */
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "read only=maybe", err, sizeof(err)), -1);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "definitely not rsync=1", err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "unknown global key") != NULL);

  daemon_conf_free(conf);
}

/* rsync modules default to READ-ONLY; `read only = no` / `write only = yes`
 * opt a module into writability, and an explicit module value wins over a
 * global default. */
static void test_daemon_conf_read_only_default_and_opt_in() {
  char* path;
  char err[256];
  DaemonConf* conf;

  /* A module that never mentions read only/write only is READ-ONLY, matching
   * rsync (a migrated rsyncd.conf must not be served writable). */
  EXPECT_EQ_INT(write_conf("[m]\npath = /x\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_TRUE(conf->modules[0].read_only);
  EXPECT_FALSE(conf->modules[0].read_only_explicit);
  daemon_conf_free(conf);

  /* `read only = no` opts in to writable. */
  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nread only = no\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_FALSE(conf->modules[0].read_only);
  EXPECT_TRUE(conf->modules[0].read_only_explicit);
  daemon_conf_free(conf);

  /* `write only = yes` opts in to writable (FastSync is push-only). */
  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nwrite only = yes\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_FALSE(conf->modules[0].read_only);
  EXPECT_TRUE(conf->modules[0].read_only_explicit);
  daemon_conf_free(conf);

  /* `write only = no` is rsync's default and does not undo read-only. */
  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nwrite only = no\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_TRUE(conf->modules[0].read_only);
  EXPECT_FALSE(conf->modules[0].read_only_explicit);
  daemon_conf_free(conf);

  /* A global `read only = no` is the default for later modules; an explicit
   * module `read only`/`write only = yes` still wins. */
  EXPECT_EQ_INT(write_conf("read only = no\n[a]\npath = /a\n"
                           "[b]\npath = /b\nread only = yes\n"
                           "[c]\npath = /c\nwrite only = yes\n",
                           &path),
                0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_FALSE(conf->global.read_only_default);
  EXPECT_FALSE(conf->modules[0].read_only);
  EXPECT_TRUE(conf->modules[1].read_only);
  EXPECT_FALSE(conf->modules[2].read_only);
  daemon_conf_free(conf);

  /* A global `read only = yes` keeps modules without an explicit value
   * read-only. */
  EXPECT_EQ_INT(write_conf("read only = yes\n[a]\npath = /a\n"
                           "[b]\npath = /b\nread only = no\n"
                           "[c]\npath = /c\nwrite only = yes\n",
                           &path),
                0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NOT_NULL(conf);
  EXPECT_TRUE(conf->global.read_only_default);
  EXPECT_TRUE(conf->modules[0].read_only);
  EXPECT_FALSE(conf->modules[1].read_only);
  EXPECT_FALSE(conf->modules[2].read_only);
  daemon_conf_free(conf);

  /* An invalid `write only` value is a clear parse error. */
  EXPECT_EQ_INT(write_conf("[m]\npath = /x\nwrite only = maybe\n", &path), 0);
  conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "write only") != NULL);
}

/* Security-relevant rsync keys are accepted for migration but have no FastSync
 * effect, so loading must warn loudly (naming the key and module) rather than
 * letting an operator believe the restriction is enforced. */
static void test_daemon_conf_unenforced_security_keys_warned() {
  char* path;
  char err[256];
  EXPECT_EQ_INT(write_conf("use chroot = yes\n"
                           "uid = nobody\n"
                           "[m]\n"
                           "path = /x\n"
                           "read only = no\n"
                           "secrets file = /etc/rsyncd.secrets\n"
                           "refuse options = delete\n"
                           "exclude = *.tmp\n"
                           "max size = 1M\n"
                           "pre-xfer exec = /bin/true\n"
                           "incoming chmod = F644\n"
                           "name converter = sh\n",
                           &path),
                0);

  set_log_level(LOG_LEVEL_WARNING);
  FILE* log_capture = tmpfile();
  EXPECT_NOT_NULL(log_capture);
  log_set_file(log_capture);
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  fflush(log_capture);
  rewind(log_capture);
  log_set_file(NULL);
  free(path);

  /* Inert security keys must never fail the load. */
  EXPECT_NOT_NULL(conf);
  EXPECT_FALSE(conf->modules[0].read_only);

  bool saw_secrets = false;
  bool saw_refuse = false;
  bool saw_filter = false;
  bool saw_size = false;
  bool saw_hook = false;
  bool saw_chmod = false;
  bool saw_converter = false;
  bool saw_global_chroot = false;
  bool saw_global_uid = false;
  char line[512];
  while (fgets(line, sizeof(line), log_capture) != NULL) {
    if (strstr(line, "NOT enforced") == NULL)
      continue;
    if (strstr(line, "module 'm'") && strstr(line, "secrets file"))
      saw_secrets = true;
    if (strstr(line, "module 'm'") && strstr(line, "refuse options"))
      saw_refuse = true;
    if (strstr(line, "module 'm'") && strstr(line, "exclude"))
      saw_filter = true;
    if (strstr(line, "module 'm'") && strstr(line, "max size"))
      saw_size = true;
    if (strstr(line, "module 'm'") && strstr(line, "pre-xfer exec"))
      saw_hook = true;
    if (strstr(line, "module 'm'") && strstr(line, "incoming chmod"))
      saw_chmod = true;
    if (strstr(line, "module 'm'") && strstr(line, "name converter"))
      saw_converter = true;
    if (strstr(line, "global key 'use chroot'"))
      saw_global_chroot = true;
    if (strstr(line, "global key 'uid'"))
      saw_global_uid = true;
  }
  fclose(log_capture);

  EXPECT_TRUE(saw_secrets);
  EXPECT_TRUE(saw_refuse);
  EXPECT_TRUE(saw_filter);
  EXPECT_TRUE(saw_size);
  EXPECT_TRUE(saw_hook);
  EXPECT_TRUE(saw_chmod);
  EXPECT_TRUE(saw_converter);
  EXPECT_TRUE(saw_global_chroot);
  EXPECT_TRUE(saw_global_uid);
  daemon_conf_free(conf);
}

void test_daemon_conf() {
  test_daemon_conf_create_defaults();
  test_daemon_conf_full_parse();
  test_daemon_conf_comments_and_blank_lines();
  test_daemon_conf_case_insensitive_and_bool_variants();
  test_daemon_conf_quoted_value();
  test_daemon_conf_global_defaults_when_absent();
  test_daemon_conf_unknown_key_rejected();
  test_daemon_conf_malformed_rejected();
  test_daemon_conf_duplicate_module_rejected();
  test_daemon_conf_long_line_rejected();
  test_daemon_conf_missing_file_rejected();
  test_daemon_conf_find_module();
  test_daemon_conf_dparam_override();
  test_daemon_conf_auth_users_validated();
  test_daemon_conf_limits_and_hosts_parse();
  test_daemon_conf_module_count_capped();
  test_daemon_hosts_allowed();
  test_daemon_module_name_valid();
  test_daemon_conf_rsync_global_keys();
  test_daemon_conf_rsync_module_keys();
  test_daemon_conf_rsync_unknown_keys_rejected();
  test_daemon_conf_rsync_read_only_invalid();
  test_daemon_conf_dparam_rsync_keys();
  test_daemon_conf_read_only_default_and_opt_in();
  test_daemon_conf_unenforced_security_keys_warned();
}