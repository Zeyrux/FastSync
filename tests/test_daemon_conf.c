#include "test_daemon_conf.h"
#include "daemon_conf.h"
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
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
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
  DaemonConf* conf;

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
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
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
  DaemonConf* conf = daemon_conf_load(path, err, sizeof(err));
  free(path);
  EXPECT_NULL(conf);
  EXPECT_TRUE(strstr(err, "exceeds the") != NULL);
}

static void test_daemon_conf_missing_file_rejected() {
  char err[256];
  DaemonConf* conf = daemon_conf_load("/nonexistent/fastsync_daemon_conf_zzz", err, sizeof(err));
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

  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "port=notaport", err, sizeof(err)), -1);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "bogus=1", err, sizeof(err)), -1);
  EXPECT_TRUE(strstr(err, "unknown global key") != NULL);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "port", err, sizeof(err)), -1);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "=1", err, sizeof(err)), -1);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "port=", err, sizeof(err)), -1);
  EXPECT_EQ_INT(daemon_conf_apply_dparam(conf, "", err, sizeof(err)), -1);

  daemon_conf_free(conf);
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
  test_daemon_module_name_valid();
}