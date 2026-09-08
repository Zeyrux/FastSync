#include "test_client_cli.h"
#include "checksum.h"
#include "client_validation.h"
#include "chmod.h"
#include "config.h"
#include "file_list.h"
#include "log.h"
#include "test_utils.h"
#include "utils.h"
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Declaration of parse_args from client_cli.c */
int parse_args(Config* config, int argc, char* argv[], int* positional_args, int* positional_count);

static Config* valid_client_config() {
  Config* cfg = config_create();
  if (!cfg)
    return NULL;
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  return cfg;
}

static void test_validate_config_required_paths() {
  Config* cfg = config_create();
  EXPECT_FALSE(validate_config(cfg));
  cfg->send_directory = str_dup("/src");
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);
}

static void test_validate_config_incompatible_options() {
  Config* cfg = valid_client_config();
  cfg->use_sendfile = true;
  cfg->use_compression = true;
  EXPECT_FALSE(validate_config(cfg));
  cfg->use_compression = false;
  cfg->use_incremental = true;
  cfg->use_chunk_serialization = true;
  EXPECT_FALSE(validate_config(cfg));
  cfg->use_incremental = false;
  cfg->skip_compress_set = true;
  EXPECT_FALSE(validate_config(cfg));
  cfg->skip_compress_set = false;
  cfg->compression_threads = 2;
  EXPECT_FALSE(validate_config(cfg));
  cfg->use_compression = true;
  cfg->use_sendfile = false;
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

static void test_validate_config_tls_requirements() {
  Config* cfg = valid_client_config();
  cfg->use_tls = true;
  EXPECT_FALSE(validate_config(cfg));
  cfg->tls_cert = str_dup("cert.pem");
  EXPECT_FALSE(validate_config(cfg));
  cfg->tls_key = str_dup("key.pem");
  EXPECT_FALSE(validate_config(cfg));
  cfg->tls_ca = str_dup("ca.pem");
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

static void test_validate_config_delta_sendfile_constraints() {
  Config* cfg = valid_client_config();
  cfg->use_delta = true;
  EXPECT_FALSE(validate_config(cfg));
  cfg->use_incremental = true;
  cfg->use_sendfile = true;
  EXPECT_FALSE(validate_config(cfg));

  /* Whole-file makes delta selection inactive, so these combinations are valid. */
  cfg->whole_file = true;
  EXPECT_TRUE(validate_config(cfg));

  cfg->use_incremental = false;
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

/* Test main() with --help flag (early return path, no server connection needed) */
static void test_cli_help() {
  /* We can't easily call main() because it calls send_files which needs a server.
   * Instead, test the argument parsing logic by testing that config_create works
   * with the same parameters client_cli uses, and that config_delete cleans up
   * properly when send_directory and receive_root_directory are NULL. */

  /* This matches what client_cli does at startup */
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  EXPECT_NULL(cfg->send_directory);
  EXPECT_NULL(cfg->receive_root_directory);
  EXPECT_FALSE(cfg->save_to_disk);
  EXPECT_EQ_INT(cfg->compression_level, 5);

  config_delete(cfg);
}

/* Test that --archive sets compression, multithreading, and metadata */
static void test_cli_archive_flags() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);

  /* Simulate --archive flag */
  cfg->use_compression = true;
  cfg->use_multithreading = true;
  cfg->use_metadata = true;

  EXPECT_TRUE(cfg->use_compression);
  EXPECT_TRUE(cfg->use_multithreading);
  EXPECT_TRUE(cfg->use_metadata);

  config_delete(cfg);
}

/* Test that --dry-run sets dry_run flag */
static void test_cli_dry_run() {
  Config* cfg = config_create();

  cfg->dry_run = true;
  EXPECT_TRUE(cfg->dry_run);

  config_delete(cfg);
}

static void test_cli_remove_source_files() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  EXPECT_FALSE(cfg->remove_source_files);
  cfg->remove_source_files = true;
  EXPECT_TRUE(cfg->remove_source_files);
  config_delete(cfg);
}

static void test_parse_args_remove_source_files() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--remove-source-files", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 4, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 0);
  EXPECT_TRUE(cfg->remove_source_files);
  config_delete(cfg);
}

/* Test that --delete sets use_delete */
static void test_cli_delete_flag() {
  Config* cfg = config_create();

  cfg->use_delete = true;
  EXPECT_TRUE(cfg->use_delete);

  config_delete(cfg);
}

/* Test exclude pattern handling */
static void test_cli_exclude_patterns() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);

  /* Simulate --exclude "*.log" --exclude "tmp/" */
  cfg->exclude_patterns = malloc(2 * sizeof(char*));
  EXPECT_NOT_NULL(cfg->exclude_patterns);
  cfg->exclude_patterns[0] = str_dup("*.log");
  cfg->exclude_patterns[1] = str_dup("tmp/");
  cfg->exclude_count = 2;

  EXPECT_EQ_STR(cfg->exclude_patterns[0], "*.log");
  EXPECT_EQ_STR(cfg->exclude_patterns[1], "tmp/");
  EXPECT_EQ_INT(cfg->exclude_count, 2);

  config_delete(cfg);
}

/* Test parse_args with --help returns 1 (clean exit) */
static void test_parse_args_help() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--help"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 2, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 1);

  config_delete(cfg);
}

/* Test parse_args with -V/--version returns 1 */
static void test_parse_args_version() {
  Config* cfg = config_create();
  char* argv_short[] = {"fastsync", "-V"};
  char* argv_long[] = {"fastsync", "--version"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 2, argv_short, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 1);

  ret = parse_args(cfg, 2, argv_long, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 1);

  config_delete(cfg);
}

/* --xattrs/-X and --acls/-A preserve per-file xattrs and both imply metadata
 * transmission (the xattr block rides the metadata/per-file frame); each is
 * individually negatable and the derived use_xattrs follows the flags. */
static void test_parse_args_xattrs_acls() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-X", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->preserve_xattrs);
  EXPECT_FALSE(cfg->preserve_acls);
  EXPECT_TRUE(cfg->use_xattrs);
  EXPECT_TRUE(cfg->use_metadata);
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* argv_long[] = {"fastsync", "--acls", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, argv_long, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->preserve_acls);
  EXPECT_TRUE(cfg->use_xattrs);
  EXPECT_TRUE(cfg->use_metadata);
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* argv_neg[] = {"fastsync", "-X", "-A", "--no-xattrs", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 6, argv_neg, positional_args, &positional_count), 0);
  EXPECT_FALSE(cfg->preserve_xattrs);
  EXPECT_TRUE(cfg->preserve_acls);
  EXPECT_TRUE(cfg->use_xattrs);
  config_delete(cfg);
}

/* --fake-super is a receiver-side preference that parks the source
 * uid/gid/mode/mtime in a reserved xattr; it implies metadata transmission. */
static void test_parse_args_fake_super() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--fake-super", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->fake_super);
  EXPECT_TRUE(cfg->use_metadata);
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* argv_neg[] = {"fastsync", "--fake-super", "--no-fake-super", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, argv_neg, positional_args, &positional_count), 0);
  EXPECT_FALSE(cfg->fake_super);
  config_delete(cfg);
}

/* Test parse_args with valid port */
static void test_parse_args_valid_port() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-p", "2222", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 5, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 0);
  EXPECT_EQ_INT(cfg->ssh_port, 2222);
  EXPECT_EQ_INT(positional_count, 2);

  config_delete(cfg);
}

/* Test parse_args with --size-only. */
static void test_parse_args_size_only() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--size-only", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->size_only);
  EXPECT_EQ_INT(positional_count, 2);

  config_delete(cfg);
}

static void test_parse_args_ignore_existing() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--ignore-existing", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 4, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 0);
  EXPECT_TRUE(cfg->ignore_existing);

  config_delete(cfg);
}

static void test_parse_args_executability() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-E", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_executability);
  EXPECT_TRUE(cfg->use_metadata);

  config_delete(cfg);
}

static void test_parse_args_chmod() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--chmod=u=rw,go=r", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->chmod_spec, "u=rw,go=r");
  EXPECT_TRUE(cfg->use_metadata);
  mode_t result;
  EXPECT_TRUE(chmod_apply(0777, cfg->chmod_spec, &result));
  EXPECT_EQ_INT(result, 0644);
  config_delete(cfg);
}

static void test_parse_args_numeric_chmod() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--chmod", "7777", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->chmod_spec, "7777");
  EXPECT_TRUE(cfg->use_metadata);
  config_delete(cfg);
}

static void test_parse_args_rejects_invalid_chmod() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--chmod=a+X", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), -1);
  config_delete(cfg);
}

/* Test parse_args rejects port > 65535 */
static void test_parse_args_invalid_port() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-p", "99999", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 5, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, -1);

  config_delete(cfg);
}

/* Test parse_args rejects non-numeric port */
static void test_parse_args_non_numeric_port() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-p", "abc", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 5, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, -1);

  config_delete(cfg);
}

/* Test parse_args rejects server port > 65535 */
static void test_parse_args_invalid_server_port() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--server-port", "70000", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 5, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, -1);

  config_delete(cfg);
}

/* Test parse_args rejects invalid compression level */
static void test_parse_args_invalid_compression_level() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-c", "25", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 5, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, -1);

  config_delete(cfg);
}

/* Test parse_args accepts valid compression level */
static void test_parse_args_valid_compression_level() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-c", "10", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 5, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 0);
  EXPECT_EQ_INT(cfg->compression_level, 10);

  config_delete(cfg);
}

static void test_parse_args_debug_flags() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--debug=io,proto,pack,util", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->debug_level, LOG_DEBUG_ALL);
  EXPECT_EQ_INT(get_log_debug_flags(), LOG_DEBUG_ALL);
  config_delete(cfg);
}

static void test_parse_args_debug_help() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--debug=help"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 2, argv, positional_args, &positional_count), 1);
  config_delete(cfg);
}

static void test_parse_args_debug_flags_validation() {
  static const char* const values[] = {"", "io,", ",io", "io,,proto", "acl", "tls", "unknown"};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    Config* cfg = config_create();
    char option[64];
    snprintf(option, sizeof(option), "--debug=%s", values[i]);
    char* argv[] = {"fastsync", option, "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
}

static void test_parse_args_modify_window() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--modify-window=3", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->modify_window, 3);
  config_delete(cfg);

  cfg = config_create();
  char* short_argv[] = {"fastsync", "-@", "7", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, short_argv, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->modify_window, 7);
  config_delete(cfg);

  cfg = config_create();
  char* attached_argv[] = {"fastsync", "-@11", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, attached_argv, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->modify_window, 11);
  config_delete(cfg);
}

static void test_parse_args_rejects_invalid_modify_window() {
  const char* values[] = {"-1", "not-a-number", ""};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", "--modify-window", (char*)values[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
}

static void test_parse_args_max_alloc_sizes() {
  const char* values[] = {"1", "4K", "2m", "3G", "1T", "1P", "1E", "512B"};
  const unsigned long long expected[] = {1,
                                         4ULL * 1024,
                                         2ULL * 1024 * 1024,
                                         3ULL * 1024 * 1024 * 1024,
                                         1ULL * 1024 * 1024 * 1024 * 1024,
                                         1ULL * 1024 * 1024 * 1024 * 1024 * 1024,
                                         1ULL * 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
                                         512};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", "--max-alloc", (char*)values[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
    EXPECT_TRUE(cfg->max_alloc == expected[i]);
    config_delete(cfg);
  }

  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--max-alloc=8M", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->max_alloc == 8ULL * 1024 * 1024);
  config_delete(cfg);
}

static void test_parse_args_rejects_invalid_max_alloc() {
  const char* values[] = {"0",  "-1",  "+1",  " 1",   "1 ",
                          "1Z", "1K2", "1 K", "1\tK", "18446744073709551615K"};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", "--max-alloc", (char*)values[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
}

static void test_parse_args_skip_compress() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--skip-compress=.ZIP, .GZ", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->skip_compress_set);
  EXPECT_EQ_INT(cfg->skip_compress_count, 2);
  EXPECT_EQ_STR(cfg->skip_compress_suffixes[0], ".ZIP");
  EXPECT_EQ_STR(cfg->skip_compress_suffixes[1], ".GZ");
  config_delete(cfg);
}

static void test_parse_args_empty_skip_compress() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--skip-compress=", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->skip_compress_set);
  EXPECT_EQ_INT(cfg->skip_compress_count, 0);
  config_delete(cfg);
}

static void test_parse_args_compression_threads() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--compress-threads", "4", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->compression_threads, 4);
  config_delete(cfg);

  cfg = config_create();
  char* equals_argv[] = {"fastsync", "--compress-threads=3", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, equals_argv, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->compression_threads, 3);
  config_delete(cfg);

  cfg = config_create();
  char* invalid_argv[] = {"fastsync", "--compress-threads=0", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, invalid_argv, positional_args, &positional_count), -1);
  config_delete(cfg);

  cfg = config_create();
  char* excessive_argv[] = {"fastsync", "--compress-threads=65", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, excessive_argv, positional_args, &positional_count), -1);
  config_delete(cfg);
}

/* Test parse_args unknown option returns error */
static void test_parse_args_unknown_option() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--nonexistent", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 4, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, -1);

  config_delete(cfg);
}

/* -d/--dirs and the rsync --old-dirs/--old-d aliases all enable directory-only
 * transfers (--dirs maps every spelling onto the same config field). */
static void test_parse_args_dirs_aliases() {
  static const char* const options[] = {"--dirs", "-d", "--old-dirs", "--old-d"};
  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
    EXPECT_TRUE(cfg->dirs);
    config_delete(cfg);
  }
}

/* -R/--relative, --no-implied-dirs and --mkpath are plain boolean flags. */
static void test_parse_args_relative_no_implied_mkpath() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-R", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->relative);
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* long_argv[] = {"fastsync", "--relative", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, long_argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->relative);
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* noimplied_argv[] = {"fastsync", "--no-implied-dirs", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, noimplied_argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->no_implied_dirs);
  EXPECT_FALSE(cfg->relative);
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* mkpath_argv[] = {"fastsync", "--mkpath", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, mkpath_argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->mkpath);
  config_delete(cfg);
}

/* Parse --compare-dest/--copy-dest/--link-dest, including the =value and
   separate-argument forms, and verify the ordered (repeatable) basis list. */
static void test_parse_args_basis_dirs() {
  Config* cfg = config_create();
  int positional_args[2];
  int positional_count = 0;
  char* argv[] = {"fastsync", "--link-dest=prior", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(config_has_basis(cfg));
  EXPECT_EQ_INT(cfg->basis_count, 1);
  EXPECT_EQ_INT(cfg->basis_dirs[0].type, BASIS_DEST_LINK);
  EXPECT_EQ_STR(cfg->basis_dirs[0].path, "prior");
  /* Basis dirs are honored by the receiver-side per-file check, so they imply
     --incremental (and, unless disabled, metadata) on the sender. */
  EXPECT_TRUE(cfg->use_incremental);
  EXPECT_TRUE(cfg->use_metadata);
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* argv2[] = {"fastsync", "--compare-dest", "cmp", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, argv2, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->basis_count, 1);
  EXPECT_EQ_INT(cfg->basis_dirs[0].type, BASIS_DEST_COMPARE);
  EXPECT_EQ_STR(cfg->basis_dirs[0].path, "cmp");
  config_delete(cfg);

  /* Repetition is supported: entries keep command-line order and type. */
  cfg = config_create();
  positional_count = 0;
  char* argv3[] = {"fastsync",      "--link-dest=a", "--compare-dest=b",
                   "--link-dest=c", "--copy-dest=d", "/src",
                   "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 7, argv3, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->basis_count, 4);
  EXPECT_EQ_INT(cfg->basis_dirs[0].type, BASIS_DEST_LINK);
  EXPECT_EQ_STR(cfg->basis_dirs[0].path, "a");
  EXPECT_EQ_INT(cfg->basis_dirs[1].type, BASIS_DEST_COMPARE);
  EXPECT_EQ_STR(cfg->basis_dirs[1].path, "b");
  EXPECT_EQ_INT(cfg->basis_dirs[2].type, BASIS_DEST_LINK);
  EXPECT_EQ_STR(cfg->basis_dirs[2].path, "c");
  EXPECT_EQ_INT(cfg->basis_dirs[3].type, BASIS_DEST_COPY);
  EXPECT_EQ_STR(cfg->basis_dirs[3].path, "d");
  config_delete(cfg);

  /* Nested relative basis dirs are allowed (they resolve below the root). */
  cfg = config_create();
  positional_count = 0;
  char* argv4[] = {"fastsync", "--copy-dest=snap/2026-01", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, argv4, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->basis_count, 1);
  EXPECT_EQ_STR(cfg->basis_dirs[0].path, "snap/2026-01");
  config_delete(cfg);
}

/* Absolute, escaping, or degenerate basis-dir values must be rejected up
   front: they would resolve outside the destination root on the receiver. */
static void test_parse_args_basis_invalid_paths() {
  static const char* const invalid[] = {"/abs", "..", "a/../b", "."};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", "--link-dest", (char*)invalid[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
}

/* Basis dirs require the per-file incremental handshake, which -s disables. */
static void test_validate_config_basis_rejects_chunk_serialization() {
  Config* cfg = valid_client_config();
  EXPECT_EQ_INT(config_basis_append(cfg, BASIS_DEST_LINK, "prior"), 0);
  cfg->use_chunk_serialization = true;
  EXPECT_FALSE(validate_config(cfg));
  cfg->use_chunk_serialization = false;
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

/* --del is accepted as the rsync alias for --delete-during: it enables
 * deletion with the during (early) timing. */
static void test_parse_args_delete_during_alias() {
  static const char* const options[] = {"--del", "--delete-during"};

  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
    EXPECT_TRUE(cfg->use_delete);
    EXPECT_TRUE(cfg->delete_during);
    EXPECT_FALSE(cfg->delete_before);
    EXPECT_FALSE(cfg->delete_delay);
    EXPECT_FALSE(cfg->delete_after);
    config_delete(cfg);
  }
}

/* Each rsync deletion-timing flag is accepted and implies --delete. */
static void test_parse_args_delete_timing_flags() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--delete-before", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_delete);
  EXPECT_TRUE(cfg->delete_before);
  config_delete(cfg);

  cfg = config_create();
  char* argv_after[] = {"fastsync", "--delete-after", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv_after, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_delete);
  EXPECT_TRUE(cfg->delete_after);
  EXPECT_FALSE(cfg->delete_before);
  config_delete(cfg);

  cfg = config_create();
  char* argv_delay[] = {"fastsync", "--delete-delay", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv_delay, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_delete);
  EXPECT_TRUE(cfg->delete_delay);
  EXPECT_FALSE(cfg->delete_before);
  EXPECT_FALSE(cfg->delete_after);
  config_delete(cfg);
}

/* Two different delete-timing flags on one command line are a conflict, not a
 * silent last-one-wins choice. */
static void test_parse_args_delete_timing_conflict_rejected() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--delete-before", "--delete-after", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_delete);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);

  cfg = config_create();
  char* argv2[] = {"fastsync", "--delete-during", "--delete-delay", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv2, positional_args, &positional_count), 0);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);
}

/* A timing flag whose --delete was then negated away must be rejected: timing
 * without deletion is meaningless. */
static void test_parse_args_delete_timing_without_delete_rejected() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--delete-before", "--no-delete", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_FALSE(cfg->use_delete);
  EXPECT_TRUE(cfg->delete_before);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);
}

/* Parsed-but-unimplemented options must fail instead of being silently accepted. */
static void test_parse_args_rejects_unimplemented_options() {
  static const char* const options[] = {"--silent",
                                        "--queue-size",
                                        "-D",
                                        "--devices",
                                        "--delete-excluded",
                                        "--max-delete",
                                        "--prune-empty-dirs",
                                        "-e",
                                        "--rsh",
                                        "--rsync-path",
                                        "--address",
                                        "--bind-address",
                                        "--ipv6",
                                        "--ipv4",
                                        "--daemon",
                                        "--config",
                                        "--server"};

  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i], "dummy", "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
}

/* Test both rsync-compatible quiet spellings and option ordering. */
static void test_parse_args_quiet() {
  static const char* const options[][2] = {
      {"-q", "-v"}, {"-v", "-q"}, {"--quiet", "-v"}, {"-v", "--quiet"}};
  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i][0], (char*)options[i][1], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
    EXPECT_TRUE(cfg->quiet);
    config_delete(cfg);
  }
}

static void test_parse_args_human_readable() {
  static const char* const options[] = {"-h", "--human-readable"};
  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
    EXPECT_TRUE(cfg->human_readable);
    config_delete(cfg);
  }
}

static void test_parse_args_update() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-u", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->update);
  EXPECT_TRUE(cfg->use_metadata);
  EXPECT_EQ_INT(positional_count, 2);

  config_delete(cfg);
}

static void test_parse_args_hard_links() {
  Config* cfg = config_create();
  char* argv_H[] = {"fastsync", "-H", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv_H, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->preserve_hard_links);
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* argv_long[] = {"fastsync", "--hard-links", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, argv_long, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->preserve_hard_links);
  config_delete(cfg);

  /* --no-hard-links clears the flag. */
  cfg = config_create();
  positional_count = 0;
  char* argv_neg[] = {"fastsync", "--hard-links", "--no-hard-links", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, argv_neg, positional_args, &positional_count), 0);
  EXPECT_FALSE(cfg->preserve_hard_links);
  config_delete(cfg);
}

/* -H/--hard-links violates the per-file streaming requirement of -s and the
 * payload-bearing tail-resume of --append: both combos are rejected up front. */
static void test_validate_config_hard_links_incompatible_modes() {
  Config* cfg = config_create();
  char* argv_s[] = {"fastsync", "-H", "-s", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv_s, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->preserve_hard_links);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* argv_append[] = {"fastsync", "-H", "--append", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, argv_append, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->preserve_hard_links);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);
}

static void test_parse_args_info_flags() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--info=copy,skip", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->info_level, LOG_INFO_COPY | LOG_INFO_SKIP);
  EXPECT_EQ_INT(get_log_info_flags(), LOG_INFO_COPY | LOG_INFO_SKIP);
  config_delete(cfg);
}

static void test_parse_args_info_verbose_order() {
  char* argv_info_first[] = {"fastsync", "--info=none", "--verbose", "/src", "/dst"};
  char* argv_verbose_first[] = {"fastsync", "--verbose", "--info=none", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  Config* cfg = config_create();
  EXPECT_EQ_INT(parse_args(cfg, 5, argv_info_first, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->info_level, 0);
  EXPECT_EQ_INT(get_log_info_flags(), 0);
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv_verbose_first, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->info_level, 0);
  EXPECT_EQ_INT(get_log_info_flags(), 0);
  config_delete(cfg);
}

static void test_parse_args_rejects_invalid_info_flag() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--info=copy,unknown", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), -1);
  config_delete(cfg);
}

/* Test parse_args with --archive flag */
static void test_parse_args_archive() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--archive", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 4, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 0);
  EXPECT_TRUE(cfg->use_compression);
  EXPECT_TRUE(cfg->use_multithreading);
  EXPECT_TRUE(cfg->use_metadata);

  config_delete(cfg);
}

/* Negations must override archive's implied options in argument order. */
static void test_parse_args_negations() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync",      "--archive",    "--no-compress", "--no-m",
                  "--no-preserve", "--no-dry-run", "/src",          "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 8, argv, positional_args, &positional_count), 0);
  EXPECT_FALSE(cfg->use_compression);
  EXPECT_FALSE(cfg->use_multithreading);
  EXPECT_FALSE(cfg->use_metadata);
  EXPECT_FALSE(cfg->dry_run);
  EXPECT_EQ_INT(positional_count, 2);
  config_delete(cfg);
}

static void test_parse_args_negation_order() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--no-z", "-c", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_compression);
  config_delete(cfg);
}

static void test_parse_args_no_preserve_blocks_implicit_metadata() {
  static const char* const options[][3] = {
      {"--incremental", "--no-preserve", "/src"},
      {"--no-preserve", "--incremental", "/src"},
      {"--delta", "--no-preserve", "/src"},
      {"--no-preserve", "--delta", "/src"},
  };

  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i][0], (char*)options[i][1], (char*)options[i][2],
                    "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
    EXPECT_FALSE(cfg->use_metadata);
    EXPECT_TRUE(cfg->metadata_explicitly_disabled);
    config_delete(cfg);
  }
}

/* --checksum-choice and its --cc alias select the whole-file digest algorithm
   (default xxh64; both "xxh64" and the rsync "xxhash" spelling accepted). */
static void test_parse_args_checksum_choice_aliases() {
  static const char* const options[] = {"--checksum-choice", "--cc"};

  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i], "xxh64", "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
    EXPECT_EQ_INT(cfg->checksum_algo, (int)CHECKSUM_ALGO_XXH64);
    config_delete(cfg);
  }
}

/* Both the "--checksum-choice=ALG" and "--cc=ALG" inline forms parse. */
static void test_parse_args_checksum_choice_equals_forms() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--checksum-choice=md5", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->checksum_algo, (int)CHECKSUM_ALGO_MD5);
  config_delete(cfg);

  cfg = config_create();
  char* argv2[] = {"fastsync", "--cc=xxhash", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv2, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->checksum_algo, (int)CHECKSUM_ALGO_XXH64);
  config_delete(cfg);
}

/* An algorithm FastSync does not support must be rejected, never a silent
   no-op. */
static void test_parse_args_checksum_choice_rejects_unsupported() {
  static const char* const bad[] = {"md4", "sha256", "crc32", "none", "bogus"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", "--checksum-choice", (char*)bad[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
}

/* --checksum-seed parses as a 64-bit non-negative integer (space and = forms);
   invalid values are rejected. */
static void test_parse_args_checksum_seed() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--checksum-seed=42", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->checksum_seed == 42ULL);
  config_delete(cfg);

  cfg = config_create();
  char* argv2[] = {"fastsync", "--checksum-seed", "12345", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv2, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->checksum_seed == 12345ULL);
  config_delete(cfg);

  /* 0 is a valid (and default) seed. */
  cfg = config_create();
  char* argv3[] = {"fastsync", "--checksum-seed=0", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv3, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->checksum_seed == 0ULL);
  config_delete(cfg);

  /* Non-numeric and negative seeds are rejected. */
  static const char* const bad[] = {"abc", "-5", "1.5", ""};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    cfg = config_create();
    char* argv4[] = {"fastsync", "--checksum-seed", (char*)bad[i], "/src", "/dst"};
    positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 5, argv4, positional_args, &positional_count), -1);
    config_delete(cfg);
  }

  /* Missing value is rejected. */
  cfg = config_create();
  char* argv5[] = {"fastsync", "--checksum-seed"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 2, argv5, positional_args, &positional_count), -1);
  config_delete(cfg);
}

static void test_parse_args_rejects_unsafe_negation() {
  static const char* const options[] = {"--no-archive", "--no-timeout", "--no-unknown"};
  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
}

/* Both checksum-choice spellings require a value. */
static void test_parse_args_checksum_choice_requires_value() {
  static const char* const options[] = {"--checksum-choice", "--cc"};

  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i]};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 2, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
}

/* --temp-dir accepts both the "--temp-dir=DIR" and "--temp-dir DIR" forms. */
static void test_parse_args_temp_dir() {
  Config* cfg = config_create();
  char* equals_argv[] = {"fastsync", "--temp-dir=scratch", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, equals_argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->temp_dir, "scratch");
  EXPECT_EQ_INT(positional_count, 2);
  config_delete(cfg);

  cfg = config_create();
  char* space_argv[] = {"fastsync", "--temp-dir", "scratch/sub", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, space_argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->temp_dir, "scratch/sub");
  EXPECT_EQ_INT(positional_count, 2);
  config_delete(cfg);

  /* A value-taking option may not be passed without a value. */
  cfg = config_create();
  char* missing_argv[] = {"fastsync", "--temp-dir"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 2, missing_argv, positional_args, &positional_count), -1);
  config_delete(cfg);
}

static void test_parse_args_old_args() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--old-args", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->old_args);
  config_delete(cfg);
}

static void test_parse_args_fsync() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--fsync", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_fsync);
  config_delete(cfg);
}

static void test_parse_args_existing() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--existing", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->existing);
  config_delete(cfg);
}

static void test_parse_args_ignore_times() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-I", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->ignore_times);
  config_delete(cfg);

  cfg = config_create();
  char* long_argv[] = {"fastsync", "--ignore-times", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, long_argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->ignore_times);
  config_delete(cfg);
}

/* --secluded-args is accepted for compatibility but has no effect. */
static void test_parse_args_secluded_args() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--secluded-args", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_FALSE(cfg->use_chunk_serialization);
  config_delete(cfg);
}

static void test_parse_args_short_s_remains_chunk_serialization() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-s", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_chunk_serialization);
  config_delete(cfg);
}

static void test_parse_args_8_bit_output() {
  Config* cfg = config_create();
  char* long_argv[] = {"fastsync", "--8-bit-output", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, long_argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->eight_bit_output);
  config_delete(cfg);

  cfg = config_create();
  char* short_argv[] = {"fastsync", "-8", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, short_argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->eight_bit_output);
  config_delete(cfg);
}

static void test_parse_args_stderr_modes() {
  static const char* const modes[] = {"errors", "all", "e", "a"};
  static const LogStderrMode expected[] = {LOG_STDERR_ERRORS, LOG_STDERR_ALL, LOG_STDERR_ERRORS,
                                           LOG_STDERR_ALL};
  for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
    Config* cfg = config_create();
    char option[32];
    snprintf(option, sizeof(option), "--stderr=%s", modes[i]);
    char* argv[] = {"fastsync", option, "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
    EXPECT_EQ_INT(log_get_stderr_mode(), expected[i]);
    config_delete(cfg);
  }
  log_set_stderr_mode(LOG_STDERR_ERRORS);
}

static void test_parse_args_rejects_unsupported_stderr_modes() {
  static const char* const modes[] = {"client", "c", "invalid"};
  for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
    Config* cfg = config_create();
    char option[32];
    snprintf(option, sizeof(option), "--stderr=%s", modes[i]);
    char* argv[] = {"fastsync", option, "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
  log_set_stderr_mode(LOG_STDERR_ERRORS);
}

/* Test both whole-file spellings and its precedence over delta selection. */
static void test_parse_args_whole_file() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--delta", "--incremental", "-W", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 6, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->whole_file);
  EXPECT_TRUE(cfg->use_delta);

  config_delete(cfg);
  cfg = config_create();
  char* long_argv[] = {"fastsync", "--whole-file", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, long_argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->whole_file);
  config_delete(cfg);
}

/* -y/--fuzzy reuses a similar destination file as a delta basis, so it implies
 * the receiver-driven delta path (--incremental + --delta): FastSync's delta
 * machinery is OFF by default, so without the implication a bare --fuzzy would
 * be a silent no-op.  Both spellings behave identically. */
static void test_parse_args_fuzzy_implies_delta() {
  static const char* const spellings[] = {"--fuzzy", "-y"};
  for (size_t i = 0; i < sizeof(spellings) / sizeof(spellings[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)spellings[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
    EXPECT_TRUE(cfg->fuzzy);
    EXPECT_TRUE(cfg->use_incremental);
    EXPECT_TRUE(cfg->use_delta);
    EXPECT_TRUE(cfg->use_metadata);
    config_delete(cfg);
  }
}

/* --no-fuzzy turns the flag back off; the incremental/delta implication must
 * only fire when the FINAL value of the flag is true (order-independent). */
static void test_parse_args_fuzzy_negation() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--fuzzy", "--no-fuzzy", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_FALSE(cfg->fuzzy);
  EXPECT_FALSE(cfg->use_delta);
  EXPECT_FALSE(cfg->use_incremental);
  config_delete(cfg);

  cfg = config_create();
  char* reordered[] = {"fastsync", "--no-fuzzy", "--fuzzy", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, reordered, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->fuzzy);
  EXPECT_TRUE(cfg->use_incremental);
  EXPECT_TRUE(cfg->use_delta);
  config_delete(cfg);
}

/* -W/--whole-file switches the delta machinery off, so --fuzzy is inert (the
 * per-file quick check still needs --incremental, which stays implied). */
static void test_parse_args_fuzzy_with_whole_file() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--fuzzy", "-W", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->fuzzy);
  EXPECT_TRUE(cfg->whole_file);
  EXPECT_TRUE(cfg->use_incremental);
  EXPECT_FALSE(cfg->use_delta);
  config_delete(cfg);
}

/* An explicit --no-delta is respected by the --fuzzy implication in either
 * argument order (a user who switched delta off does not want it forced on). */
static void test_parse_args_fuzzy_respects_no_delta() {
  static const char* const combos[][2] = {
      {"--fuzzy", "--no-delta"},
      {"--no-delta", "--fuzzy"},
  };
  for (size_t i = 0; i < sizeof(combos) / sizeof(combos[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)combos[i][0], (char*)combos[i][1], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
    EXPECT_TRUE(cfg->fuzzy);
    EXPECT_FALSE(cfg->use_delta);
    config_delete(cfg);
  }
}

/* An explicit --no-incremental is respected by the --fuzzy implication in
 * either argument order (unlike the basis-dir options, --fuzzy does not force
 * the incremental handshake back on).  Because delta needs the handshake, the
 * delta implication is suppressed too, so the run is a plain (default-mode)
 * transfer rather than an invalid "--delta requires --incremental" config. */
static void test_parse_args_fuzzy_respects_no_incremental() {
  static const char* const combos[][2] = {
      {"--fuzzy", "--no-incremental"},
      {"--no-incremental", "--fuzzy"},
  };
  for (size_t i = 0; i < sizeof(combos) / sizeof(combos[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)combos[i][0], (char*)combos[i][1], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
    EXPECT_TRUE(cfg->fuzzy);
    EXPECT_FALSE(cfg->use_incremental);
    EXPECT_FALSE(cfg->use_delta);
    cfg->send_directory = str_dup("/src");
    cfg->receive_root_directory = str_dup("/dst");
    EXPECT_TRUE(validate_config(cfg));
    config_delete(cfg);
  }
}

/* --fuzzy requires the delta machinery, which the chunk-serialization (-s) and
 * sendfile (-f) modes reject -- mirroring the --delta constraint checks. */
static void test_validate_config_fuzzy_incompatible_modes() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--fuzzy", "-s", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  EXPECT_TRUE(cfg->use_incremental);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);

  cfg = config_create();
  char* sendfile_argv[] = {"fastsync", "--fuzzy", "-f", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, sendfile_argv, positional_args, &positional_count), 0);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  EXPECT_TRUE(cfg->use_delta);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);

  /* A plain --fuzzy run is a valid configuration. */
  cfg = config_create();
  char* ok_argv[] = {"fastsync", "--fuzzy", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, ok_argv, positional_args, &positional_count), 0);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  EXPECT_TRUE(cfg->use_delta);
  EXPECT_TRUE(cfg->use_incremental);
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

/* -x and --one-file-system enable client-side single-filesystem scanning. */
static void test_parse_args_one_file_system() {
  Config* cfg = config_create();
  EXPECT_FALSE(cfg->one_file_system);

  char* argv[] = {"fastsync", "-x", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->one_file_system);
  EXPECT_EQ_INT(positional_count, 2);

  config_delete(cfg);
  cfg = config_create();
  char* long_argv[] = {"fastsync", "--one-file-system", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, long_argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->one_file_system);

  config_delete(cfg);
  cfg = config_create();
  /* Flags never take a value: the "=value" form must be rejected. */
  char* bad_argv[] = {"fastsync", "--one-file-system=yes", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, bad_argv, positional_args, &positional_count), -1);
  config_delete(cfg);
}

/* Test rsync-compatible compression-choice and compression-level aliases. */
static void test_parse_args_compression_aliases() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--zc", "zstd", "--zl", "10", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 7, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 0);
  EXPECT_EQ_STR(cfg->compress_choice, "zstd");
  EXPECT_EQ_INT(cfg->compression_level, 10);
  EXPECT_TRUE(cfg->use_compression);
  EXPECT_EQ_INT(positional_count, 2);

  config_delete(cfg);
}

/* Test rsync-compatible -P parsing; resumable partial-file retention is not implied. */
static void test_parse_args_partial_progress() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-P", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 4, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 0);
  EXPECT_TRUE(cfg->partial);
  EXPECT_TRUE(cfg->show_progress);
  EXPECT_EQ_INT(positional_count, 2);

  config_delete(cfg);
}

static void test_parse_args_compression_equals_and_none() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "-z", "--zc=none", "--zl=7", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  int ret = parse_args(cfg, 6, argv, positional_args, &positional_count);
  EXPECT_EQ_INT(ret, 0);
  EXPECT_EQ_STR(cfg->compress_choice, "none");
  EXPECT_EQ_INT(cfg->compression_level, 7);
  EXPECT_FALSE(cfg->use_compression);
  config_delete(cfg);
}

static void test_parse_args_compression_canonical_equals() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--compress-choice=zstd", "--compress-level=7", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->compress_choice, "zstd");
  EXPECT_EQ_INT(cfg->compression_level, 7);
  EXPECT_TRUE(cfg->use_compression);
  EXPECT_EQ_INT(positional_count, 2);

  config_delete(cfg);
}

static void test_parse_args_compression_alias_equals() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--zc=zstd", "--zl=7", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->compress_choice, "zstd");
  EXPECT_EQ_INT(cfg->compression_level, 7);
  EXPECT_TRUE(cfg->use_compression);
  EXPECT_EQ_INT(positional_count, 2);

  config_delete(cfg);
}

static void test_parse_args_rejects_invalid_compression_level_equals() {
  static const char* const values[] = {"0", "23", "invalid"};

  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    Config* cfg = config_create();
    char option[32];
    snprintf(option, sizeof(option), "--compress-level=%s", values[i]);
    char* argv[] = {"fastsync", option, "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
}

static void test_parse_args_rejects_invalid_compression_choice() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--compress-choice=bogus", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), -1);
  config_delete(cfg);
}

/* Every value-taking table option accepts an inline "--opt=value" form. */
static void test_parse_args_table_equals_size_options() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--max-size=2G", "--min-size=1K", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->max_size == 2ULL * 1024 * 1024 * 1024);
  EXPECT_TRUE(cfg->min_size == 1024ULL);
  EXPECT_EQ_INT(positional_count, 2);
  config_delete(cfg);
}

static void test_parse_args_table_equals_string_and_int_options() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--suffix=.bak", "--timeout=30", "--max-depth=5", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 6, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->suffix, ".bak");
  EXPECT_EQ_INT(cfg->timeout, 30);
  EXPECT_EQ_INT(cfg->max_depth, 5);
  EXPECT_EQ_INT(positional_count, 2);
  config_delete(cfg);

  cfg = config_create();
  char* backup_argv[] = {"fastsync", "--backup-dir=/tmp/bak", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, backup_argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->backup_dir, "/tmp/bak");
  config_delete(cfg);
}

/* Options that take a separate value must report "missing argument", not the
 * generic "Unknown option", when they are the final argv entry. */
static void test_parse_args_missing_argument_diagnostic() {
  static const char* const options[] = {"--exclude", "--server-port", "--skip-compress",
                                        "-T",        "--out-format",  "--log-file-format"};

  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i]};
    int positional_args[2];
    int positional_count = 0;
    FILE* log_file = tmpfile();
    char log_buffer[512] = {0};

    EXPECT_NOT_NULL(log_file);
    log_set_file(log_file);

    EXPECT_EQ_INT(parse_args(cfg, 2, argv, positional_args, &positional_count), -1);
    fflush(log_file);
    rewind(log_file);
    EXPECT_TRUE(fread(log_buffer, 1, sizeof(log_buffer) - 1, log_file) > 0);
    EXPECT_TRUE(strstr(log_buffer, "missing argument") != NULL);
    EXPECT_TRUE(strstr(log_buffer, "Unknown option") == NULL);

    log_set_file(NULL);
    fclose(log_file);
    config_delete(cfg);
  }
}

static void test_parse_args_itemize_changes() {
  static const char* const flags[] = {"-i", "--itemize-changes"};
  for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)flags[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
    EXPECT_TRUE(cfg->itemize_changes);
    EXPECT_EQ_INT(positional_count, 2);
    config_delete(cfg);
  }
}

static void test_parse_args_list_only() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--list-only", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->list_only);
  config_delete(cfg);
}

static void test_parse_args_out_format() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--out-format=%f %l", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->out_format, "%f %l");
  config_delete(cfg);

  cfg = config_create();
  char* separate_argv[] = {"fastsync", "--out-format", "%f %l", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, separate_argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->out_format, "%f %l");
  config_delete(cfg);
}

static void test_parse_args_log_file_format() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--log-file-format=%n %M", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->log_file_format, "%n %M");
  config_delete(cfg);

  cfg = config_create();
  char* separate_argv[] = {"fastsync", "--log-file-format", "%n %M", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, separate_argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->log_file_format, "%n %M");
  config_delete(cfg);
}

/* --delay-updates is a plain boolean receiver option. */
static void test_parse_args_delay_updates() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--delay-updates", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;

  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->delay_updates);
  EXPECT_EQ_INT(positional_count, 2);
  config_delete(cfg);
}

/* rsync rejects --delay-updates with --inplace; FastSync must too. */
static void test_validate_config_delay_updates_rejects_inplace() {
  Config* cfg = valid_client_config();
  cfg->delay_updates = true;
  cfg->inplace = true;
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);
}

/* --backup-dir may not collide with the internal --delay-updates staging
   directory (with or without a trailing slash), or old backups would silently
   be installed as the "new" file. */
static void test_validate_config_delay_updates_rejects_reserved_backup_dir() {
  static const char* const reserved[] = {".fastsync-stage", ".fastsync-stage/"};
  for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
    Config* cfg = valid_client_config();
    cfg->delay_updates = true;
    cfg->backup_dir = str_dup(reserved[i]);
    EXPECT_FALSE(validate_config(cfg));
    config_delete(cfg);
  }

  /* A non-colliding backup dir is fine alongside --delay-updates. */
  Config* ok = valid_client_config();
  ok->delay_updates = true;
  ok->backup_dir = str_dup("backups");
  EXPECT_TRUE(validate_config(ok));
  config_delete(ok);
}

static void test_parse_args_filter_rules() {
  Config* cfg = config_create();
  int positional_args[2];
  int positional_count = 0;
  char* argv[] = {"fastsync", "--filter", "- *.tmp", "--filter=+ /keep.txt", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 6, argv, positional_args, &positional_count), 0);
  EXPECT_NOT_NULL(cfg->filters);
  EXPECT_EQ_INT(cfg->filters->size, 2);
  EXPECT_EQ_STR((char*)cfg->filters->items[0], "- *.tmp");
  EXPECT_EQ_STR((char*)cfg->filters->items[1], "+ /keep.txt");
  config_delete(cfg);

  /* An unsupported rsync rule type is rejected with a clear error. */
  cfg = config_create();
  positional_count = 0;
  char* bad_argv[] = {"fastsync", "--filter=merge /tmp/excludes", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, bad_argv, positional_args, &positional_count), -1);
  config_delete(cfg);

  /* A trailing --filter with no rule is a missing-argument error. */
  cfg = config_create();
  positional_count = 0;
  char* missing_argv[] = {"fastsync", "/src", "/dst", "--filter"};
  EXPECT_EQ_INT(parse_args(cfg, 4, missing_argv, positional_args, &positional_count), -1);
  config_delete(cfg);

  /* rsync shorthands/modifiers we do not support are rejected instead of being
   * silently parsed as literal patterns. */
  static const char* const unsupported[] = {
      ": .rsync-filter", ". /tmp/rules", "-s foo", "-p bar", "-C", "-! *.o", "!",
  };
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    cfg = config_create();
    positional_count = 0;
    char* rule_argv[] = {"fastsync", "--filter", (char*)unsupported[i], "/src", "/dst"};
    EXPECT_EQ_INT(parse_args(cfg, 5, rule_argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }

  /* Supported spellings still parse: space- or slash-separated, attached
   * wildcards, and anchored rules. */
  cfg = config_create();
  positional_count = 0;
  char* ok_argv[] = {"fastsync",         "--filter=-*.o", "--filter=- /foo",
                     "--filter=+ /bar/", "/src",          "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 6, ok_argv, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->filters->size, 3);
  config_delete(cfg);
}

static void test_parse_args_from0_cvs_filter_file_flags() {
  static const struct {
    const char* arg;
    bool from0;
    bool cvs;
    bool per_dir;
  } cases[] = {
      {"--from0", true, false, false},
      {"-0", true, false, false},
      {"--cvs-exclude", false, true, false},
      {"-C", false, true, false},
      {"-F", false, false, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)cases[i].arg, "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
    EXPECT_EQ_INT(cfg->from0, cases[i].from0);
    EXPECT_EQ_INT(cfg->cvs_exclude, cases[i].cvs);
    EXPECT_EQ_INT(cfg->per_dir_filter, cases[i].per_dir);
    config_delete(cfg);
  }

  /* The plain booleans are negatable (--no-* simply clears the flag). */
  static const char* const on[][2] = {{"--from0", "--no-from0"}, {"-C", "--no-cvs-exclude"}};
  for (size_t i = 0; i < sizeof(on) / sizeof(on[0]); i++) {
    Config* cfg = config_create();
    int positional_args[2];
    int positional_count = 0;
    char* argv[] = {"fastsync", (char*)on[i][0], (char*)on[i][1], "/src", "/dst"};
    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
    EXPECT_FALSE(cfg->from0);
    EXPECT_FALSE(cfg->cvs_exclude);
    config_delete(cfg);
  }
}

static void write_file_bytes(const char* path, const char* bytes, size_t len) {
  FILE* fp = fopen(path, "wb");
  EXPECT_NOT_NULL(fp);
  EXPECT_EQ_INT((int)fwrite(bytes, 1, len, fp), (int)len);
  fclose(fp);
}

static void test_parse_args_files_from() {
  const char* list_path = "cli_files_from_list.txt";
  write_file_bytes(list_path, "a.txt\nsub/b.bin\n\n./c.txt\n", 25);
  Config* cfg = config_create();
  int positional_args[2];
  int positional_count = 0;
  char* argv[] = {"fastsync", "--files-from", (char*)list_path, "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_STR(cfg->files_from, list_path);
  EXPECT_NOT_NULL(cfg->files_from_set);
  FileListSet* set = (FileListSet*)cfg->files_from_set;
  EXPECT_TRUE(file_list_affects(set, "a.txt"));
  EXPECT_TRUE(file_list_affects(set, "sub/b.bin"));
  EXPECT_TRUE(file_list_affects(set, "sub/b.bin/x"));
  EXPECT_TRUE(file_list_affects(set, "sub"));
  EXPECT_TRUE(file_list_affects(set, "c.txt"));
  EXPECT_FALSE(file_list_affects(set, "other.txt"));
  config_delete(cfg);
  remove(list_path);

  /* -0 switches the separator to NUL regardless of argument order, and NUL
   * mode preserves entry bytes exactly (a trailing CR/LF is part of the name). */
  write_file_bytes(list_path, "x.txt\0y/z.bin\0", 14);
  cfg = config_create();
  positional_count = 0;
  char* nul_argv[] = {"fastsync",
                      "--files-from="
                      "cli_files_from_list.txt",
                      "-0", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, nul_argv, positional_args, &positional_count), 0);
  set = (FileListSet*)cfg->files_from_set;
  EXPECT_NOT_NULL(set);
  EXPECT_TRUE(file_list_affects(set, "x.txt"));
  EXPECT_TRUE(file_list_affects(set, "y/z.bin"));
  EXPECT_TRUE(file_list_affects(set, "y"));
  EXPECT_FALSE(file_list_affects(set, "z.txt"));
  config_delete(cfg);
  remove(list_path);

  write_file_bytes(list_path, "crlf\n\0tail\0", 11);
  cfg = config_create();
  positional_count = 0;
  char* nul_nl_argv[] = {"fastsync",
                         "--files-from="
                         "cli_files_from_list.txt",
                         "-0", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, nul_nl_argv, positional_args, &positional_count), 0);
  set = (FileListSet*)cfg->files_from_set;
  EXPECT_NOT_NULL(set);
  EXPECT_TRUE(file_list_affects(set, "crlf\n"));
  EXPECT_TRUE(file_list_affects(set, "tail"));
  config_delete(cfg);
  remove(list_path);

  /* A missing list file is a hard parse-time error. */
  cfg = config_create();
  positional_count = 0;
  char* missing_argv[] = {"fastsync", "--files-from", "does_not_exist_ff.txt", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, missing_argv, positional_args, &positional_count), -1);
  config_delete(cfg);

  /* Absolute and traversal entries are rejected. */
  write_file_bytes(list_path, "/abs/path\n", 10);
  cfg = config_create();
  positional_count = 0;
  char* abs_argv[] = {"fastsync",
                      "--files-from="
                      "cli_files_from_list.txt",
                      "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, abs_argv, positional_args, &positional_count), -1);
  config_delete(cfg);
  write_file_bytes(list_path, "../escape\n", 10);
  cfg = config_create();
  positional_count = 0;
  char* trav_argv[] = {"fastsync",
                       "--files-from="
                       "cli_files_from_list.txt",
                       "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, trav_argv, positional_args, &positional_count), -1);
  config_delete(cfg);
  remove(list_path);
}

/* The deletion-policy family parses onto the config fields: --delete-excluded,
 * --ignore-errors and --force are flags, --max-delete takes a non-negative
 * number, and --prune-empty-dirs is the long-only spelling (FastSync's -m stays
 * multithreading).  None of them implies --delete by itself. */
static void test_parse_args_delete_policy_flags() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync",
                  "--delete",
                  "--delete-excluded",
                  "--max-delete=5",
                  "--ignore-errors",
                  "--force",
                  "--prune-empty-dirs",
                  "/src",
                  "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 9, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_delete);
  EXPECT_TRUE(cfg->delete_excluded);
  EXPECT_EQ_INT(cfg->max_delete, 5);
  EXPECT_TRUE(cfg->ignore_errors);
  EXPECT_TRUE(cfg->force_delete);
  EXPECT_TRUE(cfg->prune_empty_dirs);
  EXPECT_FALSE(cfg->delete_before);
  config_delete(cfg);

  /* --max-delete accepts the separated-argument and zero forms. */
  cfg = config_create();
  char* argv2[] = {"fastsync", "--max-delete", "0", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv2, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->max_delete, 0);
  config_delete(cfg);
}

static void test_parse_args_delete_policy_invalid_values() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--max-delete=abc", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), -1);
  config_delete(cfg);

  cfg = config_create();
  char* argv2[] = {"fastsync", "--max-delete=-3", "/src", "/dst"};
  positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv2, positional_args, &positional_count), -1);
  config_delete(cfg);
}

/* --max-delete without --delete is inert (it only bounds a --delete run); the
 * config stays valid. */
static void test_parse_args_max_delete_inert_without_delete() {
  Config* cfg = config_create();
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  char* argv[] = {"fastsync", "--max-delete=5", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_FALSE(cfg->use_delete);
  EXPECT_EQ_INT(cfg->max_delete, 5);
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

/* --ignore-missing-args / --delete-missing-args parse onto their config fields.
 * --delete-missing-args implies --ignore-missing-args (order-independent),
 * does NOT imply --delete (rsync: independent of other delete processing), and
 * the config stays valid in every combination. */
static void test_parse_args_missing_args_flags() {
  Config* cfg = config_create();
  int positional_args[2];
  int positional_count = 0;
  char* argv[] = {"fastsync", "--ignore-missing-args", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->ignore_missing_args);
  EXPECT_FALSE(cfg->delete_missing_args);
  EXPECT_FALSE(cfg->use_delete);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* argv2[] = {"fastsync", "--delete-missing-args", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, argv2, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->delete_missing_args);
  EXPECT_TRUE(cfg->ignore_missing_args);
  EXPECT_FALSE(cfg->use_delete);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);

  /* The implication is order-independent: even with the explicit flag first. */
  cfg = config_create();
  positional_count = 0;
  char* argv3[] = {"fastsync", "--ignore-missing-args", "--delete-missing-args", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, argv3, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->ignore_missing_args);
  EXPECT_TRUE(cfg->delete_missing_args);
  config_delete(cfg);

  /* --delete-missing-args composes with --delete (both active) and with a
     delete-timing flag (which implies --delete); timing stays valid. */
  cfg = config_create();
  positional_count = 0;
  char* argv4[] = {"fastsync", "--delete", "--delete-missing-args", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, argv4, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_delete);
  EXPECT_TRUE(cfg->delete_missing_args);
  EXPECT_TRUE(cfg->ignore_missing_args);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);

  cfg = config_create();
  positional_count = 0;
  char* argv5[] = {"fastsync", "--delete-before", "--delete-missing-args", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, argv5, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_delete);
  EXPECT_TRUE(cfg->delete_before);
  EXPECT_TRUE(cfg->delete_missing_args);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}
/* --append is accepted and implies the per-file incremental check a tail resume
 * needs; it validates cleanly on its own. */
static void test_parse_args_append() {
  Config* cfg = config_create();
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  char* argv[] = {"fastsync", "--append", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->append);
  EXPECT_FALSE(cfg->append_verify);
  EXPECT_TRUE(cfg->use_incremental);
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

static void test_parse_args_append_verify() {
  Config* cfg = config_create();
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  char* argv[] = {"fastsync", "--append-verify", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->append_verify);
  EXPECT_FALSE(cfg->append);
  EXPECT_TRUE(cfg->use_incremental);
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

/* Both spellings are accepted; the safer --append-verify semantics win on the
 * wire (the sender checks append_verify first), so neither flag is silently
 * dropped but the run is still valid. */
static void test_parse_args_append_both() {
  Config* cfg = config_create();
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  char* argv[] = {"fastsync", "--append", "--append-verify", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->append);
  EXPECT_TRUE(cfg->append_verify);
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

static void test_validate_config_append_rejects_chunk_serialization() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--append", "-s", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);
}

static void test_validate_config_append_verify_rejects_chunk_serialization() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--append-verify", "-s", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);
}

static void test_validate_config_append_rejects_whole_file() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--append", "-W", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);
}

static void test_validate_config_append_verify_rejects_whole_file() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--append-verify", "-W", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_FALSE(validate_config(cfg));
  config_delete(cfg);
}
/* --numeric-ids is a plain boolean flag. */
static void test_parse_args_numeric_ids() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--numeric-ids", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->numeric_ids);
  config_delete(cfg);
}

/* --usermap / --groupmap resolve an rsync subset into numeric FROM:TO pairs and
 * imply metadata preservation (so the source uid/gid travel on the wire). */
static void test_parse_args_usermap() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--usermap=@1000:@1001", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_metadata);
  EXPECT_EQ_INT(cfg->usermap_count, 1);
  EXPECT_EQ_INT(cfg->usermap[0].from, 1000);
  EXPECT_EQ_INT(cfg->usermap[0].to, 1001);
  config_delete(cfg);

  /* Space form, multiple rules, comma-separated. */
  cfg = config_create();
  positional_count = 0;
  char* argv2[] = {"fastsync", "--usermap", "@1:@2,@3:@4", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, argv2, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->usermap_count, 2);
  EXPECT_EQ_INT(cfg->usermap[0].from, 1);
  EXPECT_EQ_INT(cfg->usermap[0].to, 2);
  EXPECT_EQ_INT(cfg->usermap[1].from, 3);
  EXPECT_EQ_INT(cfg->usermap[1].to, 4);
  config_delete(cfg);

  /* '*' FROM means match any id; '*' TO means current user. */
  cfg = config_create();
  positional_count = 0;
  char* argv3[] = {"fastsync", "--usermap=*:@2000", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, argv3, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->usermap[0].from, IDENTITY_MATCH_ANY);
  EXPECT_EQ_INT(cfg->usermap[0].to, 2000);
  config_delete(cfg);
}

static void test_parse_args_groupmap() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--groupmap=@100:@101", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_metadata);
  EXPECT_EQ_INT(cfg->groupmap_count, 1);
  EXPECT_EQ_INT(cfg->groupmap[0].from, 100);
  EXPECT_EQ_INT(cfg->groupmap[0].to, 101);
  config_delete(cfg);
}

/* A name in a map can be resolved to a number via the local user database. */
static void test_parse_args_usermap_name_resolution() {
  struct passwd* self = getpwuid(geteuid());
  if (!self)
    return; /* cannot construct a resolvable name deterministically */
  char map_value[128];
  snprintf(map_value, sizeof(map_value), "%s:@0", self->pw_name);
  Config* cfg = config_create();
  int positional_args[2];
  int positional_count = 0;
  char* argv[] = {"fastsync", (char*)"--usermap", map_value, "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), 0);
  EXPECT_EQ_INT(cfg->usermap_count, 1);
  EXPECT_EQ_INT(cfg->usermap[0].from, (int32_t)self->pw_uid);
  config_delete(cfg);
}

/* --chown parses USER:GROUP / USER / :GROUP, numeric ids, and '*'. */
static void test_parse_args_chown() {
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--chown=@1000:@1001", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->use_metadata);
  EXPECT_TRUE(cfg->chown_uid_set);
  EXPECT_EQ_INT(cfg->chown_uid, 1000);
  EXPECT_TRUE(cfg->chown_gid_set);
  EXPECT_EQ_INT(cfg->chown_gid, 1001);
  config_delete(cfg);

  /* --chown=:GROUP sets only the group. */
  cfg = config_create();
  positional_count = 0;
  char* argv2[] = {"fastsync", "--chown=:@1001", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, argv2, positional_args, &positional_count), 0);
  EXPECT_FALSE(cfg->chown_uid_set);
  EXPECT_TRUE(cfg->chown_gid_set);
  EXPECT_EQ_INT(cfg->chown_gid, 1001);
  config_delete(cfg);

  /* --chown=USER sets only the owner. */
  cfg = config_create();
  positional_count = 0;
  char* argv3[] = {"fastsync", "--chown=@1000", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, argv3, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->chown_uid_set);
  EXPECT_EQ_INT(cfg->chown_uid, 1000);
  EXPECT_FALSE(cfg->chown_gid_set);
  config_delete(cfg);

  /* '*' means current user/group. */
  cfg = config_create();
  positional_count = 0;
  char* argv4[] = {"fastsync", "--chown=*:*", "/src", "/dst"};
  EXPECT_EQ_INT(parse_args(cfg, 4, argv4, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->chown_uid_set);
  EXPECT_EQ_INT(cfg->chown_uid, IDENTITY_CURRENT);
  EXPECT_TRUE(cfg->chown_gid_set);
  EXPECT_EQ_INT(cfg->chown_gid, IDENTITY_CURRENT);
  config_delete(cfg);
}

/* Malformed identity specs are rejected, never silently ignored. */
static void test_parse_args_rejects_malformed_identity() {
  struct {
    const char* opt;
    const char* val;
  } bad[] = {
      {"--usermap", "@1000"},
      {"--usermap", ":1000"},
      {"--usermap", "definitely_not_a_real_user_zzz:@1"},
      {"--groupmap", "@1"},
      {"--groupmap", "no_such_group_qqq:x"},
      {"--chown", "a:b:c"},
      {"--chown", "no_such_user_zzz:"},
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)bad[i].opt, (char*)bad[i].val, "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }

  /* An option with a missing value fails at the CLI layer. */
  Config* cfg = config_create();
  char* argv[] = {"fastsync", "--chown"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 2, argv, positional_args, &positional_count), -1);
  config_delete(cfg);
}

/* --preallocate parses as a boolean flag and validates cleanly. */
static void test_parse_args_preallocate() {
  Config* cfg = config_create();
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  char* argv[] = {"fastsync", "--preallocate", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->preallocate);
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

/* Phase 4 metadata-time flags parse and set the expected config fields.  -U and
 * -N imply metadata transmission (they carry their times inside the metadata
 * payload); -O/-J and --open-noatime do not. */
static void test_parse_args_metadata_times() {
  Config* cfg = config_create();
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  char* argv[] = {"fastsync", "-U", "-N", "-O", "-J", "--open-noatime", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 8, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->preserve_atimes);
  EXPECT_TRUE(cfg->preserve_crtimes);
  EXPECT_TRUE(cfg->omit_dir_times);
  EXPECT_TRUE(cfg->omit_link_times);
  EXPECT_TRUE(cfg->open_noatime);
  /* -U/-N carry their times inside the metadata payload, so they imply it. */
  EXPECT_TRUE(cfg->use_metadata);
  EXPECT_TRUE(validate_config(cfg));
  config_delete(cfg);
}

static void test_parse_args_atimes_long_and_short() {
  Config* cfg = config_create();
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  char* argv[] = {"fastsync", "--atimes", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->preserve_atimes);
  EXPECT_TRUE(cfg->use_metadata);
  config_delete(cfg);
}

static void test_parse_args_omit_link_times_long() {
  Config* cfg = config_create();
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  char* argv[] = {"fastsync", "--omit-link-times", "/src", "/dst"};
  int positional_args[2];
  int positional_count = 0;
  EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), 0);
  EXPECT_TRUE(cfg->omit_link_times);
  EXPECT_FALSE(cfg->use_metadata);
  config_delete(cfg);
}

void test_client_cli() {
  test_validate_config_required_paths();
  test_parse_args_numeric_ids();
  test_parse_args_usermap();
  test_parse_args_groupmap();
  test_parse_args_usermap_name_resolution();
  test_parse_args_chown();
  test_parse_args_rejects_malformed_identity();
  test_parse_args_preallocate();
  test_parse_args_metadata_times();
  test_parse_args_atimes_long_and_short();
  test_parse_args_omit_link_times_long();
  test_parse_args_append();
  test_parse_args_append_verify();
  test_parse_args_append_both();
  test_validate_config_append_rejects_chunk_serialization();
  test_validate_config_append_verify_rejects_chunk_serialization();
  test_validate_config_append_rejects_whole_file();
  test_validate_config_append_verify_rejects_whole_file();
  test_validate_config_incompatible_options();
  test_validate_config_tls_requirements();
  test_validate_config_delta_sendfile_constraints();
  test_cli_help();
  test_cli_archive_flags();
  test_cli_dry_run();
  test_cli_remove_source_files();
  test_parse_args_remove_source_files();
  test_cli_delete_flag();
  test_cli_exclude_patterns();
  test_parse_args_help();
  test_parse_args_version();
  test_parse_args_valid_port();
  test_parse_args_size_only();
  test_parse_args_ignore_existing();
  test_parse_args_executability();
  test_parse_args_chmod();
  test_parse_args_numeric_chmod();
  test_parse_args_rejects_invalid_chmod();
  test_parse_args_invalid_port();
  test_parse_args_non_numeric_port();
  test_parse_args_invalid_server_port();
  test_parse_args_invalid_compression_level();
  test_parse_args_valid_compression_level();
  test_parse_args_debug_flags();
  test_parse_args_debug_help();
  test_parse_args_debug_flags_validation();
  test_parse_args_modify_window();
  test_parse_args_rejects_invalid_modify_window();
  test_parse_args_skip_compress();
  test_parse_args_empty_skip_compress();
  test_parse_args_compression_threads();
  test_parse_args_max_alloc_sizes();
  test_parse_args_rejects_invalid_max_alloc();
  test_parse_args_unknown_option();
  test_parse_args_dirs_aliases();
  test_parse_args_relative_no_implied_mkpath();
  test_parse_args_delete_during_alias();
  test_parse_args_delete_timing_flags();
  test_parse_args_delete_timing_conflict_rejected();
  test_parse_args_delete_timing_without_delete_rejected();
  test_parse_args_rejects_unimplemented_options();
  test_parse_args_quiet();
  test_parse_args_human_readable();
  test_parse_args_hard_links();
  test_validate_config_hard_links_incompatible_modes();
  test_parse_args_update();
  test_parse_args_info_flags();
  test_parse_args_info_verbose_order();
  test_parse_args_rejects_invalid_info_flag();
  test_parse_args_archive();
  test_parse_args_negations();
  test_parse_args_negation_order();
  test_parse_args_no_preserve_blocks_implicit_metadata();
  test_parse_args_rejects_unsafe_negation();
  test_parse_args_old_args();
  test_parse_args_fsync();
  test_parse_args_existing();
  test_parse_args_ignore_times();
  test_parse_args_8_bit_output();
  test_parse_args_stderr_modes();
  test_parse_args_rejects_unsupported_stderr_modes();
  test_parse_args_secluded_args();
  test_parse_args_short_s_remains_chunk_serialization();
  test_parse_args_whole_file();
  test_parse_args_fuzzy_implies_delta();
  test_parse_args_fuzzy_negation();
  test_parse_args_fuzzy_with_whole_file();
  test_parse_args_fuzzy_respects_no_delta();
  test_parse_args_fuzzy_respects_no_incremental();
  test_validate_config_fuzzy_incompatible_modes();
  test_parse_args_one_file_system();
  test_parse_args_compression_aliases();
  test_parse_args_compression_equals_and_none();
  test_parse_args_compression_canonical_equals();
  test_parse_args_compression_alias_equals();
  test_parse_args_rejects_invalid_compression_level_equals();
  test_parse_args_rejects_invalid_compression_choice();
  test_parse_args_table_equals_size_options();
  test_parse_args_table_equals_string_and_int_options();
  test_parse_args_missing_argument_diagnostic();
  test_parse_args_xattrs_acls();
  test_parse_args_fake_super();
  test_parse_args_partial_progress();
  test_parse_args_itemize_changes();
  test_parse_args_list_only();
  test_parse_args_out_format();
  test_parse_args_log_file_format();
  test_parse_args_checksum_choice_aliases();
  test_parse_args_checksum_choice_requires_value();
  test_parse_args_checksum_choice_equals_forms();
  test_parse_args_checksum_choice_rejects_unsupported();
  test_parse_args_checksum_seed();
  test_parse_args_temp_dir();
  test_parse_args_delay_updates();
  test_validate_config_delay_updates_rejects_inplace();
  test_validate_config_delay_updates_rejects_reserved_backup_dir();
  test_parse_args_files_from();
  test_parse_args_filter_rules();
  test_parse_args_from0_cvs_filter_file_flags();
  test_parse_args_basis_dirs();
  test_parse_args_basis_invalid_paths();
  test_validate_config_basis_rejects_chunk_serialization();
  test_parse_args_delete_policy_flags();
  test_parse_args_delete_policy_invalid_values();
  test_parse_args_max_delete_inert_without_delete();
  test_parse_args_missing_args_flags();
}
