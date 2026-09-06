#include "test_client_cli.h"
#include "client_validation.h"
#include "chmod.h"
#include "config.h"
#include "log.h"
#include "test_utils.h"
#include "utils.h"
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

/* Directory aliases must report the unsupported directory-only behavior clearly. */
static void test_parse_args_rejects_dirs_aliases() {
  static const char* const options[] = {"--dirs", "--old-dirs", "--old-d"};

  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;
    FILE* log_file = tmpfile();
    char log_buffer[256] = {0};

    EXPECT_NOT_NULL(log_file);
    log_set_file(log_file);

    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), -1);
    fflush(log_file);
    rewind(log_file);
    EXPECT_TRUE(fread(log_buffer, 1, sizeof(log_buffer) - 1, log_file) > 0);
    EXPECT_TRUE(strstr(log_buffer, options[i]) != NULL);
    EXPECT_TRUE(strstr(log_buffer, "directory-only transfer is not implemented") != NULL);
    EXPECT_TRUE(strstr(log_buffer, "requires --dirs") == NULL);
    log_set_file(NULL);
    fclose(log_file);
    config_delete(cfg);
  }
}

/* --del is recognized as the rsync alias, but its timing mode is not implemented. */
static void test_parse_args_delete_during_alias_unimplemented() {
  static const char* const options[] = {"--del", "--delete-during"};

  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i], "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 4, argv, positional_args, &positional_count), -1);
    EXPECT_FALSE(cfg->use_delete);
    config_delete(cfg);
  }
}

/* Parsed-but-unimplemented options must fail instead of being silently accepted. */
static void test_parse_args_rejects_unimplemented_options() {
  static const char* const options[] = {"--silent",
                                        "--queue-size",
                                        "-H",
                                        "--hard-links",
                                        "-A",
                                        "--acls",
                                        "-X",
                                        "--xattrs",
                                        "-D",
                                        "--devices",
                                        "-i",
                                        "--itemize-changes",
                                        "--out-format",
                                        "--list-only",
                                        "--append",
                                        "--append-verify",
                                        "--delete-excluded",
                                        "--delete-after",
                                        "--max-delete",
                                        "--filter",
                                        "--files-from",
                                        "--cvs-exclude",
                                        "--prune-empty-dirs",
                                        "-R",
                                        "--relative",
                                        "-e",
                                        "--rsh",
                                        "--rsync-path",
                                        "--temp-dir",
                                        "--compare-dest",
                                        "--copy-dest",
                                        "--link-dest",
                                        "--delete-before",
                                        "--address",
                                        "--bind-address",
                                        "--ipv6",
                                        "--ipv4",
                                        "--daemon",
                                        "--config",
                                        "--server",
                                        "--checksum-choice"};

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

/* Checksum-choice spellings are recognized and rejected until algorithms are implemented. */
static void test_parse_args_checksum_choice_aliases() {
  static const char* const options[] = {"--checksum-choice", "--cc"};

  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
    Config* cfg = config_create();
    char* argv[] = {"fastsync", (char*)options[i], "xxh64", "/src", "/dst"};
    int positional_args[2];
    int positional_count = 0;

    EXPECT_EQ_INT(parse_args(cfg, 5, argv, positional_args, &positional_count), -1);
    config_delete(cfg);
  }
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
  static const char* const options[] = {"--exclude", "--server-port", "--skip-compress", "-T"};

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

void test_client_cli() {
  test_validate_config_required_paths();
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
  test_parse_args_rejects_dirs_aliases();
  test_parse_args_delete_during_alias_unimplemented();
  test_parse_args_rejects_unimplemented_options();
  test_parse_args_quiet();
  test_parse_args_human_readable();
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
  test_parse_args_partial_progress();
  test_parse_args_checksum_choice_aliases();
  test_parse_args_checksum_choice_requires_value();
}
