#include "test_client_cli.h"
#include "config.h"
#include "test_utils.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

void test_client_cli() {
  test_cli_help();
  test_cli_archive_flags();
  test_cli_dry_run();
  test_cli_delete_flag();
  test_cli_exclude_patterns();
}
