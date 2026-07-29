#include "test_client_cli.h"
#include "config.h"
#include "test_utils.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Test basic config creation matching client_cli startup */
static void test_cli_default_config() {
  Config* cfg = config_create(str_dup("1.0"), NULL, NULL, false, false, false, false, false, 5,
                              false, 0);
  EXPECT_NOT_NULL(cfg);
  EXPECT_NULL(cfg->send_directory);
  EXPECT_NULL(cfg->receive_root_directory);
  EXPECT_EQ_INT(cfg->compression_level, 5);
  config_delete(cfg);
}

/* Test that --archive sets compression, multithreading, and metadata */
static void test_cli_archive_flags() {
  Config* cfg = config_create(str_dup("1.0"), NULL, NULL, false, false, false, false, false, 5,
                              false, 0);
  EXPECT_NOT_NULL(cfg);

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
  Config* cfg = config_create(str_dup("1.0"), NULL, NULL, false, false, false, false, false, 5,
                              false, 0);
  cfg->dry_run = true;
  EXPECT_TRUE(cfg->dry_run);
  config_delete(cfg);
}

/* Test that --delete sets use_delete */
static void test_cli_delete_flag() {
  Config* cfg = config_create(str_dup("1.0"), NULL, NULL, false, false, false, false, false, 5,
                              false, 0);
  cfg->use_delete = true;
  EXPECT_TRUE(cfg->use_delete);
  config_delete(cfg);
}

/* Test exclude pattern handling */
static void test_cli_exclude_patterns() {
  Config* cfg = config_create(str_dup("1.0"), NULL, NULL, false, false, false, false, false, 5,
                              false, 0);
  EXPECT_NOT_NULL(cfg);

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
  test_cli_default_config();
  test_cli_archive_flags();
  test_cli_dry_run();
  test_cli_delete_flag();
  test_cli_exclude_patterns();
}
