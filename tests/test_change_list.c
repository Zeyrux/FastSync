#include "test_change_list.h"
#include "change_list.h"
#include "config.h"
#include "test_utils.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

static ChangeEvent sample_event(void) {
  ChangeEvent event;
  memset(&event, 0, sizeof(event));
  event.path = "src/sub/file.txt";
  event.name = "sub/file.txt";
  event.decision = CHANGE_SENT;
  event.is_directory = false;
  event.size = 12345;
  event.bytes_sent = 999;
  event.mtime_sec = 1700000000;
  event.mtime_nsec = 0;
  event.mode = 0100644;
  event.uid = 1000;
  event.gid = 1000;
  return event;
}

/* Expected %M expansion computed independently with localtime_r. */
static void expected_mtime(time_t when, char out[32]) {
  struct tm broken_down;
  localtime_r(&when, &broken_down);
  strftime(out, 32, "%Y/%m/%d-%H:%M:%S", &broken_down);
}

static void test_format_tokens() {
  ChangeEvent event = sample_event();
  Config* config = config_create();
  char when[32];
  expected_mtime(event.mtime_sec, when);
  char* line = change_render_format("%f %n %l %b %M %%", config, &event);
  EXPECT_NOT_NULL(line);
  char expected[256];
  snprintf(expected, sizeof(expected), "src/sub/file.txt sub/file.txt 12345 999 %s %%", when);
  EXPECT_EQ_STR(line, expected);
  free(line);
  config_delete(config);
}

static void test_format_unknown_tokens_preserved() {
  ChangeEvent event = sample_event();
  Config* config = config_create();
  char* line = change_render_format("x%q=%f%z", config, &event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, "x%q=src/sub/file.txt%z");
  free(line);
  config_delete(config);
}

static void test_format_directory_name_has_trailing_slash() {
  ChangeEvent event = sample_event();
  event.is_directory = true;
  event.path = "src/sub";
  event.name = "sub";
  Config* config = config_create();
  char* line = change_render_format("%n|%f", config, &event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, "sub/|src/sub");
  free(line);
  config_delete(config);
}

static void test_render_itemize_sent_file() {
  ChangeEvent event = sample_event();
  Config* config = config_create();
  char* line = change_render_itemize(config, &event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, ">f+++++++++ sub/file.txt");
  free(line);
  config_delete(config);
}

static void test_render_itemize_directory() {
  ChangeEvent event = sample_event();
  event.is_directory = true;
  event.path = "src/sub";
  event.name = "sub";
  Config* config = config_create();
  char* line = change_render_itemize(config, &event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, "cd+++++++++ sub/");
  free(line);
  config_delete(config);
}

static void test_render_itemize_symlink() {
  ChangeEvent event = sample_event();
  event.is_symlink = true;
  event.path = "src/link";
  event.name = "link";
  event.symlink_target = "a.txt";
  Config* config = config_create();
  char* line = change_render_itemize(config, &event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, "cL+++++++++ link -> a.txt");
  free(line);
  config_delete(config);
}

static void test_render_itemize_compares_destination() {
  ChangeEvent event = sample_event();
  Config* config = config_create();
  config->preserve_perms = true;
  config->preserve_owner = true;
  config->preserve_group = true;
  event.dest.known = true;
  event.dest.existed = true;
  event.dest.size = 1;
  event.dest.mtime_sec = 1700000000;
  event.dest.mtime_nsec = 0;
  event.dest.mode = 0100600;
  event.dest.uid = 1;
  event.dest.gid = 2;
  char* line = change_render_itemize(config, &event);
  EXPECT_NOT_NULL(line);
  /* size, perms, owner and group differ; time matches. */
  EXPECT_EQ_STR(line, ">f.s.pog... sub/file.txt");
  free(line);
  config_delete(config);
}

static void test_render_itemize_up_to_date_is_empty() {
  ChangeEvent event = sample_event();
  Config* config = config_create();
  event.decision = CHANGE_UP_TO_DATE;
  char* line = change_render_itemize(config, &event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, "");
  free(line);
  config_delete(config);
}

static void test_render_list_line() {
  ChangeEvent event;
  memset(&event, 0, sizeof(event));
  Config* config = config_create();
  event.name = "sub/x.txt";
  event.path = "sub/x.txt";
  event.mode = 0100644;
  event.size = 4096;
  event.mtime_sec = 1700000000;
  char* line = change_render_list_line(config, &event);
  EXPECT_NOT_NULL(line);
  EXPECT_TRUE(strncmp(line, "-rw-r--r--", 10) == 0);
  EXPECT_TRUE(strstr(line, "4,096") != NULL);
  EXPECT_TRUE(strstr(line, "sub/x.txt") != NULL);
  free(line);
  config_delete(config);
}

static void test_change_list_enabled() {
  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  EXPECT_FALSE(change_list_enabled(config));
  config->itemize_changes = true;
  EXPECT_TRUE(change_list_enabled(config));
  config->itemize_changes = false;
  config->out_format = str_dup("%f");
  EXPECT_TRUE(change_list_enabled(config));
  free(config->out_format);
  config->out_format = NULL;
  EXPECT_FALSE(change_list_enabled(config));
  /* config_delete() closes log_file, so use a throwaway tmpfile. */
  config->log_file = tmpfile();
  EXPECT_NOT_NULL(config->log_file);
  EXPECT_FALSE(change_list_enabled(config)); /* needs a format too */
  config->log_file_format = str_dup("%n");
  EXPECT_TRUE(change_list_enabled(config));
  config_delete(config); /* closes config->log_file */
}

/* %C uses the negotiated TRANSFER checksum's column width (not the pre-transfer
 * whole-file digest), and `none` renders as a blank 2-char column, matching
 * rsync.  A not-yet-filled checksum renders as spaces. */
static void test_format_C_padding_uses_transfer_algo() {
  ChangeEvent event = sample_event();
  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  /* Deliberately different pre-transfer algorithm: the transfer one must win. */
  config->checksum_algo = (int)CHECKSUM_ALGO_MD4;
  struct {
    int algo;
    int width;
  } cases[] = {
      {CHECKSUM_ALGO_XXH128, 32}, {CHECKSUM_ALGO_XXH64, 16}, {CHECKSUM_ALGO_XXH3, 16},
      {CHECKSUM_ALGO_MD5, 32},    {CHECKSUM_ALGO_MD4, 32},   {CHECKSUM_ALGO_SHA1, 40},
      {CHECKSUM_ALGO_NONE, 2},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    config->cli.checksum_transfer_algo = cases[i].algo;
    char expected[64];
    size_t n = 0;
    expected[n++] = '[';
    for (int j = 0; j < cases[i].width; j++)
      expected[n++] = ' ';
    expected[n++] = ']';
    expected[n] = '\0';
    char* line = change_render_format("[%C]", config, &event);
    EXPECT_NOT_NULL(line);
    EXPECT_EQ_STR(line, expected);
    free(line);
  }
  config_delete(config);
}

void test_change_list() {
  test_format_tokens();
  test_format_unknown_tokens_preserved();
  test_format_directory_name_has_trailing_slash();
  test_render_itemize_sent_file();
  test_render_itemize_directory();
  test_render_itemize_symlink();
  test_render_itemize_compares_destination();
  test_render_itemize_up_to_date_is_empty();
  test_render_list_line();
  test_change_list_enabled();
  test_format_C_padding_uses_transfer_algo();
}
