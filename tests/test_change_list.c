#include "test_change_list.h"
#include "change_list.h"
#include "test_utils.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

static ChangeEvent sample_event(void) {
  ChangeEvent event;
  memset(&event, 0, sizeof(event));
  event.path = "/srv/root/sub/file.txt";
  event.decision = CHANGE_SENT;
  event.is_directory = false;
  event.size = 12345;
  event.bytes_sent = 999;
  event.mtime_sec = 1700000000;
  return event;
}

static void test_format_tokens() {
  ChangeEvent event = sample_event();
  char* line = change_render_format("%f %n %l %b %M %%", &event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, "/srv/root/sub/file.txt file.txt 12345 999 1700000000 %");
  free(line);
}

static void test_format_unknown_tokens_preserved() {
  ChangeEvent event = sample_event();
  char* line = change_render_format("x%q=%f%z", &event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, "x%q=/srv/root/sub/file.txt%z");
  free(line);
}

static void test_format_leaf_name() {
  ChangeEvent event = sample_event();
  event.path = "bare.txt";
  char* line = change_render_format("%n|%f", &event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, "bare.txt|bare.txt");
  free(line);
}

static void test_render_itemize_sent_file() {
  ChangeEvent event = sample_event();
  char* line = change_render_itemize(&event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, ">f+++++++++ /srv/root/sub/file.txt");
  free(line);
}

static void test_render_itemize_up_to_date_is_empty() {
  ChangeEvent event = sample_event();
  event.decision = CHANGE_UP_TO_DATE;
  char* line = change_render_itemize(&event);
  EXPECT_NOT_NULL(line);
  EXPECT_EQ_STR(line, "");
  free(line);
}

static void test_render_list_line() {
  char* line = change_render_list_line(0100644, 4096, 1700000000, "/srv/x.txt");
  EXPECT_NOT_NULL(line);
  EXPECT_TRUE(strncmp(line, "-rw-r--r--", 10) == 0);
  EXPECT_TRUE(strstr(line, "4096") != NULL);
  EXPECT_TRUE(strstr(line, "/srv/x.txt") != NULL);
  free(line);
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

void test_change_list() {
  test_format_tokens();
  test_format_unknown_tokens_preserved();
  test_format_leaf_name();
  test_render_itemize_sent_file();
  test_render_itemize_up_to_date_is_empty();
  test_render_list_line();
  test_change_list_enabled();
}
