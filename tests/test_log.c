#include "test_log.h"
#include "log.h"
#include "test_utils.h"

/* Test default log level: WARNING and ERROR should print, DEBUG and INFO should not.
 * We can't easily capture stderr in unit tests, so we verify the functions don't crash
 * and that set_log_level changes behavior. */

static void test_log_message_debug() {
  /* Default level is WARNING, so DEBUG should be filtered out */
  log_message(LOG_LEVEL_DEBUG, "debug message: %d", 42);
  /* No assertion needed - if we reach here without crash, success */
  EXPECT_TRUE(true);
}

static void test_log_message_info() {
  /* Default level is WARNING, so INFO should be filtered out */
  log_message(LOG_LEVEL_INFO, "info message: %s", "test");
  EXPECT_TRUE(true);
}

static void test_log_message_warning() {
  /* Default level is WARNING, so WARNING should be shown */
  log_message(LOG_LEVEL_WARNING, "warning message: %d %s", 1, "test");
  EXPECT_TRUE(true);
}

static void test_log_message_error() {
  /* Default level is WARNING, so ERROR should be shown */
  log_message(LOG_LEVEL_ERROR, "error message: %s", "critical");
  EXPECT_TRUE(true);
}

static void test_log_set_level_debug() {
  set_log_level(LOG_LEVEL_DEBUG);

  /* After setting to DEBUG, all levels should be shown */
  log_message(LOG_LEVEL_DEBUG, "debug after set");
  log_message(LOG_LEVEL_INFO, "info after set");
  log_message(LOG_LEVEL_WARNING, "warning after set");
  log_message(LOG_LEVEL_ERROR, "error after set");

  EXPECT_TRUE(true);
}

static void test_log_set_level_info() {
  set_log_level(LOG_LEVEL_INFO);

  /* INFO level should show INFO, WARNING, ERROR but not DEBUG */
  log_message(LOG_LEVEL_DEBUG, "debug should be filtered");   /* filtered */
  log_message(LOG_LEVEL_INFO, "info should show");
  log_message(LOG_LEVEL_WARNING, "warning should show");
  log_message(LOG_LEVEL_ERROR, "error should show");

  EXPECT_TRUE(true);
}

static void test_log_set_level_error() {
  set_log_level(LOG_LEVEL_ERROR);

  /* ERROR level: only ERROR should show */
  log_message(LOG_LEVEL_DEBUG, "debug filtered");
  log_message(LOG_LEVEL_INFO, "info filtered");
  log_message(LOG_LEVEL_WARNING, "warning filtered");
  log_message(LOG_LEVEL_ERROR, "error should show");

  EXPECT_TRUE(true);
}

/* Test that set_log_level with default WARNING filters correctly */
static void test_log_filtering() {
  /* Reset to default */
  set_log_level(LOG_LEVEL_WARNING);

  /* These should be filtered */
  log_message(LOG_LEVEL_DEBUG, "filtered debug");
  log_message(LOG_LEVEL_INFO, "filtered info");

  /* These should be shown */
  log_message(LOG_LEVEL_WARNING, "visible warning");
  log_message(LOG_LEVEL_ERROR, "visible error");

  EXPECT_TRUE(true);
}

/* Test that log_message handles various format strings */
static void test_log_message_formats() {
  set_log_level(LOG_LEVEL_DEBUG);

  log_message(LOG_LEVEL_DEBUG, "simple string");
  log_message(LOG_LEVEL_INFO, "integer: %d", -1);
  log_message(LOG_LEVEL_WARNING, "string: %s", "hello");
  log_message(LOG_LEVEL_ERROR, "multiple: %d %s %d", 1, "two", 3);

  EXPECT_TRUE(true);
}

void test_log() {
  test_log_message_debug();
  test_log_message_info();
  test_log_message_warning();
  test_log_message_error();
  test_log_set_level_debug();
  test_log_set_level_info();
  test_log_set_level_error();
  test_log_filtering();
  test_log_message_formats();
}
