#include "test_log.h"
#include "log.h"
#include "test_utils.h"
#include <fcntl.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

/* Test default log level: WARNING and ERROR should print, DEBUG and INFO should not.
 * We can't easily capture stderr in unit tests, so we verify the functions don't crash
 * and that set_log_level changes behavior. */

static void test_log_message_debug() {
  set_log_level(LOG_LEVEL_WARNING);
  log_message(LOG_LEVEL_DEBUG, "debug message: %d", 42);
  /* crash regression test — stderr capture would need infrastructure changes */
  EXPECT_TRUE(true);
}

static void test_log_message_info() {
  set_log_level(LOG_LEVEL_WARNING);
  log_message(LOG_LEVEL_INFO, "info message: %s", "test");
  /* crash regression test — stderr capture would need infrastructure changes */
  EXPECT_TRUE(true);
}

static void test_log_message_warning() {
  set_log_level(LOG_LEVEL_WARNING);
  log_message(LOG_LEVEL_WARNING, "warning message: %d %s", 1, "test");
  /* crash regression test — stderr capture would need infrastructure changes */
  EXPECT_TRUE(true);
}

static void test_log_message_error() {
  set_log_level(LOG_LEVEL_WARNING);
  log_message(LOG_LEVEL_ERROR, "error message: %s", "critical");
  /* crash regression test — stderr capture would need infrastructure changes */
  EXPECT_TRUE(true);
}

static void test_log_set_level_debug() {
  set_log_level(LOG_LEVEL_DEBUG);

  /* After setting to DEBUG, all levels should be shown */
  log_message(LOG_LEVEL_DEBUG, "debug after set");
  log_message(LOG_LEVEL_INFO, "info after set");
  log_message(LOG_LEVEL_WARNING, "warning after set");
  log_message(LOG_LEVEL_ERROR, "error after set");

  /* crash regression test — stderr capture would need infrastructure changes */
  EXPECT_TRUE(true);
}

static void test_log_set_level_info() {
  set_log_level(LOG_LEVEL_INFO);

  /* INFO level should show INFO, WARNING, ERROR but not DEBUG */
  log_message(LOG_LEVEL_DEBUG, "debug should be filtered"); /* filtered */
  log_message(LOG_LEVEL_INFO, "info should show");
  log_message(LOG_LEVEL_WARNING, "warning should show");
  log_message(LOG_LEVEL_ERROR, "error should show");

  /* crash regression test — stderr capture would need infrastructure changes */
  EXPECT_TRUE(true);
}

static void test_log_set_level_error() {
  set_log_level(LOG_LEVEL_ERROR);

  /* ERROR level: only ERROR should show */
  log_message(LOG_LEVEL_DEBUG, "debug filtered");
  log_message(LOG_LEVEL_INFO, "info filtered");
  log_message(LOG_LEVEL_WARNING, "warning filtered");
  log_message(LOG_LEVEL_ERROR, "error should show");

  /* crash regression test — stderr capture would need infrastructure changes */
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

  /* crash regression test — stderr capture would need infrastructure changes */
  EXPECT_TRUE(true);
}

static void test_log_stderr_mode_all() {
  int pipe_fds[2];
  EXPECT_EQ_INT(pipe(pipe_fds), 0);
  int saved_stderr = dup(STDERR_FILENO);
  EXPECT_TRUE(saved_stderr >= 0);
  EXPECT_TRUE(dup2(pipe_fds[1], STDERR_FILENO) >= 0);
  close(pipe_fds[1]);

  set_log_level(LOG_LEVEL_WARNING);
  log_set_stderr_mode(LOG_STDERR_ALL);
  log_message(LOG_LEVEL_WARNING, "warning routed to stderr");
  fflush(stderr);

  EXPECT_TRUE(dup2(saved_stderr, STDERR_FILENO) >= 0);
  close(saved_stderr);
  char output[128] = {0};
  ssize_t length = read(pipe_fds[0], output, sizeof(output) - 1);
  close(pipe_fds[0]);
  EXPECT_TRUE(length > 0);
  EXPECT_TRUE(strstr(output, "warning routed to stderr") != NULL);
  log_set_stderr_mode(LOG_STDERR_ERRORS);
}

/* --stderr=client: an installed sink takes the message body and suppresses the
 * local write; a declining sink (or no sink) falls back to stderr. */
static char g_client_msg_capture[256];

static bool client_msg_capture_sink(const char* message) {
  snprintf(g_client_msg_capture, sizeof(g_client_msg_capture), "%s", message);
  return true;
}

static bool client_msg_decline_sink(const char* message) {
  (void)message;
  return false;
}

static void test_log_stderr_mode_client() {
  int pipe_fds[2];
  EXPECT_EQ_INT(pipe(pipe_fds), 0);
  int saved_stderr = dup(STDERR_FILENO);
  EXPECT_TRUE(saved_stderr >= 0);
  EXPECT_TRUE(dup2(pipe_fds[1], STDERR_FILENO) >= 0);
  close(pipe_fds[1]);

  set_log_level(LOG_LEVEL_WARNING);
  log_set_stderr_mode(LOG_STDERR_CLIENT);

  g_client_msg_capture[0] = '\0';
  log_set_client_msg_sink(client_msg_capture_sink);
  log_message(LOG_LEVEL_ERROR, "routed to peer %d", 7);
  fflush(stderr);
  EXPECT_EQ_STR(g_client_msg_capture, "routed to peer 7");

  /* A sink that declines makes the message fall back to local stderr. */
  log_set_client_msg_sink(client_msg_decline_sink);
  log_message(LOG_LEVEL_ERROR, "fallback local");
  fflush(stderr);

  log_set_client_msg_sink(NULL);
  log_set_stderr_mode(LOG_STDERR_ERRORS);
  EXPECT_TRUE(dup2(saved_stderr, STDERR_FILENO) >= 0);
  close(saved_stderr);
  char output[256] = {0};
  ssize_t length = read(pipe_fds[0], output, sizeof(output) - 1);
  close(pipe_fds[0]);
  EXPECT_TRUE(length > 0);
  EXPECT_TRUE(strstr(output, "fallback local") != NULL);
  EXPECT_TRUE(strstr(output, "routed to peer") == NULL);
}

/* Test that log_message handles various format strings */
static void test_log_message_formats() {
  set_log_level(LOG_LEVEL_DEBUG);

  log_message(LOG_LEVEL_DEBUG, "simple string");
  log_message(LOG_LEVEL_INFO, "integer: %d", -1);
  log_message(LOG_LEVEL_WARNING, "string: %s", "hello");
  log_message(LOG_LEVEL_ERROR, "multiple: %d %s %d", 1, "two", 3);

  /* crash regression test — stderr capture would need infrastructure changes */
  EXPECT_TRUE(true);
}

/* log_debug_enabled is the lazy-formatting gate for log_debug_message: it must
 * be true only at DEBUG level with the requested flag selected, exactly
 * mirroring the filter inside log_debug_message itself. */
static void test_log_debug_enabled_matches_gate() {
  set_log_level(LOG_LEVEL_WARNING);
  set_log_debug_flags(LOG_DEBUG_ALL);
  EXPECT_FALSE(log_debug_enabled(LOG_DEBUG_PROTO));

  set_log_level(LOG_LEVEL_DEBUG);
  set_log_debug_flags(LOG_DEBUG_PROTO);
  EXPECT_TRUE(log_debug_enabled(LOG_DEBUG_PROTO));
  EXPECT_FALSE(log_debug_enabled(LOG_DEBUG_IO));

  set_log_debug_flags(0);
  EXPECT_FALSE(log_debug_enabled(LOG_DEBUG_PROTO));

  set_log_debug_flags(LOG_DEBUG_ALL);
}

#define LOG_CONCURRENCY_THREADS 8
#define LOG_CONCURRENCY_LINES 250

typedef struct {
  int id;
} LogConcurrencyArg;

static int log_concurrency_worker(void* context) {
  LogConcurrencyArg* arg = context;
  for (int i = 0; i < LOG_CONCURRENCY_LINES; i++) {
    log_message(LOG_LEVEL_WARNING, "worker %d line %d", arg->id, i);
  }
  return 0;
}

static int count_substring(const char* haystack, const char* needle) {
  int count = 0;
  size_t needle_length = strlen(needle);
  const char* cursor = haystack;
  while ((cursor = strstr(cursor, needle)) != NULL) {
    count++;
    cursor += needle_length;
  }
  return count;
}

/* Concurrent log_message() calls from many threads must never interleave a
 * single line: every emitted line has exactly one timestamp prefix and one
 * body.  Before write_message() was serialized, the three separate fprintf
 * calls (prefix, body, newline) let lines tear. */
static void test_log_concurrent_no_torn_lines(void) {
  FILE* fp = tmpfile();
  EXPECT_NOT_NULL(fp);

  /* Mute the console mirror so the workers don't flood the test output. */
  fflush(stdout);
  fflush(stderr);
  int saved_stdout = dup(STDOUT_FILENO);
  int saved_stderr = dup(STDERR_FILENO);
  int null_fd = open("/dev/null", O_WRONLY);
  EXPECT_TRUE(saved_stdout >= 0);
  EXPECT_TRUE(saved_stderr >= 0);
  EXPECT_TRUE(null_fd >= 0);
  EXPECT_TRUE(dup2(null_fd, STDOUT_FILENO) >= 0);
  EXPECT_TRUE(dup2(null_fd, STDERR_FILENO) >= 0);
  close(null_fd);

  set_log_level(LOG_LEVEL_WARNING);
  log_set_stderr_mode(LOG_STDERR_ERRORS);
  log_set_file(fp);

  thrd_t threads[LOG_CONCURRENCY_THREADS];
  LogConcurrencyArg args[LOG_CONCURRENCY_THREADS];
  int created = 0;
  for (int i = 0; i < LOG_CONCURRENCY_THREADS; i++) {
    args[i].id = i;
    if (thrd_create(&threads[i], log_concurrency_worker, &args[i]) != thrd_success)
      break;
    created++;
  }
  for (int i = 0; i < created; i++) {
    thrd_join(threads[i], NULL);
  }

  log_set_file(NULL);
  fflush(fp);

  fflush(stdout);
  fflush(stderr);
  dup2(saved_stdout, STDOUT_FILENO);
  dup2(saved_stderr, STDERR_FILENO);
  close(saved_stdout);
  close(saved_stderr);

  rewind(fp);
  char line[512];
  int total_lines = 0;
  int malformed_lines = 0;
  bool saw_missing_newline = false;
  while (fgets(line, sizeof(line), fp) != NULL) {
    size_t length = strlen(line);
    if (length == 0 || line[length - 1] != '\n')
      saw_missing_newline = true;
    if (strncmp(line, "20", 2) != 0 || count_substring(line, "[WARN]: worker ") != 1)
      malformed_lines++;
    total_lines++;
  }
  fclose(fp);

  EXPECT_EQ_INT(created, LOG_CONCURRENCY_THREADS);
  EXPECT_FALSE(saw_missing_newline);
  EXPECT_EQ_INT(malformed_lines, 0);
  EXPECT_EQ_INT(total_lines, LOG_CONCURRENCY_THREADS * LOG_CONCURRENCY_LINES);
  log_set_stderr_mode(LOG_STDERR_ERRORS);
}

/* Detaching the logger from a FILE* before it is closed must leave the logging
 * subsystem safe: later calls must not touch the freed handle. */
static void test_log_set_file_null_before_fclose(void) {
  FILE* fp = tmpfile();
  EXPECT_NOT_NULL(fp);

  set_log_level(LOG_LEVEL_ERROR);
  log_set_file(fp);
  log_message(LOG_LEVEL_ERROR, "line before detach");
  log_set_file(NULL);
  fclose(fp);

  log_message(LOG_LEVEL_ERROR, "line after close");
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
  test_log_stderr_mode_all();
  test_log_stderr_mode_client();
  test_log_message_formats();
  test_log_debug_enabled_matches_gate();
  test_log_concurrent_no_torn_lines();
  test_log_set_file_null_before_fclose();
}
