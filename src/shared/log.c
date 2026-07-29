#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static const char* log_level_strings[] = {"DEBUG", "INFO", "WARN", "ERROR"};
static LogLevel current_log_level = LOG_LEVEL_WARNING;

void set_log_level(LogLevel level) {
  current_log_level = level;
}

void log_message(LogLevel log_level, const char* format, ...) {
  if (log_level < current_log_level)
    return;
  time_t now = time(NULL);
  struct tm result_buf;
  const struct tm* t = localtime_r(&now, &result_buf);
  if (t == NULL)
    return;

  fprintf(stderr, "%04d-%02d-%02d %02d:%02d:%02d [%s]: ", t->tm_year + 1900, t->tm_mon + 1,
          t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, log_level_strings[log_level]);

  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
}
