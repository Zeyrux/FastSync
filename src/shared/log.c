#include "log.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char* log_level_strings[] = {"DEBUG", "INFO", "WARN", "ERROR"};
static LogLevel current_log_level = LOG_LEVEL_WARNING;
static FILE* log_fp = NULL;
static _Thread_local bool eight_bit_output;

void set_log_level(LogLevel level) {
  current_log_level = level;
}

void log_set_file(FILE* fp) {
  log_fp = fp;
}

void log_set_8_bit_output(bool enabled) {
  eight_bit_output = enabled;
}

bool log_get_8_bit_output(void) {
  return eight_bit_output;
}

static inline void write_message(FILE* dest_io, LogLevel log_level, struct tm t, const char* format,
                                 va_list args) {
  fprintf(dest_io, "%04d-%02d-%02d %02d:%02d:%02d [%s]: ", t.tm_year + 1900, t.tm_mon + 1,
          t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, log_level_strings[log_level]);

  vfprintf(dest_io, format, args);
  fprintf(dest_io, "\n");
}

void log_message(LogLevel log_level, const char* format, ...) {
  if (log_level < current_log_level)
    return;
  if (log_level < 0 || log_level >= (int)(sizeof(log_level_strings) / sizeof(log_level_strings[0])))
    return;
  time_t now = time(NULL);
  struct tm t;
  if (!localtime_r(&now, &t))
    return;

  FILE* dest_io = stdout;
  if (log_level == LOG_LEVEL_ERROR) {
    dest_io = stderr;
  }

  va_list args;
  va_start(args, format);
  write_message(dest_io, log_level, t, format, args);
  va_end(args);

  if (log_fp) {
    va_start(args, format);
    write_message(log_fp, log_level, t, format, args);
    va_end(args);
  }
}

void log_perror(const char* context) {
  log_message(LOG_LEVEL_ERROR, "%s: %s", context, strerror(errno));
}
