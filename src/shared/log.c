#include "log.h"
#include "utils.h"
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>

static const char* log_level_strings[] = {"DEBUG", "INFO", "WARN", "ERROR"};
static LogLevel current_log_level = LOG_LEVEL_WARNING;
static uint32_t current_debug_flags = 0;
static uint32_t info_flags = 0;
static bool info_flags_explicit = false;
static FILE* log_fp = NULL;
static _Thread_local bool eight_bit_output;
static LogStderrMode stderr_mode = LOG_STDERR_ERRORS;
static LogClientMsgSink client_msg_sink = NULL;

/* Serializes access to log_fp and makes each emitted line atomic: the
 * timestamp prefix, formatted body, and trailing newline are written as one
 * critical section so concurrent threads cannot interleave partial lines.
 * Initialized lazily (matching the protocol.c bw_mutex idiom) because logging
 * can happen before main() installs any synchronization. */
static mtx_t log_mutex;
static once_flag log_mutex_once = ONCE_FLAG_INIT;

static void log_mutex_init(void) {
  mtx_init(&log_mutex, mtx_plain);
}

void set_log_level(LogLevel level) {
  current_log_level = level;
}

void set_log_debug_flags(uint32_t flags) {
  current_debug_flags = flags;
}

uint32_t get_log_debug_flags(void) {
  return current_debug_flags;
}

bool log_debug_enabled(LogDebugFlag flag) {
  return current_log_level <= LOG_LEVEL_DEBUG && (current_debug_flags & flag) != 0;
}

void set_log_info_flags(uint32_t flags) {
  info_flags = flags;
  info_flags_explicit = true;
}

uint32_t get_log_info_flags(void) {
  return info_flags;
}

void log_set_file(FILE* fp) {
  call_once(&log_mutex_once, log_mutex_init);
  mtx_lock(&log_mutex);
  log_fp = fp;
  mtx_unlock(&log_mutex);
}

void log_set_8_bit_output(bool enabled) {
  eight_bit_output = enabled;
}

bool log_get_8_bit_output(void) {
  return eight_bit_output;
}

void log_set_stderr_mode(LogStderrMode mode) {
  stderr_mode = mode;
}

LogStderrMode log_get_stderr_mode(void) {
  return stderr_mode;
}

void log_set_client_msg_sink(LogClientMsgSink sink) {
  client_msg_sink = sink;
}

LogClientMsgSink log_get_client_msg_sink(void) {
  return client_msg_sink;
}

/* Format just the message body (no prefix/newline) into a freshly allocated
 * buffer.  Shared by log_message (which may hand the body to a client-message
 * sink) and log_client_message.  Returns NULL on allocation/format failure. */
static char* format_log_body(const char* format, va_list args) {
  va_list copy;
  va_copy(copy, args);
  int body_len = vsnprintf(NULL, 0, format, copy);
  va_end(copy);
  if (body_len < 0)
    return NULL;
  char* body = malloc((size_t)body_len + 1);
  if (!body)
    return NULL;
  vsnprintf(body, (size_t)body_len + 1, format, args);
  return body;
}

/* Assemble a complete log line (prefix + body + newline) from an already
 * formatted body.  Returns NULL on allocation failure. */
static char* format_log_line_from_body(LogLevel log_level, const struct tm* t, const char* body) {
  char prefix[64];
  int prefix_len = snprintf(
      prefix, sizeof(prefix), "%04d-%02d-%02d %02d:%02d:%02d [%s]: ", t->tm_year + 1900,
      t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, log_level_strings[log_level]);
  if (prefix_len < 0 || prefix_len >= (int)sizeof(prefix))
    return NULL;
  size_t body_len = strlen(body);
  char* line = malloc((size_t)prefix_len + body_len + 2); /* body + '\n' + NUL */
  if (!line)
    return NULL;
  memcpy(line, prefix, (size_t)prefix_len);
  memcpy(line + prefix_len, body, body_len);
  line[(size_t)prefix_len + body_len] = '\n';
  line[(size_t)prefix_len + body_len + 1] = '\0';
  return line;
}

/* Format one complete log line (timestamp prefix + body + newline) into a
 * freshly allocated buffer.  This is pure CPU/malloc work and must happen
 * OUTSIDE the log mutex: the mutex only guards the log_fp pointer, so a
 * stalled stderr/stdout pipe cannot block every logging thread.  Returns NULL
 * on allocation/formatting failure. */
static char* format_log_line(LogLevel log_level, const struct tm* t, const char* format,
                             va_list args) {
  char* body = format_log_body(format, args);
  if (!body)
    return NULL;
  char* line = format_log_line_from_body(log_level, t, body);
  free(body);
  return line;
}

/* Write an already-formatted line to the console and, if configured, the log
 * file.  Only the log_fp pointer is read under the mutex (so log_set_file /
 * config_delete cannot free it while it is in use); the single console fputs
 * runs unlocked but is internally atomic per stdio stream. */
static void emit_log_line(FILE* console, const char* line) {
  fputs(line, console);
  call_once(&log_mutex_once, log_mutex_init);
  mtx_lock(&log_mutex);
  FILE* file = log_fp;
  if (file)
    fputs(line, file);
  mtx_unlock(&log_mutex);
}

void log_client_message(const char* message) {
  if (!message)
    return;
  /* The body is peer-controlled: escape every non-printable byte (newlines,
     CR, ANSI ESC, ...) so a hostile client cannot forge log lines or inject
     terminal control sequences.  output_escape() is the codebase's canonical
     escaper and leaves printable text untouched. */
  char* escaped = output_escape(message, log_get_8_bit_output());
  if (!escaped)
    return;
  /* Route through the ordinary log level / destination gate (log_message):
     this respects --log-file, the configured stderr mode and the level
     threshold instead of always writing to stderr.  The wire body carries no
     severity, so the forwarded diagnostic is emitted as a warning -- the
     lowest level the default gate admits, which keeps the peer's messages
     visible without bypassing --quiet. */
  log_message(LOG_LEVEL_WARNING, "%s", escaped);
  free(escaped);
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
  if (stderr_mode == LOG_STDERR_ALL || log_level == LOG_LEVEL_ERROR) {
    dest_io = stderr;
  }

  va_list args;
  va_start(args, format);
  char* body = format_log_body(format, args);
  va_end(args);
  if (!body)
    return;
  /* LOG_STDERR_CLIENT: hand the diagnostic to the client-message channel.  A
     sink that takes ownership suppresses the local write; otherwise (no sink
     yet, or the peer connection is not up) fall through to local output so the
     diagnostic is never lost. */
  if (stderr_mode == LOG_STDERR_CLIENT) {
    LogClientMsgSink sink = client_msg_sink;
    if (sink && sink(body)) {
      free(body);
      return;
    }
  }
  char* line = format_log_line_from_body(log_level, &t, body);
  free(body);
  if (!line)
    return;
  emit_log_line(dest_io, line);
  free(line);
}

void log_debug_message(LogDebugFlag flag, const char* format, ...) {
  if (current_log_level > LOG_LEVEL_DEBUG || !(current_debug_flags & flag))
    return;

  time_t now = time(NULL);
  struct tm t;
  if (!localtime_r(&now, &t))
    return;

  va_list args;
  va_start(args, format);
  char* line = format_log_line(LOG_LEVEL_DEBUG, &t, format, args);
  va_end(args);
  if (!line)
    return;
  emit_log_line(stdout, line);
  free(line);
}

void log_info_message(LogInfoFlag flag, const char* format, ...) {
  if ((info_flags_explicit && (info_flags & flag) == 0) ||
      (!info_flags_explicit && current_log_level > LOG_LEVEL_DEBUG))
    return;

  time_t now = time(NULL);
  struct tm t;
  if (!localtime_r(&now, &t))
    return;

  va_list args;
  va_start(args, format);
  char* line = format_log_line(LOG_LEVEL_INFO, &t, format, args);
  va_end(args);
  if (!line)
    return;
  emit_log_line(stdout, line);
  free(line);
}

void log_perror(const char* context) {
  log_message(LOG_LEVEL_ERROR, "%s: %s", context, strerror(errno));
}
