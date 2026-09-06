#include "change_list.h"
#include "utils.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* Itemize code emitted for a transferred regular file.
 *
 * Layout (rsync-compatible 11-char item): `>f` marks a regular file that was
 * transferred to the remote host; the trailing nine markers are, in order,
 * c(hecksum) s(ize) t(ime) p(erms) o(wner) g(roup) u(ser/acl) a(ttrs) x(attrs).
 * Every marker is `+` (FastSync does not compare each attribute on the
 * receiving side, so a sent file is reported as fully updated).  Files that
 * are already up to date print no line at all, matching rsync's single -i
 * which only itemizes changes.
 *
 * Because the scanner only yields regular-file transfer candidates, `>d`
 * (directory) lines are never produced; directories are not transferred as
 * items by FastSync. */
#define ITEMIZE_SENT_FILE ">f+++++++++"

typedef struct {
  char* data;
  size_t length;
  size_t capacity;
} StrBuf;

static void strbuf_free(StrBuf* buf) {
  if (buf == NULL)
    return;
  free(buf->data);
  buf->data = NULL;
  buf->length = 0;
  buf->capacity = 0;
}

static bool strbuf_reserve(StrBuf* buf, size_t extra) {
  if (buf->length > SIZE_MAX - extra - 1)
    return false;
  size_t need = buf->length + extra + 1;
  if (need <= buf->capacity)
    return true;
  size_t capacity = buf->capacity > 0 ? buf->capacity : 32;
  while (capacity < need) {
    if (capacity > SIZE_MAX / 2) {
      capacity = need;
      break;
    }
    capacity *= 2;
  }
  char* grown = realloc(buf->data, capacity);
  if (!grown)
    return false;
  buf->data = grown;
  buf->capacity = capacity;
  return true;
}

static bool strbuf_append_char(StrBuf* buf, char c) {
  if (!strbuf_reserve(buf, 1))
    return false;
  buf->data[buf->length++] = c;
  buf->data[buf->length] = '\0';
  return true;
}

static bool strbuf_append(StrBuf* buf, const char* text) {
  if (text == NULL)
    return true;
  size_t length = strlen(text);
  if (!strbuf_reserve(buf, length))
    return false;
  memcpy(buf->data + buf->length, text, length);
  buf->length += length;
  buf->data[buf->length] = '\0';
  return true;
}

static bool strbuf_append_ull(StrBuf* buf, unsigned long long value) {
  char digits[32];
  int written = snprintf(digits, sizeof(digits), "%llu", value);
  if (written < 0 || (size_t)written >= sizeof(digits))
    return false;
  return strbuf_append(buf, digits);
}

static bool strbuf_append_longlong(StrBuf* buf, long long value) {
  char digits[32];
  int written = snprintf(digits, sizeof(digits), "%lld", value);
  if (written < 0 || (size_t)written >= sizeof(digits))
    return false;
  return strbuf_append(buf, digits);
}

bool change_list_enabled(const Config* config) {
  return config != NULL && (config->itemize_changes || config->out_format != NULL ||
                            (config->log_file != NULL && config->log_file_format != NULL));
}

char* change_render_itemize(const ChangeEvent* event) {
  if (event == NULL || event->decision != CHANGE_SENT)
    return str_dup("");
  const char* code = event->is_directory ? ">d+++++++++" : ITEMIZE_SENT_FILE;
  StrBuf line = {0};
  bool ok = strbuf_append(&line, code) && strbuf_append(&line, " ") &&
            strbuf_append(&line, event->path != NULL ? event->path : "");
  if (!ok) {
    strbuf_free(&line);
    return NULL;
  }
  return line.data;
}

static const char* leaf_name(const char* path) {
  if (path == NULL)
    return "";
  const char* slash = strrchr(path, '/');
  return slash != NULL && slash[1] != '\0' ? slash + 1 : path;
}

char* change_render_format(const char* format, const ChangeEvent* event) {
  if (format == NULL)
    return NULL;
  StrBuf line = {0};
  bool ok = true;
  for (const char* p = format; *p != '\0' && ok;) {
    if (*p != '%') {
      ok = strbuf_append_char(&line, *p);
      p++;
      continue;
    }
    char token = p[1];
    if (token == '\0') {
      ok = strbuf_append_char(&line, '%');
      break;
    }
    switch (token) {
    case '%':
      ok = strbuf_append_char(&line, '%');
      break;
    case 'f':
      ok = strbuf_append(&line, event->path != NULL ? event->path : "");
      break;
    case 'n':
      ok = strbuf_append(&line, leaf_name(event->path));
      break;
    case 'l':
      ok = strbuf_append_ull(&line, event->size);
      break;
    case 'b':
      ok = strbuf_append_ull(&line, event->bytes_sent);
      break;
    case 'M':
      ok = strbuf_append_longlong(&line, (long long)event->mtime_sec);
      break;
    default:
      /* Unknown escape sequences are preserved verbatim. */
      ok = strbuf_append_char(&line, '%') && strbuf_append_char(&line, token);
      break;
    }
    p += 2;
  }
  if (!ok) {
    strbuf_free(&line);
    return NULL;
  }
  if (line.data == NULL) {
    line.data = str_dup("");
    if (!line.data)
      return NULL;
  }
  return line.data;
}

/* Format a mode as an `ls -l` permission string, e.g. `-rw-r--r--`. */
static void mode_to_ls_string(mode_t mode, char out[11]) {
  out[0] = S_ISDIR(mode)    ? 'd'
           : S_ISLNK(mode)  ? 'l'
           : S_ISCHR(mode)  ? 'c'
           : S_ISBLK(mode)  ? 'b'
           : S_ISFIFO(mode) ? 'p'
           : S_ISSOCK(mode) ? 's'
                            : '-';
  mode_t bits = mode & 07777;
  out[1] = (bits & S_IRUSR) ? 'r' : '-';
  out[2] = (bits & S_IWUSR) ? 'w' : '-';
  out[3] = (bits & S_IXUSR) ? (bits & S_ISUID ? 's' : 'x') : (bits & S_ISUID ? 'S' : '-');
  out[4] = (bits & S_IRGRP) ? 'r' : '-';
  out[5] = (bits & S_IWGRP) ? 'w' : '-';
  out[6] = (bits & S_IXGRP) ? (bits & S_ISGID ? 's' : 'x') : (bits & S_ISGID ? 'S' : '-');
  out[7] = (bits & S_IROTH) ? 'r' : '-';
  out[8] = (bits & S_IWOTH) ? 'w' : '-';
  out[9] = (bits & S_IXOTH) ? (bits & S_ISVTX ? 't' : 'x') : (bits & S_ISVTX ? 'T' : '-');
  out[10] = '\0';
}

char* change_render_list_line(mode_t mode, unsigned long long size, time_t mtime,
                              const char* path) {
  char permission[11];
  mode_to_ls_string(mode, permission);
  char date[32];
  struct tm broken_down;
  if (localtime_r(&mtime, &broken_down) != NULL) {
    if (strftime(date, sizeof(date), "%Y/%m/%d %H:%M:%S", &broken_down) == 0)
      snprintf(date, sizeof(date), "?");
  } else {
    snprintf(date, sizeof(date), "?");
  }
  StrBuf line = {0};
  char size_field[32];
  int written = snprintf(size_field, sizeof(size_field), "%llu", size);
  if (written < 0 || (size_t)written >= sizeof(size_field)) {
    strbuf_free(&line);
    return NULL;
  }
  bool ok = strbuf_append(&line, permission) && strbuf_append_char(&line, ' ') &&
            strbuf_append(&line, size_field) && strbuf_append_char(&line, ' ') &&
            strbuf_append(&line, date) && strbuf_append_char(&line, ' ') &&
            strbuf_append(&line, path != NULL ? path : "");
  if (!ok) {
    strbuf_free(&line);
    return NULL;
  }
  return line.data;
}

static void print_escaped_line(FILE* stream, const char* line, bool eight_bit_output) {
  char* escaped = output_escape(line, eight_bit_output);
  if (escaped != NULL) {
    fprintf(stream, "%s\n", escaped);
    free(escaped);
  } else {
    fprintf(stream, "%s\n", line);
  }
  fflush(stream);
}

void change_emit(const Config* config, const ChangeEvent* event) {
  if (event == NULL || !change_list_enabled(config))
    return;
  if (event->decision == CHANGE_UP_TO_DATE)
    return;
  bool to_stdout = config->itemize_changes || config->out_format != NULL;
  bool to_log = config->log_file != NULL && config->log_file_format != NULL;
  if (to_stdout) {
    char* line = config->out_format != NULL ? change_render_format(config->out_format, event)
                                            : change_render_itemize(event);
    if (line != NULL) {
      print_escaped_line(stdout, line, config->eight_bit_output);
      free(line);
    }
  }
  if (to_log) {
    char* line = change_render_format(config->log_file_format, event);
    if (line != NULL) {
      print_escaped_line(config->log_file, line, config->eight_bit_output);
      free(line);
    }
  }
}

static bool format_uses_mtime(const char* format) {
  if (format == NULL)
    return false;
  for (const char* p = format; *p != '\0'; p++) {
    if (p[0] == '%' && p[1] == 'M')
      return true;
  }
  return false;
}

void change_emit_file_sent(const Config* config, const File* file) {
  if (file == NULL || !change_list_enabled(config))
    return;
  ChangeEvent event;
  memset(&event, 0, sizeof(event));
  event.path = file->path;
  event.decision = CHANGE_SENT;
  event.is_directory = false;
  event.size = file->data != NULL ? file->data->size : 0;
  /* FastSync does not currently count post-compression/delta wire bytes, so
   * the reported value is the source length that had to be delivered. */
  event.bytes_sent = event.size;
  if (file->metadata != NULL) {
    event.mtime_sec = file->metadata->mtime_sec;
  } else if (format_uses_mtime(config->out_format) || format_uses_mtime(config->log_file_format)) {
    struct stat st;
    if (file->path != NULL && stat(file->path, &st) == 0)
      event.mtime_sec = st.st_mtime;
  }
  change_emit(config, &event);
}
