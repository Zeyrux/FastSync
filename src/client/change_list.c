#include "change_list.h"
#include "checksum.h"
#include "log.h"
#include "utils.h"
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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

bool change_list_enabled(const Config* config) {
  return config != NULL && (config->itemize_changes || config->out_format != NULL ||
                            (config->log_file != NULL && config->log_file_format != NULL) ||
                            (config->info_level & LOG_INFO_NAME) != 0);
}

/* ---- Itemize code ---- */

/* Format the permission bits as an `ls -l` string, e.g. `-rw-r--r--`. */
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

static char itemize_type_char(const ChangeEvent* event) {
  if (event->is_directory)
    return 'd';
  if (event->is_symlink)
    return 'L';
  if (event->is_special) {
    if (S_ISCHR(event->mode) || S_ISBLK(event->mode))
      return 'D';
    return 'S';
  }
  return 'f';
}

static bool times_match(const Config* config, const ChangeEvent* event) {
  if (!event->dest.known || !event->dest.existed)
    return false;
  if (event->mtime_sec == event->dest.mtime_sec)
    return event->mtime_nsec == event->dest.mtime_nsec;
  long long delta = (long long)event->mtime_sec - (long long)event->dest.mtime_sec;
  if (delta < 0)
    delta = -delta;
  return delta <= (long long)config->modify_window;
}

/* Fill the 11-character itemize code (10 chars + NUL).  `created` means the
 * destination entry did not exist, so every attribute marker is `+`. */
static void itemize_code(const Config* config, const ChangeEvent* event, char code[12]) {
  bool known = event->dest.known;
  bool created = !known || !event->dest.existed;
  char update;
  if (event->is_hardlink)
    update = 'h';
  else if (created)
    update = (event->is_directory || event->is_symlink || event->is_special) ? 'c' : '>';
  else
    update = '>';
  code[0] = update;
  code[1] = itemize_type_char(event);
  if (created) {
    for (int i = 0; i < 9; i++)
      code[2 + i] = '+';
    code[11] = '\0';
    return;
  }
  bool size_diff = event->size != event->dest.size;
  bool time_diff = !times_match(config, event);
  bool perms_diff = (event->mode & 07777) != (event->dest.mode & 07777);
  bool owner_diff = event->uid != (uid_t)event->dest.uid;
  bool group_diff = event->gid != (gid_t)event->dest.gid;
  code[2] = '.'; /* checksum: no destination digest available */
  code[3] = size_diff ? 's' : '.';
  code[4] = time_diff ? 't' : '.';
  code[5] = (config->preserve_perms && perms_diff) ? 'p' : '.';
  code[6] = (config->preserve_owner && owner_diff) ? 'o' : '.';
  code[7] = (config->preserve_group && group_diff) ? 'g' : '.';
  code[8] = '.'; /* reserved */
  code[9] = '.'; /* acl: not compared */
  code[10] = '.';
  code[11] = '\0';
}

/* rsync %n: the transfer-relative name, with a trailing slash for directories. */
static bool append_name(StrBuf* buf, const ChangeEvent* event) {
  if (!strbuf_append(buf, event->name != NULL ? event->name : ""))
    return false;
  if (event->is_directory && (event->name == NULL || event->name[0] == '\0' ||
                              event->name[strlen(event->name) - 1] != '/'))
    return strbuf_append_char(buf, '/');
  return true;
}

/* rsync %L: " -> target" for a symlink, " => target" for a hard link, else "". */
static bool append_link_suffix(StrBuf* buf, const ChangeEvent* event) {
  if (event->is_symlink && event->symlink_target != NULL)
    return strbuf_append(buf, " -> ") && strbuf_append(buf, event->symlink_target);
  if (event->is_hardlink && event->hardlink_target != NULL)
    return strbuf_append(buf, " => ") && strbuf_append(buf, event->hardlink_target);
  return true;
}

char* change_render_itemize(const Config* config, const ChangeEvent* event) {
  if (event == NULL || event->decision != CHANGE_SENT)
    return str_dup("");
  char code[12];
  itemize_code(config, event, code);
  StrBuf line = {0};
  bool ok = strbuf_append(&line, code) && strbuf_append_char(&line, ' ') &&
            append_name(&line, event) && append_link_suffix(&line, event);
  if (!ok) {
    strbuf_free(&line);
    return NULL;
  }
  return line.data;
}

/* rsync's `--info=name` line for an updated entry: the transfer-relative name
 * (trailing slash for directories) plus the ` -> target` / ` => target` link
 * suffix.  `--info=name` does not alter an itemize/out-format run. */
static char* change_render_name(const ChangeEvent* event) {
  StrBuf line = {0};
  bool ok = append_name(&line, event) && append_link_suffix(&line, event);
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

/* ---- --out-format / --log-file-format ---- */

/* rsync 3.4.1's `%C` uses the negotiated TRANSFER checksum (the first name of a
 * two-name "transfer,pre-transfer" --checksum-choice), not the pre-transfer
 * whole-file digest FastSync compares against on the wire.  The default "auto"
 * resolves to xxh128, so an explicit selection and the default both render the
 * selected algorithm's digest. */
static ChecksumAlgo out_format_checksum_algo(const Config* config) {
  return (ChecksumAlgo)config->checksum_transfer_algo;
}

/* Render a digest as rsync's sum_as_hex: xxh128 prints the HIGH 64-bit half
 * before the low half, and xxh64/xxh3 print their 64-bit value big-endian; every
 * other algorithm prints its bytes in order. */
static void digest_to_hex(ChecksumAlgo algo, const uint8_t* digest, size_t len, char* out) {
  if (algo == CHECKSUM_ALGO_XXH128 && len == 16) {
    uint64_t low = 0;
    uint64_t high = 0;
    memcpy(&low, digest, sizeof(low));
    memcpy(&high, digest + 8, sizeof(high));
    snprintf(out, len * 2 + 1, "%016llx%016llx", (unsigned long long)high, (unsigned long long)low);
    return;
  }
  if ((algo == CHECKSUM_ALGO_XXH64 || algo == CHECKSUM_ALGO_XXH3) && len == 8) {
    uint64_t value = 0;
    memcpy(&value, digest, sizeof(value));
    snprintf(out, len * 2 + 1, "%016llx", (unsigned long long)value);
    return;
  }
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = hex[(digest[i] >> 4) & 0xf];
    out[i * 2 + 1] = hex[digest[i] & 0xf];
  }
  out[len * 2] = '\0';
}

static bool format_uses_checksum(const char* format) {
  if (format == NULL)
    return false;
  for (const char* p = format; *p != '\0';) {
    if (*p != '%') {
      p++;
      continue;
    }
    char token = p[1];
    if (token == '\0')
      break;
    if (token == 'C')
      return true;
    p += 2;
  }
  return false;
}

/* Fill event->checksum/checksum_known for a transferred regular file.  A
 * non-regular entry (or a hard-link sibling) leaves checksum_known false, which
 * renders as spaces like rsync. */
static void fill_event_checksum(const Config* config, const File* file, ChangeEvent* event) {
  if (file == NULL || file->is_dir || file->is_symlink || file->is_special ||
      (file->link_group != 0 && !file->link_first))
    return;
  if (!format_uses_checksum(config->out_format) && !format_uses_checksum(config->log_file_format))
    return;
  if (file->path == NULL)
    return;
  ChecksumAlgo algo = out_format_checksum_algo(config);
  /* rsync renders `--checksum-choice=none` as a blank 2-character column. */
  if (algo == CHECKSUM_ALGO_NONE)
    return;
  uint8_t digest[CHECKSUM_MAX_DIGEST_LEN];
  size_t len = 0;
  /* rsync's %C is the transfer checksum, which is always seeded with 0 (it is
   * independent of --checksum-seed, as rsync 3.4.1 demonstrates). */
  if (!checksum_digest_file(algo, 0, file->path, digest, sizeof(digest), &len))
    return;
  digest_to_hex(algo, digest, len, event->checksum);
  event->checksum_known = true;
}

char* change_render_format(const char* format, const Config* config, const ChangeEvent* event) {
  if (format == NULL || event == NULL)
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
    case 'i': {
      if (event->deleted) {
        /* rsync's ITEM_DELETED itemize code: `*deleting  ` (11 chars). */
        ok = strbuf_append(&line, "*deleting  ");
        break;
      }
      char code[12];
      itemize_code(config, event, code);
      ok = strbuf_append(&line, code);
      break;
    }
    case 'f':
      ok = strbuf_append(&line, event->path != NULL ? event->path : "");
      break;
    case 'n':
      ok = append_name(&line, event);
      break;
    case 'L':
      ok = append_link_suffix(&line, event);
      break;
    case 'l': {
      char digits[32];
      int written = snprintf(digits, sizeof(digits), "%llu", event->size);
      ok = written >= 0 && (size_t)written < sizeof(digits) && strbuf_append(&line, digits);
    } break;
    case 'b': {
      char digits[32];
      int written = snprintf(digits, sizeof(digits), "%llu", event->bytes_sent);
      ok = written >= 0 && (size_t)written < sizeof(digits) && strbuf_append(&line, digits);
    } break;
    case 'c': {
      char digits[32];
      int written = snprintf(digits, sizeof(digits), "%llu", event->bytes_read);
      ok = written >= 0 && (size_t)written < sizeof(digits) && strbuf_append(&line, digits);
    } break;
    case 'C': {
      if (event->checksum_known) {
        ok = strbuf_append(&line, event->checksum);
      } else {
        /* rsync pads a non-regular / untransferred / `none` entry with spaces;
           `none` renders as a blank 2-character column. */
        ChecksumAlgo algo = out_format_checksum_algo(config);
        int width = algo == CHECKSUM_ALGO_NONE ? 2 : checksum_digest_len(algo) * 2;
        for (int i = 0; i < width && ok; i++)
          ok = strbuf_append_char(&line, ' ');
      }
    } break;
    case 'M': {
      char when[32];
      if (format_rsync_datetime(event->mtime_sec, true, when, sizeof(when)))
        ok = strbuf_append(&line, when);
    } break;
    case 't': {
      char when[32];
      if (format_rsync_datetime(time(NULL), false, when, sizeof(when)))
        ok = strbuf_append(&line, when);
    } break;
    case 'o':
      ok = strbuf_append(&line, "send");
      break;
    case 'p': {
      char digits[32];
      int written = snprintf(digits, sizeof(digits), "%ld", (long)getpid());
      ok = written >= 0 && (size_t)written < sizeof(digits) && strbuf_append(&line, digits);
    } break;
    case 'B': {
      char permission[11];
      mode_to_ls_string(event->mode, permission);
      ok = strbuf_append(&line, permission + 1);
    } break;
    case 'U': {
      char digits[32];
      int written = snprintf(digits, sizeof(digits), "%u", (unsigned)event->uid);
      ok = written >= 0 && (size_t)written < sizeof(digits) && strbuf_append(&line, digits);
    } break;
    case 'G': {
      char digits[32];
      int written = snprintf(digits, sizeof(digits), "%u", (unsigned)event->gid);
      ok = written >= 0 && (size_t)written < sizeof(digits) && strbuf_append(&line, digits);
    } break;
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

/* ---- --list-only ---- */

char* change_render_list_line(const Config* config, const ChangeEvent* event) {
  (void)config;
  if (event == NULL)
    return NULL;
  char permission[11];
  mode_to_ls_string(event->mode, permission);
  char date[32];
  if (!format_rsync_datetime(event->mtime_sec, false, date, sizeof(date)))
    snprintf(date, sizeof(date), "?");
  StrBuf line = {0};
  char size_field[40];
  char grouped[32];
  if (!format_big_num(event->size, false, grouped, sizeof(grouped))) {
    strbuf_free(&line);
    return NULL;
  }
  int written = snprintf(size_field, sizeof(size_field), "%15s", grouped);
  if (written < 0 || (size_t)written >= sizeof(size_field)) {
    strbuf_free(&line);
    return NULL;
  }
  const char* name = event->name != NULL && event->name[0] != '\0' ? event->name : ".";
  bool ok = strbuf_append(&line, permission) && strbuf_append(&line, size_field) &&
            strbuf_append_char(&line, ' ') && strbuf_append(&line, date) &&
            strbuf_append_char(&line, ' ') && strbuf_append(&line, name);
  if (!ok) {
    strbuf_free(&line);
    return NULL;
  }
  return line.data;
}

/* ---- Event emission ---- */

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
    char* line = config->out_format != NULL
                     ? change_render_format(config->out_format, config, event)
                     : change_render_itemize(config, event);
    if (line != NULL) {
      print_escaped_line(stdout, line, config->eight_bit_output);
      free(line);
    }
  } else if ((config->info_level & LOG_INFO_NAME) != 0 &&
             !(config->show_progress || (config->info_level & LOG_INFO_PROGRESS))) {
    /* --info=name without -i/--out-format: print the updated entry's name.  The
       --progress path owns the name line when progress output is active (it
       emits the same names before the progress frames), so do not duplicate. */
    char* line = change_render_name(event);
    if (line != NULL) {
      print_escaped_line(stdout, line, config->eight_bit_output);
      free(line);
    }
  }
  if (to_log) {
    char* line = change_render_format(config->log_file_format, config, event);
    if (line != NULL) {
      print_escaped_line(config->log_file, line, config->eight_bit_output);
      free(line);
    }
  }
}

static bool format_uses_mtime(const char* format) {
  if (format == NULL)
    return false;
  for (const char* p = format; *p != '\0';) {
    if (*p != '%') {
      p++;
      continue;
    }
    char token = p[1];
    if (token == '\0')
      break;
    if (token == 'M')
      return true;
    p += 2;
  }
  return false;
}

/* Relative path of an entry below the transfer root (no leading slash).  Uses
 * the sender-side send_path override when present (bare-relative -R layout). */
static char* relative_name(const Config* config, const File* file) {
  const char* full = file_wire_path(file);
  if (file->send_path != NULL)
    return str_dup(full != NULL ? full : "");
  const char* root = config->send_directory;
  if (root == NULL || full == NULL)
    return str_dup(full != NULL ? full : "");
  size_t root_len = strlen(root);
  while (root_len > 1 && root[root_len - 1] == '/')
    root_len--;
  if (strncmp(root, full, root_len) == 0) {
    if (full[root_len] == '\0')
      return str_dup("");
    if (full[root_len] == '/')
      return str_dup(full + root_len + 1);
  }
  return str_dup(full);
}

/* rsync %f long form: the source argument as typed (leading '/' removed,
 * trailing '/' removed, leading "./" removed) joined to the relative name. */
static char* display_name(const Config* config, const char* name) {
  const char* root = config->send_directory;
  if (root == NULL)
    return str_dup(name != NULL ? name : "");
  const char* p = root;
  while (*p == '/')
    p++;
  if (p[0] == '.' && p[1] == '/')
    p += 2;
  size_t root_len = strlen(p);
  while (root_len > 0 && p[root_len - 1] == '/')
    root_len--;
  size_t name_len = name != NULL ? strlen(name) : 0;
  if (root_len == 0 && name_len == 0)
    return str_dup("");
  char* out = malloc(root_len + (root_len > 0 && name_len > 0 ? 1 : 0) + name_len + 1);
  if (!out)
    return NULL;
  size_t offset = 0;
  if (root_len > 0) {
    memcpy(out, p, root_len);
    offset = root_len;
  }
  if (root_len > 0 && name_len > 0)
    out[offset++] = '/';
  if (name_len > 0)
    memcpy(out + offset, name, name_len);
  out[offset + name_len] = '\0';
  return out;
}

static void fill_event_from_file(const Config* config, const File* file, ChangeEvent* event,
                                 char** name_out, char** path_out) {
  char* name = relative_name(config, file);
  char* path = display_name(config, name);
  event->name = name;
  event->path = path;
  *name_out = name;
  *path_out = path;
  if (file->metadata != NULL) {
    event->mtime_sec = file->metadata->mtime_sec;
    event->mtime_nsec = file->metadata->mtime_nsec;
    event->mode = file->metadata->mode;
    event->uid = file->metadata->uid;
    event->gid = file->metadata->gid;
  } else if (format_uses_mtime(config->out_format) || format_uses_mtime(config->log_file_format)) {
    struct stat st;
    if (file->path != NULL && stat(file->path, &st) == 0) {
      event->mtime_sec = st.st_mtime;
      event->mtime_nsec = st.st_mtim.tv_nsec;
    }
  }
}

void change_emit_file_sent_bytes(const Config* config, const File* file,
                                 unsigned long long bytes_sent, unsigned long long bytes_read) {
  if (file == NULL || !change_list_enabled(config))
    return;
  ChangeEvent event;
  memset(&event, 0, sizeof(event));
  event.decision = CHANGE_SENT;
  event.is_directory = false;
  event.is_symlink = false;
  event.is_special = false;
  event.is_hardlink = false;
  event.size = file->data != NULL ? file->data->size : 0;
  event.dest = file->dest_state;
  if (file->is_symlink) {
    event.is_symlink = true;
    event.symlink_target = file->symlink_target;
    event.size = file->symlink_target != NULL ? strlen(file->symlink_target) : 0;
    event.bytes_sent = 0;
  } else if (file->is_special) {
    event.is_special = true;
    event.bytes_sent = 0;
  } else if (file->link_group != 0 && !file->link_first) {
    event.is_hardlink = true;
    event.hardlink_target = file->hardlink_target;
    event.bytes_sent = 0;
  } else {
    event.bytes_sent = bytes_sent;
    /* rsync's %c is the block-checksum bytes received for the file.  Even a
     * whole-file transfer (no basis; --append/--inplace included) receives
     * rsync's 16-byte sum header, so rsync reports 16; a dry run transfers
     * nothing and reports 0.  FastSync's whole-file path has no sum header, so
     * report rsync's value for parity.  With delta enabled the real received
     * bytes are kept, but FastSync's signature framing differs from rsync's so
     * those stay numerically divergent. */
    bool delta_active = config->use_delta && !config->whole_file;
    event.bytes_read = (!config->dry_run && !delta_active) ? 16 : bytes_read;
  }
  char* name = NULL;
  char* path = NULL;
  fill_event_from_file(config, file, &event, &name, &path);
  if (name != NULL && path != NULL) {
    fill_event_checksum(config, file, &event);
    change_emit(config, &event);
  }
  free(name);
  free(path);
}

void change_emit_file_sent(const Config* config, const File* file) {
  if (file == NULL)
    return;
  unsigned long long payload = file->data != NULL ? file->data->size : 0;
  change_emit_file_sent_bytes(config, file, payload, 0);
}

void change_emit_dir_sent(const Config* config, const File* file) {
  if (file == NULL || !change_list_enabled(config))
    return;
  ChangeEvent event;
  memset(&event, 0, sizeof(event));
  event.decision = CHANGE_SENT;
  event.is_directory = true;
  event.size = 0;
  event.bytes_sent = 0;
  event.dest = file->dest_state;
  char* name = NULL;
  char* path = NULL;
  fill_event_from_file(config, file, &event, &name, &path);
  if (name != NULL && path != NULL)
    change_emit(config, &event);
  free(name);
  free(path);
}
