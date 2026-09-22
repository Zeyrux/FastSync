#include "client_send_internal.h"
#include "array_list.h"
#include "change_list.h"
#include "charset.h"
#include "config.h"
#include "file.h"
#include "format.h"
#include "log.h"
#include "protocol.h"
#include "utils.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Surface a server rejection to the user.  When the last status exchange
   carried a STATUS_ERROR_DETAIL reason (protocol 2.21.0) it is appended to the
   client-side context; a bare STATUS_ERROR still logs the context alone. */
void log_server_rejection(const char* context) {
  const char* detail = protocol_last_error();
  if (detail && detail[0] != '\0') {
    /* The detail is peer-controlled: escape it so terminal/log-format
     * metacharacters cannot be injected into the client's output. */
    char* escaped = output_escape(detail, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "%s: %s", context, escaped ? escaped : "<allocation failed>");
    free(escaped);
  } else {
    log_message(LOG_LEVEL_ERROR, "%s", context);
  }
}

const char* display_bytes(unsigned long long bytes, bool human_readable, char* buffer,
                          size_t buffer_size) {
  if (human_readable && format_human_size_decimal(bytes, buffer, buffer_size))
    return buffer;
  snprintf(buffer, buffer_size, "%.1f MB", (double)bytes / (double)BYTES_PER_MIB);
  return buffer;
}

/* rsync byte count: human-readable decimal when -h was given, otherwise a
 * comma-grouped integer (rsync's big_num in the C locale). */
static const char* stats_bytes(const Config* config, unsigned long long bytes, char* buffer,
                               size_t buffer_size) {
  if (!format_big_num(bytes, config->human_readable, buffer, buffer_size))
    snprintf(buffer, buffer_size, "%llu", bytes);
  return buffer;
}

/* Build rsync's per-type parenthetical: each non-zero category, in
   reg/dir/link/special order.  Empty when every count is zero. */
static void type_breakdown(unsigned long long reg, unsigned long long dir, unsigned long long link,
                           unsigned long long special, char* out, size_t out_size) {
  if (reg + dir + link + special == 0) {
    out[0] = '\0';
    return;
  }
  out[0] = '\0';
  size_t used = 0;
  const struct {
    const char* name;
    unsigned long long count;
  } parts[4] = {{"reg", reg}, {"dir", dir}, {"link", link}, {"special", special}};
  bool first = true;
  for (size_t i = 0; i < 4; i++) {
    if (parts[i].count == 0)
      continue;
    int written = snprintf(out + used, out_size - used, "%s%s: %llu", first ? "(" : ", ",
                           parts[i].name, parts[i].count);
    if (written < 0 || (size_t)written >= out_size - used)
      break;
    used += (size_t)written;
    first = false;
  }
  if (!first && used + 1 < out_size)
    out[used++] = ')';
  out[used] = '\0';
}

/* Build rsync's `Number of files` parenthetical from the scan's flist counts. */
static void stats_type_breakdown(const TransferStats* stats, char* out, size_t out_size) {
  type_breakdown(stats->flist_reg, stats->flist_dir, stats->flist_link, stats->flist_special, out,
                 out_size);
}

/* rsync's `Number of files` counts every directory.  A recursive scan that
   preserves a directory attribute captures them in `dir_entries`; a `-r` scan
   (no -t/-p) captures nothing, so fall back to the scanner's shared counter of
   traversed directories that are not already represented by an inline
   directory entry.  The -d generator counts its explicit directory entries
   inline and does not traverse, so it is excluded here. */
unsigned long long dir_count_for_stats(const Config* config, const ArrayList* dir_entries,
                                       atomic_ullong* counter) {
  if (config == NULL || config->dirs || config->list_only)
    return 0;
  if (dir_metadata_should_capture(config))
    return dir_entries != NULL ? (unsigned long long)dir_entries->size : 0;
  return counter != NULL ? (unsigned long long)atomic_load(counter) : 0;
}

/* Print the rsync `--stats` block on stdout.  The source-side flist and
   transferred counters come from `stats` (filled while scanning/sending), the
   receiver-only counters from the STATUS_STATS frame, and the wire byte totals
   from the process-wide protocol counters.  The labels, layout and
   rate/speedup formulas match rsync 3.4.1.  Shared by the single-threaded and
   multithreaded send paths. */
void report_transfer_stats(const Config* config, const TransferStats* stats, time_t start,
                           const ReceiverStats* recv) {
  if (!config->stats || config->quiet)
    return;
  TransferStats empty = {0};
  if (stats == NULL)
    stats = &empty;
  ReceiverStats none = {0};
  if (recv == NULL)
    recv = &none;
  unsigned long long sent = protocol_bytes_written();
  unsigned long long received = protocol_bytes_read();
  /* rsync: bytes_per_sec = (written + read) / (0.5 + (end - start)). */
  double elapsed = difftime(time(NULL), start);
  double rate = (double)(sent + received) / (0.5 + elapsed);
  char total_buffer[32];
  char transferred_buffer[32];
  char literal_buffer[32];
  char matched_buffer[32];
  char sent_buffer[32];
  char recv_buffer[32];
  char rate_buffer[32] = {0};
  char human_rate[32] = {0};
  const char* total =
      stats_bytes(config, stats->total_file_size, total_buffer, sizeof(total_buffer));
  const char* transferred = stats_bytes(config, stats->transferred_file_size, transferred_buffer,
                                        sizeof(transferred_buffer));
  /* Protocol 2.28.0: the receiver reports the bytes it literally stored, which
     is exact for a delta transfer (the sender's own literal_data counts each
     stored file's whole source size and is only an upper bound).  Fall back to
     the sender total when the receiver reported no delta/literal accounting
     (e.g. a local no-server path). */
  unsigned long long literal_bytes = (recv->literal_bytes != 0 || recv->matched_data != 0)
                                         ? recv->literal_bytes
                                         : stats->literal_data;
  const char* literal = stats_bytes(config, literal_bytes, literal_buffer, sizeof(literal_buffer));
  const char* sent_s = stats_bytes(config, sent, sent_buffer, sizeof(sent_buffer));
  const char* recv_s = stats_bytes(config, received, recv_buffer, sizeof(recv_buffer));
  const char* rate_str = rate_buffer;
  if (config->human_readable) {
    if (!format_human_size_decimal((unsigned long long)rate, human_rate, sizeof(human_rate)))
      snprintf(human_rate, sizeof(human_rate), "0");
    rate_str = human_rate;
  } else {
    snprintf(rate_buffer, sizeof(rate_buffer), "%.2f", rate);
  }
  double speedup =
      (sent + received) > 0 ? (double)stats->total_file_size / (double)(sent + received) : 0.0;
  char breakdown[128];
  stats_type_breakdown(stats, breakdown, sizeof(breakdown));
  unsigned long long flist_total =
      stats->flist_reg + stats->flist_dir + stats->flist_link + stats->flist_special;
  char created_breakdown[128];
  type_breakdown(recv->created_reg, recv->created_dir, recv->created_link, recv->created_special,
                 created_breakdown, sizeof(created_breakdown));
  unsigned long long created_total =
      recv->created_reg + recv->created_dir + recv->created_link + recv->created_special;
  printf("\n");
  if (breakdown[0] != '\0')
    printf("Number of files: %llu %s\n", flist_total, breakdown);
  else
    printf("Number of files: %llu\n", flist_total);
  /* Protocol 2.28.0: the receiver reports which destination entries it newly
     created, split by type, so this line matches rsync exactly. */
  if (created_breakdown[0] != '\0')
    printf("Number of created files: %llu %s\n", created_total, created_breakdown);
  else
    printf("Number of created files: %llu\n", created_total);
  printf("Number of deleted files: %llu\n", recv->deleted_files);
  printf("Number of regular files transferred: %llu\n", stats->transferred_regular);
  printf("Total file size: %s bytes\n", total);
  printf("Total transferred file size: %s bytes\n", transferred);
  printf("Literal data: %s bytes\n", literal);
  const char* matched =
      stats_bytes(config, recv->matched_data, matched_buffer, sizeof(matched_buffer));
  printf("Matched data: %s bytes\n", matched);
  printf("File list size: 0\n");
  printf("File list generation time: 0.000 seconds\n");
  printf("File list transfer time: 0.000 seconds\n");
  printf("Total bytes sent: %s\n", sent_s);
  printf("Total bytes received: %s\n", recv_s);
  printf("\n");
  printf("sent %s bytes  received %s bytes  %s bytes/sec\n", sent_s, recv_s, rate_str);
  printf("total size is %s  speedup is %.2f%s\n", total, speedup,
         config->dry_run ? " (DRY RUN)" : "");
  fflush(stdout);
}

/* Classify one scanned source entry into the rsync flist counters.  Called for
   every entry the sender walks, transferred or skipped.  Directory entries are
   counted here only for the explicit -d/--dirs generator; a recursive scan's
   directories are accounted from the scanner's dir_entries list at report time. */
void transfer_stats_note_entry(TransferStats* stats, const File* file) {
  if (stats == NULL || file == NULL)
    return;
  if (file->is_dir) {
    stats->flist_dir++;
    return;
  }
  if (file->is_symlink) {
    stats->flist_link++;
    stats->total_file_size += file->symlink_target ? strlen(file->symlink_target) : 0;
    return;
  }
  if (file->is_special) {
    stats->flist_special++;
    return;
  }
  stats->flist_reg++;
  stats->total_file_size += file->data ? file->data->size : 0;
}

/* Account for a regular file (or a whole-file append) the receiver actually
   stored: rsync's transferred-file count and transferred/literal byte totals.
   `literal_data` counts the whole source size, which is exact for a whole-file
   send but an upper bound for a delta send (the receiver reuses basis blocks
   the sender never ships); see TransferStats.literal_data in format.h. */
void transfer_stats_note_transferred(TransferStats* stats, const File* file) {
  if (stats == NULL || file == NULL)
    return;
  if (file->is_dir || file->is_symlink || file->is_special)
    return;
  if (file->link_group != 0 && !file->link_first)
    return;
  unsigned long long size = file->data ? file->data->size : 0;
  stats->transferred_regular++;
  stats->transferred_file_size += size;
  stats->literal_data += size;
}

/* ---- rsync-style per-file --progress ------------------------------------
 * rsync prints, for each transferred regular file, the file name followed by a
 * two-frame progress line: the first at the initial 32 KiB read window (always
 * 0.00 kB/s / 0:00:00 on a sub-second transfer) and a final 100% frame carrying
 * `(xfr#N, to-chk=X/Y)`.  Rates are wall-clock dependent, so only the final
 * rate is measured here; the layout matches rsync 3.4.1's progress.c. */
#define RSYNC_PROGRESS_IO_WINDOW (32ULL * 1024ULL)

/* Paths-only pre-count of the source file list, built once at transfer start
 * when progress output or -i/--out-format needs it.  rsync's `to-chk`
 * denominator is the whole file list -- every regular file, directory, symlink
 * and special plus the transfer root -- while the streaming scan only emits
 * empty directories.  A metadata-only walk (no file reads, no hashing) supplies
 * that total and a metadata-bearing File for every directory, so --progress can
 * name them and -i/--out-format can itemize them without a second full scan. */
/* One directory in the pre-count, keyed by its transfer-relative display name
 * ("" is the transfer root).  `file` is owned by ProgressPrecount.dir_files and
 * carries the source metadata needed by -i/--out-format (%M/%B/%U/%G). */
typedef struct {
  char* name; /* owned */
  File* file;
} DirRef;

typedef struct {
  unsigned long long total;
  ArrayList* dir_paths; /* owned char* in transfer-relative display form */
  ArrayList* dir_files; /* owned File* captured during the metadata walk */
  ArrayList* dir_refs;  /* owned DirRef*, sorted by name for prefix lookup */
} ProgressPrecount;

static bool g_progress_active;
/* True when -i/--out-format need the pre-counted directory entries fed into the
 * change-event stream (independent of --progress). */
static bool g_change_dirs_active;
static unsigned long long g_progress_xferred;
static unsigned long long g_progress_index;
static unsigned long long g_progress_total;
static struct timespec g_progress_file_start;
static ProgressPrecount g_progress_precount;
static PathIndex g_progress_dir_index;
static bool g_progress_dir_index_valid;
static StrHashSet g_progress_emitted;
static bool g_progress_emitted_valid;
static ArrayList* g_progress_emitted_keys;

bool progress_requested(const Config* config) {
  return config != NULL && !config->quiet &&
         (config->show_progress || (config->info_level & LOG_INFO_PROGRESS) != 0);
}

static void dir_ref_destroy(void* item) {
  DirRef* ref = (DirRef*)item;
  if (ref == NULL)
    return;
  free(ref->name);
  free(ref);
}

/* Sort DirRef pointers by their transfer-relative name for binary search. */
static int dir_ref_compare(const void* left, const void* right) {
  const DirRef* a = *(const DirRef* const*)left;
  const DirRef* b = *(const DirRef* const*)right;
  return strcmp(a->name, b->name);
}

/* Look up the pre-counted directory File for a transfer-relative name ("" is
 * the transfer root).  Returns NULL when no pre-count was built or the name is
 * not a known directory. */
static File* progress_dir_lookup(const char* name) {
  if (name == NULL || g_progress_precount.dir_refs == NULL)
    return NULL;
  ArrayList* refs = g_progress_precount.dir_refs;
  size_t lo = 0;
  size_t hi = (size_t)refs->size;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    DirRef* ref = (DirRef*)refs->items[mid];
    int cmp = strcmp(ref->name, name);
    if (cmp < 0)
      lo = mid + 1;
    else if (cmp > 0)
      hi = mid;
    else
      return ref->file;
  }
  return NULL;
}

static void progress_precount_dispose(ProgressPrecount* p) {
  if (p->dir_paths != NULL) {
    array_list_delete(p->dir_paths);
    p->dir_paths = NULL;
  }
  if (p->dir_files != NULL) {
    array_list_delete(p->dir_files);
    p->dir_files = NULL;
  }
  if (p->dir_refs != NULL) {
    array_list_delete(p->dir_refs);
    p->dir_refs = NULL;
  }
  p->total = 0;
}

/* Record the transfer root's pre-transfer state for -i/--out-format.  The
 * receive root always exists, so rsync never marks it `cd`; its only observable
 * change is its timestamp, which FastSync cannot observe remotely.  Force a time
 * mismatch so the root renders rsync's `.d..t...... ./` rather than the `cd`
 * a zeroed destination state would produce. */
static void progress_precount_mark_root(File* root) {
  if (root == NULL)
    return;
  root->dest_state.known = true;
  root->dest_state.existed = true;
  root->dest_state.mode = root->metadata != NULL ? root->metadata->mode : 0;
  root->dest_state.uid = root->metadata != NULL ? root->metadata->uid : 0;
  root->dest_state.gid = root->metadata != NULL ? root->metadata->gid : 0;
  root->dest_state.size = 0;
  root->dest_state.mtime_sec = (root->metadata != NULL ? root->metadata->mtime_sec : 0) - 3600;
  root->dest_state.mtime_nsec = root->metadata != NULL ? root->metadata->mtime_nsec : 0;
}

/* Append one DirRef (name -> file) to the pre-count, marking the transfer
 * root's destination state.  Returns false on allocation failure. */
static bool progress_precount_add_ref(ProgressPrecount* p, const Config* config, File* file) {
  const char* rel = delete_display_path(config, file_wire_path(file));
  char* name = rel != NULL ? str_dup(rel) : NULL;
  if (name == NULL)
    return false;
  DirRef* ref = malloc(sizeof(*ref));
  if (ref == NULL) {
    free(name);
    return false;
  }
  ref->name = name;
  ref->file = file;
  if (name[0] == '\0')
    progress_precount_mark_root(file);
  if (!array_list_add(p->dir_refs, ref)) {
    dir_ref_destroy(ref);
    return false;
  }
  return true;
}

void client_progress_cleanup(void) {
  if (g_progress_dir_index_valid) {
    path_index_free(&g_progress_dir_index);
    g_progress_dir_index_valid = false;
  }
  if (g_progress_emitted_valid) {
    str_hash_set_free(&g_progress_emitted);
    g_progress_emitted_valid = false;
  }
  if (g_progress_emitted_keys != NULL) {
    array_list_delete(g_progress_emitted_keys);
    g_progress_emitted_keys = NULL;
  }
  progress_precount_dispose(&g_progress_precount);
  g_progress_active = false;
  g_change_dirs_active = false;
  g_progress_total = 0;
  g_progress_index = 0;
  g_progress_xferred = 0;
}

static void progress_first_frame(unsigned long long size, char* out, size_t out_size) {
  char ofs_buf[32];
  unsigned long long ofs = size < RSYNC_PROGRESS_IO_WINDOW ? size : RSYNC_PROGRESS_IO_WINDOW;
  if (!format_big_num(ofs, false, ofs_buf, sizeof(ofs_buf)))
    snprintf(ofs_buf, sizeof(ofs_buf), "%llu", ofs);
  int pct = size == 0 ? 100 : (ofs == size ? 100 : (int)(100.0 * (double)ofs / (double)size));
  snprintf(out, out_size, "\r%15s %3d%% %7.2f%s %s%s", ofs_buf, pct, 0.0, "kB/s", "   0:00:00",
           "  ");
}

static void progress_final_frame(unsigned long long size, char* out, size_t out_size) {
  char ofs_buf[32];
  char rembuf[32];
  unsigned long long last_ofs = size < RSYNC_PROGRESS_IO_WINDOW ? size : RSYNC_PROGRESS_IO_WINDOW;
  if (!format_big_num(size, false, ofs_buf, sizeof(ofs_buf)))
    snprintf(ofs_buf, sizeof(ofs_buf), "%llu", size);
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  long long diff_ms = (long long)(now.tv_sec - g_progress_file_start.tv_sec) * 1000 +
                      (now.tv_nsec - g_progress_file_start.tv_nsec) / 1000000;
  if (diff_ms <= 0)
    diff_ms = 1;
  double rate =
      size > last_ofs ? (double)(size - last_ofs) * 1000.0 / (double)diff_ms / 1024.0 : 0.0;
  const char* units = "kB/s";
  if (rate > 1024.0 * 1024.0) {
    rate /= 1024.0 * 1024.0;
    units = "GB/s";
  } else if (rate > 1024.0) {
    rate /= 1024.0;
    units = "MB/s";
  }
  unsigned long long remain = (unsigned long long)(diff_ms / 1000);
  snprintf(rembuf, sizeof(rembuf), "%4u:%02u:%02u", (unsigned)(remain / 3600),
           (unsigned)((remain / 60) % 60), (unsigned)(remain % 60));
  /* rsync's `to-chk` denominator is the whole file list (the pre-count); the
     numerator falls as each entry is processed, root first.  Without a
     pre-count (the paths-only walk failed) fall back to the transferred-file
     count so the single-file layout stays intact. */
  unsigned long long total = g_progress_total > 0 ? g_progress_total : g_progress_xferred + 1;
  unsigned long long to_chk = total > g_progress_index ? total - g_progress_index - 1 : 0;
  snprintf(out, out_size, "\r%15s %3d%% %7.2f%s %s (xfr#%llu, to-chk=%llu/%llu)\n", ofs_buf, 100,
           rate, units, rembuf, g_progress_xferred, to_chk, total);
}

bool info_flag_enabled(const Config* config, LogInfoFlag flag) {
  return config != NULL && (config->info_level & flag) != 0;
}

/* Print rsync's deletion lines for a received list of destination-relative
 * paths: `*deleting   PATH` when itemizing, the --out-format expansion when a
 * format is set, else `deleting PATH` for --info=del.  Used by both the dry-run
 * would-delete report and the real --info=del report. */
void print_delete_reports(const Config* config, const ArrayList* paths) {
  if (!config || !paths || config->quiet)
    return;
  /* --debug=del is independent of the --info=del/itemize/out-format display:
     emit the debug trace even when no deletion line would be printed. */
  if (log_debug_enabled(LOG_DEBUG_DEL)) {
    for (int i = 0; i < paths->size; i++) {
      const char* raw = (const char*)paths->items[i];
      const char* path = delete_display_path(config, raw);
      log_debug_message(LOG_DEBUG_DEL, "del: %s", path ? path : raw);
    }
  }
  if (!(config->itemize_changes || config->out_format != NULL ||
        info_flag_enabled(config, LOG_INFO_DEL)))
    return;
  for (int i = 0; i < paths->size; i++) {
    const char* raw = (const char*)paths->items[i];
    const char* path = delete_display_path(config, raw);
    if (config->out_format != NULL) {
      ChangeEvent event;
      memset(&event, 0, sizeof(event));
      event.decision = CHANGE_SENT;
      event.deleted = true;
      event.name = path;
      event.path = path;
      char* line = change_render_format(config->out_format, config, &event);
      if (line) {
        char* escaped = output_escape(line, config->eight_bit_output);
        printf("%s\n", escaped ? escaped : line);
        free(escaped);
        free(line);
      }
    } else {
      char* escaped = output_escape(path, config->eight_bit_output);
      if (config->itemize_changes)
        printf("*deleting   %s\n", escaped ? escaped : path);
      else
        printf("deleting %s\n", escaped ? escaped : path);
      free(escaped);
    }
  }
  fflush(stdout);
}

/* Emit every not-yet-seen ancestor directory of `rel`, outermost first, in the
 * order rsync's depth-first flist walk visits them.  With -i/--out-format each
 * ancestor becomes a real change line (`cd+++++++++ sub/`, `.d..t...... ./`)
 * rendered by the shared itemize code; otherwise it is the `--info=name` /
 * --progress directory name line. */
static void client_progress_emit_ancestors(const Config* config, const char* rel) {
  if (!g_progress_dir_index_valid || !g_progress_emitted_valid || g_progress_emitted_keys == NULL ||
      rel == NULL)
    return;
  size_t rel_len = strlen(rel);
  for (size_t i = 0; i < rel_len; i++) {
    if (rel[i] != '/')
      continue;
    char* prefix = malloc(i + 1);
    if (prefix == NULL)
      return;
    memcpy(prefix, rel, i);
    prefix[i] = '\0';
    if (path_index_contains(&g_progress_dir_index, prefix) &&
        !str_hash_set_lookup(&g_progress_emitted, prefix)) {
      char* key = str_dup(prefix);
      if (key != NULL && array_list_add(g_progress_emitted_keys, key)) {
        str_hash_set_insert_ref(&g_progress_emitted, key);
        if (g_change_dirs_active) {
          const File* dir = progress_dir_lookup(prefix);
          if (dir != NULL)
            change_emit_dir_sent(config, dir);
        } else {
          char* escaped = output_escape(prefix, config->eight_bit_output);
          printf("%s/\n", escaped ? escaped : prefix);
          free(escaped);
        }
        g_progress_index++;
      } else {
        free(key);
      }
    }
    free(prefix);
  }
}

/* Feed a transferred entry's ancestor directories into the change-event stream
 * before the entry's own line, so -i/--out-format and --progress report
 * directories in rsync's depth-first order.  Every directory is an ancestor of
 * some emitted entry (a file, symlink, special, hard link or the empty-directory
 * entry the scanner emits for a leaf), so this covers the whole tree. */
void client_change_emit_ancestors(const Config* config, const File* file) {
  if (config == NULL || file == NULL)
    return;
  if (!g_progress_active && !g_change_dirs_active)
    return;
  const char* rel = delete_display_path(config, file_wire_path(file));
  client_progress_emit_ancestors(config, rel);
}

/* rsync's --info=name/progress line for one entry: transfer-relative name (a
 * trailing slash for directories) plus the ` -> target` symlink suffix. */
static char* progress_entry_line(const File* file, const char* rel) {
  const char* arrow = NULL;
  const char* target = NULL;
  if (file->is_symlink && file->symlink_target != NULL) {
    arrow = " -> ";
    target = file->symlink_target;
  } else if (file->link_group != 0 && !file->link_first && file->hardlink_target != NULL) {
    arrow = " => ";
    target = file->hardlink_target;
  }
  size_t rel_len = strlen(rel);
  bool dir_slash = file->is_dir && (rel_len == 0 || rel[rel_len - 1] != '/');
  size_t extra = (dir_slash ? 1u : 0u) + (target != NULL ? 4u + strlen(target) : 0u);
  char* line = malloc(rel_len + extra + 1);
  if (line == NULL)
    return NULL;
  memcpy(line, rel, rel_len);
  size_t off = rel_len;
  if (dir_slash)
    line[off++] = '/';
  if (target != NULL) {
    memcpy(line + off, arrow, 4);
    off += 4;
    memcpy(line + off, target, strlen(target));
    off += strlen(target);
  }
  line[off] = '\0';
  return line;
}

void client_progress_begin(const Config* config) {
  change_reset_name_root();
  g_progress_active = progress_requested(config);
  g_progress_xferred = 0;
  g_progress_index = 1; /* the transfer root is file-list entry #0 */
  if (!g_progress_active && !g_change_dirs_active) {
    /* `--info=flist` prints rsync's file-list header even without progress. */
    if (!config->quiet && info_flag_enabled(config, LOG_INFO_FLIST)) {
      printf("sending incremental file list\n");
      fflush(stdout);
    }
    return;
  }
  if (g_progress_active)
    printf("sending incremental file list\n");
  /* rsync prints the transfer-root directory before the first entry.  Under
     -i/--out-format it is the root change line (`.d..t...... ./`); otherwise it
     is the plain --info=name / --progress name line. */
  if (g_change_dirs_active) {
    const File* root = progress_dir_lookup("");
    if (root != NULL)
      change_emit_dir_sent(config, root);
  } else {
    printf("./\n");
  }
  fflush(stdout);
}

/* Emit the name (unless itemize/out-format already did) and the two progress
 * frames for one transferred regular file. */
void client_progress_file(const Config* config, const File* file) {
  if (!g_progress_active || file == NULL || !file->data)
    return;
  g_progress_xferred++;
  unsigned long long size = file->data->size;
  if (!config->itemize_changes && config->out_format == NULL) {
    const char* rel = delete_display_path(config, file_wire_path(file));
    char* escaped = output_escape(rel, config->eight_bit_output);
    printf("%s\n", escaped ? escaped : (rel ? rel : ""));
    free(escaped);
  }
  clock_gettime(CLOCK_MONOTONIC, &g_progress_file_start);
  char frame[160];
  progress_first_frame(size, frame, sizeof(frame));
  fputs(frame, stdout);
  progress_final_frame(size, frame, sizeof(frame));
  fputs(frame, stdout);
  g_progress_index++;
  fflush(stdout);
}

/* Emit the name line for a transferred non-regular entry (directory, symlink,
 * special or hard-link sibling): rsync prints these in the file list but has no
 * progress frame for them. */
void client_progress_name(const Config* config, const File* file) {
  if (!g_progress_active || file == NULL)
    return;
  const char* rel = delete_display_path(config, file_wire_path(file));
  if (!config->itemize_changes && config->out_format == NULL) {
    char* line = progress_entry_line(file, rel ? rel : "");
    if (line != NULL) {
      char* escaped = output_escape(line, config->eight_bit_output);
      printf("%s\n", escaped ? escaped : line);
      free(escaped);
      free(line);
      fflush(stdout);
    }
  }
  g_progress_index++;
}

/* An entry the receiver already had prints no name under --progress but still
 * occupies a file-list slot in the `to-chk` numerator. */
void client_progress_uptodate(const Config* config, const File* file) {
  (void)config;
  (void)file;
  if (!g_progress_active)
    return;
  g_progress_index++;
}

static bool progress_precount_add_dir(ProgressPrecount* p, const char* path) {
  if (path == NULL || path[0] == '\0')
    return true;
  char* dup = str_dup(path);
  if (dup == NULL)
    return false;
  if (array_list_add(p->dir_paths, dup))
    return true;
  free(dup);
  return false;
}

/* Metadata-only walk collecting the full file-list total and every directory
 * name.  It uses its own scanner (fresh filter compilation and hard-link table)
 * so the data pass's link-group state is never perturbed. */
static bool progress_precount_scan(const Config* config, ProgressPrecount* out) {
  out->dir_paths = array_list_create(free);
  out->dir_files = array_list_create(file_destroy);
  out->dir_refs = array_list_create(dir_ref_destroy);
  if (out->dir_paths == NULL || out->dir_files == NULL || out->dir_refs == NULL) {
    progress_precount_dispose(out);
    return false;
  }
  out->total = 0;
  PreparedScanner prepared;
  memset(&prepared, 0, sizeof(prepared));
  if (!prepare_scanner(config, 0, &prepared)) {
    progress_precount_dispose(out);
    return false;
  }
  ScannerOptions local = prepared.options;
  local.list_dirs = true;
  local.note_nonreg = false;
  local.note_mount = false;
  local.dir_count = NULL;
  local.use_metadata = false;
  local.preserve_xattrs = false;
  local.preserve_acls = false;
  local.checksum = false;
  /* Capture one metadata-bearing File per traversed directory (including the
     transfer root) so -i/--out-format can render %M/%B/%U/%G for directories. */
  local.capture_dir_times = true;
  local.excluded_paths = NULL;
  local.size_skipped_paths = NULL;
  local.synced_dirs = NULL;
  local.plan_dirs = NULL;
  local.dir_entries = out->dir_files;
  local.dir_entries_mutex = NULL;
  local.hardlinks = NULL;
  DirectoryScanner* scanner = directory_scanner_create_with_options(config->send_directory, &local);
  bool ok = scanner != NULL;
  if (scanner != NULL) {
    Chunk* chunk;
    while (ok && (chunk = directory_scanner_next(scanner)) != NULL) {
      out->total += (unsigned long long)chunk->element_count;
      for (int i = 0; i < chunk->element_count && ok; i++) {
        const File* f = chunk->items[i];
        if (f != NULL && f->is_dir)
          ok = progress_precount_add_dir(out, delete_display_path(config, file_wire_path(f)));
      }
      chunk_destroy(chunk);
    }
    if (ok && directory_scanner_failed(scanner))
      ok = false;
    directory_scanner_destroy(scanner);
  }
  prepared_scanner_destroy(&prepared);
  if (!ok) {
    progress_precount_dispose(out);
    return false;
  }
  /* Build the name -> File lookup from the captured directory Files. */
  for (int i = 0; i < out->dir_files->size; i++) {
    File* f = (File*)out->dir_files->items[i];
    if (f == NULL)
      continue;
    if (!progress_precount_add_ref(out, config, f)) {
      progress_precount_dispose(out);
      return false;
    }
  }
  if (out->dir_refs->size > 1)
    qsort(out->dir_refs->items, (size_t)out->dir_refs->size, sizeof(DirRef*), dir_ref_compare);
  out->total += 1; /* the transfer root "." */
  return true;
}

/* Reuse the --delete-during/--delete-delay keep-set pre-scan: its traversed
 * directory list already holds every directory and `non_dir_count` the entries
 * counted during that same pass, so progress costs no second walk. */
static bool progress_precount_from_plan_dirs(const Config* config, const ArrayList* plan_dirs,
                                             unsigned long long non_dir_count,
                                             ProgressPrecount* out) {
  out->dir_paths = array_list_create(free);
  out->dir_files = array_list_create(file_destroy);
  out->dir_refs = array_list_create(dir_ref_destroy);
  if (out->dir_paths == NULL || out->dir_files == NULL || out->dir_refs == NULL) {
    progress_precount_dispose(out);
    return false;
  }
  out->total = non_dir_count + 1;
  /* The delete pre-scan's plan list omits the transfer root, so synthesize its
     entry here; it is only used for the root change line. */
  File* root = file_create("");
  if (root == NULL || !array_list_add(out->dir_files, root)) {
    file_destroy(root);
    progress_precount_dispose(out);
    return false;
  }
  root->is_dir = true;
  if (!progress_precount_add_ref(out, config, root)) {
    progress_precount_dispose(out);
    return false;
  }
  for (int i = 0; i < plan_dirs->size; i++) {
    const char* path = (const char*)plan_dirs->items[i];
    const char* rel = config->send_directory != NULL
                          ? utils_strip_transfer_root(path, config->send_directory)
                          : path;
    if (!progress_precount_add_dir(out, rel)) {
      progress_precount_dispose(out);
      return false;
    }
    File* dir = file_create("");
    if (dir == NULL) {
      progress_precount_dispose(out);
      return false;
    }
    dir->is_dir = true;
    dir->send_path = str_dup(rel != NULL ? rel : "");
    if (dir->send_path == NULL || !array_list_add(out->dir_files, dir)) {
      file_destroy(dir);
      progress_precount_dispose(out);
      return false;
    }
    if (!progress_precount_add_ref(out, config, dir)) {
      progress_precount_dispose(out);
      return false;
    }
  }
  if (out->dir_refs->size > 1)
    qsort(out->dir_refs->items, (size_t)out->dir_refs->size, sizeof(DirRef*), dir_ref_compare);
  out->total += (unsigned long long)out->dir_paths->size;
  return true;
}

/* Build the optional progress pre-count.  A failed pre-count is non-fatal: the
 * transfer proceeds and the progress denominator falls back to the transferred
 * file count. */
void client_progress_prepare(const Config* config, const ArrayList* plan_dirs,
                             unsigned long long plan_non_dir_count) {
  client_progress_cleanup();
  g_progress_active = progress_requested(config);
  g_change_dirs_active = config->itemize_changes || config->out_format != NULL;
  if (!g_progress_active && !g_change_dirs_active)
    return;
  bool ok = plan_dirs != NULL ? progress_precount_from_plan_dirs(
                                    config, plan_dirs, plan_non_dir_count, &g_progress_precount)
                              : progress_precount_scan(config, &g_progress_precount);
  if (!ok) {
    g_progress_total = 0;
    return;
  }
  g_progress_total = g_progress_precount.total;
  if (g_progress_precount.dir_paths != NULL && g_progress_precount.dir_paths->size > 0 &&
      path_index_build(&g_progress_dir_index,
                       (const char* const*)g_progress_precount.dir_paths->items,
                       (size_t)g_progress_precount.dir_paths->size))
    g_progress_dir_index_valid = true;
  if (str_hash_set_init(&g_progress_emitted, (size_t)(g_progress_precount.dir_paths != NULL
                                                          ? g_progress_precount.dir_paths->size + 1
                                                          : 1)))
    g_progress_emitted_valid = true;
  g_progress_emitted_keys = array_list_create(free);
}

/* Read the optional STATUS_STATS record (protocol 2.25.0) that the receiver
 * sends just before its terminal status when report_stats was negotiated.
 * Consumes the would-delete path list into `would_delete` (optional). */
bool receive_stats_record(int fd, ReceiverStats* stats, ArrayList* would_delete) {
  if (!format_stats_receive(fd, stats))
    return false;
  int count = 0;
  if (!receive_int(fd, &count) || count < 0 || count > MAX_MANIFEST_ENTRIES)
    return false;
  /* Mirror the delete-plan parser: every retained path must be a valid
     destination-relative path, and the whole list shares one MAX_MANIFEST_BYTES
     budget so a hostile peer cannot make the client retain unbounded memory. */
  size_t bytes = 0;
  for (int i = 0; i < count; i++) {
    char* path = receive_wire_str(fd);
    if (!path)
      return false;
    if (path[0] == '\0' || path[0] == '/' || has_path_traversal(path)) {
      free(path);
      return false;
    }
    if (would_delete) {
      size_t entry_size = strlen(path) + sizeof(char*) + 16;
      if (entry_size > MAX_MANIFEST_BYTES - bytes) {
        free(path);
        return false;
      }
      bytes += entry_size;
      if (!array_list_add(would_delete, path)) {
        free(path);
        return false;
      }
    } else {
      free(path);
    }
  }
  return true;
}

/* Strip the transfer-root prefix from a receiver-reported destination-relative
 * delete path so a `*deleting` line matches rsync's transfer-relative name
 * (FastSync's destination mirror includes the source's absolute path). */
const char* delete_display_path(const Config* config, const char* path) {
  if (!config || !path || !config->send_directory)
    return path;
  return utils_strip_transfer_root(path, config->send_directory);
}
