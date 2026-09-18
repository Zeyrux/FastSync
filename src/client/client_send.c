#include "client_send.h"
#include "array_list.h"
#include "batch.h"
#include "change_list.h"
#include "charset.h"
#include "chunk.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delete_plan.h"
#include "delta.h"
#include "file.h"
#include "file_list.h"
#include "filter.h"
#include "format.h"
#include "hardlink.h"
#include "metadata.h"
#include "motd.h"
#include "log.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "scanner.h"
#include "stop_condition.h"
#include "transport_tcp.h"
#include "transport_ssh.h"
#include "transport_tls.h"
#include "utils.h"
#include "xattr.h"
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define STREAM_THRESHOLD (64ULL * 1024 * 1024)

/* Aggregate loaded payload bytes the sender may buffer across the loader queue
   and the chunk in flight.  Sending one chunk adds up to ~2 * MAX_CHUNK_SIZE of
   transient serialize/compress buffers on top of the queued payloads, so this
   ceiling keeps total pipeline memory within MAX_CONNECTION_MEMORY (mirrors the
   receiver's RECEIVER_QUEUE_MAX_BYTES). */
#define SENDER_QUEUE_MAX_BYTES (MAX_CONNECTION_MEMORY - 2 * MAX_CHUNK_SIZE)

/* One mebibyte in bytes; the unit used by the --stats/--progress lines.
   Always cast to double when dividing so the output stays fractional. */
#define BYTES_PER_MIB (1024ULL * 1024ULL)

/* Surface a server rejection to the user.  When the last status exchange
   carried a STATUS_ERROR_DETAIL reason (protocol 2.21.0) it is appended to the
   client-side context; a bare STATUS_ERROR still logs the context alone. */
static void log_server_rejection(const char* context) {
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

/* rsync's --ignore-errors semantics: an I/O error during the transfer normally
 * suppresses deletion entirely ("IO error encountered -- skipping file
 * deletion"); --ignore-errors lets the deletion run anyway.  FastSync always
 * continues past an unreadable subdirectory so the readable tree transfers, and
 * always reports the partial transfer (exit 23); this only decides whether the
 * deletion phase is skipped.  Returns true when deletion may proceed. */
static bool ignore_errors_allows_delete(const Config* config, bool had_io_error) {
  return !had_io_error || (config && config->ignore_errors);
}

static const char* display_bytes(unsigned long long bytes, bool human_readable, char* buffer,
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

/* Build rsync's `Number of files` parenthetical: each non-zero category, in
   reg/dir/link/special order.  Empty when the flist counted nothing. */
static void stats_type_breakdown(const TransferStats* stats, char* out, size_t out_size) {
  unsigned long long total =
      stats->flist_reg + stats->flist_dir + stats->flist_link + stats->flist_special;
  if (total == 0) {
    out[0] = '\0';
    return;
  }
  out[0] = '\0';
  size_t used = 0;
  const struct {
    const char* name;
    unsigned long long count;
  } parts[4] = {{"reg", stats->flist_reg},
                {"dir", stats->flist_dir},
                {"link", stats->flist_link},
                {"special", stats->flist_special}};
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

/* Print the rsync `--stats` block on stdout.  The source-side flist and
   transferred counters come from `stats` (filled while scanning/sending), the
   receiver-only counters from the STATUS_STATS frame, and the wire byte totals
   from the process-wide protocol counters.  The labels, layout and
   rate/speedup formulas match rsync 3.4.1.  Shared by the single-threaded and
   multithreaded send paths. */
static void report_transfer_stats(const Config* config, const TransferStats* stats, time_t start,
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
  char sent_buffer[32];
  char recv_buffer[32];
  char rate_buffer[32] = {0};
  char human_rate[32] = {0};
  const char* total =
      stats_bytes(config, stats->total_file_size, total_buffer, sizeof(total_buffer));
  const char* transferred = stats_bytes(config, stats->transferred_file_size, transferred_buffer,
                                        sizeof(transferred_buffer));
  const char* literal =
      stats_bytes(config, stats->literal_data, literal_buffer, sizeof(literal_buffer));
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
  printf("\n");
  if (breakdown[0] != '\0')
    printf("Number of files: %llu %s\n", flist_total, breakdown);
  else
    printf("Number of files: %llu\n", flist_total);
  /* FastSync cannot tell which entries the receiver newly created, so it
     reports the transferred regular files (which are created on a fresh
     destination).  See RSYNC_COMPAT.md for the documented residual. */
  printf("Number of created files: %llu\n", stats->transferred_regular);
  printf("Number of deleted files: %llu\n", recv->deleted_files);
  printf("Number of regular files transferred: %llu\n", stats->transferred_regular);
  printf("Total file size: %s bytes\n", total);
  printf("Total transferred file size: %s bytes\n", transferred);
  printf("Literal data: %s bytes\n", literal);
  printf("Matched data: %llu bytes\n", recv->matched_data);
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
static void transfer_stats_note_entry(TransferStats* stats, const File* file) {
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
   stored: rsync's transferred-file count and transferred/literal byte totals. */
static void transfer_stats_note_transferred(TransferStats* stats, const File* file) {
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

static const char* delete_display_path(const Config* config, const char* path);

static bool g_progress_active;
static unsigned long long g_progress_xferred;
static unsigned long long g_progress_seen;
static struct timespec g_progress_file_start;

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
  /* rsync's `to-chk` denominator is the whole file list, which includes the
     transfer-root directory FastSync never emits as a transfer entry.  Count
     that root entry so a single-file transfer matches rsync exactly. */
  unsigned long long total = g_progress_seen + 1;
  unsigned long long to_chk =
      g_progress_seen > g_progress_xferred ? g_progress_seen - g_progress_xferred : 0;
  snprintf(out, out_size, "\r%15s %3d%% %7.2f%s %s (xfr#%llu, to-chk=%llu/%llu)\n", ofs_buf, 100,
           rate, units, rembuf, g_progress_xferred, to_chk, total);
}

static bool info_flag_enabled(const Config* config, LogInfoFlag flag) {
  return config != NULL && (config->info_level & flag) != 0;
}

/* Print rsync's deletion lines for a received list of destination-relative
 * paths: `*deleting   PATH` when itemizing, the --out-format expansion when a
 * format is set, else `deleting PATH` for --info=del.  Used by both the dry-run
 * would-delete report and the real --info=del report. */
static void print_delete_reports(const Config* config, const ArrayList* paths) {
  if (!config || !paths || config->quiet)
    return;
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

static void client_progress_begin(const Config* config) {
  g_progress_active =
      (config->show_progress || info_flag_enabled(config, LOG_INFO_PROGRESS)) && !config->quiet;
  g_progress_xferred = 0;
  g_progress_seen = 0;
  if (!g_progress_active) {
    /* `--info=flist` prints rsync's file-list header even without progress. */
    if (!config->quiet && info_flag_enabled(config, LOG_INFO_FLIST)) {
      printf("sending incremental file list\n");
      fflush(stdout);
    }
    return;
  }
  printf("sending incremental file list\n");
  /* rsync prints the transfer-root directory's name before the first file when
     that directory is created; FastSync mirrors the source root below the
     receive root and creates it on a fresh destination, so emit it here. */
  printf("./\n");
  fflush(stdout);
}

/* Emit the name (unless itemize/out-format already did) and the two progress
 * frames for one transferred regular file. */
static void client_progress_file(const Config* config, const File* file) {
  if (!g_progress_active || file == NULL || !file->data)
    return;
  g_progress_seen++;
  g_progress_xferred++;
  unsigned long long size = file->data->size;
  if (!config->itemize_changes && config->out_format == NULL) {
    const char* name = delete_display_path(config, file_wire_path(file));
    printf("%s\n", name ? name : "");
  }
  clock_gettime(CLOCK_MONOTONIC, &g_progress_file_start);
  char frame[160];
  progress_first_frame(size, frame, sizeof(frame));
  fputs(frame, stdout);
  progress_final_frame(size, frame, sizeof(frame));
  fputs(frame, stdout);
  fflush(stdout);
}

/* Compiled scanner inputs that are shared read-only across scanner instances
 * and, in -m mode, across worker threads. `base_filters` owns the compiled
 * command-line + -C rules; the FileListSet allow-set lives in the Config.
 * `hardlinks` owns the --hard-links/-H link-group detection table (NULL when
 * off) and is shared (mutex-guarded) across every scanner/worker of one scan. */
typedef struct {
  ScannerOptions options;
  FilterRuleList* base_filters; /* owned; may be NULL */
  HardLinkTable* hardlinks;     /* owned; may be NULL */
  char* relative_prefix;        /* owned -R prefix; may be NULL */
} PreparedScanner;

/* Build the scanner options for one scan. Returns false and logs on failure. */
static bool prepare_scanner(const Config* config, int num_threads, PreparedScanner* out) {
  if (!out)
    return false;
  out->base_filters = NULL;
  out->hardlinks = NULL;
  out->relative_prefix = NULL;
  memset(&out->options, 0, sizeof(out->options));

  int rule_count = config->filters ? config->filters->size : 0;
  const char** texts = NULL;
  if (rule_count > 0) {
    texts = malloc((size_t)rule_count * sizeof(char*));
    if (!texts) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed for filter rules");
      return false;
    }
    for (int i = 0; i < rule_count; i++)
      texts[i] = (const char*)config->filters->items[i];
  }
  if (rule_count > 0 || config->cvs_exclude) {
    char err[160];
    out->base_filters = filter_base_build(texts, rule_count, config->cvs_exclude,
                                          config->delete_excluded, err, sizeof(err));
    free(texts);
    if (!out->base_filters) {
      log_message(LOG_LEVEL_ERROR, "invalid filter rule: %s", err);
      return false;
    }
  } else {
    free(texts);
  }

  ScannerOptions* options = &out->options;
  options->use_metadata = config->use_metadata;
  options->preserve_atimes = config->preserve_atimes;
  options->preserve_crtimes = config->preserve_crtimes;
  options->preserve_xattrs = config->preserve_xattrs;
  options->preserve_acls = config->preserve_acls;
  options->chunk_size = config->chunk_size;
  /* --exclude/--include are compiled, in command-line order, into the SAME
   * ordered filter rule list as --filter/-f (see config_add_selection_rule), so
   * the legacy per-kind arrays are deliberately NOT passed to the scanner:
   * doing so would re-apply them with the old "excludes first, then includes as
   * a mandatory whitelist" precedence and defeat rsync's first-match-wins
   * ordering.  The arrays remain populated purely for the Config API surface. */
  options->exclude_patterns = NULL;
  options->exclude_count = 0;
  options->include_patterns = NULL;
  options->include_count = 0;
  options->max_size = config->max_size;
  options->min_size = config->min_size;
  options->max_depth = config->max_depth;
  options->num_threads = num_threads;
  options->follow_symlinks = config->follow_symlinks;
  options->copy_links = config->copy_links;
  options->safe_links = config->safe_links;
  options->copy_unsafe_links = config->copy_unsafe_links;
  options->copy_dirlinks = config->copy_dirlinks;
  options->munge_links = config->munge_links;
  options->checksum = config->checksum;
  options->one_file_system = config->one_file_system;
  options->preserve_devices = config->preserve_devices;
  options->preserve_specials = config->preserve_specials;
  options->copy_devices = config->copy_devices;
  options->file_list = (const FileListSet*)config->files_from_set;
  options->base_filters = out->base_filters;
  options->per_dir_filters = config->per_dir_filter;
  options->delete_excluded = config->delete_excluded;
  options->exclude_per_dir_filter_files = config->per_dir_filter_count >= 2;
  options->dirs = config->dirs;
  options->relative = config->relative;
  /* A real recursive transfer recreates empty source directories (rsync
     parity); low-level scanner users leave this off. */
  options->emit_empty_dirs = true;
  /* --no-implied-dirs only has meaning with -R (rsync): without it the option
     is a documented no-op, so the scanner must not suppress directory
     metadata. */
  options->no_implied_dirs = config->no_implied_dirs && config->relative;
  /* -R/--relative outside --files-from reconstructs every destination path from
   * the source spec (rsync's '/./' cut point).  With --files-from the listed
   * entry already supplies the bare relative path, so no prefix is built. */
  if (config->relative && config->files_from_set == NULL && config->send_directory) {
    out->relative_prefix = scanner_relative_prefix(config->send_directory);
    if (!out->relative_prefix) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed building --relative path prefix");
      filter_rule_list_free(out->base_filters);
      out->base_filters = NULL;
      return false;
    }
    options->relative_prefix = out->relative_prefix;
  }
  options->prune_empty_dirs = config->prune_empty_dirs;
  options->ignore_io_errors = config->ignore_errors;
  options->ignore_missing_args = config->ignore_missing_args || config->delete_missing_args;
  options->note_nonreg = (config->info_level & LOG_INFO_NONREG) != 0 && !config->quiet;
  options->send_directory = config->send_directory;
  options->eight_bit_output = config->eight_bit_output;
  options->excluded_paths = NULL;
  options->excluded_mutex = NULL;
  options->size_skipped_paths = NULL;
  options->synced_dirs = NULL;
  options->hardlinks = NULL;
  /* P7 Wave D: capture source directory metadata when a directory attribute is
     requested (-p for modes, -t for times unless -O omits them).  Whether they
     are APPLIED is decided receiver-side. */
  options->capture_dir_times = dir_metadata_should_capture(config);
  options->dir_entries = NULL;
  options->dir_entries_mutex = NULL;
  if (config->preserve_hard_links) {
    out->hardlinks = hardlink_table_create();
    if (!out->hardlinks) {
      filter_rule_list_free(out->base_filters);
      out->base_filters = NULL;
      return false;
    }
    options->hardlinks = out->hardlinks;
  }
  return true;
}

static void prepared_scanner_destroy(PreparedScanner* prepared) {
  if (!prepared)
    return;
  filter_rule_list_free(prepared->base_filters);
  prepared->base_filters = NULL;
  hardlink_table_destroy(prepared->hardlinks);
  prepared->hardlinks = NULL;
  free(prepared->relative_prefix);
  prepared->relative_prefix = NULL;
}

/* -R/--relative implied directories: rsync transmits the metadata of the
 * parent directories implied by the source path (every prefix component above
 * the source root) so the receiver applies their attributes to the created
 * parents.  FastSync's scan only covers the source root and below, so append
 * one metadata-only directory entry per implied ancestor.  --no-implied-dirs
 * suppresses this exactly like rsync.  A missing ancestor is never fatal. */
static bool append_implied_dir_times(const Config* config, ArrayList* dir_entries) {
  if (!dir_entries || !config->relative || config->files_from_set != NULL ||
      config->no_implied_dirs || !config->send_directory)
    return true;
  char* prefix = scanner_relative_prefix(config->send_directory);
  if (!prefix)
    return true;
  int ncomp = 0;
  for (const char* s = prefix; *s;) {
    while (*s == '/')
      s++;
    if (!*s)
      break;
    while (*s && *s != '/')
      s++;
    ncomp++;
  }
  if (ncomp <= 1) {
    free(prefix);
    return true;
  }
  char* fs = str_dup(config->send_directory);
  if (!fs) {
    free(prefix);
    return true;
  }
  size_t flen = strlen(fs);
  while (flen > 1 && fs[flen - 1] == '/')
    fs[--flen] = '\0';
  bool ok = true;
  /* Walk the source path upwards one component at a time (fs is truncated in
     place, so each step targets the next implied ancestor). */
  for (int depth = ncomp - 2; depth >= 0 && ok; depth--) {
    char* slash = strrchr(fs, '/');
    if (!slash || slash == fs)
      break;
    *slash = '\0';
    char* p = prefix;
    int c = 0;
    while (c <= depth) {
      while (*p == '/')
        p++;
      while (*p && *p != '/')
        p++;
      c++;
    }
    char saved = *p;
    *p = '\0';
    struct stat st;
    if (stat(fs, &st) == 0 && S_ISDIR(st.st_mode)) {
      File* file = file_create(fs);
      if (!file) {
        ok = false;
      } else {
        file->is_dir = true;
        file->metadata =
            file_metadata_create(fs, &st, config->preserve_atimes, config->preserve_crtimes);
        file->send_path = str_dup(prefix);
        if (!file->metadata || !file->send_path || !array_list_add(dir_entries, file)) {
          file_destroy(file);
          ok = false;
        }
      }
    }
    *p = saved;
  }
  free(fs);
  free(prefix);
  return ok;
}

/* The delete-walk root scope for a full (non---files-from) transfer: rsync
 * confines --delete to the directories it actually transferred.  A plain
 * recursive run mirrors the source under the receive root, so "." (the whole
 * tree) is correct; an -R run transfers only the reconstructed prefix subtree,
 * so the walk is scoped to that prefix instead.  Returns a malloc'd wire path
 * (or "."), or NULL on allocation failure. */
static char* delete_scope_root_marker(const Config* config) {
  if (config->relative && config->files_from_set == NULL && config->send_directory) {
    char* prefix = scanner_relative_prefix(config->send_directory);
    if (!prefix)
      return NULL;
    if (prefix[0] != '\0')
      return prefix;
    free(prefix);
  }
  return str_dup(".");
}

/* The -R destination prefix that confines a per-directory delete walk, or NULL
 * when the whole receive root is in scope.  The marker was installed into
 * `synced_dirs` by delete_scope_root_marker(); for a plain recursive transfer
 * it is "." (whole root) and for --files-from the list is not a single prefix. */
static const char* delete_plan_walk_root(const Config* config, const ArrayList* synced_dirs) {
  if (!config || config->files_from_set != NULL || !config->relative || !config->send_directory)
    return NULL;
  if (!synced_dirs || synced_dirs->size != 1)
    return NULL;
  const char* marker = (const char*)synced_dirs->items[0];
  if (marker[0] == '\0' || strcmp(marker, ".") == 0)
    return NULL;
  return marker;
}

/* The destination-relative mirror path for a missing --files-from entry: where
   a PRESENT entry with the same name would have been written.  With -R that is
   the entry's bare relative path (the bare wire path the receiver uses);
   otherwise it is the full source mirror below the destination root
   (`send_directory` joined to the entry, leading '/' stripped), exactly the
   path the manifest records for a present sibling.  Returns an owned string, or
   NULL on allocation failure. */
static char* files_from_missing_dest_path(const Config* config, const char* entry) {
  if (config->relative)
    return str_dup(entry);
  char* joined = path_cat(config->send_directory, entry);
  if (!joined)
    return NULL;
  const char* rel = *joined == '/' ? joined + 1 : joined;
  char* dup = str_dup(rel);
  free(joined);
  return dup;
}

/* --files-from semantics: every listed entry must resolve under the source
 * root, otherwise rsync reports a hard error instead of silently transferring
 * nothing. An entry of "." (the whole tree) and listed-but-empty directories
 * are valid.  An empty list is valid too: rsync transfers nothing and exits 0.
 * With --ignore-missing-args
 * (implied by --delete-missing-args) a listed-but-missing entry is instead
 * skipped: nothing is transferred for it, it never enters the keep-set and the
 * run succeeds for the rest (an all-missing non-empty list succeeds
 * transferring nothing, matching rsync).  With --delete-missing-args
 * `missing_dest` (when non-NULL) collects the entry's destination-relative
 * mirror for the receiver's exact-deletion request.  Runs before any
 * transfer so the failure/skip is surfaced uniformly in the single-threaded,
 * -m, dry-run and --list-only paths. */
static bool files_from_list_check(const Config* config, ArrayList* missing_dest, int* skipped_out) {
  *skipped_out = 0;
  const FileListSet* set = (const FileListSet*)config->files_from_set;
  if (!set)
    return true;
  if (!config->send_directory) {
    log_message(LOG_LEVEL_ERROR, "--files-from requires a source directory");
    return false;
  }
  if (set->count == 0) {
    /* rsync treats an empty --files-from list as "nothing to transfer" and
       exits 0 (the source directory is still a valid source arg), so this is
       not an error.  Nothing passes the (empty) allow-set, so no file is sent
       and no keep-set entry is produced. */
    return true;
  }
  bool ignore = config->ignore_missing_args || config->delete_missing_args;
  for (int i = 0; i < set->count; i++) {
    const char* entry = set->entries[i];
    if (entry[0] == '\0')
      continue; /* "." == list the whole tree */
    char* full = path_cat(config->send_directory, entry);
    if (!full) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed while validating --files-from");
      return false;
    }
    struct stat st;
    if (lstat(full, &st) != 0) {
      free(full);
      if (ignore) {
        (*skipped_out)++;
        char* escaped_entry = output_escape(entry, log_get_8_bit_output());
        log_info_message(LOG_INFO_MISC, "skipping missing --files-from entry '%s'",
                         escaped_entry ? escaped_entry : "<allocation failed>");
        free(escaped_entry);
        if (config->delete_missing_args && missing_dest) {
          char* mirror = files_from_missing_dest_path(config, entry);
          if (!mirror || !array_list_add(missing_dest, mirror)) {
            free(mirror);
            log_message(LOG_LEVEL_ERROR, "memory allocation failed while validating --files-from");
            return false;
          }
        }
        continue;
      }
      char* escaped_entry = output_escape(entry, log_get_8_bit_output());
      char* escaped_src = output_escape(config->send_directory, log_get_8_bit_output());
      log_message(LOG_LEVEL_ERROR, "--files-from entry '%s' not found in source '%s'",
                  escaped_entry ? escaped_entry : "<allocation failed>",
                  escaped_src ? escaped_src : "<allocation failed>");
      free(escaped_entry);
      free(escaped_src);
      return false;
    }
    free(full);
  }
  if (*skipped_out > 0) {
    if (config->delete_missing_args) {
      /* --list-only never deletes and a --dry-run only shows intent, so the
         summary must not claim a real deletion happened in those modes. */
      if (config->list_only)
        log_message(LOG_LEVEL_WARNING,
                    "--delete-missing-args: %d missing --files-from entr%s skipped (--list-only "
                    "never deletes)",
                    *skipped_out, *skipped_out == 1 ? "y" : "ies");
      else if (config->dry_run)
        log_message(LOG_LEVEL_WARNING,
                    "--delete-missing-args: %d missing --files-from entr%s would be deleted from "
                    "the destination (dry run)",
                    *skipped_out, *skipped_out == 1 ? "y" : "ies");
      else
        log_message(
            LOG_LEVEL_WARNING,
            "--delete-missing-args: %d missing --files-from entr%s will be deleted from the "
            "destination",
            *skipped_out, *skipped_out == 1 ? "y" : "ies");
    } else if (config->ignore_missing_args)
      log_message(LOG_LEVEL_WARNING,
                  "--ignore-missing-args: ignored %d missing --files-from entr%s", *skipped_out,
                  *skipped_out == 1 ? "y" : "ies");
  }
  return true;
}

/* Basis directories are honored by the receiver's per-file incremental check,
   which (like every whole-file payload path in FastSync) is bounded by
   MAX_RECEIVE_WHOLE_FILE_SIZE.  rsync would apply basis dirs to files of any
   size; FastSync cannot, so when basis dirs are requested this preflight scan
   refuses the run up front with a clear diagnostic instead of letting the
   receiver abort the whole transfer mid-stream with no client explanation.
   Returns true when the tree can be transferred. */
static bool basis_oversize_preflight(const Config* config) {
  PreparedScanner prepared;
  if (!prepare_scanner(config, 0, &prepared))
    return false;
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner) {
    prepared_scanner_destroy(&prepared);
    return false;
  }
  bool ok = true;
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count; i++) {
      File* f = chunk->items[i];
      if (f == NULL || f->is_dir || f->data == NULL || f->data->size <= MAX_RECEIVE_WHOLE_FILE_SIZE)
        continue;
      char* escaped = output_escape(file_wire_path(f), config->eight_bit_output);
      log_message(LOG_LEVEL_ERROR,
                  "%s is %llu bytes, larger than the %llu-byte whole-file transfer limit; "
                  "--compare-dest/--copy-dest/--link-dest cannot sync files above this limit",
                  escaped ? escaped : "<allocation failed>", (unsigned long long)f->data->size,
                  (unsigned long long)MAX_RECEIVE_WHOLE_FILE_SIZE);
      free(escaped);
      ok = false;
      break;
    }
    chunk_destroy(chunk);
    if (!ok)
      break;
  }
  if (directory_scanner_failed(scanner) || directory_scanner_had_io_error(scanner))
    ok = false;
  /* The scanner borrows prepared.options' base_filters/hardlinks pointers, so
     prepared must outlive the scanner. */
  directory_scanner_destroy(scanner);
  prepared_scanner_destroy(&prepared);
  return ok;
}

/* Read the daemon's MOTD frame and, unless --no-motd, display it on stdout.
 *
 * The daemon sends the MOTD as the first thing after the config-frame STATUS_OK
 * on a host::module/path connection (rsync semantics), so this runs immediately
 * after config_send succeeds.  The frame is ALWAYS consumed for a daemon
 * connection -- even with --no-motd -- so the byte stream stays in sync; the
 * flag only suppresses the display.  A non-daemon (local TCP / SSH) connection
 * has no MOTD frame.  The text is rendered through motd_render so a hostile
 * server cannot inject terminal escape sequences.  A read failure is not fatal
 * here: the transfer that follows surfaces the real connection error. */
static void receive_daemon_motd(Client* client, const Config* config) {
  if (!config->module || config->module[0] == '\0')
    return;
  char* motd = motd_receive(client->file_descriptor);
  if (!motd)
    return;
  if (!config->no_motd && motd[0] != '\0') {
    char* rendered = motd_render(motd, config->eight_bit_output);
    if (rendered) {
      fputs(rendered, stdout);
      size_t length = strlen(rendered);
      if (length == 0 || rendered[length - 1] != '\n')
        fputc('\n', stdout);
      fflush(stdout);
      free(rendered);
    }
  }
  free(motd);
}

/* Select the configured transport for both transfer execution paths. */
static Client* connect_transfer_client(const Config* config) {
  if (config->transport == TRANSPORT_SSH) {
    if (config->use_sendfile) {
      log_message(LOG_LEVEL_ERROR, "--sendfile is not supported with SSH transport");
      return NULL;
    }
    return client_connect_ssh(config->ssh_destination, config->ssh_port,
                              config->fastsync_server_path, config->old_args, config->rsh_command,
                              config->blocking_io, config->remote_options,
                              config->remote_option_count);
  }

  Client* client = client_create();
  if (!client)
    return NULL;
  /* Socket/connect concerns that never cross the wire: --address (source bind),
   * -4/-6 (family pinning), and --sockopts.  Passed straight to the TCP layer. */
  TcpConnectOptions connect_opts;
  connect_opts.bind_address = config->address;
  connect_opts.family = tcp_connect_family(config->ipv4, config->ipv6);
  connect_opts.sockopts = config->sockopts;
  connect_opts.sockopt_count = config->sockopt_count;
  bool connected;
  if (config->use_tls) {
    connected =
        client_connect_tls_ex(client, config->server_host, config->server_port, config->tls_cert,
                              config->tls_key, config->tls_ca, &connect_opts);
  } else {
    connected = client_connect_ex(client, config->server_host, config->server_port, &connect_opts);
  }
  if (!connected) {
    client_disconnect(client);
    client_delete(client);
    return NULL;
  }
  return client;
}

static void disconnect_transfer_client(Client* client) {
  if (!client)
    return;
  client_disconnect(client);
  client_delete(client);
}

/* True when --dry-run should contact a receiver rather than running the
 * client-side local manifest.  Any target a real run would reach over the wire
 * selects the server-contacting path: a remote (SSH host:path), a daemon
 * (host::module/path), an explicit --server-host, --server-port/--port, TLS, or
 * a source-bind --address.  A plain local destination (none of these) keeps the
 * original client-side behavior, which never dials the default 127.0.0.1:8080. */
static bool dry_run_targets_server(const Config* config) {
  if (!config)
    return false;
  if (config->transport == TRANSPORT_SSH)
    return true;
  if (config->module && config->module[0] != '\0')
    return true;
  if (config->server_host_set || config->server_port_set)
    return true;
  if (config->use_tls)
    return true;
  if (config->address != NULL)
    return true;
  return false;
}

static bool add_chunk_to_manifest(ArrayList* manifest, const Chunk* chunk) {
  if (!manifest)
    return true;
  for (int i = 0; i < chunk->element_count; i++) {
    const char* path = file_wire_path(chunk->items[i]);
    if (*path == '/')
      path++;
    char* entry = str_dup(path);
    if (!entry) {
      log_message(LOG_LEVEL_ERROR, "Failed to allocate manifest entry");
      return false;
    }
    if (!array_list_add(manifest, entry)) {
      free(entry);
      return false;
    }
  }
  return true;
}

/* (finalize_transfer is defined after the SourceFile helpers below.) */

typedef struct SourceFile {
  char* path;
  dev_t device;
  ino_t inode;
  bool skipped; /* receiver reported the file was not written */
} SourceFile;

static void source_file_destroy(void* item) {
  SourceFile* source = item;
  if (source) {
    free(source->path);
    free(source);
  }
}

static const char* delete_display_path(const Config* config, const char* path);

/* Remove only the same regular source file that was sent. */
static void remove_transferred_sources(const Config* config, ArrayList* paths) {
  if (!config->remove_source_files || !paths)
    return;
  for (int i = 0; i < paths->size; i++) {
    SourceFile* source = paths->items[i];
    if (source->skipped)
      continue;
    const char* slash = strrchr(source->path, '/');
    const char* leaf = slash ? slash + 1 : source->path;
    char parent[PATH_MAX];
    if (slash) {
      size_t parent_length = (size_t)(slash - source->path);
      if (parent_length == 0)
        parent_length = 1;
      if (parent_length >= sizeof(parent))
        continue;
      memcpy(parent, source->path, parent_length);
      parent[parent_length] = '\0';
    } else {
      (void)snprintf(parent, sizeof(parent), ".");
    }

    int dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
      continue;
    struct stat st;
    if (fstatat(dirfd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode) ||
        st.st_dev != source->device || st.st_ino != source->inode) {
      close(dirfd);
      continue;
    }
    if (unlinkat(dirfd, leaf, 0) != 0) {
      char* escaped_path = output_escape(source->path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING, "Could not remove source file %s",
                  escaped_path ? escaped_path : "<allocation failed>");
      free(escaped_path);
    } else if (info_flag_enabled(config, LOG_INFO_REMOVE) && !config->quiet) {
      /* rsync's --info=remove line: the transfer-relative name. */
      const char* rel = delete_display_path(config, source->path);
      char* escaped = output_escape(rel, config->eight_bit_output);
      printf("sender removed %s\n", escaped ? escaped : rel);
      free(escaped);
      fflush(stdout);
    }
    close(dirfd);
  }
}

static SourceFile* source_file_create(const File* file) {
  if (!file || !file->path)
    return NULL;
  struct stat st;
  if (lstat(file->path, &st) != 0 || !S_ISREG(st.st_mode))
    return NULL;
  SourceFile* source = malloc(sizeof(*source));
  if (!source)
    return NULL;
  source->path = str_dup(file->path);
  source->device = st.st_dev;
  source->inode = st.st_ino;
  source->skipped = false;
  if (!source->path) {
    source_file_destroy(source);
    return NULL;
  }
  return source;
}

static bool remember_source_file(ArrayList* paths, const File* file) {
  if (!paths || !file || !file->path)
    return true;
  SourceFile* source = source_file_create(file);
  if (!source)
    return true;
  if (!array_list_add(paths, source)) {
    source_file_destroy(source);
    return false;
  }
  return true;
}

static void mark_sender_done(PipelineContextSender* context) {
  mtx_lock(&context->mutex_progress);
  context->sender_done = true;
  mtx_unlock(&context->mutex_progress);
}

/* Read the optional STATUS_STATS record (protocol 2.25.0) that the receiver
 * sends just before its terminal status when report_stats was negotiated.
 * Consumes the would-delete path list into `would_delete` (optional). */
static bool receive_stats_record(int fd, ReceiverStats* stats, ArrayList* would_delete) {
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
static const char* delete_display_path(const Config* config, const char* path) {
  if (!config || !path || !config->send_directory)
    return path;
  const char* root = config->send_directory;
  while (*root == '/')
    root++;
  const char* rel = path;
  while (*rel == '/')
    rel++;
  size_t root_len = strlen(root);
  while (root_len > 0 && root[root_len - 1] == '/')
    root_len--;
  if (root_len == 0)
    return rel;
  if (strncmp(rel, root, root_len) == 0 && (rel[root_len] == '/' || rel[root_len] == '\0'))
    return rel + root_len + (rel[root_len] == '/' ? 1 : 0);
  return rel;
}

/* Send the final STATUS_FINISHED frame and await the receiver's verdict.
   When --remove-source-files is active the receiver acknowledges each data
   file it processed, in send order: STATUS_NEXT means the file was written,
   STATUS_OK means the file was skipped/unchanged.  Skipped sources are marked
   so the later removal pass keeps them. */
static bool finalize_transfer(Client* client, const Config* config, ArrayList* remove_sources,
                              bool* delete_limit_out, ReceiverStats* stats_out) {
  if (delete_limit_out)
    *delete_limit_out = false;
  if (!send_status(client->file_descriptor, STATUS_FINISHED))
    return false;
  /* The receiver emits its optional wire-stats frame (protocol 2.25.0) FIRST,
     then any per-file --remove-source-files acks, then the terminal status. */
  Status status;
  if (!receive_status(client->file_descriptor, &status))
    return false;
  if (status == STATUS_STATS) {
    ReceiverStats scratch;
    /* A real --info=del run carries the actually-removed paths in the stats
       frame's path list; collect and print them in rsync's format. */
    ArrayList* deleted = config->report_deletes ? array_list_create(free) : NULL;
    if (config->report_deletes && !deleted)
      return false;
    if (!receive_stats_record(client->file_descriptor, stats_out ? stats_out : &scratch, deleted)) {
      array_list_delete(deleted);
      return false;
    }
    if (deleted) {
      print_delete_reports(config, deleted);
      array_list_delete(deleted);
    }
    if (!receive_status(client->file_descriptor, &status))
      return false;
  }
  if (config->remove_source_files && remove_sources && remove_sources->size > 0) {
    for (int i = 0; i < remove_sources->size; i++) {
      if (i > 0 && !receive_status(client->file_descriptor, &status))
        return false;
      if (status == STATUS_ERROR) {
        log_server_rejection("Receiver reported a per-file error");
        return false;
      }
      if (status == STATUS_OK) {
        ((SourceFile*)remove_sources->items[i])->skipped = true;
      } else if (status != STATUS_NEXT) {
        log_message(LOG_LEVEL_ERROR, "Unexpected per-file status from receiver");
        return false;
      }
    }
    if (!receive_status(client->file_descriptor, &status))
      return false;
  }
  /* A capped --max-delete commit is a successful transfer that the client must
     report with rsync's exit code 25 (not an error). */
  if (status == STATUS_DELETE_LIMIT) {
    log_message(LOG_LEVEL_ERROR,
                "Deletions stopped due to --max-delete limit; some deletions were skipped");
    if (delete_limit_out)
      *delete_limit_out = true;
    return true;
  }
  if (status != STATUS_OK) {
    log_server_rejection("Receiver reported transfer failure");
    return false;
  }
  return true;
}

static void pipeline_cancel(PipelineContextSender* context) {
  mtx_lock(&context->mutex_scanner);
  mtx_lock(&context->mutex_loader);
  atomic_store(&context->cancelled, true);
  context->scanner_done = true;
  context->loader_done = true;
  cnd_broadcast(&context->condition_not_full_scanner);
  cnd_broadcast(&context->condition_not_empty_scanner);
  cnd_broadcast(&context->condition_not_full_loader);
  cnd_broadcast(&context->condition_not_empty_loader);
  mtx_unlock(&context->mutex_loader);
  mtx_unlock(&context->mutex_scanner);
}

/* Print dry-run manifest showing files that would be transferred. Returns 0 on success. */
static int send_dry_run_manifest(const Config* config) {
  int skipped = 0;
  ArrayList* missing_dest = NULL;
  if (config->delete_missing_args) {
    missing_dest = array_list_create(free);
    if (!missing_dest)
      return -1;
  }
  if (!files_from_list_check(config, missing_dest, &skipped)) {
    if (missing_dest)
      array_list_delete(missing_dest);
    return -1;
  }
  PreparedScanner prepared;
  if (!prepare_scanner(config, 0, &prepared)) {
    if (missing_dest)
      array_list_delete(missing_dest);
    return -1;
  }
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner) {
    prepared_scanner_destroy(&prepared);
    if (missing_dest)
      array_list_delete(missing_dest);
    return -1;
  }
  Chunk* chunk;
  int file_count = 0;
  unsigned long long total_bytes = 0;
  char size_buffer[32];
  if (!config->quiet)
    printf("Dry run: files to be transferred\n");
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count; i++) {
      if (!config->quiet) {
        char* escaped_path =
            output_escape(file_wire_path(chunk->items[i]), config->eight_bit_output);
        if (!escaped_path) {
          chunk_destroy(chunk);
          directory_scanner_destroy(scanner);
          prepared_scanner_destroy(&prepared);
          if (missing_dest)
            array_list_delete(missing_dest);
          return -1;
        }
        if (config->human_readable)
          printf(
              "  %s (%s)\n", escaped_path,
              display_bytes(chunk->items[i]->data->size, true, size_buffer, sizeof(size_buffer)));
        else
          printf("  %s (%zu bytes)\n", escaped_path, chunk->items[i]->data->size);
        free(escaped_path);
      }
      total_bytes += chunk->items[i]->data->size;
      file_count++;
    }
    chunk_destroy(chunk);
  }
  directory_scanner_destroy(scanner);
  prepared_scanner_destroy(&prepared);
  /* --delete-missing-args: the missing entries' destination mirrors render as
     would-be deletions (rsync's dry-run also lists its *deleting lines). */
  if (missing_dest && !config->quiet) {
    for (int i = 0; i < missing_dest->size; i++) {
      char* escaped = output_escape((char*)missing_dest->items[i], config->eight_bit_output);
      printf("  %s (missing; would be deleted)\n", escaped ? escaped : "<allocation failed>");
      free(escaped);
    }
  }
  if (missing_dest)
    array_list_delete(missing_dest);
  if (!config->quiet) {
    if (config->human_readable)
      printf("Total: %d files, %s\n", file_count,
             display_bytes(total_bytes, true, size_buffer, sizeof(size_buffer)));
    else
      printf("Total: %d files, %.1f MB\n", file_count, (double)total_bytes / (double)BYTES_PER_MIB);
  }
  return 0;
}

typedef struct {
  char* name; /* transfer-relative name ("" == the source root) */
  mode_t mode;
  unsigned long long size;
  time_t mtime;
  long mtime_nsec;
  bool is_dir;
  bool is_symlink;
  char* link_target;
} ListEntry;

static void list_entries_destroy(ListEntry* entries, size_t count) {
  if (entries == NULL)
    return;
  for (size_t i = 0; i < count; i++) {
    free(entries[i].name);
    free(entries[i].link_target);
  }
  free(entries);
}

static int compare_list_entries(const void* left, const void* right) {
  const ListEntry* a = (const ListEntry*)left;
  const ListEntry* b = (const ListEntry*)right;
  return strcmp(a->name, b->name);
}

/* Relative path of an entry below `root` ("" for the root itself).  Mirrors
 * change_list's relative_name for list-only rendering. */
static char* list_relative_name(const char* root, const char* full) {
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

/* --list-only: print an ls-style listing of the entries that WOULD be
 * transferred and exit without contacting the server or writing anything.
 * Names are transfer-relative (rsync prints `a.txt`, `sub/b.txt`, `.`) and
 * directory entries are included.  Returns 0 on success, 1 on error. */
static int send_list_only(const Config* config) {
  int skipped = 0;
  if (!files_from_list_check(config, NULL, &skipped))
    return 1;
  PreparedScanner prepared;
  if (!prepare_scanner(config, 0, &prepared))
    return 1;
  prepared.options.use_metadata = true; /* capture mode + mtime for the listing */
  prepared.options.list_dirs = true;
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner) {
    prepared_scanner_destroy(&prepared);
    return 1;
  }
  ListEntry* entries = NULL;
  size_t count = 0;
  size_t capacity = 0;
  bool oom = false;

  /* rsync lists the source root itself (as ".").  Only when the source is a
   * directory and no --files-from subset is in effect. */
  if (config->files_from_set == NULL && config->send_directory != NULL) {
    struct stat st;
    if (stat(config->send_directory, &st) == 0 && S_ISDIR(st.st_mode)) {
      capacity = 64;
      entries = calloc(capacity, sizeof(ListEntry));
      if (entries == NULL) {
        oom = true;
      } else if ((entries[0].name = str_dup("")) == NULL) {
        /* A NULL name would be dereferenced by qsort/render: fail the listing. */
        oom = true;
      } else {
        entries[0].mode = st.st_mode;
        entries[0].mtime = st.st_mtime;
        entries[0].mtime_nsec = st.st_mtim.tv_nsec;
        entries[0].size = (unsigned long long)st.st_size;
        entries[0].is_dir = true;
        count = 1;
      }
    }
  }

  Chunk* chunk;
  while (!oom && (chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count; i++) {
      File* f = chunk->items[i];
      if (f == NULL)
        continue;
      if (count == capacity) {
        size_t new_capacity = capacity > 0 ? capacity * 2 : 64;
        if (new_capacity <= capacity) {
          oom = true;
          break;
        }
        ListEntry* grown = realloc(entries, new_capacity * sizeof(ListEntry));
        if (!grown) {
          oom = true;
          break;
        }
        entries = grown;
        memset(entries + capacity, 0, (new_capacity - capacity) * sizeof(ListEntry));
        capacity = new_capacity;
      }
      char* name = list_relative_name(config->send_directory, file_wire_path(f));
      if (!name) {
        oom = true;
        break;
      }
      mode_t mode = 0;
      time_t mtime = 0;
      long mtime_nsec = 0;
      if (f->metadata != NULL) {
        mode = f->metadata->mode;
        mtime = f->metadata->mtime_sec;
        mtime_nsec = f->metadata->mtime_nsec;
      } else {
        struct stat st;
        if (lstat(f->path, &st) == 0) {
          mode = st.st_mode;
          mtime = st.st_mtime;
          mtime_nsec = st.st_mtim.tv_nsec;
        }
      }
      entries[count].name = name;
      entries[count].mode = mode;
      entries[count].mtime = mtime;
      entries[count].mtime_nsec = mtime_nsec;
      if (f->is_symlink)
        entries[count].size = f->symlink_target != NULL ? strlen(f->symlink_target) : 0;
      else if (f->is_dir) {
        struct stat dir_st;
        entries[count].size = stat(f->path, &dir_st) == 0 ? (unsigned long long)dir_st.st_size : 0;
      } else
        entries[count].size = f->data != NULL ? f->data->size : 0;
      entries[count].is_dir = f->is_dir;
      entries[count].is_symlink = f->is_symlink;
      entries[count].link_target =
          f->is_symlink && f->symlink_target ? str_dup(f->symlink_target) : NULL;
      count++;
    }
    chunk_destroy(chunk);
  }
  bool failed = oom || directory_scanner_failed(scanner) || directory_scanner_had_io_error(scanner);
  directory_scanner_destroy(scanner);
  prepared_scanner_destroy(&prepared);
  if (failed) {
    list_entries_destroy(entries, count);
    if (oom)
      log_message(LOG_LEVEL_ERROR, "memory allocation failed while listing");
    return 1;
  }
  if (count > 1)
    qsort(entries, count, sizeof(ListEntry), compare_list_entries);
  for (size_t i = 0; i < count; i++) {
    ChangeEvent event;
    memset(&event, 0, sizeof(event));
    event.name = entries[i].name;
    event.path = entries[i].name;
    event.mode = entries[i].mode;
    event.size = entries[i].size;
    event.mtime_sec = entries[i].mtime;
    event.mtime_nsec = entries[i].mtime_nsec;
    event.is_directory = entries[i].is_dir;
    event.is_symlink = entries[i].is_symlink;
    event.symlink_target = entries[i].link_target;
    char* line = change_render_list_line(config, &event);
    if (line != NULL) {
      char* escaped = output_escape(line, config->eight_bit_output);
      printf("%s\n", escaped != NULL ? escaped : line);
      free(escaped);
      free(line);
    }
  }
  list_entries_destroy(entries, count);
  return 0;
}

/* Send the delete manifest to the server.  Returns 0 on success, -1 on
   failure.  It carries FOUR sections: the keep-set paths, the protected
   excluded prefixes, the --delete-missing-args exact-delete paths, and the
   destination-relative directories the sender synchronized this run.
   When --delete-excluded is given `protected` is empty: excluded destination
   mirrors are then ordinary extras and are removed.  When
   --delete-missing-args is active `missing_args` holds the destination mirrors
   of missing --files-from entries: each is an explicit receiver-side deletion
   request, independent of the extras walk.  `synced_dirs` confines the extras
   walk to entries directly inside a synchronized directory.  A NULL
   keep-set / protected / missing / dirs list transmits an empty section.  All
   four sections are unbounded on the sender; the receiver enforces
   MAX_MANIFEST_ENTRIES per section and a single MAX_MANIFEST_BYTES budget
   shared across the sections, rejecting (with STATUS_ERROR) an over-budget
   frame.  A heavily filtered source whose exclusion list is large therefore
   fails the run cleanly on the receiver rather than being truncated. */
static int send_delete_manifest(int fd, ArrayList* manifest, ArrayList* protected_prefixes,
                                ArrayList* size_skipped, ArrayList* missing_args,
                                ArrayList* synced_dirs) {
  if (!send_status(fd, STATUS_MANIFEST))
    return -1;
  int keep_count = manifest ? manifest->size : 0;
  if (!send_int(fd, keep_count))
    return -1;
  for (int i = 0; i < keep_count; i++) {
    if (!send_wire_str(fd, (char*)manifest->items[i]))
      return -1;
  }
  /* The receiver has ONE protected-prefix section; filter-excluded prefixes
     (dropped under --delete-excluded) and size-pruned prefixes (always
     protected) are concatenated into it. */
  int protected_count =
      (protected_prefixes ? protected_prefixes->size : 0) + (size_skipped ? size_skipped->size : 0);
  if (!send_int(fd, protected_count))
    return -1;
  if (protected_prefixes) {
    for (int i = 0; i < protected_prefixes->size; i++) {
      if (!send_wire_str(fd, (char*)protected_prefixes->items[i]))
        return -1;
    }
  }
  if (size_skipped) {
    for (int i = 0; i < size_skipped->size; i++) {
      if (!send_wire_str(fd, (char*)size_skipped->items[i]))
        return -1;
    }
  }
  int missing_count = missing_args ? missing_args->size : 0;
  if (!send_int(fd, missing_count))
    return -1;
  for (int i = 0; i < missing_count; i++) {
    if (!send_wire_str(fd, (char*)missing_args->items[i]))
      return -1;
  }
  int dirs_count = synced_dirs ? synced_dirs->size : 0;
  if (!send_int(fd, dirs_count))
    return -1;
  for (int i = 0; i < dirs_count; i++) {
    if (!send_wire_str(fd, (char*)synced_dirs->items[i]))
      return -1;
  }
  return 0;
}

/* Transmit the keep-set manifest and wait for the receiver's verdict.  Used by
   --delete-before/--delete-during, where the extras are removed on the receiver
   BEFORE the first byte of file data is sent: the receiver acknowledges with
   STATUS_OK once the bounded delete committed, or STATUS_ERROR if it could not
   (in which case the sender aborts without streaming any data).  The ACK may
   take much longer than an ordinary per-message round trip because the receiver
   performs the whole bounded deletion walk (up to MAX_SERVER_DELETE_COUNT
   unlinks) before replying, so the wait uses a generous explicit deadline
   instead of the default 60 s receive window. */
#define DELETE_ACK_TIMEOUT_SEC 3600
/* While waiting for the (potentially slow) receiver-side deletion, send a
 * STATUS_KEEPALIVE at most this often so the connection is demonstrably alive
 * and neither side's per-message timeout trips. */
#define DELETE_ACK_KEEPALIVE_SEC 10

static bool send_delete_manifest_early(Client* client, ArrayList* manifest,
                                       ArrayList* protected_prefixes, ArrayList* size_skipped,
                                       ArrayList* missing_args, ArrayList* synced_dirs) {
  if (!client || !manifest)
    return false;
  if (send_delete_manifest(client->file_descriptor, manifest, protected_prefixes, size_skipped,
                           missing_args, synced_dirs) != 0)
    return false;
  Status ack;
  /* The wait is long (up to an hour) and runs inline on this thread: a helper
   * thread would race the non-thread-safe protocol send path, so keepalives are
   * emitted from this wait loop itself.  A Ctrl-C/SIGTERM abort flag also ends
   * the wait; the caller then best-effort sends STATUS_ABORT. */
  if (!receive_status_keepalive(client->file_descriptor, &ack, DELETE_ACK_TIMEOUT_SEC,
                                DELETE_ACK_KEEPALIVE_SEC, client_abort_pending)) {
    /* A Ctrl-C/SIGTERM abort ends the wait above; tell the receiver before the
       caller tears the connection down (best-effort). */
    if (client_abort_pending()) {
      log_info_message(LOG_INFO_MISC,
                       "Abort requested while awaiting delete ack; sending STATUS_ABORT");
      send_status(client->file_descriptor, STATUS_ABORT);
    }
    return false;
  }
  if (ack != STATUS_OK) {
    log_server_rejection("Server failed to delete files before the transfer");
    return false;
  }
  return true;
}

/* Walk the whole source tree once collecting only destination-relative wire
   paths, loading and sending nothing.  --delete-before/--delete-during need the
   complete keep-set manifest before the first data byte, so it is built by a
   dedicated pre-scan pass and transmitted early; the data pass then re-scans
   with a fresh scanner.  A source I/O error is fatal unless the options carry
   --ignore-errors, in which case the scan continues past the unreadable
   directory and *io_error_out reports it (the caller still performs the
   deletion but reports the run as errored). */
static bool scan_paths_only(const Config* config, const ScannerOptions* options,
                            ArrayList* manifest, DeletePlanSender* plans, bool* io_error_out) {
  if (io_error_out)
    *io_error_out = false;
  ScannerOptions local = *options;
  /* The pre-scan is a paths-only pass with no client output; it must not emit
     --info=nonreg lines (the data pass does that once). */
  local.note_nonreg = false;
  DirectoryScanner* scanner = directory_scanner_create_with_options(config->send_directory, &local);
  if (!scanner)
    return false;
  bool ok = true;
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    if (manifest && !add_chunk_to_manifest(manifest, chunk)) {
      ok = false;
      chunk_destroy(chunk);
      break;
    }
    if (plans) {
      for (int i = 0; i < chunk->element_count; i++) {
        File* f = chunk->items[i];
        if (!f)
          continue;
        const char* path = file_wire_path(f);
        if (!delete_plan_sender_add(plans, path, f->is_dir)) {
          ok = false;
          break;
        }
      }
      if (!ok) {
        chunk_destroy(chunk);
        break;
      }
    }
    chunk_destroy(chunk);
  }
  if (ok) {
    /* Keep every traversed source directory, including empty ones, so a plan
       no longer removes the destination directory itself.  Their own plans are
       emitted after the data stream (no file frame triggers them). */
    if (plans && options->plan_dirs) {
      for (int i = 0; i < options->plan_dirs->size; i++) {
        if (!delete_plan_sender_add(plans, (const char*)options->plan_dirs->items[i], true)) {
          ok = false;
          break;
        }
      }
    }
  }
  if (ok && directory_scanner_failed(scanner))
    ok = false;
  if (io_error_out)
    *io_error_out = directory_scanner_had_io_error(scanner);
  directory_scanner_destroy(scanner);
  return ok;
}

/* Transmit any not-yet-sent per-directory delete plan needed by the entries in
 * `chunk` (ancestors root-first, then the entry's own directory for --dirs
 * entries) before its data frames go out, so --delete-during/--delete-delay
 * clear a directory's extras (and any type conflict) before the directory's
 * first write. */
static int send_chunk_delete_plans(Client* client, DeletePlanSender* plans, const Chunk* chunk) {
  if (!plans)
    return 0;
  for (int i = 0; i < chunk->element_count; i++) {
    File* f = chunk->items[i];
    if (!f)
      continue;
    if (delete_plan_send_for_path(client->file_descriptor, plans, file_wire_path(f), f->is_dir) !=
        0)
      return -1;
  }
  return 0;
}

static int incremental_check(Client* client, File* file, const Config* config,
                             DeltaSignature** out_sig, unsigned long long* resume_offset) {
  *out_sig = NULL;
  if (resume_offset)
    *resume_offset = 0;
  if (!send_status(client->file_descriptor, STATUS_CHECK))
    return -1;
  if (!send_wire_str(client->file_descriptor, file_wire_path(file)))
    return -1;
  unsigned long long fsize = file->data->size;
  long long mtime = file->metadata ? file->metadata->mtime_sec : 0;
  long long mtime_nsec = file->metadata ? file->metadata->mtime_nsec : 0;
  if (!send_n_data(client->file_descriptor, &fsize, sizeof(fsize)))
    return -1;
  if (!send_n_data(client->file_descriptor, &mtime, sizeof(mtime)))
    return -1;
  if (!send_n_data(client->file_descriptor, &mtime_nsec, sizeof(mtime_nsec)))
    return -1;
  /* With alternate basis directories the receiver must be able to verify the
   * content of every candidate basis file, so the sender supplies its whole-file
   * digest (computed with the negotiated --checksum-choice algorithm and
   * --checksum-seed) for every file even when --checksum was not requested. */
  if (config->checksum || config_has_basis(config)) {
    uint8_t digest[CHECKSUM_MAX_DIGEST_LEN];
    size_t digest_len = 0;
    if (!file_checksum(file, (ChecksumAlgo)config->checksum_algo, config->checksum_seed, digest,
                       sizeof(digest), &digest_len))
      return -1;
    uint8_t wire_len = (uint8_t)digest_len;
    if (!send_n_data(client->file_descriptor, &wire_len, sizeof(wire_len)) ||
        !send_n_data(client->file_descriptor, digest, wire_len))
      return -1;
  }
  Status s;
  if (!receive_status(client->file_descriptor, &s))
    return -1;
  /* Output parity: when dest-info reporting is negotiated the receiver sends
   * the pre-transfer destination snapshot BEFORE its ordinary verdict.  Consume
   * it here so the following status read stays in sync. */
  if (config->report_dest_info) {
    if (s != STATUS_DEST_INFO ||
        !format_dest_state_receive(client->file_descriptor, &file->dest_state)) {
      log_message(LOG_LEVEL_ERROR, "Unexpected reply to the destination-state report");
      send_status(client->file_descriptor, STATUS_ERROR);
      return -1;
    }
    if (!receive_status(client->file_descriptor, &s))
      return -1;
  }
  if (s == STATUS_ERROR) {
    log_server_rejection("Server reported error for file");
    return -1;
  }
  if (s == STATUS_OK)
    return 1;
  if (s == STATUS_DELTA_SIGNATURE) {
    Data* sig_data = receive_data(client->file_descriptor);
    if (!sig_data) {
      send_status(client->file_descriptor, STATUS_ERROR);
      return -1;
    }
    DeltaSignature* sig = delta_signature_deserialize(sig_data);
    data_destroy(sig_data);
    if (!sig) {
      send_status(client->file_descriptor, STATUS_ERROR);
      return -1;
    }
    *out_sig = sig;
    return 2;
  }
  if (s == STATUS_APPEND) {
    /* --append / --append-verify tail resume: the receiver found an existing
       destination SHORTER than the source and wants only the tail from this
       offset (the bytes it already holds). */
    unsigned long long offset;
    if (!receive_n_data(client->file_descriptor, &offset, sizeof(offset))) {
      send_status(client->file_descriptor, STATUS_ERROR);
      return -1;
    }
    if (resume_offset)
      *resume_offset = offset;
    return 3;
  }
  /* Server-contacting --dry-run: the receiver decided the file is not up to
     date and answered "would transfer" WITHOUT expecting any data.  Treat it as
     the dry-run code ONLY when this session actually requested dry-run.  A
     hostile/buggy peer that emits it outside dry-run is a protocol error: fail
     closed (and send STATUS_ERROR) rather than fall through to the normal path,
     which would transmit file data the receiver is not reading and desync. */
  if (s == STATUS_DRY_RUN_TRANSFER) {
    if (config->dry_run)
      return 4;
    log_message(LOG_LEVEL_ERROR, "Unexpected DRY_RUN_TRANSFER status outside a --dry-run session");
    send_status(client->file_descriptor, STATUS_ERROR);
    return -1;
  }
  if (s != STATUS_NEXT) {
    log_server_rejection("Unexpected server status");
    send_status(client->file_descriptor, STATUS_ERROR);
    return -1;
  }
  return 0;
}

static int send_delta(Client* client, File* file, DeltaSignature* sig, Config* config) {
  Delta* delta = delta_compute_seeded(file->data->data, file->data->size, sig,
                                      config->delta_block_size, (uint32_t)config->checksum_seed);
  /* The receiver is blocked after sending the signature.  Every local
     fallback therefore needs the explicit NEXT response before full data. */
  if (!delta)
    return send_status(client->file_descriptor, STATUS_NEXT) ? 1 : -1;

  if (!delta_is_worthwhile(delta, file->data->size)) {
    delta_destroy(delta);
    if (!send_status(client->file_descriptor, STATUS_NEXT))
      return -1;
    return 1;
  }

  Data* delta_data = delta_serialize(delta);
  delta_destroy(delta);
  if (!delta_data)
    return send_status(client->file_descriptor, STATUS_NEXT) ? 1 : -1;

  Data* to_send = delta_data;
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  if (config->use_compression && !compression_should_skip_with_suffixes(
                                     file->path, config->skip_compress_suffixes, skip_count)) {
    to_send = data_compress_with_threads(delta_data, config->compression_level,
                                         config->compression_threads);
    data_destroy(delta_data);
    if (!to_send)
      return send_status(client->file_descriptor, STATUS_NEXT) ? 1 : -1;
  }

  bool ok = send_status(client->file_descriptor, STATUS_DELTA_DATA) &&
            send_data(client->file_descriptor, to_send);

  if (ok && config->use_metadata)
    ok = metadata_send(client->file_descriptor, file->metadata);

  if (ok && config->use_xattrs)
    ok = xattr_send(client->file_descriptor, file->xattrs);

  data_destroy(to_send);
  return ok ? 0 : -1;
}

/* --append / --append-verify tail resume.  The receiver learned the existing
 * destination is SHORTER than the source and replied STATUS_APPEND with the
 * resume offset (prefix bytes it already holds).  For plain --append we send
 * the tail immediately (the prefix is not content-verified, matching rsync).
 * For --append-verify we first send the source prefix xxHash64; the receiver
 * compares it to the retained prefix and replies STATUS_APPEND_OK (send the
 * tail) or STATUS_NEXT (prefix mismatch -> full transfer, never corrupt).
 * Returns 0 on success, 1 when a full transfer was done instead, -1 on error. */
static int send_append(const Client* client, File* file, Config* config,
                       unsigned long long offset) {
  int fd = client->file_descriptor;
  if (file->data->data == NULL && !file_load_data(file)) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  const unsigned long long fsize = file->data->size;
  if (offset >= fsize) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  size_t off = (size_t)offset;
  size_t tail_len = (size_t)(fsize - off);
  int compression_level = config->use_compression ? config->compression_level : 0;
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  bool compress = compression_level > 0 &&
                  !compression_should_skip_with_suffixes(file->path, config->skip_compress_suffixes,
                                                         skip_count);

  /* --append-verify: exchange the source prefix checksum and await the verdict. */
  if (config->append_verify) {
    uint64_t prefix_hash = delta_xxhash64(file->data->data, off);
    if (!send_status(fd, STATUS_APPEND_SIG) || !send_n_data(fd, &prefix_hash, sizeof(prefix_hash)))
      return -1;
    Status resp;
    if (!receive_status(fd, &resp))
      return -1;
    if (resp == STATUS_NEXT) {
      /* Retained prefix does not match the source: fall back to the atomic full
         transfer (byte-identical, never a corrupt prefix+tail blend). */
      int rc = file_send_single_calls_with_skip(file, fd, config->use_metadata, compression_level,
                                                false, config->skip_compress_suffixes, skip_count,
                                                config->compression_threads, config->use_xattrs)
                   ? 1
                   : -1;
      return rc;
    }
    if (resp != STATUS_APPEND_OK) {
      log_server_rejection("Unexpected append-verify response");
      send_status(fd, STATUS_ERROR);
      return -1;
    }
  }

  if (!send_status(fd, STATUS_APPEND_DATA)) {
    return -1;
  }
  if (config->use_metadata && !metadata_send(fd, file->metadata)) {
    return -1;
  }
  if (config->use_xattrs && !xattr_send(fd, file->xattrs)) {
    return -1;
  }
  bool ok;
  if (compress) {
    /* Compression needs an owned copy of the tail to compress. */
    Data* tail = data_create_empty(tail_len);
    if (!tail) {
      send_status(fd, STATUS_ERROR);
      return -1;
    }
    memcpy(tail->data, (const char*)file->data->data + off, tail_len);
    Data* comp = data_compress_with_threads(tail, compression_level, config->compression_threads);
    data_destroy(tail);
    if (!comp) {
      send_status(fd, STATUS_ERROR);
      return -1;
    }
    ok = send_data(fd, comp);
    data_destroy(comp);
  } else {
    /* Uncompressed: send directly from the source buffer (no per-file copy;
       send_data is synchronous, so the view outlives the call). */
    Data tail_view;
    tail_view.data = (char*)file->data->data + off;
    tail_view.size = tail_len;
    tail_view.protocol_charge = 0;
    tail_view.owner = NULL;
    ok = send_data(fd, &tail_view);
  }
  return ok ? 0 : -1;
}

/* Server-contacting --dry-run.  Connects to the configured remote/daemon and
 * runs the normal per-file incremental decision WITHOUT transmitting any file
 * data: the receiver (which also sees dry_run=true on the wire) answers
 * STATUS_OK for an up-to-date file and STATUS_DRY_RUN_TRANSFER for a file it
 * would otherwise write, mutating nothing on either side.  The would-transfer
 * set and the same trailer as the local dry-run are printed.  A
 * --compare-dest exact basis hit with no destination copy is reported as a
 * skip by the receiver.
 *
 * Only regular files take the receiver-consulted check; directory / symlink /
 * special / hard-link-sibling entries have no per-file content check, so they
 * are reported conservatively as would-transfer and their frames are never
 * sent (which is what keeps the receiver mutation-free).  --delete* is
 * deliberately NOT transmitted in dry-run, so no deletion can occur; the
 * would-delete manifest report is a documented follow-up.
 *
 * Returns 0 on success, 1 on error. */
static int send_dry_run_remote(Config* config) {
  int from_skipped = 0;
  ArrayList* missing_args = NULL;
  if (config->delete_missing_args) {
    missing_args = array_list_create(free);
    if (!missing_args)
      return 1;
  }
  if (!files_from_list_check(config, missing_args, &from_skipped)) {
    if (missing_args)
      array_list_delete(missing_args);
    return 1;
  }
  if (missing_args)
    array_list_delete(missing_args);
  /* Alternate basis dirs force the whole-file per-file check on the real
     receiver; refuse an oversize source up front exactly as send_files does so
     dry-run reports the same clear diagnostic instead of aborting mid-stream. */
  if (config_has_basis(config) && !basis_oversize_preflight(config))
    return 1;

  /* A live session may follow, so arm graceful abort handling. */
  client_set_abort_armed(true);
  Client* client = connect_transfer_client(config);
  if (!client) {
    if (config->transport == TRANSPORT_TCP)
      log_message(LOG_LEVEL_ERROR, "could not connect to server%s",
                  config->use_tls ? " via TLS" : "");
    client_set_abort_armed(false);
    return 1;
  }
  ProtocolSession session;
  protocol_session_init(&session, client->file_descriptor, client->file_descriptor);
  protocol_session_set_io_timeout(&session, config->timeout);
  protocol_session_set_ssl(&session, (SSL*)client->ssl);
  protocol_session_bind(&session);

  int ret = 1;
  time_t dry_start = time(NULL);
  ReceiverStats dry_stats;
  memset(&dry_stats, 0, sizeof(dry_stats));
  PreparedScanner prepared;
  memset(&prepared, 0, sizeof(prepared));
  DirectoryScanner* scanner = NULL;
  ArrayList* dry_manifest = NULL;
  ArrayList* dry_dirs = NULL;
  if (!config_send(client->file_descriptor, config))
    goto dry_fail;
  receive_daemon_motd(client, config);
  if (!prepare_scanner(config, 0, &prepared))
    goto dry_fail;
  scanner = directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner)
    goto dry_fail;

  int file_count = 0;
  unsigned long long total_bytes = 0;
  char size_buffer[32];
  /* -n --delete: build the same keep-set manifest a real run would send so the
     receiver can enumerate (read-only) the destination extras.  Filter-excluded
     and size-pruned protections are not propagated here, so a filtered dry-run
     may over-report; the no-filter case is exact. */
  dry_manifest = config->use_delete ? array_list_create(free) : NULL;
  if (config->use_delete && !dry_manifest)
    goto dry_fail;
  /* Scope the receiver-side extras walk to the receive root (the "." sentinel),
     exactly as the recursive transfer path does. */
  if (config->use_delete) {
    dry_dirs = array_list_create(free);
    char* root_marker = dry_dirs ? str_dup(".") : NULL;
    if (!dry_dirs || !root_marker || !array_list_add(dry_dirs, root_marker)) {
      free(root_marker);
      if (dry_dirs)
        array_list_delete(dry_dirs);
      dry_dirs = NULL;
      goto dry_fail;
    }
  }
  if (!config->quiet)
    printf("Dry run: files to be transferred\n");
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    if (dry_manifest && !add_chunk_to_manifest(dry_manifest, chunk)) {
      chunk_destroy(chunk);
      goto dry_fail;
    }
    for (int i = 0; i < chunk->element_count; i++) {
      File* f = chunk->items[i];
      if (!f)
        continue;
      unsigned long long fsize = f->data ? f->data->size : 0;
      bool would;
      if (f->is_dir || f->is_symlink || f->is_special ||
          (f->link_group != 0 && !f->link_first && f->hardlink_target != NULL)) {
        /* No receiver-side content check exists for these frame types; a real
           run would (re)create them, so report would-transfer and send no
           frame (the receiver must stay mutation-free). */
        would = true;
      } else if (fsize > MAX_RECEIVE_WHOLE_FILE_SIZE && !config->use_incremental &&
                 !config_has_basis(config)) {
        /* A non-incremental run streams a >whole-file-limit source without the
           STATUS_CHECK handshake, so no read-only receiver decision is possible
           (and none is needed: a real run would transfer it). */
        would = true;
      } else {
        DeltaSignature* sig = NULL;
        unsigned long long resume_offset = 0;
        int rc = incremental_check(client, f, config, &sig, &resume_offset);
        delta_signature_destroy(sig);
        if (rc < 0) {
          chunk_destroy(chunk);
          goto dry_fail;
        }
        if (rc == 1)
          continue; /* up to date; nothing to report */
        if (rc != 4) {
          log_message(LOG_LEVEL_ERROR, "Unexpected receiver reply during dry-run");
          chunk_destroy(chunk);
          goto dry_fail;
        }
        would = true;
      }
      if (would) {
        if (!config->quiet) {
          char* escaped_path = output_escape(file_wire_path(f), config->eight_bit_output);
          if (!escaped_path) {
            chunk_destroy(chunk);
            goto dry_fail;
          }
          if (config->human_readable)
            printf("  %s (%s)\n", escaped_path,
                   display_bytes(fsize, true, size_buffer, sizeof(size_buffer)));
          else
            printf("  %s (%llu bytes)\n", escaped_path, fsize);
          free(escaped_path);
        }
        total_bytes += fsize;
        file_count++;
      }
    }
    chunk_destroy(chunk);
  }
  bool io_error = directory_scanner_had_io_error(scanner);
  if (directory_scanner_failed(scanner))
    goto dry_fail;
  if (io_error)
    log_message(LOG_LEVEL_WARNING, "source scan hit an unreadable directory");
  /* Send the keep-set manifest (no data frames) so the receiver can enumerate
     the destination extras; an early-timing delete ACKs before it will accept
     the terminal FINISHED. */
  bool early_delete = config->use_delete && config_delete_timing_early(config);
  if (dry_manifest) {
    if (send_delete_manifest(client->file_descriptor, dry_manifest, NULL, NULL, NULL, dry_dirs) !=
        0)
      goto dry_fail;
    if (early_delete) {
      Status ack;
      if (!receive_status_keepalive(client->file_descriptor, &ack, DELETE_ACK_TIMEOUT_SEC,
                                    DELETE_ACK_KEEPALIVE_SEC, client_abort_pending) ||
          ack != STATUS_OK)
        goto dry_fail;
    }
  }
  /* Terminate the stream so the receiver emits its success frame; no data frame
     is ever sent in dry-run. */
  if (!send_status(client->file_descriptor, STATUS_FINISHED))
    goto dry_fail;
  Status status;
  if (!receive_status(client->file_descriptor, &status))
    goto dry_fail;
  if (status == STATUS_STATS) {
    ArrayList* would_delete = array_list_create(free);
    if (!would_delete)
      goto dry_fail;
    if (!receive_stats_record(client->file_descriptor, &dry_stats, would_delete)) {
      array_list_delete(would_delete);
      goto dry_fail;
    }
    print_delete_reports(config, would_delete);
    array_list_delete(would_delete);
    if (!receive_status(client->file_descriptor, &status))
      goto dry_fail;
  }
  if (status != STATUS_OK)
    goto dry_fail;
  if (!config->quiet) {
    if (config->human_readable)
      printf("Total: %d files, %s\n", file_count,
             display_bytes(total_bytes, true, size_buffer, sizeof(size_buffer)));
    else
      printf("Total: %d files, %.1f MB\n", file_count, (double)total_bytes / (double)BYTES_PER_MIB);
  }
  {
    TransferStats dry_transfer;
    memset(&dry_transfer, 0, sizeof(dry_transfer));
    dry_transfer.flist_reg = (unsigned long long)file_count;
    dry_transfer.total_file_size = total_bytes;
    dry_transfer.transferred_regular = (unsigned long long)file_count;
    dry_transfer.transferred_file_size = total_bytes;
    dry_transfer.literal_data = total_bytes;
    report_transfer_stats(config, &dry_transfer, dry_start, &dry_stats);
  }
  ret = io_error ? 1 : 0;

dry_fail:
  if (dry_manifest)
    array_list_delete(dry_manifest);
  if (dry_dirs)
    array_list_delete(dry_dirs);
  if (scanner)
    directory_scanner_destroy(scanner);
  prepared_scanner_destroy(&prepared);
  disconnect_transfer_client(client);
  protocol_session_unbind();
  client_set_abort_armed(false);
  return ret;
}

// Send a single file directly (non-incremental path).
static bool send_file_direct(File* file, int fd, bool use_metadata, int compression_level,
                             const Config* config) {
  if (!send_status(fd, STATUS_NEXT))
    return false;
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  return file_send_single_calls_with_skip(file, fd, use_metadata, compression_level, true,
                                          config->skip_compress_suffixes, skip_count,
                                          config->compression_threads, config->use_xattrs);
}

/* Transmit one explicit directory entry (--dirs): a STATUS_MKDIR frame whose
   payload is the destination path and, when metadata is negotiated, the
   directory's metadata frame.  The receiver validates the path, creates the
   directory under the receive root, and (metadata case) defers applying its
   times to the end of the transfer so -O/--omit-dir-times is honored. */
static bool send_directory_entry(const Client* client, File* file, const Config* config) {
  if (!file || !file_wire_path(file))
    return false;
  if (!send_status(client->file_descriptor, STATUS_MKDIR) ||
      !send_wire_str(client->file_descriptor, file_wire_path(file)))
    return false;
  if (config->use_metadata && !metadata_send(client->file_descriptor, file->metadata))
    return false;
  /* Directory xattrs/ACLs (-X/-A) ride the same trailing block as regular files
     when the xattr transport was negotiated. */
  return !config->use_xattrs || xattr_send(client->file_descriptor, file->xattrs);
}

/* P7 Wave D: transmit every captured source directory's metadata in terminal
   STATUS_DIR_TIMES frames (count, then (path, metadata) pairs) after all file
   data and the optional delete manifest.  The receiver applies them at the END
   of its own transfer (after deletion and --delay-updates publication) so a
   directory's mtime is not clobbered by writing its children.  A non-metadata
   transfer (or an empty set) sends nothing, keeping the stream byte-identical.

   The receiver rejects a frame whose count exceeds MAX_MANIFEST_ENTRIES, so a
   huge tree is CHUNKED into repeated frames of at most that many entries each
   (the receiver's loop handles repeated STATUS_DIR_TIMES frames).  Every frame
   stays within the receiver's bound, and a frame that would exceed it is never
   emitted. */
static bool send_dir_times(const Client* client, const Config* config, ArrayList* dir_entries) {
  if (!client || !config || !dir_metadata_should_capture(config) || !dir_entries ||
      dir_entries->size == 0)
    return true;
  int fd = client->file_descriptor;
  int index = 0;
  while (index < dir_entries->size) {
    int remaining = dir_entries->size - index;
    int chunk = remaining > MAX_MANIFEST_ENTRIES ? MAX_MANIFEST_ENTRIES : remaining;
    if (!send_status(fd, STATUS_DIR_TIMES) || !send_int(fd, chunk))
      return false;
    for (int i = 0; i < chunk; i++) {
      File* file = (File*)dir_entries->items[index + i];
      if (!file || !file_wire_path(file))
        return false;
      if (!send_wire_str(fd, file_wire_path(file)) || !metadata_send(fd, file->metadata))
        return false;
      /* Directory xattrs/ACLs travel with the deferred directory metadata. */
      if (config->use_xattrs && !xattr_send(fd, file->xattrs))
        return false;
    }
    index += chunk;
  }
  return true;
}

/* Transmit one symlink entry: a STATUS_SYMLINK frame carrying the destination
 * path, the (sender-munged, if --munge-links) target string, and metadata when
 * negotiated.  The receiver unmunges the target and creates the symlink beneath
 * its root.  Symlinks never need an incremental check or data payload. */
static bool send_symlink_entry(const Client* client, File* file, const Config* config) {
  if (!file || !file_wire_path(file) || !file->symlink_target)
    return false;
  int fd = client->file_descriptor;
  if (!send_status(fd, STATUS_SYMLINK) || !send_wire_str(fd, file_wire_path(file)) ||
      !send_wire_str(fd, file->symlink_target))
    return false;
  return !config->use_metadata || metadata_send(fd, file->metadata);
}

// Send a single file directly via sendfile (non-incremental path).
static bool send_file_direct_sendfile(File* file, int fd, bool use_metadata, const Config* config) {
  if (!send_status(fd, STATUS_NEXT))
    return false;
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  return file_send_sendfile_with_skip(file, fd, use_metadata, 0, true,
                                      config->skip_compress_suffixes, skip_count,
                                      config->compression_threads, config->use_xattrs);
}

// Process one file in a chunk: either via incremental check or direct send.
// Returns 0 on success, 1 if skipped (incremental match), -1 on error.
static int send_single_file(Client* client, File* file, Config* config, bool use_incremental,
                            bool use_sendfile) {
  int compression_level = config->use_compression ? config->compression_level : 0;
  log_info_message(LOG_INFO_COPY, "Transferring %s", file->path);

  if (!use_incremental) {
    if (use_sendfile) {
      return send_file_direct_sendfile(file, client->file_descriptor, config->use_metadata, config)
                 ? 0
                 : -1;
    }
    return send_file_direct(file, client->file_descriptor, config->use_metadata, compression_level,
                            config)
               ? 0
               : -1;
  }

  // Incremental path: use sendfile for the actual data if enabled and no compression
  if (use_sendfile) {
    DeltaSignature* sig = NULL;
    unsigned long long resume_offset = 0;
    int rc = incremental_check(client, file, config, &sig, &resume_offset);
    if (rc == 1) {
      log_info_message(LOG_INFO_SKIP, "Skipping unchanged %s", file->path);
      delta_signature_destroy(sig);
      return 1;
    }
    if (rc < 0) {
      delta_signature_destroy(sig);
      return -1;
    }
    // rc == 3: append resume (tail-only) -- send_append uses the data path.
    if (rc == 3) {
      delta_signature_destroy(sig);
      int arc = send_append(client, file, config, resume_offset);
      if (arc == 1) {
        log_info_message(LOG_INFO_COPY, "Append prefix mismatch; full transfer of %s", file->path);
        return 0;
      }
      return arc == 0 ? 0 : -1;
    }
    // rc == 4: the receiver answered DRY_RUN_TRANSFER, which is only valid in
    // incremental_check's dedicated dry-run consumer.  send_single_file never
    // runs a dry-run session, so this is a protocol error: abort instead of
    // falling through and sending data the receiver is not reading.
    if (rc == 4) {
      log_message(LOG_LEVEL_ERROR, "Receiver answered DRY_RUN_TRANSFER in a non-dry-run transfer");
      delta_signature_destroy(sig);
      send_status(client->file_descriptor, STATUS_ERROR);
      return -1;
    }
    // rc == 0: unchanged file, skip
    // rc == 2: server sent delta signature but sendfile doesn't support delta
    delta_signature_destroy(sig);
    if (rc == 2) {
      // Server is waiting for STATUS_NEXT after delta handshake
      if (!send_status(client->file_descriptor, STATUS_NEXT))
        return -1;
    }
    // Fall through: send full file via sendfile (pass 0 for compression_level)
    int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
    if (!file_send_sendfile_with_skip(file, client->file_descriptor, config->use_metadata, 0, false,
                                      config->skip_compress_suffixes, skip_count,
                                      config->compression_threads, config->use_xattrs))
      return -1;
    return 0;
  }

  // Incremental path with single_calls (supports compression and delta)
  DeltaSignature* sig = NULL;
  unsigned long long resume_offset = 0;
  int rc = incremental_check(client, file, config, &sig, &resume_offset);
  if (rc < 0) {
    delta_signature_destroy(sig);
    return -1;
  }
  if (rc == 1) {
    log_info_message(LOG_INFO_SKIP, "Skipping unchanged %s", file->path);
    delta_signature_destroy(sig);
    return 1;
  }
  if (rc == 3) {
    /* --append / --append-verify tail resume.  send_append reports 1 when the
       verified prefix mismatched and a full transfer was sent instead. */
    delta_signature_destroy(sig);
    int arc = send_append(client, file, config, resume_offset);
    if (arc == 1) {
      log_info_message(LOG_INFO_COPY, "Append prefix mismatch; full transfer of %s", file->path);
      return 0;
    }
    return arc == 0 ? 0 : -1;
  }
  if (rc == 4) {
    /* See the sendfile branch above: DRY_RUN_TRANSFER is only valid in the
       dedicated dry-run consumer, never in the normal per-file send path. */
    log_message(LOG_LEVEL_ERROR, "Receiver answered DRY_RUN_TRANSFER in a non-dry-run transfer");
    delta_signature_destroy(sig);
    send_status(client->file_descriptor, STATUS_ERROR);
    return -1;
  }
  if (rc == 2 && config->use_delta && !config->whole_file) {
    int drc = send_delta(client, file, sig, config);
    delta_signature_destroy(sig);
    if (drc == 0)
      return 0;
    if (drc < 0)
      return -1;
  } else {
    delta_signature_destroy(sig);
    // rc == 2 can happen if server sends STATUS_DELTA_SIGNATURE but
    // use_delta is false on the client side. Send STATUS_NEXT to
    // tell the server to proceed with the full file transfer.
    if (rc == 2) {
      if (!send_status(client->file_descriptor, STATUS_NEXT))
        return -1;
    }
  }
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  if (!file_send_single_calls_with_skip(file, client->file_descriptor, config->use_metadata,
                                        compression_level, false, config->skip_compress_suffixes,
                                        skip_count, config->compression_threads,
                                        config->use_xattrs))
    return -1;
  return 0;
}

/* Sendfile calls a blocking open() on the source (file_send_sendfile_with_skip
 * -> file_open_for_read), which never returns for a FIFO/device with no writer.
 * Only a regular file may take the zero-copy sendfile path; a non-regular source
 * (FIFO/device copied by --copy-devices) must use the buffered, size-bounded
 * read path instead.  `stat` follows symlinks, so a dereferenced symlink to a
 * regular file keeps the sendfile fast path. */
static bool source_is_regular_file(const File* file) {
  if (!file || !file->path)
    return false;
  struct stat st;
  return stat(file->path, &st) == 0 && S_ISREG(st.st_mode);
}

static int send_chunk_with_removal(Client* client, Chunk* chunk, Config* config,
                                   ArrayList* remove_sources, TransferStats* stats) {
  if (config->use_chunk_serialization) {
    if (remove_sources) {
      for (int i = 0; i < chunk->element_count; i++) {
        if (!remember_source_file(remove_sources, chunk->items[i]))
          return -1;
      }
    }
    if (!send_status(client->file_descriptor, STATUS_CHUNK))
      return -1;
    Data* data;
    if (config->use_compression) {
      data = chunk_compress_with_threads(chunk, config->compression_level, config->use_metadata,
                                         config->compression_threads);
    } else {
      data = chunk_serialize(chunk, config->use_metadata);
    }
    if (data == NULL)
      return -1;
    if (!send_data(client->file_descriptor, data)) {
      data_destroy(data);
      return -1;
    }
    data_destroy(data);
    for (int i = 0; i < chunk->element_count; i++) {
      if (chunk->items[i] == NULL)
        continue;
      transfer_stats_note_entry(stats, chunk->items[i]);
      if (chunk->items[i]->is_dir)
        change_emit_dir_sent(config, chunk->items[i]);
      else
        change_emit_file_sent(config, chunk->items[i]);
      if (!chunk->items[i]->is_dir)
        transfer_stats_note_transferred(stats, chunk->items[i]);
    }
    return 0;
  }

  for (int i = 0; i < chunk->element_count; i++) {
    File* f = chunk->items[i];
    if (f == NULL)
      continue;
    transfer_stats_note_entry(stats, f);
    if (f->is_dir) {
      /* Explicit directory entry (--dirs): a MKDIR frame carrying the
         destination path (and metadata when negotiated).  Directories have no
         source to remove and no incremental check. */
      if (!send_directory_entry(client, f, config))
        return -1;
      change_emit_dir_sent(config, f);
      continue;
    }
    /* --hard-links/-H sibling: a later member of a hard-link group that has no
       data (its payload lives in the first member).  Transmit a dedicated
       STATUS_HARDLINK frame carrying the first member's destination-relative
       wire path so the receiver links this entry to that installed file. */
    if (f->link_group != 0 && !f->link_first && f->hardlink_target != NULL) {
      if (!send_status(client->file_descriptor, STATUS_HARDLINK) ||
          !send_wire_str(client->file_descriptor, file_wire_path(f)) ||
          !send_int(client->file_descriptor, f->link_group) ||
          !send_wire_str(client->file_descriptor, f->hardlink_target))
        return -1;
      change_emit_file_sent(config, f);
      continue;
    }
    /* Symlink entry (-l / -k keep-as-symlink): only the target rides the wire. */
    if (f->is_symlink) {
      if (!send_symlink_entry(client, f, config))
        return -1;
      change_emit_file_sent(config, f);
      continue;
    }
    /* --devices/--specials: a device/special node is recreated on the receiver,
       not transferred as content.  Send the dedicated STATUS_SPECIAL frame. */
    if (f->is_special) {
      if (!file_send_special(f, client->file_descriptor, config->use_metadata))
        return -1;
      change_emit_file_sent(config, f);
      continue;
    }
    bool stream = f->data->data == NULL && f->data->size > 0;
    bool use_sendfile = ((config->use_sendfile && !config->use_compression) ||
                         (stream && !config->use_compression)) &&
                        source_is_regular_file(f);
    SourceFile* source = remove_sources ? source_file_create(f) : NULL;
    unsigned long long bytes_before = protocol_bytes_written();
    unsigned long long read_before = protocol_bytes_read();
    int rc = send_single_file(client, f, config, config->use_incremental, use_sendfile);
    if (rc == 1) {
      source_file_destroy(source);
      continue;
    }
    if (rc < 0) {
      source_file_destroy(source);
      return -1;
    }
    transfer_stats_note_transferred(stats, f);
    change_emit_file_sent_bytes(config, f, protocol_bytes_written() - bytes_before,
                                protocol_bytes_read() - read_before);
    client_progress_file(config, f);
    if (source && !array_list_add(remove_sources, source)) {
      source_file_destroy(source);
      return -1;
    }
  }
  return 0;
}

static int send_chunks_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  time_t start = time(NULL);
  Client* client = connect_transfer_client(context->config);
  if (!client) {
    if (context->config->transport == TRANSPORT_TCP)
      log_message(LOG_LEVEL_ERROR, "could not connect to server%s",
                  context->config->use_tls ? " via TLS" : "");
    pipeline_cancel(context);
    mark_sender_done(context);
    return thrd_error;
  }
  ProtocolSession session;
  protocol_session_init(&session, client->file_descriptor, client->file_descriptor);
  protocol_session_set_io_timeout(&session, context->config->timeout);
  protocol_session_set_ssl(&session, (SSL*)client->ssl);
  protocol_session_bind(&session);
  if (!config_send(client->file_descriptor, context->config)) {
    pipeline_cancel(context);
    disconnect_transfer_client(client);
    mark_sender_done(context);
    protocol_session_unbind();
    return thrd_error;
  }
  receive_daemon_motd(client, context->config);
  if (context->early_delete) {
    /* The keep-set manifest was prebuilt by a path-only pre-scan.  Transmit it
       and wait for the receiver to delete extras before streaming any data. */
    if (!send_delete_manifest_early(client, context->manifest, context->excluded_paths,
                                    context->size_skipped_paths, context->missing_args,
                                    context->synced_dirs)) {
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
  } else if (context->delete_plans) {
    /* --delete-during/--delete-delay: transmit the receive root's plan before
       any data, exactly like rsync's first generator directory. */
    if (delete_plan_send_root(client->file_descriptor, context->delete_plans) != 0) {
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
  }

  client_progress_begin(context->config);
  while (true) {
    /* Graceful abort (Ctrl-C/SIGTERM): tell the receiver to clean up instead of
       dying abruptly.  Best-effort: a failed send just means the peer is gone.
       Only reached while the session is active (config_send already succeeded). */
    if (client_abort_pending()) {
      log_info_message(LOG_INFO_MISC,
                       "Abort requested; sending STATUS_ABORT to server and disconnecting");
      send_status(client->file_descriptor, STATUS_ABORT);
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
    /* Phase 6: stop-elegantly at the next chunk boundary once the --stop-after
       / --stop-at deadline has passed.  Everything already sent is finalized by
       the completion tail below; the run still returns success. */
    if (stop_condition_reached(&context->stop_condition)) {
      log_info_message(LOG_INFO_MISC,
                       "Stop deadline reached; stopping transfer at the next chunk boundary");
      context->scan_stopped_early = true;
      pipeline_cancel(context);
      break;
    }
    Chunk* current_chunk = queue_dequeue_multithreaded(
        context->queue_loader, &context->mutex_loader, &context->condition_not_empty_loader,
        &context->condition_not_full_loader, &context->loader_done);
    if (current_chunk == NULL) {
      if (atomic_load(&context->cancelled)) {
        pipeline_cancel(context);
        disconnect_transfer_client(client);
        mark_sender_done(context);
        protocol_session_unbind();
        return thrd_error;
      }
      break;
    }
    if (send_chunk_delete_plans(client, context->delete_plans, current_chunk) != 0) {
      log_message(LOG_LEVEL_ERROR, "unexpected error while sending delete plan");
      chunk_destroy(current_chunk);
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
    if (send_chunk_with_removal(client, current_chunk, context->config,
                                context->remove_source_files, &context->stats) != 0) {
      log_message(LOG_LEVEL_ERROR, "unexpected error while sending chunk");
      chunk_destroy(current_chunk);
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
    /* Payload bytes this chunk was charged for on the loader's byte budget.
       Computed before destruction and released after the memory is actually
       freed, so a loader blocked on the budget wakes only once room exists. */
    size_t queued_payload = pipeline_context_sender_chunk_bytes(current_chunk);
    unsigned long long chunk_bytes = 0;
    int chunk_files = 0;
    for (int i = 0; i < current_chunk->element_count; i++) {
      if (current_chunk->items[i] && current_chunk->items[i]->data) {
        chunk_files++;
        chunk_bytes += current_chunk->items[i]->data->size;
      }
    }
    mtx_lock(&context->mutex_progress);
    context->total_files += chunk_files;
    context->total_bytes += chunk_bytes;
    context->progress_bytes = context->total_bytes;
    mtx_unlock(&context->mutex_progress);
    chunk_destroy(current_chunk);
    pipeline_context_sender_note_bytes_released(context, queued_payload);
  }

  /* Completion tail: reached on natural exhaustion or an early stop deadline.
     A deadline that cut the scan short leaves an incomplete keep-set manifest;
     transmitting it would make the receiver --delete the unscanned source
     mirrors (data loss), so it is deliberately suppressed.  Suppressing it also
     means the manifest (which the scanner thread may still be appending) is
     never read here on the early-stop path, so no scanner synchronization is
     required to enter the tail. */
  context->scan_stopped_early =
      context->scan_stopped_early || stop_condition_reached(&context->stop_condition);
  if (context->scan_stopped_early) {
    if (context->config->use_delete || context->config->delete_missing_args)
      log_message(LOG_LEVEL_WARNING,
                  "transfer stopped early (stop deadline); skipping --delete keep-set so "
                  "unscanned source mirrors are not deleted");
    else
      log_message(LOG_LEVEL_WARNING, "transfer stopped early (stop deadline)");
  } else if (context->config->use_delete && !context->early_delete && !context->delete_plans &&
             !context->delete_suppressed) {
    /* Empty keep-set + scan I/O error must not delete the whole destination
       (the source may not be genuinely empty -- see send_files). */
    bool empty_io;
    mtx_lock(&context->mutex_scanner);
    empty_io = context->scan_had_io_error && context->manifest && context->manifest->size == 0;
    mtx_unlock(&context->mutex_scanner);
    if (empty_io) {
      log_message(LOG_LEVEL_ERROR,
                  "source scan hit an I/O error before finding any file; refusing to delete "
                  "with an empty keep-set (--delete)");
      goto send_fail;
    }
    /* rsync default: an I/O error suppresses deletion unless --ignore-errors.
       The keep-set manifest is not sent, so the receiver removes nothing. */
    mtx_lock(&context->mutex_scanner);
    bool scan_io_now = context->scan_had_io_error;
    mtx_unlock(&context->mutex_scanner);
    if (!ignore_errors_allows_delete(context->config, scan_io_now)) {
      log_message(LOG_LEVEL_WARNING, "IO error encountered -- skipping file deletion");
    } else if (send_delete_manifest(client->file_descriptor, context->manifest,
                                    context->excluded_paths, context->size_skipped_paths,
                                    context->missing_args, context->synced_dirs) != 0) {
      goto send_fail;
    }
  } else if (context->config->delete_missing_args && !context->early_delete &&
             !context->delete_suppressed && !context->delete_plans) {
    /* --delete-missing-args without --delete: no keep-set is built, but the
       exact-delete paths still ride the same manifest frame (commit once the
       transfer succeeded). */
    if (send_delete_manifest(client->file_descriptor, NULL, NULL, NULL, context->missing_args,
                             NULL) != 0)
      goto send_fail;
  }
  /* Emit the plans for source directories the data stream never triggered
     (empty directories): their extras are still cleared while the directory
     itself is kept. */
  if (!context->scan_stopped_early && context->delete_plans && context->plan_dirs &&
      delete_plan_send_remaining(client->file_descriptor, context->delete_plans,
                                 context->plan_dirs) != 0)
    goto send_fail;
  /* P7 Wave D: transmit the captured directory times last.  The scanner thread
     (and all parallel workers) has been joined before scanner_done was set, so
     the list is complete and race-free; on an early stop the list may be
     incomplete and is deliberately not sent. */
  if (!context->scan_stopped_early &&
      !send_dir_times(client, context->config, context->dir_entries))
    goto send_fail;
  bool delete_limit = false;
  ReceiverStats recv_stats;
  memset(&recv_stats, 0, sizeof(recv_stats));
  bool ok = finalize_transfer(client, context->config, context->remove_source_files, &delete_limit,
                              &recv_stats);
  context->delete_limit = delete_limit;
  if (!ok && context->config->use_delete)
    log_message(LOG_LEVEL_ERROR,
                "server reported a deletion failure (--delete); see the server log for the reason");
  if (ok)
    remove_transferred_sources(context->config, context->remove_source_files);
  if (context->dir_entries)
    context->stats.flist_dir += (unsigned long long)context->dir_entries->size;
  report_transfer_stats(context->config, &context->stats, start, &recv_stats);
  log_info_message(LOG_INFO_STATS, "Transfer summary: %llu files, %.1f MB",
                   context->stats.transferred_regular,
                   (double)context->stats.transferred_file_size / (double)BYTES_PER_MIB);
  disconnect_transfer_client(client);
  mark_sender_done(context);
  protocol_session_unbind();
  return ok ? thrd_success : thrd_error;

send_fail:
  pipeline_cancel(context);
  disconnect_transfer_client(client);
  mark_sender_done(context);
  protocol_session_unbind();
  return thrd_error;
}

/* Scan thread of the -m pipeline.  --dirs disables recursive traversal (the
   transfer is a small set of explicit directory/file entries), so it uses the
   sequential scanner rather than spawning worker threads. */
static int scan_directory_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  protocol_session_bind(&context->allocation_session);
  PreparedScanner prepared;
  /* -j/--threads=N sizes the parallel scanner's worker pool; 0 (bare -j) lets
   * the scanner apply its built-in default. */
  if (!prepare_scanner(context->config, context->config->scanner_threads, &prepared)) {
    pipeline_cancel(context);
    protocol_session_unbind();
    return thrd_error;
  }
  prepared.options.stop_condition = &context->stop_condition;
  /* P7 Wave D: the recursive scan feeds the shared directory-time list; the
     parallel workers append under the context's dedicated mutex. */
  prepared.options.dir_entries = context->dir_entries;
  prepared.options.dir_entries_mutex = &context->dir_entries_mutex;
  if (!append_implied_dir_times(context->config, context->dir_entries)) {
    pipeline_cancel(context);
    protocol_session_unbind();
    return thrd_error;
  }
  /* The keep-set manifest for the late modes is built from this data pass, so
     the parallel scanner records the protected excluded prefixes and the
     synchronized directories here (the size-prune protection is collected in
     every mode).  The early modes already transmitted the pre-scan keep-set and
     its protected lists, so the data pass must not append to them again. */
  if (!context->early_delete && !context->delete_plans) {
    prepared.options.excluded_paths = context->excluded_paths;
    /* The root marker for a full recursive transfer is already in the list; do
       not let the scanner append every directory to it. */
    if (context->config->files_from_set != NULL)
      prepared.options.synced_dirs = context->synced_dirs;
  }
  if (!context->delete_plans)
    prepared.options.size_skipped_paths = context->size_skipped_paths;
  bool dirs_mode = prepared.options.dirs;
  /* -H also selects the sequential scanner (see the comment at the branch),
   * so the loop below must choose the scanner by which object exists, not by
   * --dirs alone. */
  bool use_dscanner = dirs_mode || prepared.options.hardlinks;
  DirectoryScanner* dscanner = NULL;
  ParallelScanner* scanner = NULL;
  /* --hard-links/-H forces the sequential scanner even in -m mode: a hard-link
     group's first member must be emitted before any of its siblings so the
     receiver always links to an already-installed first member.  The parallel
     scanner hands different subdirectories to different worker threads, which
     can reorder a group whose members span directories. */
  if (use_dscanner) {
    dscanner =
        directory_scanner_create_with_options(context->config->send_directory, &prepared.options);
  } else {
    scanner = parallel_scanner_create_with_options(context->config->send_directory,
                                                   &prepared.options, &context->allocation_session);
  }
  if (dscanner == NULL && scanner == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to create scanner");
    pipeline_cancel(context);
    prepared_scanner_destroy(&prepared);
    protocol_session_unbind();
    return thrd_error;
  }
  bool failed = false;
  Chunk* current_chunk;
  while (1) {
    if (use_dscanner)
      current_chunk = directory_scanner_next(dscanner);
    else
      current_chunk = parallel_scanner_next(scanner);
    if (current_chunk == NULL) {
      failed = use_dscanner ? directory_scanner_failed(dscanner) : parallel_scanner_failed(scanner);
      break;
    }
    if (context->config->use_delete && !context->early_delete && !context->delete_plans &&
        !context->delete_suppressed) {
      mtx_lock(&context->mutex_scanner);
      bool manifest_ok = add_chunk_to_manifest(context->manifest, current_chunk);
      mtx_unlock(&context->mutex_scanner);
      if (!manifest_ok) {
        failed = true;
        chunk_destroy(current_chunk);
        break;
      }
    }
    if (!queue_enqueue_multithreaded_cancel(
            context->queue_scanner, current_chunk, &context->mutex_scanner,
            &context->condition_not_empty_scanner, &context->condition_not_full_scanner,
            &context->cancelled)) {
      chunk_destroy(current_chunk);
      failed = true;
      break;
    }
  }
  /* Capture the scanner results BEFORE destroying the scanner objects (the
     io_error flag lives on the scanner, so reading it after destroy would be a
     use-after-free). */
  bool had_io = use_dscanner ? directory_scanner_had_io_error(dscanner)
                             : parallel_scanner_had_io_error(scanner);
  if (use_dscanner)
    directory_scanner_destroy(dscanner);
  else
    parallel_scanner_destroy(scanner);
  if (failed) {
    prepared_scanner_destroy(&prepared);
    mtx_lock(&context->mutex_scanner);
    context->scanner_done = true;
    cnd_broadcast(&context->condition_not_empty_scanner);
    cnd_broadcast(&context->condition_not_full_scanner);
    mtx_unlock(&context->mutex_scanner);
    pipeline_cancel(context);
    protocol_session_unbind();
    return thrd_error;
  }
  /* --ignore-errors: an unreadable subdirectory was skipped (workers recorded
     io_error, not failure); the deletion still runs but the run reports it. */
  if (had_io) {
    mtx_lock(&context->mutex_scanner);
    context->scan_had_io_error = true;
    mtx_unlock(&context->mutex_scanner);
  }
  mtx_lock(&context->mutex_scanner);
  context->scanner_done = true;
  cnd_signal(&context->condition_not_empty_scanner);
  mtx_unlock(&context->mutex_scanner);

  prepared_scanner_destroy(&prepared);
  protocol_session_unbind();
  return thrd_success;
}

static int load_files_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  protocol_session_bind(&context->allocation_session);
  while (true) {
    Chunk* chunk = queue_dequeue_multithreaded(
        context->queue_scanner, &context->mutex_scanner, &context->condition_not_empty_scanner,
        &context->condition_not_full_scanner, &context->scanner_done);
    if (chunk == NULL) {
      mtx_lock(&context->mutex_loader);
      context->loader_done = true;
      cnd_signal(&context->condition_not_empty_loader);
      mtx_unlock(&context->mutex_loader);
      protocol_session_unbind();
      return thrd_success;
    }
    if (!context->config->use_sendfile) {
      for (int i = 0; i < chunk->element_count; i++) {
        File* f = chunk->items[i];
        if (f->data->size > STREAM_THRESHOLD && !context->config->use_compression)
          continue;
        if (!file_load_data(f)) {
          log_message(LOG_LEVEL_ERROR, "Failed to load file data");
          chunk_destroy(chunk);
          pipeline_cancel(context);
          protocol_session_unbind();
          return thrd_error;
        }
      }
    }
    if (!pipeline_context_sender_enqueue_chunk(context, chunk)) {
      pipeline_cancel(context);
      protocol_session_unbind();
      return thrd_error;
    }
  }
}

/* Phase 6 residual-batch (client-only).  --write-batch=FILE / --only-write-batch
 * emit a self-contained single-file batch of a whole source tree from a
 * deterministic separate scan pass.  Each chunk's file images are fully loaded
 * into memory (so chunk_serialize sees complete content, matching the -s wire
 * codec byte-for-byte) and written to FILE as a length-prefixed record.  The
 * batch never crosses the wire and needs no server.  Returns 0 on success. */
int write_batch_from_source(const Config* config, const char* batch_path) {
  if (!config || !batch_path || !config->send_directory)
    return 1;
  PreparedScanner prepared;
  memset(&prepared, 0, sizeof(prepared));
  if (!prepare_scanner(config, 0, &prepared))
    return 1;
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner) {
    prepared_scanner_destroy(&prepared);
    return 1;
  }
  int fd = open(batch_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    log_perror("could not create batch file");
    directory_scanner_destroy(scanner);
    prepared_scanner_destroy(&prepared);
    return 1;
  }
  bool ok = batch_write_header(fd, config);
  Chunk* chunk;
  while (ok && (chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count && ok; i++) {
      File* f = chunk->items[i];
      if (f == NULL || f->data == NULL)
        continue;
      if (f->data->size > 0 && f->data->data == NULL && !file_load_data(f)) {
        char* escaped_path = output_escape(f->path ? f->path : "", log_get_8_bit_output());
        log_message(LOG_LEVEL_ERROR, "batch: failed to load data for %s",
                    escaped_path ? escaped_path : "<allocation failed>");
        free(escaped_path);
        ok = false;
        break;
      }
    }
    if (ok)
      ok = batch_write_chunk(fd, chunk);
    chunk_destroy(chunk);
  }
  if (ok && directory_scanner_failed(scanner))
    ok = false;
  if (directory_scanner_had_io_error(scanner))
    log_message(LOG_LEVEL_WARNING, "batch: source scan hit an unreadable directory");
  close(fd);
  directory_scanner_destroy(scanner);
  prepared_scanner_destroy(&prepared);
  if (!ok && batch_path[0] != '\0')
    unlink(batch_path); /* never leave a partial batch behind */
  return ok ? 0 : 1;
}

/* Apply a batch FILE to DEST_ROOT (client-only, no server).  Returns 0 on
 * success; a malformed/truncated/oversized record or an apply error fails the
 * whole apply. */
int apply_batch_to_dest(const Config* config, const char* batch_path, const char* dest_root) {
  if (!batch_path || !dest_root)
    return 1;
  int fd = open(batch_path, O_RDONLY);
  if (fd < 0) {
    log_perror("could not open batch file");
    return 1;
  }
  int rc = batch_read_apply(fd, config, dest_root);
  close(fd);
  return rc;
}

int send_files(Config* config) {
  if (config->list_only)
    return send_list_only(config);
  if (config->dry_run)
    return dry_run_targets_server(config) ? send_dry_run_remote(config)
                                          : send_dry_run_manifest(config);
  ArrayList* missing_args = NULL;
  int skipped = 0;
  if (config->delete_missing_args) {
    missing_args = array_list_create(free);
    if (!missing_args)
      return 1;
  }
  if (!files_from_list_check(config, missing_args, &skipped)) {
    if (missing_args)
      array_list_delete(missing_args);
    return 1;
  }
  if (config_has_basis(config) && !basis_oversize_preflight(config)) {
    if (missing_args)
      array_list_delete(missing_args);
    return 1;
  }

  /* From here on a server session may be live, so Ctrl-C/SIGTERM should set the
     abort flag (and be forwarded as STATUS_ABORT) instead of terminating. */
  client_set_abort_armed(true);
  Client* client = connect_transfer_client(config);
  if (!client) {
    if (config->transport == TRANSPORT_TCP)
      log_message(LOG_LEVEL_ERROR, "could not connect to server%s",
                  config->use_tls ? " via TLS" : "");
    if (missing_args)
      array_list_delete(missing_args);
    return 1;
  }
  ProtocolSession session;
  protocol_session_init(&session, client->file_descriptor, client->file_descriptor);
  protocol_session_set_io_timeout(&session, config->timeout);
  protocol_session_set_ssl(&session, (SSL*)client->ssl);
  protocol_session_bind(&session);
  int ret = 1;
  DirectoryScanner* scanner = NULL;
  ArrayList* manifest = NULL;
  DeletePlanSender* plan_sender = NULL;
  ArrayList* remove_sources = NULL;
  /* P7 Wave D: captured source directory times, transmitted in trailing
     STATUS_DIR_TIMES frame(s) (only when metadata rides the wire). */
  ArrayList* dir_entries = NULL;
  /* Protected excluded prefixes (delete-excluded default protection). */
  ArrayList* excluded = NULL;
  /* Size-pruned prefixes (always protected) and synchronized directories. */
  ArrayList* size_skipped = NULL;
  ArrayList* synced_dirs = NULL;
  /* Traversed source directories for the per-directory delete keep set. */
  ArrayList* plan_dirs = NULL;
  bool delete_early = config->use_delete && config_delete_timing_early(config);
  /* -d/--dirs does not recurse, so a per-directory plan would carry no child
     information and could delete the contents of an untraversed directory;
     fall back to the whole-tree end-of-transfer commit for that mode. */
  bool delete_per_dir = config->use_delete && config_delete_timing_per_dir(config) && !config->dirs;
  bool send_failed = false;
  bool had_scan_io = false;
  PreparedScanner prepared;
  memset(&prepared, 0, sizeof(prepared));
  if (!config_send(client->file_descriptor, config))
    goto send_fail;
  receive_daemon_motd(client, config);
  if (!prepare_scanner(config, 0, &prepared))
    goto send_fail;
  if (dir_metadata_should_capture(config)) {
    dir_entries = array_list_create(file_destroy);
    if (!dir_entries)
      goto send_fail;
    if (!append_implied_dir_times(config, dir_entries))
      goto send_fail;
  }
  if (config->remove_source_files)
    remove_sources = array_list_create(source_file_destroy);
  if (config->remove_source_files && !remove_sources)
    goto send_fail;
  /* Unless --delete-excluded opts out, collect the paths the source scan prunes
     by user-selection rules so the receiver protects their destination mirrors
     from --delete (rsync's default).  Only scans that build the keep-set get the
     sink attached (prescan for early timing, the streaming data pass otherwise). */
  if (config->use_delete) {
    if (!config->delete_excluded) {
      excluded = array_list_create(free);
      if (!excluded)
        goto send_fail;
      prepared.options.excluded_paths = excluded;
    }
    size_skipped = array_list_create(free);
    synced_dirs = array_list_create(free);
    if (!size_skipped || !synced_dirs)
      goto send_fail;
    prepared.options.size_skipped_paths = size_skipped;
    /* Only a --files-from subset confines the extras walk to the directories
       the scan synchronized; a full recursive transfer deletes throughout the
       receive root, so mark the root itself (the "." sentinel) and let the
       scanner record nothing extra. */
    if (config->files_from_set == NULL) {
      char* root_marker = delete_scope_root_marker(config);
      if (!root_marker || !array_list_add(synced_dirs, root_marker)) {
        free(root_marker);
        goto send_fail;
      }
    } else {
      prepared.options.synced_dirs = synced_dirs;
    }
  }
  /* The late-timing modes (plain --delete / --delete-after) build the manifest
     while streaming and send it after the last data frame.  --delete-before
     sends a whole-tree keep-set up front; --delete-during/--delete-delay build a
     per-directory plan set up front (paths only) and stream the plans alongside
     the data, so no manifest is kept during the data pass. */
  if (delete_early) {
    /* Pass 1: collect the complete keep-set (paths only, no data loaded) and
       transmit it now, before any file data.  The receiver removes extras and
       acks; the transfer aborts here if the deletion could not commit. */
    ArrayList* early_manifest = array_list_create(free);
    if (!early_manifest)
      goto send_fail;
    bool prescan_ok =
        scan_paths_only(config, &prepared.options, early_manifest, NULL, &had_scan_io);
    bool early_ok = false;
    bool skip_delete = false;
    if (prescan_ok) {
      /* A scan that hit an I/O error and produced NO keep entries is ambiguous
         (the source may not be genuinely empty -- part of it was unreadable),
         and an empty keep-set would delete the whole destination.  Refuse to
         delete; the genuine-empty-source case has no io_error and still sends
         its (empty) keep-set. */
      if (had_scan_io && early_manifest->size == 0) {
        log_message(LOG_LEVEL_ERROR,
                    "source scan hit an I/O error before finding any file; refusing to delete "
                    "with an empty keep-set (--delete)");
        prescan_ok = false;
      } else if (!ignore_errors_allows_delete(config, had_scan_io)) {
        /* rsync default: an I/O error suppresses deletion unless
           --ignore-errors.  Skip the manifest; the transfer still proceeds. */
        log_message(LOG_LEVEL_WARNING, "IO error encountered -- skipping file deletion");
        skip_delete = true;
      } else {
        early_ok = send_delete_manifest_early(client, early_manifest, excluded, size_skipped,
                                              missing_args, synced_dirs);
      }
    }
    array_list_delete(early_manifest);
    /* The keep-set (and its protected prefixes and synchronized directories) are
       already on the wire; the data pass must not append to those lists again. */
    prepared.options.excluded_paths = NULL;
    prepared.options.size_skipped_paths = NULL;
    prepared.options.synced_dirs = NULL;
    if (!prescan_ok || (!early_ok && !skip_delete))
      goto send_fail;
  } else if (delete_per_dir) {
    /* --delete-during/--delete-delay: build one plan per source directory from a
       path-only pre-scan and transmit the root plan now, before any data, so the
       receive root's extras are handled exactly like rsync's first generator
       directory.  The remaining plans are streamed with the data below. */
    plan_sender = delete_plan_sender_create();
    plan_dirs = array_list_create(free);
    if (!plan_sender || !plan_dirs)
      goto send_fail;
    prepared.options.plan_dirs = plan_dirs;
    bool prescan_ok = scan_paths_only(config, &prepared.options, NULL, plan_sender, &had_scan_io);
    bool plans_ok = false;
    bool skip_delete = false;
    if (prescan_ok) {
      const char* walk_root = delete_plan_walk_root(config, synced_dirs);
      const ArrayList* scope =
          config->files_from_set ? synced_dirs : (walk_root ? synced_dirs : NULL);
      delete_plan_sender_finalize(plan_sender, scope, walk_root);
      delete_plan_sender_set_config(plan_sender, excluded, size_skipped, missing_args);
      if (had_scan_io && delete_plan_sender_empty(plan_sender)) {
        log_message(LOG_LEVEL_ERROR,
                    "source scan hit an I/O error before finding any file; refusing to delete "
                    "with an empty keep-set (--delete)");
        prescan_ok = false;
      } else if (!ignore_errors_allows_delete(config, had_scan_io)) {
        /* rsync default: an I/O error suppresses deletion unless
           --ignore-errors.  Drop the plans; the transfer still proceeds. */
        log_message(LOG_LEVEL_WARNING, "IO error encountered -- skipping file deletion");
        delete_plan_sender_destroy(plan_sender);
        plan_sender = NULL;
        array_list_delete(plan_dirs);
        plan_dirs = NULL;
        skip_delete = true;
      } else {
        plans_ok = delete_plan_send_root(client->file_descriptor, plan_sender) == 0;
      }
    }
    prepared.options.excluded_paths = NULL;
    prepared.options.size_skipped_paths = NULL;
    prepared.options.synced_dirs = NULL;
    prepared.options.plan_dirs = NULL;
    if (!prescan_ok || (!plans_ok && !skip_delete))
      goto send_fail;
  } else if (config->use_delete) {
    manifest = array_list_create(free);
    if (!manifest)
      goto send_fail;
  }
  /* Phase 6: compute the client-only stop deadline once at transfer start.  The
     early-delete pre-scan above deliberately ignores it so the keep-set (and
     its committed deletion) is always complete and correct. */
  struct timespec now_mono;
  if (clock_gettime(CLOCK_MONOTONIC, &now_mono) != 0) {
    now_mono.tv_sec = 0;
    now_mono.tv_nsec = 0;
  }
  StopCondition stop = stop_condition_make(config->stop_after_mins > 0, config->stop_after_mins,
                                           config->stop_at_set, config->stop_at, now_mono);
  prepared.options.stop_condition = &stop;
  /* The early-delete pre-scan above already ran; only the data pass should feed
     the directory-time list (otherwise every directory would be captured
     twice). */
  prepared.options.dir_entries = dir_entries;
  scanner = directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner)
    goto send_fail;

  Chunk* current_chunk;
  TransferStats transfer_stats;
  memset(&transfer_stats, 0, sizeof(transfer_stats));
  time_t start = time(NULL);
  client_progress_begin(config);
  /* True when the stop deadline cut the scan short so the keep-set manifest is
     only a prefix of the source. */
  bool scan_stopped_early = false;
  while ((current_chunk = directory_scanner_next(scanner)) != NULL) {
    /* Graceful abort (Ctrl-C/SIGTERM): notify the receiver and clean up.  The
       session is active (config_send already succeeded); a send failure here is
       fine because the client is exiting anyway. */
    if (client_abort_pending()) {
      log_info_message(LOG_INFO_MISC, "Abort requested; sending STATUS_ABORT to server");
      chunk_destroy(current_chunk);
      send_status(client->file_descriptor, STATUS_ABORT);
      goto send_fail;
    }
    /* Phase 6: stop-elegantly at the next chunk boundary once the deadline has
       passed.  The scanner may also have stopped early itself; either way the
       completion tail below keeps everything already sent. */
    if (stop_condition_reached(&stop)) {
      chunk_destroy(current_chunk);
      log_info_message(LOG_INFO_MISC,
                       "Stop deadline reached; stopping transfer at the next chunk boundary");
      scan_stopped_early = true;
      break;
    }
    if (manifest && !add_chunk_to_manifest(manifest, current_chunk)) {
      chunk_destroy(current_chunk);
      goto send_fail;
    }
    if (!config->use_sendfile) {
      bool load_ok = true;
      for (int i = 0; i < current_chunk->element_count; i++) {
        File* f = current_chunk->items[i];
        if (f->data->size > STREAM_THRESHOLD && !config->use_compression)
          continue;
        if (!file_load_data(f)) {
          log_message(LOG_LEVEL_ERROR, "Failed to load file data");
          load_ok = false;
          break;
        }
      }
      if (!load_ok) {
        chunk_destroy(current_chunk);
        goto send_fail;
      }
    }
    if (send_chunk_delete_plans(client, plan_sender, current_chunk) != 0) {
      chunk_destroy(current_chunk);
      send_failed = true;
      break;
    }
    if (send_chunk_with_removal(client, current_chunk, config, remove_sources, &transfer_stats) !=
        0) {
      log_message(LOG_LEVEL_ERROR, "Failed to send chunk");
      chunk_destroy(current_chunk);
      send_failed = true;
      break;
    }
    chunk_destroy(current_chunk);
  }
  if (send_failed) {
    if (manifest) {
      array_list_delete(manifest);
      manifest = NULL;
    }
    goto send_fail;
  }
  if (directory_scanner_failed(scanner))
    goto send_fail;
  if (directory_scanner_had_io_error(scanner))
    had_scan_io = true;
  /* An abort that arrived after the last chunk must still stop the completion
     tail (manifest/finalize) rather than let it run to success. */
  if (client_abort_pending()) {
    log_info_message(LOG_INFO_MISC, "Abort requested; sending STATUS_ABORT to server");
    send_status(client->file_descriptor, STATUS_ABORT);
    goto send_fail;
  }
  /* Phase 6: the scanner may have stopped early (returning NULL without a
     failure) as soon as the deadline passed, so reflect that here too.  A
     deadline that cut the scan short leaves an incomplete keep-set; transmitting
     it would make the receiver --delete the unscanned source mirrors (data
     loss), so the late delete manifest is suppressed below. */
  scan_stopped_early = scan_stopped_early || stop_condition_reached(&stop);
  if (scan_stopped_early) {
    if (config->use_delete || config->delete_missing_args)
      log_message(LOG_LEVEL_WARNING,
                  "transfer stopped early (stop deadline); skipping --delete keep-set so "
                  "unscanned source mirrors are not deleted");
    else
      log_message(LOG_LEVEL_WARNING, "transfer stopped early (stop deadline)");
  } else {
    if (had_scan_io && manifest && manifest->size == 0) {
      /* A scan that hit an I/O error and produced no keep entries is ambiguous;
         an empty keep-set would delete the whole destination.  Refuse to delete
         (see the early-timing comment above). */
      log_message(LOG_LEVEL_ERROR,
                  "source scan hit an I/O error before finding any file; refusing to delete with "
                  "an empty keep-set (--delete)");
      goto send_fail;
    }
    /* rsync default: a scan I/O error suppresses deletion unless
       --ignore-errors, even in the late (commit) modes.  Drop the keep-set so
       the receiver removes nothing; the readable tree still transferred. */
    bool late_delete =
        (manifest || config->delete_missing_args) && !delete_early && !delete_per_dir;
    if (late_delete && !ignore_errors_allows_delete(config, had_scan_io)) {
      log_message(LOG_LEVEL_WARNING, "IO error encountered -- skipping file deletion");
      if (manifest) {
        array_list_delete(manifest);
        manifest = NULL;
      }
    } else if (late_delete) {
      /* Late (commit) ordering: all file data is out; transmit the manifest so
         the receiver commits the extras walk (--delete) and/or the
         --delete-missing-args exact-path deletions only after the transfer
         succeeds.  In the early modes (--delete-before) and the per-directory
         modes the deletion already went out with the data, so nothing is
         re-sent here. */
      if (send_delete_manifest(client->file_descriptor, manifest, excluded, size_skipped,
                               missing_args, synced_dirs) != 0) {
        if (manifest) {
          array_list_delete(manifest);
          manifest = NULL;
        }
        goto send_fail;
      }
      if (manifest) {
        array_list_delete(manifest);
        manifest = NULL;
      }
    }
  }
  /* Emit the plans for any source directories the data stream never triggered
     (an empty directory has no file frame).  Sending them now still clears that
     directory's destination extras while keeping the directory itself. */
  if (!scan_stopped_early && plan_sender && plan_dirs &&
      delete_plan_send_remaining(client->file_descriptor, plan_sender, plan_dirs) != 0)
    goto send_fail;
  /* P7 Wave D: every directory has now been traversed (or the scan stopped
     early), so transmit the captured directory times last.  The receiver defers
     applying them until after its own deletion/publication phase. */
  if (!send_dir_times(client, config, dir_entries))
    goto send_fail;
  bool delete_limit = false;
  ReceiverStats recv_stats;
  memset(&recv_stats, 0, sizeof(recv_stats));
  bool ok = finalize_transfer(client, config, remove_sources, &delete_limit, &recv_stats);
  if (!ok && config->use_delete)
    log_message(LOG_LEVEL_ERROR,
                "server reported a deletion failure (--delete); see the server log for the reason");
  if (ok)
    remove_transferred_sources(config, remove_sources);
  /* A recursive -a scan has no directory entries in its chunks; account them
     from the scanner's captured directory list (present whenever a directory
     attribute is preserved, e.g. -a/-t/-p).  The -d generator counts its
     explicit directory entries inline instead. */
  if (dir_entries)
    transfer_stats.flist_dir += (unsigned long long)dir_entries->size;
  report_transfer_stats(config, &transfer_stats, start, &recv_stats);
  log_info_message(LOG_INFO_STATS, "Transfer summary: %llu files, %.1f MB",
                   transfer_stats.transferred_regular,
                   (double)transfer_stats.transferred_file_size / (double)BYTES_PER_MIB);
  /* A skipped source entry (--ignore-errors past an unreadable directory, or a
     dereferenced symlink with no referent) makes rsync report a partial
     transfer (exit 23) even though the rest of the run succeeded.  A
     --max-delete-capped commit is a successful transfer that rsync reports
     with exit code 25. */
  if (!ok)
    ret = 1;
  else if (had_scan_io)
    ret = 23;
  else
    ret = delete_limit ? 25 : 0;

send_fail:
  /* Single cleanup path for all exits. The manifest is intentionally deleted
     here even on success without --delete, fixing a pre-existing leak. */
  if (manifest)
    array_list_delete(manifest);
  if (plan_sender)
    delete_plan_sender_destroy(plan_sender);
  if (excluded)
    array_list_delete(excluded);
  if (size_skipped)
    array_list_delete(size_skipped);
  if (synced_dirs)
    array_list_delete(synced_dirs);
  if (plan_dirs)
    array_list_delete(plan_dirs);
  if (missing_args)
    array_list_delete(missing_args);
  if (remove_sources)
    array_list_delete(remove_sources);
  if (dir_entries)
    array_list_delete(dir_entries);
  if (scanner)
    directory_scanner_destroy(scanner);
  prepared_scanner_destroy(&prepared);
  disconnect_transfer_client(client);
  protocol_session_unbind();
  client_set_abort_armed(false);
  return ret;
}

int send_files_multithreaded(Config** config_ptr) {
  if (!config_ptr || !*config_ptr)
    return 1;
  Config* config = *config_ptr;
  if (config->list_only)
    return send_list_only(config);
  if (config->dry_run)
    return dry_run_targets_server(config) ? send_dry_run_remote(config)
                                          : send_dry_run_manifest(config);
  ArrayList* missing_args = NULL;
  int skipped = 0;
  if (config->delete_missing_args) {
    missing_args = array_list_create(free);
    if (!missing_args)
      return 1;
  }
  if (!files_from_list_check(config, missing_args, &skipped)) {
    if (missing_args)
      array_list_delete(missing_args);
    return 1;
  }
  if (config_has_basis(config) && !basis_oversize_preflight(config)) {
    if (missing_args)
      array_list_delete(missing_args);
    return 1;
  }

  /* Armed only once a session may go live (see send_files). */
  client_set_abort_armed(true);

  long pages = sysconf(_SC_AVPHYS_PAGES);
  long page_size = sysconf(_SC_PAGE_SIZE);
  unsigned long long available_memory =
      pages > 0 && page_size > 0 ? (unsigned long long)pages * (unsigned long long)page_size
                                 : 512ULL * 1024 * 1024;
  /* Size the chunk queues from the actual chunk size rather than a fixed 1 MiB
     average: a chunk holds roughly `chunk_size` bytes of file data, so counting
     chunks at 1 MiB over-estimated the queue capacity by up to 10x.  The byte
     budget below is the authoritative bound; this count keeps the unloaded
     chunks waiting in the scanner queue bounded too. */
  unsigned long long chunk_size = config->chunk_size > 0 ? config->chunk_size : DEFAULT_CHUNK_SIZE;
  int qsize = (int)(available_memory / chunk_size);
  if (qsize < 10)
    qsize = 10;
  if (qsize > 1000)
    qsize = 1000;

  Queue* q1 = queue_create(qsize, chunk_destroy);
  Queue* q2 = queue_create(qsize, chunk_destroy);
  if (!q1 || !q2) {
    if (q1)
      queue_destroy(q1);
    if (q2)
      queue_destroy(q2);
    return 1;
  }
  PipelineContextSender* context = pipeline_context_sender_create(config, q1, q2);
  if (!context) {
    queue_destroy(q1);
    queue_destroy(q2);
    if (missing_args)
      array_list_delete(missing_args);
    return 1;
  }
  context->missing_args = missing_args;
  missing_args = NULL; /* owned by the context from here on */
  pipeline_context_sender_set_queue_byte_limit(context, SENDER_QUEUE_MAX_BYTES);
  /* The context borrows `config`; the caller (main) still owns and frees it. */
  struct timespec now_mono;
  if (clock_gettime(CLOCK_MONOTONIC, &now_mono) != 0) {
    now_mono.tv_sec = 0;
    now_mono.tv_nsec = 0;
  }
  context->stop_condition =
      stop_condition_make(config->stop_after_mins > 0, config->stop_after_mins, config->stop_at_set,
                          config->stop_at, now_mono);
  bool collect_excluded = config->use_delete && !config->delete_excluded;
  if (config->use_delete) {
    if (collect_excluded) {
      context->excluded_paths = array_list_create(free);
      if (!context->excluded_paths) {
        pipeline_context_sender_destroy(context);
        return 1;
      }
    }
    /* Size-pruned mirrors stay protected under every mode (even
       --delete-excluded); synchronized directories confine the walk.  A full
       recursive transfer marks the receive root itself (".") so the walk is not
       confined; only a --files-from subset records concrete directories. */
    context->size_skipped_paths = array_list_create(free);
    context->synced_dirs = array_list_create(free);
    if (!context->size_skipped_paths || !context->synced_dirs) {
      pipeline_context_sender_destroy(context);
      return 1;
    }
    if (config->files_from_set == NULL) {
      char* root_marker = delete_scope_root_marker(config);
      if (!root_marker || !array_list_add(context->synced_dirs, root_marker)) {
        free(root_marker);
        pipeline_context_sender_destroy(context);
        return 1;
      }
    }
    /* -d/--dirs does not recurse, so a per-directory plan would carry no child
       information and could delete the contents of an untraversed directory;
       fall back to the whole-tree end-of-transfer commit for that mode. */
    bool per_dir = config_delete_timing_per_dir(config) && !config->dirs;
    if (config_delete_timing_early(config) || per_dir) {
      /* --delete-before / --delete-during / --delete-delay: build the keep-set
         (paths only, nothing loaded or sent) up front so the sender thread can
         transmit it before/with the data.  The path-only pre-scan also fills the
         protected excluded prefixes and synchronized directories. */
      PreparedScanner prepared;
      memset(&prepared, 0, sizeof(prepared));
      bool prepared_ok = prepare_scanner(config, config->scanner_threads, &prepared);
      if (prepared_ok) {
        if (context->excluded_paths)
          prepared.options.excluded_paths = context->excluded_paths;
        prepared.options.size_skipped_paths = context->size_skipped_paths;
        /* The root marker for a full recursive transfer is already in the list;
           only a --files-from subset needs the scanner to record directories. */
        if (config->files_from_set != NULL)
          prepared.options.synced_dirs = context->synced_dirs;
      }
      if (per_dir) {
        context->delete_plans = delete_plan_sender_create();
        context->plan_dirs = array_list_create(free);
        prepared_ok = prepared_ok && context->delete_plans != NULL && context->plan_dirs != NULL;
        if (prepared_ok)
          prepared.options.plan_dirs = context->plan_dirs;
      } else {
        context->manifest = array_list_create(free);
        prepared_ok = prepared_ok && context->manifest != NULL;
      }
      bool prebuilt =
          prepared_ok && scan_paths_only(config, &prepared.options, context->manifest,
                                         context->delete_plans, &context->scan_had_io_error);
      prepared_scanner_destroy(&prepared);
      if (per_dir && prebuilt) {
        const char* walk_root = delete_plan_walk_root(config, context->synced_dirs);
        const ArrayList* scope = config->files_from_set ? context->synced_dirs
                                                        : (walk_root ? context->synced_dirs : NULL);
        delete_plan_sender_finalize(context->delete_plans, scope, walk_root);
        delete_plan_sender_set_config(context->delete_plans, context->excluded_paths,
                                      context->size_skipped_paths, context->missing_args);
      }
      bool empty = per_dir
                       ? (context->delete_plans && delete_plan_sender_empty(context->delete_plans))
                       : (context->manifest && context->manifest->size == 0);
      if (prebuilt && context->scan_had_io_error && empty) {
        /* Empty keep-set + scan I/O error: refusing an empty keep-set would
           have deleted the whole destination (see send_files). */
        log_message(LOG_LEVEL_ERROR,
                    "source scan hit an I/O error before finding any file; refusing to delete "
                    "with an empty keep-set (--delete)");
        prebuilt = false;
      }
      if (!prebuilt) {
        pipeline_context_sender_destroy(context);
        return 1;
      }
      if (context->scan_had_io_error && !ignore_errors_allows_delete(config, true)) {
        /* rsync default: an I/O error suppresses deletion unless
           --ignore-errors.  Drop the prebuilt keep-set so nothing is sent; the
           data pass still transfers the readable tree and exits 23. */
        log_message(LOG_LEVEL_WARNING, "IO error encountered -- skipping file deletion");
        if (context->manifest) {
          array_list_delete(context->manifest);
          context->manifest = NULL;
        }
        if (context->delete_plans) {
          delete_plan_sender_destroy(context->delete_plans);
          context->delete_plans = NULL;
        }
        if (context->plan_dirs) {
          array_list_delete(context->plan_dirs);
          context->plan_dirs = NULL;
        }
        /* A later --delete pass must not try to rebuild/send a keep-set. */
        context->delete_suppressed = true;
      } else if (!per_dir) {
        context->early_delete = true;
      }
    } else {
      context->manifest = array_list_create(free);
      if (!context->manifest) {
        pipeline_context_sender_destroy(context);
        return 1;
      }
    }
  }
  if (config->remove_source_files)
    context->remove_source_files = array_list_create(source_file_destroy);
  if ((config->use_delete && !context->manifest && !context->delete_plans &&
       !context->delete_suppressed) ||
      (config->remove_source_files && !context->remove_source_files)) {
    pipeline_context_sender_destroy(context);
    return 1;
  }

  thrd_t scanner, loader, sender;
  bool scanner_created = false;
  bool loader_created = false;
  bool sender_created = false;

  scanner_created = (thrd_create(&scanner, scan_directory_multithreaded, context) == thrd_success);
  if (scanner_created)
    loader_created = (thrd_create(&loader, load_files_multithreaded, context) == thrd_success);
  if (scanner_created && loader_created)
    sender_created = (thrd_create(&sender, send_chunks_multithreaded, context) == thrd_success);

  if (!scanner_created || !loader_created || !sender_created) {
    log_perror("Error creating threads");
    pipeline_cancel(context);
    mtx_lock(&context->mutex_progress);
    context->sender_done = true;
    mtx_unlock(&context->mutex_progress);
    if (sender_created)
      thrd_join(sender, NULL);
    if (loader_created)
      thrd_join(loader, NULL);
    if (scanner_created)
      thrd_join(scanner, NULL);
    pipeline_context_sender_destroy(context);
    return 1;
  }

  int sender_result;
  thrd_join(scanner, NULL);
  thrd_join(loader, NULL);
  thrd_join(sender, &sender_result);

  bool scan_io;
  mtx_lock(&context->mutex_scanner);
  scan_io = context->scan_had_io_error;
  mtx_unlock(&context->mutex_scanner);
  bool sender_ok = sender_result == thrd_success;
  bool delete_limit = context->delete_limit;
  /* A skipped source entry (--ignore-errors past an unreadable directory, or a
     dereferenced symlink with no referent) makes rsync report a partial
     transfer (exit 23).  A --max-delete-capped commit is a successful transfer
     that rsync reports with exit code 25. */
  pipeline_context_sender_destroy(context);
  client_set_abort_armed(false);
  if (!sender_ok)
    return 1;
  if (scan_io)
    return 23;
  return delete_limit ? 25 : 0;
}
