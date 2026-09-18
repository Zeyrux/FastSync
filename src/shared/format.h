#ifndef FORMAT_H
#define FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Low-level output-formatting primitives shared by the change-event model
 * (change_list.c) and the transfer driver (client_send.c).
 *
 * The functions here are pure/string-level except for the STATUS_DEST_INFO
 * codec, which lets the receiver report the pre-transfer destination entry so
 * the sender can render rsync-accurate --itemize-changes / --out-format
 * columns (see protocol.h). */

/* Pre-transfer destination snapshot, reported by the receiver when the wire
 * config carries report_dest_info.  `known` distinguishes "no report was
 * requested/received" from "the destination did not exist" (`existed == false`
 * with `known == true`). */
typedef struct {
  bool known;
  bool existed;
  unsigned long long size;
  long long mtime_sec;
  long long mtime_nsec;
  uint32_t mode;
  int32_t uid;
  int32_t gid;
} OutputDestState;

/* rsync's -h/--human-readable size (decimal, base 1000): integers below 1000
 * print verbatim; larger values use the largest unit that keeps the value
 * below 1000 (K/M/G/T/P/E) with exactly two decimals, so 1500000 -> "1.50M"
 * and 999999 -> "1000.00K" (matching rsync's human_num).  Returns false when
 * the buffer is too small (nothing is written). */
bool format_human_size_decimal(unsigned long long bytes, char* buffer, size_t buffer_size);

/* rsync's general number formatting (big_num).  When `human_readable` is true
 * this is format_human_size_decimal; otherwise the integer is rendered with a
 * ',' thousands separator every three digits (rsync's separator in the C
 * locale).  Returns false on an undersized buffer. */
bool format_big_num(unsigned long long value, bool human_readable, char* buffer,
                    size_t buffer_size);

/* rsync's %M/%t timestamp.  When `dash` is true the separator between the date
 * and the time is '-' (the %M form: "YYYY/MM/DD-HH:MM:SS"); otherwise it is a
 * space (the %t form: "YYYY/MM/DD HH:MM:SS").  Local time.  Returns false on a
 * bad time or an undersized buffer. */
bool format_rsync_datetime(time_t when, bool dash, char* buffer, size_t buffer_size);

/* Fixed-width STATUS_DEST_INFO record codec (int32 has_old, uint64 size,
 * int64 mtime, int64 mtime_nsec, uint32 mode, int32 uid, int32 gid).  The
 * status frame itself is sent/received by the caller.  Returns false on I/O
 * failure. */
bool format_dest_state_send(int fd, const OutputDestState* state);
bool format_dest_state_receive(int fd, OutputDestState* state);

/* End-of-transfer receiver counters reported through STATUS_STATS (protocol
 * 2.25.0) when the wire config carries report_stats.  `would_delete_count` is
 * the number of destination-relative paths the receiver would have deleted in a
 * -n/--dry-run --delete run; that many wire strings immediately follow the
 * fixed record (sent/read by the caller). */
typedef struct {
  unsigned long long matched_data;
  unsigned long long deleted_files;
  unsigned long long would_delete_count;
} ReceiverStats;

/* Fixed-width STATUS_STATS counter record.  The status frame and the optional
 * would-delete path list are sent/received by the caller.  Returns false on I/O
 * failure. */
bool format_stats_send(int fd, const ReceiverStats* stats);
bool format_stats_receive(int fd, ReceiverStats* stats);

/* Sender-side file-list accounting for rsync's `--stats` block.  Filled while
 * the scan/send loops walk each entry: the flist counters describe every
 * scanned source entry (transferred or skipped), while the transferred/literal
 * counters describe only the regular files the receiver actually stored.  The
 * type split lets the client print rsync's `Number of files` breakdown; the
 * receiver-only counters (matched data, deleted, created) come from
 * STATUS_STATS. */
typedef struct {
  unsigned long long flist_reg;
  unsigned long long flist_dir;
  unsigned long long flist_link;
  unsigned long long flist_special;
  unsigned long long total_file_size;       /* sum of entry sizes (link target len) */
  unsigned long long transferred_regular;   /* regular files actually stored */
  unsigned long long transferred_file_size; /* source size of those files */
  /* Whole-file accuracy: the `--stats` "Literal data" row.  The sender counts
   * the source size of every stored file, so a whole-file transfer matches
   * rsync.  A delta run actually ships only the literal fragments of the diff
   * (the rest is matched/copied), so here the value is an upper bound, not
   * rsync's literal-byte total; see RSYNC_COMPAT.md's `--stats` row. */
  unsigned long long literal_data;
} TransferStats;

#endif
