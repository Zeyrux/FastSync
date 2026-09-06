#ifndef CHANGE_LIST_H
#define CHANGE_LIST_H

#include "config.h"
#include "file_types.h"
#include <stdbool.h>
#include <sys/stat.h>
#include <time.h>

/*
 * Shared per-file change-event / output model (rsync --itemize-changes,
 * --out-format, --log-file-format, and --list-only all render from here).
 *
 * FastSync is a push-style tool: the client sends files from the source tree
 * to a server that writes them under the destination root.  Events are
 * emitted by whichever code path decides a file's fate (the single-threaded
 * send loop and the `-m` sender thread both call the same per-file sender, so
 * only that one thread ever reports events - no cross-thread printing races).
 */

typedef enum {
  CHANGE_SENT,       /* file data (full or delta) was transmitted */
  CHANGE_UP_TO_DATE, /* receiver already had an identical file; skipped */
} ChangeDecision;

typedef struct {
  const char* path; /* full source path */
  ChangeDecision decision;
  bool is_directory;
  unsigned long long size;       /* source file length in bytes */
  unsigned long long bytes_sent; /* payload bytes sent (best effort) */
  time_t mtime_sec;              /* 0 when unknown */
} ChangeEvent;

/* True when any output mode is active and per-file events matter. */
bool change_list_enabled(const Config* config);

/* Render the rsync-style itemize line for a transferred file:
 *   `>f+++++++++ <path>`
 * The 11-char code is `>f` (regular file transferred to the remote host)
 * followed by c/s/t/p/o/g/u/a/x markers that are all `+` (value will be set
 * / differs) because FastSync does not separately compare checksums, size,
 * mtime, perms, owner, group, uid, acl, or xattr on the receiving side, so a
 * sent file is reported as fully updated.  Up-to-date files print no line
 * (rsync single `-i` only shows changes).  Caller frees the result. */
char* change_render_itemize(const ChangeEvent* event);

/* Expand an --out-format/--log-file-format template.  Tokens:
 *   %f  full source path        %b  bytes sent (== %l for a whole file)
 *   %n  leaf (base) name        %M  mtime in whole seconds since the epoch
 *   %l  file length in bytes    %%  a literal percent sign
 * Unknown %X sequences are preserved verbatim.  Caller frees the result. */
char* change_render_format(const char* format, const ChangeEvent* event);

/* Render one --list-only long-listing entry:
 *   `-rw-r--r--           12 2026/09/06 10:00:00 <path>`
 * (ls -l style columns; mtime in the local time zone).  Caller frees it. */
char* change_render_list_line(mode_t mode, unsigned long long size, time_t mtime, const char* path);

/* Emit an event to every active destination:
 *   stdout: --itemize-changes line, or the --out-format expansion when set;
 *   log file: the --log-file-format expansion (requires --log-file).
 * CHANGE_UP_TO_DATE events produce no output. */
void change_emit(const Config* config, const ChangeEvent* event);

/* Build and emit a CHANGE_SENT event for a file the client just sent. */
void change_emit_file_sent(const Config* config, const File* file);

#endif
