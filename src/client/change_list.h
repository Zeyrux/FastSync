#ifndef CHANGE_LIST_H
#define CHANGE_LIST_H

#include "config.h"
#include "file_types.h"
#include "format.h"
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
 * send loop and the `-m` sender thread both call the same per-file sender), so
 * all change events are emitted by exactly one thread and itemize/out-format
 * lines never interleave with each other.  They may still interleave with
 * legacy log messages (log.c) that share the same stdout/log-file stream.
 */

typedef enum {
  CHANGE_SENT,       /* file data (full or delta) was transmitted */
  CHANGE_UP_TO_DATE, /* receiver already had an identical file; skipped */
} ChangeDecision;

typedef struct {
  const char* path; /* long-form display path (rsync %f) */
  const char* name; /* transfer-relative path (rsync %n), no trailing slash */
  ChangeDecision decision;
  bool is_directory;
  bool is_symlink;
  bool is_special;
  bool is_hardlink; /* a hard-link sibling (linked, no data sent) */
  const char* symlink_target;
  const char* hardlink_target;
  unsigned long long size;       /* source file length in bytes */
  unsigned long long bytes_sent; /* literal data bytes actually transferred */
  time_t mtime_sec;
  long mtime_nsec;
  mode_t mode;
  uid_t uid;
  gid_t gid;
  /* Receiver-reported pre-transfer destination state (OutputDestState.known is
   * false when no report was requested/received). */
  OutputDestState dest;
} ChangeEvent;

/* True when any output mode is active and per-file events matter. */
bool change_list_enabled(const Config* config);

/* Render the rsync-style itemize line for a transferred item
 * (`%i %n%L`): `>f+++++++++ sub/b.txt`.  Caller frees the result. */
char* change_render_itemize(const Config* config, const ChangeEvent* event);

/* Render only the 11-character itemize code (rsync %i).  Caller frees. */
char* change_render_itemize_code(const Config* config, const ChangeEvent* event);

/* Expand an --out-format/--log-file-format template.  Supported tokens:
 *   %i  itemize code            %n  transfer-relative name (dir: trailing /)
 *   %f  long display path       %l  file length in bytes
 *   %b  bytes actually sent     %M  mtime (YYYY/MM/DD-HH:MM:SS)
 *   %t  current time            %o  operation ("send"/"del.")
 *   %p  pid                     %B  permission bits without the type char
 *   %U  uid                     %G  gid
 *   %L  " -> target" / " => target"    %%  a literal percent sign
 * Unknown %X sequences are preserved verbatim.  Caller frees the result. */
char* change_render_format(const char* format, const Config* config, const ChangeEvent* event);

/* Render one --list-only long-listing entry:
 *   `-rw-r--r--           12 2026/09/06 10:00:00 sub/b.txt`
 * (ls -l style columns; mtime in the local time zone).  Caller frees it. */
char* change_render_list_line(const Config* config, const ChangeEvent* event);

/* Emit an event to every active destination:
 *   stdout: --itemize-changes line, or the --out-format expansion when set;
 *   log file: the --log-file-format expansion (requires --log-file).
 * CHANGE_UP_TO_DATE events produce no output. */
void change_emit(const Config* config, const ChangeEvent* event);

/* Build and emit a CHANGE_SENT event for a file the client just sent. */
void change_emit_file_sent(const Config* config, const File* file);

/* Build and emit a CHANGE_SENT event for an explicit directory entry (-d). */
void change_emit_dir_sent(const Config* config, const File* file);

#endif
