#ifndef FILE_RECEIVE_H
#define FILE_RECEIVE_H

#include "config.h"
#include "delete_commit.h"
#include "file_save.h"
#include "file_types.h"
#include "incremental_check.h"
#include "utils.h"
#include <stdbool.h>

/* Server-side file receive/save path.
 *
 * This header is the public facade for the file_receive module family: the
 * wire receive dispatch (this file) plus the save-to-disk (file_save.h), the
 * incremental check (incremental_check.h) and the delete-commit
 * (delete_commit.h) modules. */

/* Cumulative caps for the deferred directory-time accumulator.  The sender may
 * legitimately split a large tree across repeated STATUS_DIR_TIMES frames, so a
 * per-frame bound is not enough: the receiver must bound the TOTAL it retains
 * against a hostile sender.  Mirror the delete-manifest limits
 * (MAX_MANIFEST_ENTRIES / MAX_MANIFEST_BYTES): the entry count bounds the
 * metadata array and the byte budget bounds the concatenated path strings. */
#define MAX_DIR_TIME_ENTRIES (1024 * 1024)
#define MAX_DIR_TIME_BYTES (16ULL * 1024 * 1024)

File* file_receive(const Config* config, int file_descriptor);
File* file_receive_directory(int file_descriptor, const Config* config);
File* file_receive_dir_time(int file_descriptor, const Config* config);
File* file_receive_hardlink(int file_descriptor);
File* file_receive_symlink(int file_descriptor, const Config* config);
File* file_receive_special(int file_descriptor);

/* P7 Wave D directory-time accumulator.  The receiver collects the metadata of
 * every directory it creates/receives (STATUS_MKDIR with metadata and/or the
 * trailing STATUS_DIR_TIMES frame(s)) and applies the times only at the END of the
 * transfer, after all children have been written and after the delete /
 * --delay-updates phases have committed (writing or removing a child bumps the
 * parent's mtime).  -O/--omit-dir-times skips the application entirely.  The
 * list owns deep copies of the paths and metadata; freed on every path. */
typedef struct {
  char** paths;           /* owned, destination-relative wire paths */
  FileMetadata* entries;  /* owned, parallel to paths */
  FileXattrList** xattrs; /* owned, parallel to paths; NULL when none */
  size_t count;
  size_t capacity;
  size_t bytes; /* cumulative strlen of every retained path */
} DirTimeList;

/* Capture gate shared by the sender-side and receiver-side sinks: directory
 * metadata is accumulated only when a directory attribute is requested
 * (-p/--perms for directory modes, or -t/--times for directory mtimes with
 * -O/--omit-dir-times not suppressing them) and metadata rides the wire.  Kept
 * here, next to the accumulator it guards, so both call sites express the same
 * condition. */
bool dir_metadata_should_capture(const Config* config);

void dir_time_list_init(DirTimeList* list);
void dir_time_list_free(DirTimeList* list);
/* Deep-copy one directory's path + metadata (and, when non-NULL, its captured
 * xattr/ACL block) into the list.  Returns false on allocation failure OR when
 * the cumulative entry/byte caps would be exceeded (the caller fails the
 * transfer). */
bool dir_time_list_add(DirTimeList* list, const char* wire_path, const FileMetadata* metadata,
                       const FileXattrList* xattrs);
/* Apply every accumulated directory's metadata beneath `root_directory`,
 * confined fd-relative: ownership through the negotiated identity policy,
 * times (mtime, plus atime when -U captured one under -t), the mode (through
 * --chmod when configured, under -p), and the captured xattrs/ACLs (under
 * -X/-A).  Best-effort per entry: an absent directory (an empty/pruned source
 * dir that was deliberately not created) or a non-directory at the path is
 * skipped QUIETLY, an unreachable one with a warning, and never fatal. */
void dir_metadata_list_apply(const DirTimeList* list, const char* root_directory,
                             const Config* config);

#endif
