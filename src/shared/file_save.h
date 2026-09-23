#ifndef FILE_SAVE_H
#define FILE_SAVE_H

#include "config.h"
#include "file_types.h"
#include "format.h"
#include <stdbool.h>

/* Save-to-disk module: regular-file/symlink/hardlink/special install, xattr
 * application, --fake-super and the --delay-updates staging path.  These
 * declarations are re-exported by the file_receive.h facade. */

/* Outcome of a single file_save_to_disk operation.  The receiver needs to
   distinguish "written" from "skipped" so --remove-source-files can be told
   which sources were actually stored.  FILE_SAVE_FAILED is a per-entry failure
   (for example a device node that mknodat() refused with EPERM/EACCES): it is
   logged and counted by the receiver but does NOT abort the transfer, matching
   rsync's continue-and-exit-partial behavior. */
typedef enum {
  FILE_SAVE_ERROR = 0,
  FILE_SAVE_WRITTEN = 1,
  FILE_SAVE_SKIPPED = 2,
  FILE_SAVE_FAILED = 3
} FileSaveResult;

bool file_special_rdev_valid(int32_t major, int32_t minor, mode_t mode);

FileSaveResult file_save_to_disk_full(const char* root_directory, const File* file,
                                      const Config* config);
/* Protocol 2.28.0 variant: also reports through `created` (when non-NULL)
 * whether the destination entry did not exist before this save, and through
 * `created_dirs` how many parent directories the confined walk created, so the
 * receiver can build rsync's `Number of created files` breakdown.  The plain
 * file_save_to_disk_full() is this with both out-params NULL. */
FileSaveResult file_save_to_disk_full_ex(const char* root_directory, const File* file,
                                         const Config* config, bool* created,
                                         unsigned* created_dirs);
bool file_save_to_disk(const char* root_directory, const File* file, const Config* config);

/* Protocol 2.28.0 receiver counter accumulator: fold one successfully saved
 * entry into `stats`, adding its receiver-observed literal bytes and, when
 * `created`, the matching created-by-type counter (regular file / symlink /
 * special) plus `created_dirs` implicitly-created parent directories.
 * Non-first hardlink siblings contribute no literal bytes. */
void receiver_stats_note_saved(ReceiverStats* stats, const File* file, bool created,
                               unsigned created_dirs);

#endif
