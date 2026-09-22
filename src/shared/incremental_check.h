#ifndef INCREMENTAL_CHECK_H
#define INCREMENTAL_CHECK_H

#include "config.h"
#include "file_types.h"
#include "protocol.h"
#include <stdbool.h>

/* Incremental-check module: the per-file STATUS_CHECK state machine, the
 * incremental delta / alternate-basis / fuzzy matching helpers and the shared
 * xattr receive helper.  These declarations are re-exported by the
 * file_receive.h facade. */

/* Whole-file payload bound shared by the plain receive path and the
 * incremental check paths. */
#define MAX_FILE_DATA_SIZE MAX_RECEIVE_WHOLE_FILE_SIZE

/* Receive a file's xattr block (when the config enables xattr transport) and
 * attach it to `file`.  Returns false on a malformed/oversized frame. */
bool receive_file_xattrs(File* file, int fd, const Config* config);

File* receive_incremental_check(int fd, const Config* config, bool* skipped);
/* Extended variant used by the receiver.  `would_transfer` (may be NULL) is set
 * true only on the server-contacting --dry-run path when the file is not up to
 * date: the receiver has already sent STATUS_DRY_RUN_TRANSFER and returns NULL
 * without storing anything.  On that path `*skipped` is true for an up-to-date
 * (STATUS_OK) file and both flags are false for a genuine error. */
File* receive_incremental_check_ex(int fd, const Config* config, bool* skipped,
                                   bool* would_transfer);

/* Testable basis quick-check / verification policy.  file_basis_quick_match is
 * rsync's metadata quick-check for a basis candidate (equal size is required
 * separately by the caller; this adds the --size-only / mtime / --modify-window
 * leg).  file_basis_content_required reports whether a hit must ALSO be
 * confirmed by a whole-file content digest (--verify-basis; false is the
 * default rsync-parity behavior). */
bool file_basis_quick_match(const Config* config, const struct stat* st, time_t check_mtime,
                            long check_mtime_nsec);
bool file_basis_content_required(const Config* config);

#endif
