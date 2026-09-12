#ifndef METADATA_H
#define METADATA_H

#include "file.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>

/*
 * Wire format (introduced in protocol version 2.0.0):
 *   int32_t present
 *   int32_t mode    (was mode_t, platform-dependent)
 *   int32_t uid     (was uid_t,  platform-dependent)
 *   int32_t gid     (was gid_t,  platform-dependent)
 *   int64_t mtime_sec (was time_t, platform-dependent)
 *   int64_t mtime_nsec (was long,  platform-dependent)
 *   int32_t atime_valid   (-U/--atimes; protocol 2.12.0)
 *   int64_t atime_sec
 *   int64_t atime_nsec
 *   int32_t crtime_valid  (-N/--crtimes; protocol 2.12.0)
 *   int64_t crtime_sec
 *   int64_t crtime_nsec
 *
 * Prior to 2.0.0 the wire format used the raw platform-dependent types,
 * which broke compatiblity across different systems.  All fields are now
 * serialized as fixed-width integers.
 */

/* Size of metadata fields on wire, excluding the int32_t `present` field that
 * is always sent first. The total wire size for present metadata is
 * sizeof(int32_t) + FILE_METADATA_WIRE_SIZE (68 bytes on most platforms). */
#define FILE_METADATA_WIRE_SIZE (sizeof(int32_t) * 5 + sizeof(int64_t) * 6)

void metadata_to_buf(char** buf, const FileMetadata* m);
FileMetadata* metadata_from_buf(char** buf);
bool metadata_send(int file_descriptor, const FileMetadata* m);
FileMetadata* metadata_receive(int file_descriptor, int* ok);
void file_restore_metadata(const char* path, const FileMetadata* metadata,
                           bool preserve_executability);
bool file_restore_metadata_fd(int fd, const FileMetadata* metadata, bool preserve_executability);
/* P7 Wave D: apply a SYMLINK's own metadata using no-follow primitives only
 * (utimensat/lchown/fchmodat with AT_SYMLINK_NOFOLLOW), confined fd-relative
 * under the authorized root.  `omit_link_times` (-J/--omit-link-times)
 * suppresses the timestamps; the link's mode/ownership are still attempted
 * (ownership stays gated by the identity policy and by default is not applied).
 * A null metadata or an unfollowable parent is a harmless no-op. */
void file_restore_symlink_metadata(const char* path, const FileMetadata* metadata,
                                   bool omit_link_times);

/* Compare timestamps using rsync's whole-second modification window. */
bool metadata_mtime_matches(time_t left_sec, long left_nsec, time_t right_sec, long right_nsec,
                            int modify_window);

#endif
