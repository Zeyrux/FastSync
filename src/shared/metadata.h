#ifndef METADATA_H
#define METADATA_H

#include "file.h"
#include "file_attr.h"
#include <stdbool.h>
#include <stddef.h>
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
 * sizeof(int32_t) + FILE_METADATA_WIRE_SIZE (68 bytes on most platforms).
 *
 * metadata_send()/metadata_receive() (protocol 2.20.0) frame the metadata as a
 * single packed record: one int32 present flag (0 = absent) followed, when
 * present, by exactly FILE_METADATA_WIRE_SIZE bytes of field data.  This is the
 * same present+fields byte layout metadata_to_buf()/metadata_from_buf() use, so
 * the wire metadata is now one frame instead of one frame per field. */
#define FILE_METADATA_WIRE_SIZE (sizeof(int32_t) * 5 + sizeof(int64_t) * 6)

void metadata_to_buf(char** buf, const FileMetadata* m);
/* Decode one packed metadata record (an int32 present flag followed, when
 * present, by FILE_METADATA_WIRE_SIZE field bytes) from `buf`, which has `len`
 * readable bytes.  Every read is bounds-checked against `len`, so the function
 * can never over-read the caller's buffer: a too-short record, an absent
 * (present == 0) record and a malformed record all return NULL.  A successful
 * decode returns a heap-allocated FileMetadata owned by the caller. */
FileMetadata* metadata_from_buf(const uint8_t* buf, size_t len);
bool metadata_send(int file_descriptor, const FileMetadata* m);
FileMetadata* metadata_receive(int file_descriptor, int* ok);
void file_restore_metadata(const char* path, const FileMetadata* metadata, FileAttrPolicy policy);
bool file_restore_metadata_fd(int fd, const FileMetadata* metadata, FileAttrPolicy policy);

/* Shared mode-policy helper: the single source of truth for the receiver's
 * mode rule.  Given a source mode and the destination's CURRENT mode, returns
 * true and stores the exact mode to apply in *out_mode when `policy` requests
 * a change, or false when it requests neither --perms nor --executability (the
 * caller then leaves the destination mode alone).  --perms wins over -E; the
 * -E rule derives exec bits from the destination's read bits (rsync 3.4);
 * group/other write is never granted from a client-supplied mode.  Shared by
 * file_restore_metadata_fd() and the --fake-super replay so the two cannot
 * diverge. */
bool metadata_mode_for_policy(mode_t source_mode, mode_t current_mode, FileAttrPolicy policy,
                              mode_t* out_mode);
/* P7 Wave D: apply a SYMLINK's own metadata using no-follow primitives only
 * (utimensat/lchown/fchmodat with AT_SYMLINK_NOFOLLOW), confined fd-relative
 * under the authorized root.  The link's mode is applied only when policy.perms;
 * policy.times (further suppressed by `omit_link_times` for -J) applies the
 * mtime with policy.atimes controlling the atime slot; ownership stays gated by
 * the identity policy and by default is not applied.
 * A null metadata or an unfollowable parent is a harmless no-op.  Returns false
 * only when a REQUIRED --copy-as ownership application failed, so the caller can
 * report the entry as failed instead of claiming a wrong-owner success. */
bool file_restore_symlink_metadata(const char* path, const FileMetadata* metadata,
                                   FileAttrPolicy policy, bool omit_link_times);

/* Compare timestamps using rsync's whole-second modification window. */
bool metadata_mtime_matches(time_t left_sec, long left_nsec, time_t right_sec, long right_nsec,
                            int modify_window);

#endif
