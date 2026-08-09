#ifndef METADATA_H
#define METADATA_H

#include "file.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

/*
 * Wire format (introduced in protocol version 2.0.0):
 *   int32_t present
 *   int32_t mode    (was mode_t, platform-dependent)
 *   int32_t uid     (was uid_t,  platform-dependent)
 *   int32_t gid     (was gid_t,  platform-dependent)
 *   int64_t mtime_sec (was time_t, platform-dependent)
 *   int64_t mtime_nsec (was long,  platform-dependent)
 *
 * Prior to 2.0.0 the wire format used the raw platform-dependent types,
 * which broke compatiblity across different systems.  All fields are now
 * serialized as fixed-width integers.
 */

/* Size of metadata fields on wire, excluding the int32_t `present` field that
 * is always sent first. The total wire size for present metadata is
 * sizeof(int32_t) + FILE_METADATA_WIRE_SIZE (32 bytes on most platforms). */
#define FILE_METADATA_WIRE_SIZE (sizeof(int32_t) * 3 + sizeof(int64_t) * 2)

void metadata_to_buf(char** buf, const FileMetadata* m);
FileMetadata* metadata_from_buf(char** buf);
bool metadata_send(int file_descriptor, FileMetadata* m);
FileMetadata* metadata_receive(int file_descriptor, int* ok);
void file_restore_metadata(const char* path, FileMetadata* metadata);
void file_restore_metadata_fd(int fd, FileMetadata* metadata);

#endif
