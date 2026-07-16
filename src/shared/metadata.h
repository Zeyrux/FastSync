#ifndef METADATA_H
#define METADATA_H

#include "file.h"
#include <sys/stat.h>

#define FILE_METADATA_WIRE_SIZE (sizeof(mode_t) + sizeof(uid_t) + sizeof(gid_t) + sizeof(time_t) + sizeof(long))

void metadata_to_buf(char **buf, FileMetadata *m);
FileMetadata *metadata_from_buf(char **buf);
void metadata_send(int file_descriptor, FileMetadata *m);
FileMetadata *metadata_receive(int file_descriptor);
void file_restore_metadata(const char *path, FileMetadata *metadata);

#endif
