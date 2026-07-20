#ifndef METADATA_H
#define METADATA_H

#include "file.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#define FILE_METADATA_WIRE_SIZE (sizeof(int32_t) * 3 + sizeof(int64_t) * 2)

void metadata_to_buf(char** buf, const FileMetadata* m);
FileMetadata* metadata_from_buf(char** buf);
bool metadata_send(int file_descriptor, FileMetadata* m);
FileMetadata* metadata_receive(int file_descriptor, int* ok);
void file_restore_metadata(const char* path, FileMetadata* metadata);

#endif
