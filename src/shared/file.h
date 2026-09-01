#ifndef FILE_H
#define FILE_H

#include "file_send.h"
#include "file_receive.h"
#include "file_types.h"
#include <stdbool.h>
#include <stdint.h>

/* File/FileMetadata lifecycle and local disk helpers. */

File* file_create(const char* path);
void file_destroy(void* item);
bool file_load_data(File* file);
bool file_checksum(File* file, uint64_t* checksum);
size_t file_content_to_buffer(File* file);
FileMetadata* file_metadata_create(const struct stat* stats);
void file_metadata_destroy(void* metadata);
bool file_write_to_disk(const char* path, const void* data, unsigned long long data_size,
                        bool inplace, bool sparse);
bool file_set_authorized_root(int fd, const char* canonical_path);

#endif
