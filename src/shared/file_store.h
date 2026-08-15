#ifndef FILE_STORE_H
#define FILE_STORE_H

#include "file.h"
#include <stdbool.h>

void file_store_set_authorized_root(int fd, const char* canonical_path);
int file_store_open_secure_parent(const char* path, char** leaf_out);
bool file_store_rename_secure(const char* old_path, const char* new_path);
bool file_store_write_secure(const char* path, const void* data, unsigned long long data_size,
                             bool inplace, bool sparse, const FileMetadata* metadata);

#endif
