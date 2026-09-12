#ifndef FILE_STORE_H
#define FILE_STORE_H

#include "file.h"
#include <stdbool.h>

bool file_store_set_authorized_root(int fd, const char* canonical_path);
int file_store_open_secure_parent(const char* path, char** leaf_out);
bool file_store_rename_secure(const char* old_path, const char* new_path);
bool file_store_write_secure(const char* path, const void* data, unsigned long long data_size,
                             bool inplace, bool sparse, const FileMetadata* metadata,
                             bool preserve_executability);
/* Sparse-aware write (--sparse/-S): every all-zero run of at least
 * SPARSE_HOLE_MIN bytes is skipped with lseek(SEEK_CUR) so it becomes a real
 * hole; every other byte is written.  The caller pre-sizes the file with
 * ftruncate; this function also ftruncate()s to `size` at the end so a trailing
 * hole keeps the exact logical length.  Shared by the file_store and file write
 * paths.  Returns false on write/lseek/ftruncate error. */
bool file_store_write_sparse(int fd, const unsigned char* data, unsigned long long size);

#endif
