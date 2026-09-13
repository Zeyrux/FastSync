#ifndef FILE_STORE_H
#define FILE_STORE_H

#include <stdbool.h>

/* Sparse-aware write (--sparse/-S): every all-zero run of at least
 * SPARSE_HOLE_MIN bytes is skipped with lseek(SEEK_CUR) so it becomes a real
 * hole; every other byte is written.  The caller pre-sizes the file with
 * ftruncate; this function also ftruncate()s to `size` at the end so a trailing
 * hole keeps the exact logical length.  Shared by the file_store and file write
 * paths.  Returns false on write/lseek/ftruncate error. */
bool file_store_write_sparse(int fd, const unsigned char* data, unsigned long long size);

#endif
