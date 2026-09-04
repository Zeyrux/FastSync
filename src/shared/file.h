#ifndef FILE_H
#define FILE_H

#include "file_send.h"
#include "file_receive.h"
#include "file_types.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

/* File/FileMetadata lifecycle, local disk helpers, and secure filesystem
   primitives shared by the send/receive pipelines. */

File* file_create(const char* path);
void file_destroy(void* item);
bool file_load_data(File* file);
bool file_checksum(File* file, uint64_t* checksum);
size_t file_content_to_buffer(File* file);
FileMetadata* file_metadata_create(const struct stat* stats);
void file_metadata_destroy(void* metadata);
bool file_write_to_disk(const char* path, const void* data, unsigned long long data_size,
                        bool inplace, bool sparse);

/* A configured fd without a canonical identity deliberately rejects paths. */
bool file_set_authorized_root(int fd, const char* canonical_path);

/* Secure path/filesystem primitives (symlink-safe, O_NOFOLLOW, root-confined). */
bool file_path_exists_secure(const char* path);
bool file_stat_secure(const char* path, struct stat* st);
bool file_destination_is_newer_secure(const char* path, const FileMetadata* metadata);
int file_open_secure_parent(const char* path, char** leaf_out, bool create_dirs);
bool file_ensure_directory_secure(const char* path);
bool file_rename_secure(const char* old_path, const char* new_path);
bool file_to_disk_secure(const char* path, const void* data, unsigned long long data_size,
                         bool inplace, bool sparse, const FileMetadata* metadata,
                         bool preserve_executability);
bool file_to_disk_secure_with_fsync(const char* path, const void* data,
                                    unsigned long long data_size, bool inplace, bool sparse,
                                    const FileMetadata* metadata, bool preserve_executability,
                                    bool use_fsync);
/* With update enabled, an existing newer destination is left untouched.  The
   check is descriptor-based for inplace writes; atomic replacement still has
   an unavoidable final rename race without filesystem locking. */
bool file_to_disk_secure_update(const char* path, const void* data, unsigned long long data_size,
                                bool inplace, bool sparse, const FileMetadata* metadata,
                                bool preserve_executability);
bool file_to_disk_secure_no_replace(const char* path, const void* data,
                                    unsigned long long data_size, bool sparse,
                                    const FileMetadata* metadata, bool preserve_executability);

#endif
