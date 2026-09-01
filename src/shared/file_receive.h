#ifndef FILE_RECEIVE_H
#define FILE_RECEIVE_H

#include "config.h"
#include "file_types.h"
#include <stdbool.h>

/* Server-side file receive/save path. */

File* file_receive(const Config* config, int file_descriptor);
File* receive_incremental_check(int fd, const Config* config, bool* skipped);
int receive_manifest(int fd, const Config* config, int* next_status);
bool file_save_to_disk(const char* root_directory, const File* file, const Config* config);

#endif
