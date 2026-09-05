#ifndef FILE_RECEIVE_H
#define FILE_RECEIVE_H

#include "config.h"
#include "file_types.h"
#include <stdbool.h>

/* Server-side file receive/save path. */

File* file_receive(const Config* config, int file_descriptor);
File* receive_incremental_check(int fd, const Config* config, bool* skipped);
int receive_manifest(int fd, const Config* config, int* next_status);

/* Outcome of a single file_save_to_disk operation.  The receiver needs to
   distinguish "written" from "skipped" so --remove-source-files can be told
   which sources were actually stored. */
typedef enum { FILE_SAVE_ERROR = 0, FILE_SAVE_WRITTEN = 1, FILE_SAVE_SKIPPED = 2 } FileSaveResult;

FileSaveResult file_save_to_disk_full(const char* root_directory, const File* file,
                                      const Config* config);
bool file_save_to_disk(const char* root_directory, const File* file, const Config* config);

#endif
