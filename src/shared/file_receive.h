#ifndef FILE_RECEIVE_H
#define FILE_RECEIVE_H

#include "config.h"
#include "file_types.h"
#include <stdbool.h>

/* Server-side file receive/save path. */

File* file_receive(const Config* config, int file_descriptor);
File* file_receive_directory(int file_descriptor);
File* receive_incremental_check(int fd, const Config* config, bool* skipped);
/* Read a delete-manifest frame: entry count then paths (self-delimiting; the
   leading STATUS_MANIFEST code has been consumed).  Returns an owned path
   ArrayList, or NULL after signalling STATUS_ERROR on a malformed frame. */
ArrayList* receive_manifest_entries(int fd);
/* Remove destination entries under config->receive_root_directory that are not
   in `manifest` (bounded walk, staging-dir skip).  The caller decides WHEN to
   run it based on the negotiated delete timing. */
bool manifest_delete_extras(const Config* config, ArrayList* manifest);

/* Outcome of a single file_save_to_disk operation.  The receiver needs to
   distinguish "written" from "skipped" so --remove-source-files can be told
   which sources were actually stored. */
typedef enum { FILE_SAVE_ERROR = 0, FILE_SAVE_WRITTEN = 1, FILE_SAVE_SKIPPED = 2 } FileSaveResult;

FileSaveResult file_save_to_disk_full(const char* root_directory, const File* file,
                                      const Config* config);
bool file_save_to_disk(const char* root_directory, const File* file, const Config* config);

#endif
