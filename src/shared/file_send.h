#ifndef FILE_SEND_H
#define FILE_SEND_H

#include "file_types.h"
#include <stdbool.h>

/* Client-side file send path. */

bool file_send_single_calls(File* file, int file_descriptor, bool use_metadata,
                            int compression_level, bool send_path);
bool file_send_sendfile(File* file, int file_descriptor, bool use_metadata, int compression_level,
                        bool send_path);

#endif
