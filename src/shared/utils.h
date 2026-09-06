#ifndef UTILS_H
#define UTILS_H

#include "array_list.h"
#include <stddef.h>
#include <stdbool.h>

char* str_dup(const char* string);
char* output_escape(const char* string, bool eight_bit_output);
char* path_cat(const char* path1, const char* path2);
bool glob_match(const char* pattern, const char* str);
/* Result of a bounded extra-file deletion run. */
typedef enum {
  /* Every extra entry was removed (or there were none). */
  DELETE_WALK_OK = 0,
  /* The destination holds more extras than the numeric cap for this run.  With
     the all-or-nothing max-delete semantics NOTHING was removed (the walker
     counts first and refuses to start when the run would exceed the limit). */
  DELETE_WALK_LIMIT_EXCEEDED,
  /* A traversal or unlink failure aborted the deletion (partial removal is
     possible, mirroring the delete pass). */
  DELETE_WALK_ERROR
} DeleteWalkResult;
/* One protected entry for the delete walker.  When top_level_only is true the
   prefix is skipped only as a DIRECT child of dest_root (the --delay-updates
   staging directory, which must not hide genuine extras inside a nested
   destination directory that happens to share the staging name); otherwise the
   prefix is skipped at any depth (the --compare-dest/--copy-dest/--link-dest
   basis trees, and the sender-side protected filter-excluded prefixes, which
   are never destination content). */
typedef struct {
  const char* prefix;
  bool top_level_only;
} DeleteSkipEntry;
/* Remove files/dirs under dest_root that are not listed in manifest without
   ever descending into a protected prefix (see DeleteSkipEntry).  When
   max_delete is not SIZE_MAX the run is all-or-nothing: extras are counted
   first and DELETE_WALK_LIMIT_EXCEEDED is returned (with nothing removed) when
   the count would exceed the cap.  `deleted_out` optionally receives the number
   of entries actually removed. */
DeleteWalkResult delete_extras_limited(const char* dest_root, ArrayList* manifest,
                                       size_t max_delete, const DeleteSkipEntry* skips,
                                       int skip_count, size_t* deleted_out);
bool delete_extras(const char* dest_root, ArrayList* manifest);
bool utils_set_authorized_root(int fd, const char* canonical_path);
/* The fd-only compatibility form is fail-closed for path-based operations;
 * callers should use utils_set_authorized_root with the canonical identity. */
void utils_set_authorized_root_fd(int fd);
bool has_path_traversal(const char* path);
bool utils_valid_batch_path(const char* path);
bool format_human_bytes(unsigned long long bytes, char* buffer, size_t buffer_size);

#endif
