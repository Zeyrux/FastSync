#ifndef FILE_LIST_H
#define FILE_LIST_H

#include "utils.h"
#include <stdbool.h>
#include <stddef.h>

/* --files-from allow-set. The file lists source paths RELATIVE to the source
 * root. A listed regular file is transferred; a listed directory transfers its
 * whole subtree (FastSync's recursion is always on). Blank lines are ignored.
 *
 * Entries are normalized: leading "./" and duplicate "/" are removed, an entry
 * of "." means the whole tree, absolute entries and ".." traversal are
 * rejected at parse time. The set is immutable and shared read-only across
 * scanner worker threads.
 *
 * Membership is answered from `node_index`, built once at load time: it holds
 * every entry plus every ancestor directory prefix of an entry, with the entry
 * flag distinguishing an exact listed path from a mere ancestor.  A lookup is
 * O(path length) instead of O(entry count). */
typedef struct {
  char** entries; /* normalized rel paths; "" means the whole tree */
  int count;
  StrHashSet node_index;
  bool whole_tree; /* an entry of "" lists the source root */
} FileListSet;

/* Load and validate a --files-from file. When `null_separated` (-0/--from0)
 * entries are delimited by NUL instead of newlines. Returns NULL with a message
 * in `err` on open/validation failure. An empty file yields an empty set
 * (nothing is transferred). */
FileListSet* file_list_load(const char* path, bool null_separated, char* err, size_t err_size);
void file_list_destroy(FileListSet* set);

/* True when `rel` (path relative to the source root, "" == root) is a listed
 * entry, lives under a listed directory, or is an ancestor directory of a
 * listed entry. Used to prune scanning: directories are descended only when
 * this returns true, files are transferred only when it returns true. */
bool file_list_affects(const FileListSet* set, const char* rel);

#endif
