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
 * Membership is answered from `index`, built once at load time over the exact
 * entries only: `index.exact` matches a listed path, the sorted view detects an
 * ancestor directory of a listed entry, and `rel`'s own directory prefixes are
 * matched against the exact set while descending.  No ancestor prefix is stored
 * as a separate string, so the index is O(entry count) memory however deep the
 * paths are, and each query is O(path length) comparisons. */
typedef struct {
  char** entries; /* normalized rel paths; "" means the whole tree */
  int count;
  PathIndex index;
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
