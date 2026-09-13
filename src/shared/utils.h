#ifndef UTILS_H
#define UTILS_H

#include "array_list.h"
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>

/* Small open-addressing string hash set used to turn quadratic membership
 * scans into O(path length) exact-match lookups (the --delete keep-set and the
 * --files-from allow-set).  Keys are hashed with xxHash64 (seed 0); collisions
 * are resolved by linear probing over a power-of-two table that grows at 75%
 * load.  Keys are always borrowed from the caller and must outlive the set; the
 * set never copies or owns keys, so indexing M entries costs O(M) memory.  The
 * set is not thread-safe for mutation, but a fully built set supports
 * concurrent read-only lookups. */
typedef struct {
  const char* key; /* NULL marks an empty slot */
} StrHashSetSlot;

typedef struct {
  StrHashSetSlot* slots;
  size_t capacity; /* power of two, zero before init */
  size_t size;
} StrHashSet;

/* Initialize an empty set sized for roughly `hint` entries.  Returns false on
 * allocation failure. */
bool str_hash_set_init(StrHashSet* set, size_t hint);
void str_hash_set_free(StrHashSet* set);
/* Insert a borrowed key (must outlive the set).  A duplicate is ignored.
 * Returns false on allocation failure. */
bool str_hash_set_insert_ref(StrHashSet* set, const char* key);
/* Look up a NUL-terminated key / a key of `len` bytes. */
bool str_hash_set_lookup(const StrHashSet* set, const char* key);
bool str_hash_set_lookup_n(const StrHashSet* set, const char* key, size_t len);

/* Sorted, non-owning view of NUL-terminated strings.  Built from borrowed
 * pointers (qsort), so indexing M entries costs O(M) memory and O(M log M)
 * time; exact membership and ancestor-prefix existence are binary searches
 * that never materialize a prefix copy. */
typedef struct {
  const char** items; /* sorted with strcmp; borrowed, never freed */
  size_t count;
} StrSortedArray;

/* Build `array` over the borrowed `items`.  Only the pointer array is copied,
 * never the strings.  Returns false on allocation failure. */
bool str_sorted_array_build(StrSortedArray* array, const char* const* items, size_t count);
void str_sorted_array_free(StrSortedArray* array);
/* True when some item equals `key`. */
bool str_sorted_array_contains(const StrSortedArray* array, const char* key);
/* True when some item starts with `key` followed by '/' (i.e. `key` is a proper
 * ancestor directory of an item).  Allocates nothing. */
bool str_sorted_array_has_child_prefix(const StrSortedArray* array, const char* key);

/* Read-only membership index over exact relative paths.  `exact` answers
 * O(path length) equality; `sorted` answers whether any indexed path lies
 * strictly below a query directory.  Both borrow their keys from the caller and
 * no ancestor prefix is stored as a separate string, so an index over M entries
 * is O(M) memory regardless of path depth.  Not thread-safe to build, but safe
 * for concurrent read-only queries once built. */
typedef struct {
  StrHashSet exact;
  StrSortedArray sorted;
} PathIndex;

/* Build an index borrowing `entries` (which must outlive the index).  Returns
 * false on allocation failure, freeing any partial state. */
bool path_index_build(PathIndex* index, const char* const* entries, size_t count);
void path_index_free(PathIndex* index);
/* True when `path` is an indexed entry. */
bool path_index_contains(const PathIndex* index, const char* path);
/* Length-bounded form of path_index_contains (`path` need not be terminated). */
bool path_index_contains_n(const PathIndex* index, const char* path, size_t len);
/* True when some indexed entry lies strictly below `path` (starts with
 * `path` + '/'). */
bool path_index_has_descendant(const PathIndex* index, const char* path);

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
/* True when child_rel is, or lies below, one of the protected entries (a prefix
   "a" protects "a" and "a/b/c" but not "ab"; top_level_only entries protect
   only DIRECT children of the destination root, i.e. child_rel has no '/'). */
bool path_under_skip_prefix(const char* child_rel, bool at_root, const DeleteSkipEntry* skips,
                            int skip_count);
/* Remove files/dirs under dest_root that are not listed in manifest without
   ever descending into a protected prefix (see DeleteSkipEntry).  When
   max_delete is not SIZE_MAX the run is all-or-nothing: extras are counted
   first and DELETE_WALK_LIMIT_EXCEEDED is returned (with nothing removed) when
   the count would exceed the cap.  `deleted_out` optionally receives the number
   of entries actually removed.  The all-or-nothing guarantee holds only while
   the destination tree is not being concurrently modified: the rehearsal pass
   and the delete pass are two separate walks, so a concurrent change between
   them (another process adding/removing entries) can make the second pass
   delete a different set than the first one counted. */
DeleteWalkResult delete_extras_limited(const char* dest_root, const ArrayList* manifest,
                                       size_t max_delete, const DeleteSkipEntry* skips,
                                       int skip_count, size_t* deleted_out);
bool delete_extras(const char* dest_root, const ArrayList* manifest);
bool utils_set_authorized_root(int fd, const char* canonical_path);
/* The fd-only compatibility form is fail-closed for path-based operations;
 * callers should use utils_set_authorized_root with the canonical identity. */
void utils_set_authorized_root_fd(int fd);
/* True when `path` is `root` itself or lies directly beneath it: a lexical
 * prefix test requiring the byte after `root` to be '\0' or '/'.  Both `root`
 * and `path` must be absolute canonical paths free of "."/".." components (the
 * callers guarantee this); this is containment by string, not by resolved
 * symlinks.  Shared by the utils and file secure-walk root confinement. */
bool path_is_within_root(const char* root, const char* path);
bool has_path_traversal(const char* path);
bool utils_valid_batch_path(const char* path);
bool format_human_bytes(unsigned long long bytes, char* buffer, size_t buffer_size);
/* --append / --append-verify tail-resume math (pure).  A resume is eligible only
   when an existing destination file is SHORTER than the source; the tail length
   is then the difference.  append_resume_eligible answers whether the shorter
   file makes a resume possible; append_tail_length additionally returns that
   tail length, refusing (false) the degenerate old_size >= check_size case. */
bool append_resume_eligible(unsigned long long old_size, unsigned long long check_size);
bool append_tail_length(unsigned long long old_size, unsigned long long check_size,
                        unsigned long long* tail_out);
/* Loopback / local-transport classification for the daemon auth gate and the
   client credential rule.  utils_sockaddr_is_loopback accepts 127.0.0.0/8,
   IPv6 ::1 and IPv4-mapped ::ffff:127.x.x.x; utils_host_is_loopback additionally
   accepts the literal "localhost".  utils_fd_peer_is_local is fail-closed: it is
   true only when getpeername SUCCEEDS and reports a loopback peer -- a non-socket
   descriptor (pipe/socketpair) or any getpeername error yields false.  See
   utils.c for the exact accepted forms. */
bool utils_sockaddr_is_loopback(const struct sockaddr* addr);
bool utils_fd_peer_is_local(int fd);
bool utils_host_is_loopback(const char* host);
/* Numeric peer address of a connected fd (INET6_ADDRSTRLEN is always enough).
 * Returns false and leaves buf empty when the fd is not a connected INET socket
 * or getpeername/inet_ntop fails.  Used by the daemon host-access gate; a false
 * return is "cannot tell" and must be treated as fail-closed when ACLs apply. */
bool utils_fd_peer_ip(int fd, char* buf, size_t len);
/* Format a sockaddr as "ip:port" (IPv4) or "[ip]:port" (IPv6) for logging.
 * Returns false (buf emptied) for a non-INET family or a formatting failure. */
bool utils_sockaddr_to_string(const struct sockaddr* addr, char* buf, size_t len);

#endif
