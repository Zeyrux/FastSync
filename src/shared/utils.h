#ifndef UTILS_H
#define UTILS_H

#include "array_list.h"
#include "filter.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

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

/* Resolve the first supported name from a rsync algorithm-preference
 * environment variable (RSYNC_COMPRESS_LIST / RSYNC_CHECKSUM_LIST).  `resolve`
 * maps a case-insensitive name to an algorithm id (>= 0) or -1 for an unknown
 * name.  rsync's syntax is a whitespace-separated list (comma/colon are NOT
 * separators); the client-side half ends at '&'.  Unknown entries are skipped
 * and the first resolvable one wins.  *specified is set true when the variable
 * holds at least one non-blank character.  Returns the first resolvable id, or
 * -1 when the variable is unset/blank or names no supported algorithm. */
int env_choice_first(const char* env_name, int (*resolve)(const char*), bool* specified);

/* Upper bound on one line/token read from a local list file (--files-from,
 * --exclude-from/--include-from, .rsync-filter).  Mirrors MAX_STRING_SIZE and
 * stops a hostile multi-gigabyte line from forcing unbounded allocation. */
#define UTILS_MAX_LINE_LEN (64 * 1024)
/* Read one `delim`-terminated record from `stream` into *line (grown as needed
 * and NUL-terminated), refusing to consume/allocate more than `max_len` bytes
 * of content.  Returns the number of bytes stored (delimiter included, matching
 * getdelim), 0 at end of file, or -1 on error (errno is EFBIG when the record
 * exceeds `max_len`, ENOMEM on allocation failure).  *line and *cap are updated
 * as the buffer grows and the caller owns *line. */
ssize_t utils_getdelim_bounded(FILE* stream, char** line, size_t* cap, int delim, size_t max_len);
char* path_cat(const char* path1, const char* path2);
bool glob_match(const char* pattern, const char* str);

/* Open the existing destination directory at `dest_root`, confined to the
   authorized root with an O_NOFOLLOW component walk (the same confinement the
   deletion walker uses for its root).  Returns a new fd the caller owns, or -1
   on error (including a destination that does not exist). */
int utils_open_authorized_destination(const char* dest_root);
bool utils_set_authorized_root(int fd, const char* canonical_path);
/* The fd-only compatibility form is fail-closed for path-based operations;
 * callers should use utils_set_authorized_root with the canonical identity. */
void utils_set_authorized_root_fd(int fd);
/* Read accessors for the process-wide authorized root, so every secure-walk
 * site consumes the single shared state instead of keeping its own copy.  The
 * fd is caller-owned (see the setters): it is returned verbatim, never dup'd,
 * and the caller that opened it is responsible for closing it.  With no root
 * configured the fd accessor returns -1 and the path accessor returns NULL.
 *
 * The pointer returned by utils_get_authorized_root_path() is borrowed into
 * process-global state and is invalidated by the next
 * utils_set_authorized_root() / utils_set_authorized_root_fd() call.  The fd
 * and path are stored separately and read independently, so the pair is NOT
 * observed atomically together; the accessors are non-reentrant and callers
 * must serialize configuration (the server installs the root before any worker
 * threads spawn; see utils.c). */
int utils_get_authorized_root_fd(void);
const char* utils_get_authorized_root_path(void);
/* Write a diagnostic message into a caller-supplied buffer, mirroring
 * vsnprintf.  A NULL `err` or a zero `err_size` is a no-op, so a caller that
 * only needs the boolean status may safely pass NULL.  Returns nothing; the
 * buffer is always NUL-terminated by vsnprintf when err_size > 0. */
void utils_set_error(char* err, size_t err_size, const char* fmt, ...);
/* True when `path` is `root` itself or lies directly beneath it: a lexical
 * prefix test requiring the byte after `root` to be '\0' or '/'.  Both `root`
 * and `path` must be absolute canonical paths free of "."/".." components (the
 * callers guarantee this); this is containment by string, not by resolved
 * symlinks.  Shared by the utils and file secure-walk root confinement. */
bool path_is_within_root(const char* root, const char* path);
/* Non-allocating transfer-relative view of `path`: strip any leading '/' and
 * then a `root` prefix (leading/trailing slashes tolerated), returning a
 * borrowed pointer into `path`.  A NULL/empty root, or a path not under
 * `root`, yields just the leading-slash strip.  `path`/`root` must stay alive. */
const char* utils_strip_transfer_root(const char* path, const char* root);
/* True when `path` contains a ".." component.  This is a purely lexical
 * dot-dot check: an absolute path is NOT rejected here, because default
 * (non-relative) transfers legitimately put the sender's absolute source path
 * on the wire and the receiver re-roots it under the destination with
 * path_cat().  Callers that accept a strictly relative path (e.g. batch paths)
 * must reject a leading '/' themselves (see utils_valid_batch_path). */
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
