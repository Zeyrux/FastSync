#ifndef HARDLINK_H
#define HARDLINK_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <threads.h>

/*
 * --hard-links / -H support.
 *
 * Sender side: a HardLinkTable detects regular files on the source that share
 * an (st_dev, st_ino) identity (a `cp -al`-style hard-linked tree) and assigns
 * each distinct inode a stable, run-local link-group id.  The first member
 * encountered carries the file data; every later member is marked as a sibling
 * (no data payload) that the receiver creates as a hard link to the first
 * member's destination file.  Grouping is scoped by st_dev so inode reuse
 * across different filesystems is never conflated.  The table is mutex-guarded
 * so the parallel (multi-threaded) scanner COULD share one instance across its
 * worker threads; the first-thread-to-call designates the data-carrying member,
 * which is safe because a hard-link group's members are byte-identical.  (In
 * practice the sender forces the sequential scanner whenever -H is on; the
 * mutex guards the shared table for any path that supplies one.)
 *
 * ORDERING (why there is no receiver-side handshake): the receiver stores every
 * file - including a hard-link group's first member - through a SINGLE writer
 * thread draining a single FIFO queue driven by a single receive thread, so
 * wire order == write order and every sibling is processed AFTER its group's
 * first member.  The sender additionally forces the sequential scanner with -H
 * so the first-member frame always precedes its siblings on the wire.  Sibling
 * install therefore needs no present/wait registry: it hard-links to the first
 * member (or copies it) knowing that path is already installed - or that, if
 * the first member was skipped (already up to date), its destination still
 * exists.  This guarantee is REQUIRED; do not introduce a concurrent
 * multi-writer receiver for -H without re-adding an ordering mechanism.
 */

typedef struct HardLinkItem {
  dev_t dev;
  ino_t ino;
  int gid;
  char* first_path; /* wire path of the group's data-carrying first member */
} HardLinkItem;

typedef struct HardLinkTable {
  mtx_t mutex;
  HardLinkItem* items;
  size_t count;
  size_t capacity;
  int next_gid;
} HardLinkTable;

HardLinkTable* hardlink_table_create(void);
void hardlink_table_destroy(HardLinkTable* table);

/* Assign a link-group id to the regular file at `wire_path` with (dev, ino).
 * On the first encounter the file becomes the group's first (data-carrying)
 * member (*is_first = true) and a fresh gid is allocated.  On a later member
 * *is_first = false and *first_path_out is set to a malloc'd copy of the first
 * member's wire path (the caller stores it and owns it; on the first member
 * path the returned *first_path_out is a malloc'd copy of its own wire path).
 * Returns false on allocation failure (transfer should abort). */
bool hardlink_table_assign(HardLinkTable* table, const char* wire_path, dev_t dev, ino_t ino,
                           int* gid, bool* is_first, char** first_path_out);

#endif
