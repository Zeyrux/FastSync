#ifndef DELETE_PLAN_H
#define DELETE_PLAN_H

#include "array_list.h"
#include "config.h"
#include "file_receive.h"
#include "protocol.h"
#include "utils.h"
#include <stdbool.h>

/* Per-directory delete plans (protocol 2.24.0).
 *
 * rsync's --delete-during removes a directory's extras while the generator
 * processes that directory, and --delete-delay records the deletion list during
 * the scan but applies it only after a fully-successful transfer.  FastSync has
 * no per-directory generator pass; instead the sender streams one plan per
 * source directory, in directory order, and the receiver applies it when it
 * arrives (during) or snapshots its extras and commits them at the end (delay).
 *
 * The sender side builds a plan set from the path-only pre-scan (it needs every
 * directory's complete direct-child list before the first data byte of that
 * directory).  The receiver side is a session that carries the global protected
 * prefixes (filter-excluded and size-skipped source mirrors), the
 * --delete-missing-args exact deletions, the shared --max-delete budget and,
 * for --delete-delay, the snapshotted extras. */

/* ---- Sender: plan builder ---- */

typedef struct DeletePlanSender DeletePlanSender;

DeletePlanSender* delete_plan_sender_create(void);
void delete_plan_sender_destroy(DeletePlanSender* sender);
/* Record one transmitted entry.  `path` is the destination-relative wire path;
 * is_dir marks an explicit directory entry (--dirs, a -x mount point). */
bool delete_plan_sender_add(DeletePlanSender* sender, const char* path, bool is_dir);
/* Drop plans for directories outside `synced_dirs` (the --files-from
 * synchronization scope; pass NULL when a full recursive transfer synchronized
 * every directory).  The receive root is the "." sentinel.
 *
 * `walk_root` scopes a general -R transfer: when non-NULL it is the
 * reconstructed destination prefix the run actually transferred, and only the
 * plan for that prefix (and directories below it) is ever transmitted, so the
 * prefix's parent-directory siblings are never walked.  Pass NULL for a plain
 * recursive transfer and for --files-from. */
void delete_plan_sender_finalize(DeletePlanSender* sender, const ArrayList* synced_dirs,
                                 const char* walk_root);
/* True when no transmitted FILE entry was recorded (an ambiguous empty scan).
   Directory keep entries do not count, so an I/O error that hid every file
   still refuses to delete. */
bool delete_plan_sender_empty(const DeletePlanSender* sender);
/* Attach the global config sections advertised on the first plan frame.  The
 * block is always transmitted by delete_plan_send_root(), on a config-only
 * carrier frame when the scope allows no directory plan. */
void delete_plan_sender_set_config(DeletePlanSender* sender, const ArrayList* protected_prefixes,
                                   const ArrayList* size_skipped, const ArrayList* missing_args);
/* Send the root plan (even before any data, so root extras are handled like
 * rsync's first generator directory), after transmitting the per-run config
 * block on its own carrier frame.  Returns -1 on I/O error. */
int delete_plan_send_root(int fd, DeletePlanSender* sender);
/* Send the plans for every ancestor of `path` (root-first) and, when is_dir,
 * for `path` itself; already-sent plans are skipped. */
int delete_plan_send_for_path(int fd, DeletePlanSender* sender, const char* path, bool is_dir);
/* Send the plan for every directory in `dirs` that has not been transmitted
 * yet.  Called after the data stream so an empty source directory's plan still
 * clears its destination extras even though no file frame triggered it. */
int delete_plan_send_remaining(int fd, DeletePlanSender* sender, const ArrayList* dirs);

/* ---- Receiver: delete session ---- */

typedef struct DeletePlanSession DeletePlanSession;

DeletePlanSession* delete_plan_session_create(const Config* config);
void delete_plan_session_destroy(DeletePlanSession* session);
/* Read one STATUS_DELETE_PLAN frame (the leading status already consumed) and
 * act on it.  Returns 0 on success (including a dry-run/disabled no-op) and -1
 * after signalling STATUS_ERROR on a malformed frame or a deletion failure. */
int delete_plan_session_receive(DeletePlanSession* session, const Config* config, int fd);
/* Apply the deferred snapshot (--delete-delay) and the missing-args deletions.
 * Safe to call once; returns the commit outcome. */
DeleteCommitResult delete_plan_session_commit(DeletePlanSession* session, const Config* config);
/* True once the shared --max-delete budget stopped part of a deletion. */
bool delete_plan_session_limit_reached(const DeletePlanSession* session);
/* Number of destination entries the session actually removed, for the
   end-of-transfer stats.  For --delete-delay this excludes a snapshotted entry
   that survived (e.g. a refilled directory that failed ENOTEMPTY), even though
   that entry already consumed --max-delete budget at snapshot time. */
size_t delete_plan_session_deleted(const DeletePlanSession* session);
/* Install an observer invoked for every destination-relative path the session
   truly removes (including the deferred --delete-delay commit), so the receiver
   can report rsync's `deleting PATH` lines through the terminal STATUS_STATS
   record.  Pass NULL/0 to clear. */
void delete_plan_session_set_delete_observer(DeletePlanSession* session,
                                             DeletePathObserver observer, void* context);

#endif
