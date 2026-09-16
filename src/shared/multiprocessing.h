#ifndef MULTIPROCESSING_H
#define MULTIPROCESSING_H

#include <threads.h>
#include <stdatomic.h>

#include "array_list.h"
#include "chunk.h"
#include "config.h"
#include "delete_plan.h"
#include "file.h"
#include "protocol.h"
#include "queue.h"
#include "stop_condition.h"
#include <openssl/ssl.h>

typedef struct {
  Config* config;
  Queue* queue_scanner;
  mtx_t mutex_scanner;
  cnd_t condition_not_full_scanner;
  cnd_t condition_not_empty_scanner;
  bool scanner_done;
  Queue* queue_loader;
  mtx_t mutex_loader;
  cnd_t condition_not_full_loader;
  cnd_t condition_not_empty_loader;
  bool loader_done;
  /* Aggregate loaded payload bytes queued on queue_loader but not yet released
     by the sender.  Guarded by `mutex_loader`.  When `max_queue_bytes` is
     non-zero the loader blocks before enqueueing a chunk that would push this
     total over it, so the sender buffers a bounded number of bytes rather than
     an unbounded count of chunks that may each be up to chunk_size (or a single
     file) in size.  Files streamed straight from disk by sendfile hold no
     payload, so only in-memory (`data->data`) payloads are counted. */
  size_t queued_bytes;
  size_t max_queue_bytes;
  ArrayList* manifest;
  /* Protected prefixes (paths the source scan excluded by user rules) sent
     with the keep-set manifest so --delete leaves them alone unless
     --delete-excluded is set.  NULL when not collecting.  Populated by the
     scanner thread (parallel workers append under mutex_scanner via the
     scanner's exclusion sink) or, in the early modes, by the path-only pre-scan
     on the calling thread before the pipeline starts. */
  ArrayList* excluded_paths;
  /* --max-size/--min-size pruned source paths.  These are ALWAYS sent as
     protected prefixes (even with --delete-excluded), so the destination
     mirrors of size-skipped files survive --delete like rsync.  Populated by
     the scanner thread (workers append under mutex_scanner) or, in the early
     modes, by the path-only pre-scan on the calling thread. */
  ArrayList* size_skipped_paths;
  /* Destination-relative paths of the directories the source scan synchronized
     for this run (the receive root is the "." sentinel).  Sent with the
     manifest so the receiver confines its extras walk to them, matching rsync's
     "delete only in synchronized directories" (notably for --files-from).
     Populated by the scanner thread or the early pre-scan. */
  ArrayList* synced_dirs;
  /* Destination-relative paths of every traversed source directory, for the
     per-directory delete plan keep set (so an empty source directory survives
     --delete rather than being removed as an extra).  Prebuilt by the path-only
     pre-scan on the calling thread. */
  ArrayList* plan_dirs;
  /* --delete-missing-args: the destination-relative mirrors of the --files-from
     entries that are missing under the source.  Computed by the preflight on
     the calling thread before the pipeline starts; the sender thread transmits
     them in the manifest frame's third section and the receiver deletes each as
     an explicit request. */
  ArrayList* missing_args;
  /* A source I/O error (unreadable directory) was recorded during the scan.
     Set by the pre-scan (before the threads start) or by the scanner thread
     under mutex_scanner; the caller turns it into a non-zero exit when
     --ignore-errors kept the run going. */
  bool scan_had_io_error;
  ArrayList* remove_source_files;
  /* True when --delete-before requires the whole-tree keep-set manifest to be
     transmitted before any file data: context->manifest is then prebuilt by a
     path-only pre-scan on the calling thread and the pipeline scanner must not
     append to it.  Set once before the worker threads start. */
  bool early_delete;
  /* Non-NULL for --delete-during/--delete-delay: the per-directory plan set
     prebuilt by the path-only pre-scan on the calling thread.  The sender
     thread transmits the root plan before any data and the remaining plans
     alongside the chunks.  Set once before the worker threads start. */
  DeletePlanSender* delete_plans;
  mtx_t mutex_progress;
  int total_files;
  unsigned long long progress_bytes;
  unsigned long long total_bytes;
  bool sender_done;
  atomic_bool cancelled;
  ProtocolSession allocation_session;
  /* Phase 6: client-only sender stop deadline, computed once before the worker
   * threads start and shared read-only by the scanner and the sender thread. */
  StopCondition stop_condition;
  /* Phase 6: set when the scanner/sender reached the stop deadline before the
   * scan (and thus the keep-set manifest) completed naturally.  When true the
   * completion tail must NOT transmit the partial manifest, or the receiver
   * would delete unscanned source mirrors.  Written by the sender thread
   * before it reads the manifest, so no additional synchronization is needed
   * to suppress the manifest. */
  bool scan_stopped_early;
  /* P7 Wave D: captured source directory times, filled by the scanner thread
   * (and its parallel workers, guarded by dir_entries_mutex) and drained by the
   * sender thread in trailing STATUS_DIR_TIMES frame(s).  Owned by the
   * context; NULL for non-metadata transfers. */
  ArrayList* dir_entries;
  mtx_t dir_entries_mutex;
  bool dir_entries_mutex_init;
  /* Set by the sender thread when the receiver reported a --max-delete-capped
     deletion (STATUS_DELETE_LIMIT): the transfer succeeded and the process must
     exit 25 like rsync.  Read by the caller after the sender thread is joined. */
  bool delete_limit;
} PipelineContextSender;

/* `config` is borrowed and must outlive the context: destroy does NOT free it,
   so the caller owns it and frees it with config_delete() afterwards. */
PipelineContextSender* pipeline_context_sender_create(Config* config, Queue* queue_scanner,
                                                      Queue* queue_loader);
void pipeline_context_sender_destroy(PipelineContextSender* context);
/* Bound the loaded payload bytes the sender may buffer ahead of the network
   writer (see max_queue_bytes). */
void pipeline_context_sender_set_queue_byte_limit(PipelineContextSender* context, size_t max_bytes);
/* Total payload bytes a chunk currently holds in memory (loaded file data
   only; zero for entries with no payload or data streamed from disk). */
size_t pipeline_context_sender_chunk_bytes(const Chunk* chunk);
/* Blocking enqueue used by the sender's loader stage.  Blocks while
   queue_loader is full by element count or when adding `chunk` would push the
   queued payload bytes over the configured byte limit; waits until the sender
   releases bytes.  Takes ownership of `chunk` on success and destroys it on
   failure/cancel. */
bool pipeline_context_sender_enqueue_chunk(PipelineContextSender* context, Chunk* chunk);
/* Account for `released_bytes` of payload memory that the sender freed after
   destroying a chunk, unblocking a loader waiting on the byte limit. */
void pipeline_context_sender_note_bytes_released(PipelineContextSender* context,
                                                 size_t released_bytes);
#endif
