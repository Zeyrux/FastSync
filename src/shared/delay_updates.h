#ifndef DELAY_UPDATES_H
#define DELAY_UPDATES_H

#include <stdbool.h>
#include <stddef.h>
#include <threads.h>

/* Forward-declared in config.h; full type needed by file_save_to_disk. */
typedef struct Config Config;

/* One staged file awaiting publication. */
typedef struct {
  char* staged_path; /* full path inside the staging tree */
  char* final_path;  /* full final destination path */
  char* file_path;   /* the file path as received on the wire */
} StagedFileEntry;

/* Receiver-side --delay-updates staging registry.  All successfully written
   files land under a private staging directory inside the receive root and are
   atomically renamed into their final destination only at the very end of the
   transfer.  A single PipelineContextReceiver has exactly one writer thread,
   but the registry is still mutex-protected so the same object can be safely
   shared with the publish/cleanup phase that runs after the threads join. */
typedef struct DelayUpdatesContext {
  char* root_directory; /* receive root the staging dir lives under */
  char* staging_root;   /* root_directory/<staging dir name> */
  mtx_t mutex;
  StagedFileEntry* entries;
  size_t count;
  size_t capacity;
  bool prepared; /* staging dir created, wiped, and exclusively locked */
  int lock_fd;   /* advisory exclusive flock held on the staging dir, or -1 */
} DelayUpdatesContext;

/* Name of the private staging subdirectory created under the receive root. */
#define DELAY_UPDATES_STAGING_DIR ".fastsync-stage"

/* True when `dir` (ignoring a trailing "/") is the reserved staging directory
   name.  Used to reject a --backup-dir that would collide with the internal
   staging area. */
bool delay_updates_staging_name_conflict(const char* dir);

/* Create an empty staging context rooted below root_directory.  Does not touch
   the filesystem yet. */
DelayUpdatesContext* delay_updates_context_create(const char* root_directory);
void delay_updates_context_destroy(DelayUpdatesContext* context);

/* Create the private 0700 staging directory (on first call) and wipe any
   leftovers from a previously interrupted delayed transfer.  Idempotent. */
bool delay_updates_prepare(DelayUpdatesContext* context);

/* Record a fully-written staged file for later publication.  Copies all three
   paths.  Returns false on allocation failure. */
bool delay_updates_record(DelayUpdatesContext* context, const char* staged_path,
                          const char* final_path, const char* file_path);

/* Atomically rename every staged file into its final destination.  Deferred
   --backup handling runs immediately before each rename.  On any failure the
   remaining staged files are removed (best effort); already-published files
   are not rolled back.  Afterwards the staging tree is removed so a successful
   or failed publish leaves no staging leftovers. */
bool delay_updates_publish(DelayUpdatesContext* context, const Config* config);

/* Best-effort removal of every staged file and the staging directory itself.
   Safe to call when nothing was staged or after a successful publish. */
void delay_updates_cleanup(DelayUpdatesContext* context);

#endif
