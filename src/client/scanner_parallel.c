#include "log.h"
#include "scanner.h"
#include "scanner_internal.h"
#include "array_list.h"
#include "chunk.h"
#include "file.h"
#include "queue.h"
#include "utils.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <threads.h>
#include <unistd.h>
#include <limits.h>

#include "xattr.h"

typedef struct {
  ParallelScanner* ps;
  char** dirs;
  int dir_count;
  char* root_dir; /* the transfer root, for relative-path computation */
  ScannerOptions options;
  ProtocolSession* allocation_session;
} ParallelWorkerArg;

static int parallel_worker_thread(void* arg) {
  ParallelWorkerArg* wa = (ParallelWorkerArg*)arg;
  ProtocolSession* allocation_session = wa->allocation_session;
  if (allocation_session)
    protocol_session_bind(allocation_session);
  for (int i = 0; i < wa->dir_count; i++) {
    DirectoryScanner* ds = directory_scanner_create_with_options(wa->dirs[i], &wa->options);
    if (!ds) {
      mtx_lock(&wa->ps->result_mutex);
      wa->ps->failed = true;
      atomic_store(&wa->ps->cancelled, true);
      cnd_broadcast(&wa->ps->result_not_empty);
      cnd_broadcast(&wa->ps->result_not_full);
      mtx_unlock(&wa->ps->result_mutex);
      for (int j = i; j < wa->dir_count; j++)
        free(wa->dirs[j]);
      break;
    }
    /* Root .rsync-filter rules (parsed by the parallel scanner) apply to the
     * contents of every assigned subdirectory. Relative paths (used by the
     * allow-set and per-directory rules) are computed against the transfer
     * root, not the subdirectory the worker is seeded with.  Exclusion
     * recording shares one caller-owned list across the workers. */
    free(ds->root_path);
    ds->root_path = str_dup(wa->root_dir);
    ds->seed_node = wa->ps->root_filter_node;
    ds->options.excluded_mutex = &wa->ps->result_mutex;
    Chunk* chunk;
    while ((chunk = directory_scanner_next(ds)) != NULL) {
      if (!queue_enqueue_multithreaded_cancel(wa->ps->result_queue, chunk, &wa->ps->result_mutex,
                                              &wa->ps->result_not_empty, &wa->ps->result_not_full,
                                              &wa->ps->cancelled)) {
        chunk_destroy(chunk);
        break;
      }
    }
    if (directory_scanner_failed(ds)) {
      mtx_lock(&wa->ps->result_mutex);
      wa->ps->failed = true;
      atomic_store(&wa->ps->cancelled, true);
      cnd_broadcast(&wa->ps->result_not_empty);
      cnd_broadcast(&wa->ps->result_not_full);
      mtx_unlock(&wa->ps->result_mutex);
    } else if (directory_scanner_had_io_error(ds)) {
      /* --ignore-errors path: an unreadable directory was skipped, not fatal. */
      mtx_lock(&wa->ps->result_mutex);
      wa->ps->io_error = true;
      mtx_unlock(&wa->ps->result_mutex);
    }
    directory_scanner_destroy(ds);
    free(wa->dirs[i]);
  }
  ParallelScanner* ps = wa->ps;
  free(wa->root_dir);
  free(wa->dirs);
  free(wa);
  mtx_lock(&ps->result_mutex);
  ps->completed++;
  if (ps->completed >= ps->expected_threads) {
    ps->done = true;
    cnd_signal(&ps->result_not_empty);
  }
  mtx_unlock(&ps->result_mutex);
  if (allocation_session)
    protocol_session_unbind();
  return thrd_success;
}

static void parallel_scanner_creation_failed(ParallelScanner* ps) {
  mtx_lock(&ps->result_mutex);
  ps->failed = true;
  atomic_store(&ps->cancelled, true);
  ps->expected_threads = ps->created_threads;
  if (ps->completed >= ps->expected_threads)
    ps->done = true;
  cnd_broadcast(&ps->result_not_empty);
  cnd_broadcast(&ps->result_not_full);
  mtx_unlock(&ps->result_mutex);
}

/* Initialize result queue and synchronization primitives. Returns true on success. */
static bool parallel_scanner_init(ParallelScanner* ps) {
  ps->result_queue = queue_create(100, chunk_destroy);
  if (!ps->result_queue)
    return false;
  atomic_init(&ps->cancelled, false);
  int init = 0;
  bool ok = true;
  if (mtx_init(&ps->result_mutex, mtx_plain) != thrd_success)
    ok = false;
  if (ok) {
    init++;
    if (cnd_init(&ps->result_not_empty) != thrd_success)
      ok = false;
  }
  if (ok) {
    // cppcheck-suppress unreadVariable
    init++;
    if (cnd_init(&ps->result_not_full) != thrd_success)
      ok = false;
  }
  if (!ok) {
    if (init >= 3)
      cnd_destroy(&ps->result_not_full);
    if (init >= 2)
      cnd_destroy(&ps->result_not_empty);
    if (init >= 1)
      mtx_destroy(&ps->result_mutex);
    queue_destroy(ps->result_queue);
    ps->result_queue = NULL;
    return false;
  }
  return true;
}

/* Split files into chunks of roughly chunk_size bytes. Returns the first chunk (also stored
 * chunks beyond the first are enqueued on `queue`). Nulls out consumed entries in `files`.
 * Sets *failed on allocation/enqueue errors. */
static Chunk* batch_files(ArrayList* files, unsigned long long chunk_size, Queue* queue,
                          bool* failed) {
  Chunk* first = NULL;
  if (files->size <= 0)
    return NULL;
  ArrayList* batch = array_list_create(NULL);
  if (!batch) {
    *failed = true;
    return NULL;
  }
  unsigned long long batch_size = 0;
  for (int i = 0; i < files->size; i++) {
    File* f = (File*)files->items[i];
    if (!array_list_add(batch, f)) {
      *failed = true;
      break;
    }
    batch_size += f->data->size;
    if (batch_size >= chunk_size || i == files->size - 1) {
      void** items = array_list_to_array(batch);
      if (!items) {
        *failed = true;
        array_list_delete(batch);
        batch = NULL;
        break;
      }
      Chunk* c = chunk_create((File**)items, batch->size);
      free(items);
      if (!c) {
        *failed = true;
        array_list_delete(batch);
        batch = NULL;
        break;
      }
      int batch_start = i - batch->size + 1;
      for (int j = batch_start; j <= i; j++)
        files->items[j] = NULL;
      batch->item_destroyer = NULL;
      array_list_delete(batch);
      batch = NULL;
      if (!first) {
        first = c;
      } else {
        if (!queue_enqueue(queue, c)) {
          chunk_destroy(c);
          *failed = true;
        }
      }
      if (i < files->size - 1) {
        batch = array_list_create(NULL);
        if (!batch) {
          *failed = true;
          break;
        }
        batch_size = 0;
      }
    }
  }
  if (batch) {
    batch->item_destroyer = NULL;
    array_list_delete(batch);
  }
  return first;
}

/* Scan one root-directory entry into either the subdirs or files list. */
static void scan_root_entry(const ScannerOptions* options, const FilterNode* root_node,
                            const char* root_directory, const struct dirent* entry,
                            ArrayList* root_files, ArrayList* subdirs, dev_t root_dev,
                            ParallelScanner* ps) {
  ScannerEntry inspected;
  int inspection =
      scanner_inspect_entry(options, root_directory, entry->d_name, entry->d_name, &inspected);
  if (inspection < 0) {
    ps->failed = true;
    return;
  }
  if (inspection == 0) {
    if (inspected.referent_error)
      ps->io_error = true;
    ArrayList* sink = NULL;
    if (inspected.excluded)
      sink = inspected.size_excluded ? options->size_skipped_paths : options->excluded_paths;
    if (sink) {
      /* A root-level prune protects the destination mirror of the entry's wire
         path: under -R + --files-from that is the bare relative name, otherwise
         it is the full source path with a leading '/' removed (matching the
         send_path/file_wire_path the scanner hands the sender). */
      if (options->relative && options->file_list != NULL) {
        if (!excluded_sink_append(sink, options->excluded_mutex, entry->d_name))
          ps->failed = true;
      } else if (options->relative_prefix) {
        char* wrel = scanner_prefix_send_path(options->relative_prefix, entry->d_name);
        if (!wrel) {
          ps->failed = true;
        } else {
          if (!excluded_sink_append(sink, options->excluded_mutex, wrel))
            ps->failed = true;
          free(wrel);
        }
      } else {
        char* abs_path = path_cat(root_directory, entry->d_name);
        if (!abs_path) {
          ps->failed = true;
        } else {
          const char* rel = *abs_path == '/' ? abs_path + 1 : abs_path;
          if (!excluded_sink_append(sink, options->excluded_mutex, rel))
            ps->failed = true;
          free(abs_path);
        }
      }
    }
    return;
  }
  char* cur_path = inspected.path;
  struct stat st = inspected.stats;
  bool is_dir = inspected.is_directory;
  char* rel = str_dup(entry->d_name);
  if (!rel) {
    free(cur_path);
    ps->failed = true;
    return;
  }
  bool protect = false;
  bool passes = entry_passes_selection(options->file_list, options->base_filters, root_node, rel,
                                       entry->d_name, is_dir, options->per_dir_filters,
                                       options->exclude_per_dir_filter_files, &protect);
  /* -R + --files-from: root-level files keep their bare relative send path. */
  bool use_rel = options->relative && options->file_list != NULL;
  if (!passes || protect) {
    /* --files-from subset pruning is not a filter exclusion; -R bare-wire-path
       exclusions are never recorded (see ScannerOptions.excluded_paths). */
    bool files_from_prune = options->file_list && !file_list_affects(options->file_list, rel);
    if ((!files_from_prune && !use_rel) || protect) {
      const char* rel_path;
      char* prefixed = NULL;
      if (use_rel) {
        /* -R + --files-from: the destination/wire path is the bare relative
           name, not the source path. */
        rel_path = rel;
      } else if (options->relative_prefix) {
        prefixed = scanner_prefix_send_path(options->relative_prefix, entry->d_name);
        if (!prefixed) {
          free(rel);
          free(cur_path);
          ps->failed = true;
          return;
        }
        rel_path = prefixed;
      } else {
        rel_path = *cur_path == '/' ? cur_path + 1 : cur_path;
      }
      if (options->excluded_paths &&
          !excluded_sink_append(options->excluded_paths, options->excluded_mutex, rel_path))
        ps->failed = true;
      free(prefixed);
    }
    if (!passes) {
      scanner_note_filter(options, entry->d_name);
      free(rel);
      free(cur_path);
      return;
    }
  }
  if (is_dir) {
    if (!scanner_same_filesystem(options->one_file_system, root_dev, st.st_dev)) {
      if (options->one_file_system > 1) {
        /* -xx: drop the mount-point directory entirely (rsync) and print the
           --info=mount line when enabled. */
        scanner_note_mount(options, cur_path);
        free(rel);
        free(cur_path);
        return;
      }
      /* -x/--one-file-system: emit the mount-point directory entry (empty) but
         do not descend into it (see the sequential scanner for the same rule). */
      File* mount = file_create(cur_path);
      free(cur_path);
      if (mount == NULL) {
        free(rel);
        ps->failed = true;
        return;
      }
      mount->is_dir = true;
      if (options->use_metadata) {
        mount->metadata = file_metadata_create(mount->path, &st, options->preserve_atimes,
                                               options->preserve_crtimes);
        if (!mount->metadata) {
          free(rel);
          file_destroy(mount);
          ps->failed = true;
          return;
        }
      }
      if (options->relative_prefix) {
        mount->send_path = scanner_prefix_send_path(options->relative_prefix, rel);
        if (!mount->send_path) {
          free(rel);
          file_destroy(mount);
          ps->failed = true;
          return;
        }
      }
      free(rel);
      if (!array_list_add(root_files, mount)) {
        file_destroy(mount);
        ps->failed = true;
      }
      return;
    }
    free(rel);
    if (!array_list_add(subdirs, cur_path)) {
      free(cur_path);
      ps->failed = true;
    }
    return;
  }
  File* file = file_create(cur_path);
  free(cur_path);
  if (!file) {
    free(rel);
    free(inspected.link_target);
    inspected.link_target = NULL;
    ps->failed = true;
    return;
  }
  if (inspected.is_symlink) {
    file->is_symlink = true;
    file->symlink_target = inspected.link_target;
    inspected.link_target = NULL;
  } else {
    file->data->size = st.st_size;
  }
  if (use_rel) {
    file->send_path = rel;
    rel = NULL;
  } else if (options->relative_prefix) {
    file->send_path = scanner_prefix_send_path(options->relative_prefix, rel);
    free(rel);
    rel = NULL;
    if (!file->send_path) {
      file_destroy(file);
      ps->failed = true;
      return;
    }
  }
  ScannerSpecial special = scanner_prepare_special(
      options->preserve_devices, options->preserve_specials, options->copy_devices, file, &st);
  if (special == SCANNER_SPECIAL_SKIP) {
    scanner_note_nonreg(ps->options, file->path);
    free(rel);
    file_destroy(file);
    return;
  }
  if (options->hardlinks && S_ISREG(st.st_mode)) {
    int gid;
    bool is_first;
    char* first_path = NULL;
    if (!hardlink_table_assign((HardLinkTable*)options->hardlinks, file_wire_path(file), st.st_dev,
                               st.st_ino, &gid, &is_first, &first_path)) {
      ps->failed = true;
    } else {
      file->link_group = gid;
      file->link_first = is_first;
      if (!is_first) {
        file->hardlink_target = first_path;
        file->data->size = 0;
      } else {
        free(first_path);
      }
    }
  }
  if (options->use_metadata)
    file->metadata =
        file_metadata_create(file->path, &st, options->preserve_atimes, options->preserve_crtimes);
  if (options->use_metadata && !file->metadata) {
    free(rel);
    file_destroy(file);
    ps->failed = true;
    return;
  }
  if ((options->preserve_xattrs || options->preserve_acls) &&
      !(file->link_group != 0 && !file->link_first))
    file->xattrs = file->is_symlink
                       ? xattr_capture_path_nofollow(file->path, options->preserve_acls)
                       : xattr_capture_path(file->path, options->preserve_acls);
  if (!array_list_add(root_files, file)) {
    free(rel);
    file_destroy(file);
    ps->failed = true;
    return;
  }
  free(rel);
}

/* Scan the root directory itself, collecting root files and subdirectories.
 * Returns false if the root directory could not be opened. */
static bool scan_root_directory(ParallelScanner* ps, const char* root_directory,
                                const ScannerOptions* options, const FilterNode* root_node,
                                dev_t root_dev, ArrayList* root_files, ArrayList* subdirs) {
  DIR* dir = opendir(root_directory);
  if (!dir) {
    log_perror("Could not open root directory for parallel scan");
    return false;
  }
  /* The parallel scanner opens the transfer root directly (not through
     open_next_directory), so record it as synchronized here. */
  if (!scanner_record_synced_dir(options, root_directory, "",
                                 options->relative && options->file_list != NULL)) {
    closedir(dir);
    ps->failed = true;
    return false;
  }
  log_debug_message(LOG_DEBUG_FLIST, "flist: scanning %s", root_directory);
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    scan_root_entry(options, root_node, root_directory, entry, root_files, subdirs, root_dev, ps);
  }
  closedir(dir);
  return true;
}

/* Spawn worker threads, one per group of subdirectories. */
static void spawn_parallel_workers(ParallelScanner* ps, ArrayList* subdirs,
                                   const ScannerOptions* options, const char* root_directory,
                                   unsigned long long cs) {
  if (subdirs->size <= 0)
    return;
  int n = options->num_threads > 0 ? options->num_threads : 4;
  if (n > subdirs->size)
    n = subdirs->size;

  ps->num_threads = n;
  ps->expected_threads = n;
  ps->threads = calloc(n, sizeof(thrd_t));
  if (!ps->threads) {
    ps->num_threads = 0;
    ps->expected_threads = 0;
    ps->failed = true;
    return;
  }
  int dirs_per_thread = subdirs->size / n;
  int remainder = subdirs->size % n;
  int start = 0;
  ps->num_threads = 0;
  for (int t = 0; t < n; t++) {
    int count = dirs_per_thread + (t < remainder ? 1 : 0);
    if (count == 0)
      break;
    ParallelWorkerArg* wa = calloc(1, sizeof(ParallelWorkerArg));
    if (!wa) {
      parallel_scanner_creation_failed(ps);
      break;
    }
    wa->ps = ps;
    wa->dirs = calloc(count, sizeof(char*));
    wa->root_dir = str_dup(root_directory);
    if (!wa->dirs || !wa->root_dir) {
      free(wa->root_dir);
      free(wa->dirs);
      free(wa);
      parallel_scanner_creation_failed(ps);
      break;
    }
    bool dup_ok = true;
    for (int j = 0; j < count; j++) {
      wa->dirs[j] = str_dup((char*)subdirs->items[start + j]);
      if (!wa->dirs[j])
        dup_ok = false;
    }
    if (!dup_ok) {
      for (int j = 0; j < count; j++)
        free(wa->dirs[j]);
      free(wa->root_dir);
      free(wa->dirs);
      free(wa);
      parallel_scanner_creation_failed(ps);
      break;
    }
    wa->dir_count = count;
    wa->options = *options;
    wa->options.chunk_size = cs;
    wa->allocation_session = ps->allocation_session;
    start += count;
    if (thrd_create(&ps->threads[t], parallel_worker_thread, wa) != thrd_success) {
      for (int j = 0; j < count; j++)
        free(wa->dirs[j]);
      free(wa->root_dir);
      free(wa->dirs);
      free(wa);
      parallel_scanner_creation_failed(ps);
      break;
    }
    ps->num_threads++;
    ps->created_threads++;
  }
}

ParallelScanner* parallel_scanner_create_with_options(const char* root_directory,
                                                      const ScannerOptions* options,
                                                      ProtocolSession* allocation_session) {
  if (!root_directory || !options)
    return NULL;
  ParallelScanner* ps = calloc(1, sizeof(ParallelScanner));
  if (!ps)
    return NULL;
  if (!parallel_scanner_init(ps)) {
    free(ps);
    return NULL;
  }
  ps->allocation_session = allocation_session;
  ps->options = options;

  ArrayList* root_files = array_list_create(file_destroy);
  ArrayList* subdirs = array_list_create(free);
  if (!root_files || !subdirs) {
    array_list_delete(root_files);
    array_list_delete(subdirs);
    parallel_scanner_destroy(ps);
    return NULL;
  }

  dev_t root_dev = 0;
  if (options->one_file_system) {
    struct stat root_stats;
    if (stat(root_directory, &root_stats) != 0) {
      log_perror("Could not stat source directory");
      array_list_delete(root_files);
      array_list_delete(subdirs);
      parallel_scanner_destroy(ps);
      return NULL;
    }
    root_dev = root_stats.st_dev;
  }

  /* Build the root directory's per-directory filter context once; workers seed
   * their scanners with it so per-dir rules behave identically to the sequential
   * scanner. */
  FilterNode* root_node = NULL;
  {
    char err[256];
    bool any_exists = false;
    FilterRuleList* own =
        read_dir_filters(options, root_directory, "", &any_exists, err, sizeof(err));
    if (!own) {
      /* A parse/allocation failure must fail the scan even when an earlier
         merge file in the same directory existed (see the sequential scanner). */
      if (err[0] != '\0') {
        log_message(LOG_LEVEL_ERROR, "invalid per-directory filter in %s: %s", root_directory, err);
        array_list_delete(root_files);
        array_list_delete(subdirs);
        parallel_scanner_destroy(ps);
        return NULL;
      }
      /* no files exist: leave root_node NULL */
    } else if (any_exists && (own->count > 0 || own->dir_merge_count > 0)) {
      root_node = filter_node_alloc(NULL, own);
      if (!root_node) {
        filter_rule_list_free(own);
        array_list_delete(root_files);
        array_list_delete(subdirs);
        parallel_scanner_destroy(ps);
        return NULL;
      }
    } else {
      filter_rule_list_free(own);
    }
  }
  ps->root_filter_node = root_node;

  if (!scan_root_directory(ps, root_directory, options, root_node, root_dev, root_files, subdirs)) {
    array_list_delete(root_files);
    array_list_delete(subdirs);
    parallel_scanner_destroy(ps);
    return NULL;
  }
  /* The root itself is a traversed directory (rsync counts it in
     `Number of files`); the worker DirectoryScanners account for every
     subdirectory below it. */
  scanner_dir_count_count(options);
  /* P7 Wave D: the parallel scanner never runs a DirectoryScanner over the
     transfer root itself (it hands the root's immediate subdirectories to
     workers), so capture the root's directory time here. */
  if (options->capture_dir_times &&
      !scanner_capture_dir_time(
          options->dir_entries, options->dir_entries_mutex, root_directory, root_directory,
          options->relative && options->file_list != NULL, options->relative_prefix,
          options->preserve_atimes, options->preserve_crtimes, options->preserve_xattrs,
          options->preserve_acls, options->no_implied_dirs, options->file_list)) {
    array_list_delete(root_files);
    array_list_delete(subdirs);
    parallel_scanner_destroy(ps);
    return NULL;
  }

  unsigned long long cs = options->chunk_size > 0 ? options->chunk_size : DESIRED_CHUNK_SIZE;
  ps->initial_chunk = batch_files(root_files, cs, ps->result_queue, &ps->failed);
  array_list_delete(root_files);

  spawn_parallel_workers(ps, subdirs, options, root_directory, cs);
  array_list_delete(subdirs);
  return ps;
}

Chunk* parallel_scanner_next(ParallelScanner* ps) {
  if (ps->initial_chunk) {
    Chunk* c = ps->initial_chunk;
    ps->initial_chunk = NULL;
    return c;
  }
  if (ps->num_threads == 0) {
    mtx_lock(&ps->result_mutex);
    if (!queue_is_empty(ps->result_queue)) {
      Chunk* chunk = queue_dequeue(ps->result_queue);
      mtx_unlock(&ps->result_mutex);
      return chunk;
    }
    ps->done = true;
    mtx_unlock(&ps->result_mutex);
    return NULL;
  }
  Chunk* chunk = queue_dequeue_multithreaded(
      ps->result_queue, &ps->result_mutex, &ps->result_not_empty, &ps->result_not_full, &ps->done);
  return chunk;
}

bool parallel_scanner_failed(const ParallelScanner* ps) {
  return ps == NULL || ps->failed;
}

bool parallel_scanner_had_io_error(const ParallelScanner* ps) {
  return ps != NULL && ps->io_error;
}

void parallel_scanner_destroy(ParallelScanner* ps) {
  if (!ps)
    return;
  mtx_lock(&ps->result_mutex);
  ps->done = true;
  atomic_store(&ps->cancelled, true);
  cnd_broadcast(&ps->result_not_empty);
  cnd_broadcast(&ps->result_not_full);
  mtx_unlock(&ps->result_mutex);
  for (int i = 0; i < ps->num_threads; i++)
    thrd_join(ps->threads[i], NULL);
  free(ps->threads);
  if (ps->root_filter_node)
    filter_node_destroy(ps->root_filter_node);
  if (ps->initial_chunk)
    chunk_destroy(ps->initial_chunk);
  queue_destroy(ps->result_queue);
  mtx_destroy(&ps->result_mutex);
  cnd_destroy(&ps->result_not_empty);
  cnd_destroy(&ps->result_not_full);
  free(ps);
}
