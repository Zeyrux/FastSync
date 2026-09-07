#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "array_list.h"
#include "chmod.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delay_updates.h"
#include "delta.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"

#define MAX_SERVER_DELETE_COUNT 100000U
#define MAX_FILE_DATA_SIZE MAX_RECEIVE_WHOLE_FILE_SIZE

bool file_save_to_disk(const char* root_directory, const File* file, const Config* config) {
  return file_save_to_disk_full(root_directory, file, config) != FILE_SAVE_ERROR;
}

/* --delay-updates receiver path: write the file into a private staging tree
   below the receive root instead of its final destination, and remember it so
   it can be atomically renamed into place only once the whole transfer has
   succeeded.  Existence/update policies (--existing/--ignore-existing/--update)
   are decided against the FINAL destination path at stage time so the run
   decides exactly what an immediate (non-delayed) run would decide; the staged
   file is then never re-checked at publication.  Backups are deferred to
   publication so the final destination is untouched until the transfer ends. */
static FileSaveResult file_stage_delayed_update(const char* root_directory,
                                                const char* destination_path, const File* file,
                                                Config* config) {
  if (!config)
    return FILE_SAVE_ERROR;
  bool sparse = config->preserve_sparse;
  bool preserve_executability = config->use_executability;

  if (config->existing && !file_path_exists_secure(destination_path))
    return FILE_SAVE_SKIPPED;
  if (config->ignore_existing && file_path_exists_secure(destination_path))
    return FILE_SAVE_SKIPPED;
  if (config->update && file_destination_is_newer_secure(destination_path, file->metadata))
    return FILE_SAVE_SKIPPED;

  FileMetadata adjusted_metadata;
  const FileMetadata* metadata = file->metadata;
  if (metadata && config->chmod_spec && *config->chmod_spec) {
    adjusted_metadata = *metadata;
    if (!chmod_apply(adjusted_metadata.mode, config->chmod_spec, &adjusted_metadata.mode))
      return FILE_SAVE_ERROR;
    metadata = &adjusted_metadata;
  }

  if (!config->delay_context) {
    config->delay_context = delay_updates_context_create(root_directory);
    if (!config->delay_context)
      return FILE_SAVE_ERROR;
  }
  DelayUpdatesContext* context = config->delay_context;
  if (!delay_updates_prepare(context))
    return FILE_SAVE_ERROR;

  char* staged_path = path_cat(context->staging_root, file->path);
  if (!staged_path)
    return FILE_SAVE_ERROR;

  /* The staged location is brand new (stale leftovers from a prior crash were
     wiped by prepare), so the plain atomic temp+rename engine installs the
     complete file there.  --temp-dir scratch is deliberately not layered on
     top of the delay-updates staging tree.  A --link-dest basis file is hard
     linked into the staging tree (so publication's rename keeps the link). */
  bool ok;
  if (file->basis_link) {
    ok = file_to_disk_secure_link(staged_path, file->basis_link, file->data->data, file->data->size,
                                  metadata, preserve_executability, config->use_fsync, NULL);
  } else {
    ok = file_to_disk_secure_with_fsync(staged_path, file->data->data, file->data->size, false,
                                        sparse, metadata, preserve_executability, config->use_fsync,
                                        NULL);
  }
  if (!ok) {
    free(staged_path);
    return FILE_SAVE_ERROR;
  }

  if (!delay_updates_record(context, staged_path, destination_path, file->path)) {
    unlink(staged_path);
    free(staged_path);
    return FILE_SAVE_ERROR;
  }
  free(staged_path);
  return FILE_SAVE_WRITTEN;
}

FileSaveResult file_save_to_disk_full(const char* root_directory, const File* file,
                                      const Config* config) {
  /* Backups are incompatible with ignore-existing: moving the entry first
     would make a concurrent no-replace commit overwrite its old name. */
  bool backup_enabled = config && config->backup && !config->ignore_existing;
  bool inplace = config && config->inplace;
  bool sparse = config && config->preserve_sparse;
  bool preserve_executability = config && config->use_executability;
  const char* backup_suffix = (config && config->suffix) ? config->suffix : "~";
  const char* backup_dir = (config && config->backup_dir) ? config->backup_dir : NULL;
  const char* partial_dir = (config && config->partial_dir) ? config->partial_dir : NULL;
  const char* temp_dir = (config && config->temp_dir) ? config->temp_dir : NULL;
  bool use_partial_root = partial_dir && config && config->partial;
  char *confined_backup = NULL, *confined_partial = NULL, *disk_path = NULL;
  char* destination_path = NULL;
  char *backup_path = NULL, *parent_copy = NULL;

  if (!file || !file->path || !file->data || (file->data->size != 0 && !file->data->data) ||
      has_path_traversal(file->path) ||
      (backup_enabled &&
       (!backup_suffix || backup_suffix[0] == '\0' || strchr(backup_suffix, '/') != NULL ||
        strcmp(backup_suffix, ".") == 0 || strcmp(backup_suffix, "..") == 0))) {
    log_message(LOG_LEVEL_ERROR, "Invalid file or path received");
    return FILE_SAVE_ERROR;
  }

  /* Explicit directory entries (--dirs) carry an empty payload; the entry is
     created as a directory under the receive root, applying the same secure
     mkdir-parent semantics as regular writes.  Directories are created
     immediately (they are never staged by --delay-updates, matching rsync,
     where directory creation is not delayed). */
  if (file->is_dir) {
    if (file->path[0] == '\0' || has_path_traversal(file->path)) {
      log_message(LOG_LEVEL_ERROR, "Invalid directory path received");
      return FILE_SAVE_ERROR;
    }
    char* dir_path = path_cat(root_directory, file->path);
    if (!dir_path)
      return FILE_SAVE_ERROR;
    bool ok = file_ensure_directory_secure(dir_path);
    free(dir_path);
    return ok ? FILE_SAVE_WRITTEN : FILE_SAVE_ERROR;
  }

  /* These options arrive from the client.  They are names below the server
     root, never independent filesystem roots.  --temp-dir is confined exactly
     like --backup-dir/--partial-dir: an absolute or `..`-escaping scratch
     directory is rejected outright so nothing is ever created outside the
     authorized destination root. */
  if ((backup_dir && (backup_dir[0] == '/' || has_path_traversal(backup_dir))) ||
      (partial_dir && (partial_dir[0] == '/' || has_path_traversal(partial_dir))) ||
      (temp_dir && (temp_dir[0] == '/' || has_path_traversal(temp_dir))))
    return FILE_SAVE_ERROR;
  if (backup_dir && !(confined_backup = path_cat(root_directory, backup_dir)))
    return FILE_SAVE_ERROR;
  if (partial_dir && !(confined_partial = path_cat(root_directory, partial_dir))) {
    free(confined_backup);
    return FILE_SAVE_ERROR;
  }

  const char* actual_root = use_partial_root ? confined_partial : root_directory;
  destination_path = path_cat(root_directory, file->path);
  disk_path = path_cat(actual_root, file->path);
  if (destination_path == NULL || disk_path == NULL) {
    free(confined_backup);
    free(confined_partial);
    free(destination_path);
    free(disk_path);
    return FILE_SAVE_ERROR;
  }

  /* --delay-updates diverts the whole write into the staging tree; the rest of
     this function is the immediate-install path. */
  if (config && config->delay_updates) {
    FileSaveResult result =
        file_stage_delayed_update(root_directory, destination_path, file, (Config*)config);
    free(confined_backup);
    free(confined_partial);
    free(destination_path);
    free(disk_path);
    return result;
  }

  /* --existing checks the final destination, not a temporary partial path. */
  if (config && config->existing && !file_path_exists_secure(destination_path)) {
    free(confined_backup);
    free(confined_partial);
    free(destination_path);
    free(disk_path);
    return FILE_SAVE_SKIPPED;
  }

  /* --ignore-existing checks the final destination before partial files or
     overwrite policies can modify it. */
  if (config && config->ignore_existing) {
    bool exists = file_path_exists_secure(destination_path);
    if (exists) {
      free(confined_backup);
      free(confined_partial);
      free(destination_path);
      free(disk_path);
      return FILE_SAVE_SKIPPED;
    }
  }

  /* --update is receiver-side policy: never replace a newer destination.
     In partial-dir mode the entry that would be replaced is the real
     destination, not the temporary partial file.  The secure stat does not
     require read permission on the destination. */
  const char* update_target = use_partial_root ? destination_path : disk_path;
  if (config && config->update && file_destination_is_newer_secure(update_target, file->metadata)) {
    free(confined_backup);
    free(confined_partial);
    free(destination_path);
    free(disk_path);
    return FILE_SAVE_SKIPPED;
  }

  /* --force (rsync semantics): an incoming regular file may replace a
     destination DIRECTORY by removing that (possibly non-empty, symlink-safe)
     tree first, so the atomic temp+rename below can install the file.  Only the
     immediate-install path does this: a --delay-updates run stages into its own
     tree and is unaffected here (its publication renames over regular files
     only).  The blocking directory is removed only after the --update /
     --existing / --ignore-existing decisions above, which see it as an existing
     destination entry. */
  if (config && config->force_delete && !file->is_dir &&
      file_directory_exists_secure(destination_path)) {
    if (!file_remove_tree_secure(destination_path))
      goto fail;
  }

  if (backup_enabled) {
    /* Back up the entry that the incoming write will replace.  When writing
       through a partial dir the pre-existing destination file is the one to
       preserve; any stale partial file is overwritten without a backup. */
    const char* replace_target = use_partial_root ? destination_path : disk_path;
    struct stat backup_stat;
    if (file_stat_secure(replace_target, &backup_stat)) {
      if (backup_dir) {
        backup_path = path_cat(confined_backup, file->path);
      } else {
        size_t path_len = strlen(replace_target);
        size_t suffix_len = strlen(backup_suffix);
        if (path_len > SIZE_MAX - suffix_len - 1)
          goto fail;
        backup_path = malloc(path_len + suffix_len + 1);
        if (backup_path) {
          memcpy(backup_path, replace_target, path_len);
          memcpy(backup_path + path_len, backup_suffix, suffix_len + 1);
        }
      }
      if (!backup_path)
        goto fail;
      parent_copy = str_dup(backup_path);
      if (!parent_copy || !file_ensure_directory_secure(dirname(parent_copy)))
        goto fail;
      free(parent_copy);
      parent_copy = NULL;
      if (!file_rename_secure(replace_target, backup_path))
        goto fail;
      free(backup_path);
      backup_path = NULL;
    }
  }

  FileMetadata adjusted_metadata;
  const FileMetadata* metadata = file->metadata;
  if (metadata && config && config->chmod_spec && *config->chmod_spec) {
    adjusted_metadata = *metadata;
    if (!chmod_apply(adjusted_metadata.mode, config->chmod_spec, &adjusted_metadata.mode))
      goto fail;
    metadata = &adjusted_metadata;
  }

  /* A configured --temp-dir sends the temporary working copy to a scratch
     directory resolved below the receive root; the engine then atomically
     renames the completed file into the final destination directory.  The
     partial-dir flow already keeps its working copy in a separate directory
     and --inplace writes directly, so neither diverts through the scratch
     dir (matching rsync, where --inplace/--partial-dir supersede --temp-dir). */
  char* confined_temp = NULL;
  bool use_temp_dir = temp_dir != NULL && !inplace && !use_partial_root;
  if (use_temp_dir) {
    confined_temp = path_cat(root_directory, temp_dir);
    if (!confined_temp)
      goto fail;
    /* A user-supplied trailing slash would leave the scratch path ending in
       "/", which has no final component to create/open.  Normalize it away. */
    size_t temp_len = strlen(confined_temp);
    while (temp_len > 1 && confined_temp[temp_len - 1] == '/')
      confined_temp[--temp_len] = '\0';
  }
  /* A --link-dest basis hit installs an atomic hard link (with a byte-copy
     fallback); --inplace and the update/no-replace write variants do not
     apply to a fresh hard link, whose inode attributes already match.  The
     existing/ignore-existing/update/backup preamble above has already made the
     policy decision. */
  bool ok;
  if (config && file->basis_link) {
    ok = file_to_disk_secure_link(disk_path, file->basis_link, file->data->data, file->data->size,
                                  metadata, preserve_executability, config->use_fsync,
                                  confined_temp);
  } else {
    ok = config && config->ignore_existing
             ? file_to_disk_secure_no_replace(disk_path, file->data->data, file->data->size, sparse,
                                              metadata, preserve_executability, confined_temp)
         : config && config->update
             ? file_to_disk_secure_update(disk_path, file->data->data, file->data->size, inplace,
                                          sparse, metadata, preserve_executability, confined_temp)
             : file_to_disk_secure_with_fsync(disk_path, file->data->data, file->data->size,
                                              inplace, sparse, metadata, preserve_executability,
                                              config && config->use_fsync, confined_temp);
  }
  free(confined_temp);
  confined_temp = NULL;
  if (!ok)
    goto fail;

  /* --partial --partial-dir writes the complete file under the partial dir so
     interrupted transfers leave a resumable copy there.  Once the file is
     fully written it must be atomically installed at the real destination;
     otherwise completed transfers would linger under the partial dir. */
  if (use_partial_root) {
    if (!file_rename_secure(disk_path, destination_path))
      goto fail;
  }

  free(parent_copy);
  free(backup_path);
  free(confined_backup);
  free(confined_partial);
  free(destination_path);
  free(disk_path);
  return FILE_SAVE_WRITTEN;

fail:
  free(parent_copy);
  free(backup_path);
  free(confined_backup);
  free(confined_partial);
  free(destination_path);
  free(disk_path);
  return FILE_SAVE_ERROR;
}

static File* receive_delta_file(int fd, const Config* config, const char* check_path,
                                void* old_data, unsigned long long old_size, bool* failed) {
  if (!old_data) {
    free(old_data); /* defensive: old_data is always non-NULL today */
    *failed = true;
    return NULL;
  }

  DeltaSignature* sig = delta_signature_create_seeded(old_data, old_size, config->delta_block_size,
                                                      (uint32_t)config->checksum_seed);
  if (!sig) {
    free(old_data);
    *failed = true;
    return NULL;
  }

  Data* sig_data = delta_signature_serialize(sig);
  if (!sig_data) {
    delta_signature_destroy(sig);
    free(old_data);
    *failed = true;
    return NULL;
  }

  bool sig_sent = send_status(fd, STATUS_DELTA_SIGNATURE) && send_data(fd, sig_data);
  data_destroy(sig_data);

  if (!sig_sent) {
    delta_signature_destroy(sig);
    free(old_data);
    *failed = true;
    return NULL;
  }

  Status resp;
  if (!receive_status(fd, &resp)) {
    delta_signature_destroy(sig);
    free(old_data);
    *failed = true;
    return NULL;
  }

  if (resp == STATUS_DELTA_DATA) {
    Data* delta_data = receive_data_limited(fd, MAX_RECEIVE_WHOLE_FILE_SIZE);
    if (!delta_data) {
      delta_signature_destroy(sig);
      free(old_data);
      *failed = true;
      return NULL;
    }

    Data* raw_delta = delta_data;
    if (config->use_compression &&
        !compression_should_skip_with_suffixes(
            check_path, config->skip_compress_suffixes,
            config->skip_compress_set ? config->skip_compress_count : -1)) {
      raw_delta = data_decompress_limited(delta_data, MAX_RECEIVE_WHOLE_FILE_SIZE);
      data_destroy(delta_data);
      if (!raw_delta) {
        free(old_data);
        delta_signature_destroy(sig);
        *failed = true;
        return NULL;
      }
    }

    Delta* delta = delta_deserialize(raw_delta);
    data_destroy(raw_delta);
    if (!delta) {
      free(old_data);
      delta_signature_destroy(sig);
      *failed = true;
      return NULL;
    }

    uint64_t new_size = delta->new_file_size;
    if (new_size > MAX_RECEIVE_WHOLE_FILE_SIZE || new_size > SIZE_MAX) {
      delta_destroy(delta);
      free(old_data);
      delta_signature_destroy(sig);
      send_status(fd, STATUS_ERROR);
      *failed = true;
      return NULL;
    }
    void* new_data = delta_apply(old_data, old_size, delta, config->delta_block_size);
    delta_destroy(delta);

    if (!new_data) {
      free(old_data);
      delta_signature_destroy(sig);
      *failed = true;
      return NULL;
    }

    File* file = file_create(check_path);
    if (!file) {
      free(new_data);
      free(old_data);
      delta_signature_destroy(sig);
      *failed = true;
      return NULL;
    }

    if (config->use_metadata) {
      int meta_ok = 1;
      file->metadata = metadata_receive(fd, &meta_ok);
      if (!meta_ok) {
        file_destroy(file);
        free(new_data);
        free(old_data);
        delta_signature_destroy(sig);
        *failed = true;
        return NULL;
      }
    }

    Data* replacement = data_create(new_data, (size_t)new_size);
    if (replacement == NULL) {
      file_destroy(file);
      free(old_data);
      delta_signature_destroy(sig);
      send_status(fd, STATUS_ERROR);
      *failed = true;
      return NULL;
    }
    data_destroy(file->data);
    file->data = replacement;

    free(old_data);
    delta_signature_destroy(sig);
    return file;
  }

  if (resp == STATUS_NEXT) {
    delta_signature_destroy(sig);
    free(old_data);

    File* file = file_create(check_path);
    if (!file) {
      *failed = true;
      return NULL;
    }

    if (config->use_metadata) {
      int meta_ok = 1;
      file->metadata = metadata_receive(fd, &meta_ok);
      if (!meta_ok) {
        file_destroy(file);
        *failed = true;
        return NULL;
      }
    }

    Data* file_data = receive_data_limited(fd, MAX_RECEIVE_WHOLE_FILE_SIZE);
    if (file_data == NULL) {
      file_destroy(file);
      *failed = true;
      return NULL;
    }

    if (config->use_compression &&
        !compression_should_skip_with_suffixes(
            file->path, config->skip_compress_suffixes,
            config->skip_compress_set ? config->skip_compress_count : -1)) {
      Data* uncompressed = data_decompress_limited(file_data, MAX_RECEIVE_WHOLE_FILE_SIZE);
      data_destroy(file_data);
      if (uncompressed == NULL) {
        file_destroy(file);
        *failed = true;
        return NULL;
      }
      if (uncompressed->size > MAX_FILE_DATA_SIZE) {
        data_destroy(uncompressed);
        file_destroy(file);
        send_status(fd, STATUS_ERROR);
        *failed = true;
        return NULL;
      }
      file_data = uncompressed;
    }

    data_destroy(file->data);
    file->data = file_data;
    return file;
  }

  delta_signature_destroy(sig);
  free(old_data);
  send_status(fd, STATUS_ERROR);
  *failed = true;
  return NULL;
}

/* ---- Alternate basis directories (--compare-dest / --copy-dest / --link-dest) ----
 * The receiver consults the ordered basis-dir list only when the destination
 * entry is NOT already up to date.  An "exact match" requires an equal size,
 * an equal mtime (unless --size-only), and an equal content xxHash64, so a
 * hard link / local copy is only ever made from byte-identical content. */

typedef struct BasisMatch {
  bool hit;
  BasisDestType type;
  char* basis_path; /* owned absolute path of the matched basis file */
  struct stat st;   /* fstat() of the matched basis file */
  Data* content;    /* owned basis bytes (or empty Data), NULL when not loaded */
} BasisMatch;

static void basis_match_free(BasisMatch* match) {
  if (!match)
    return;
  free(match->basis_path);
  match->basis_path = NULL;
  data_destroy(match->content);
  match->content = NULL;
  match->hit = false;
  match->type = BASIS_DEST_NONE;
}

/* Open `path` (via the secure, root-confined primitives) and require it to be
   a regular file of exactly `expected_size` bytes.  Returns an open read-only
   descriptor and its fstat on success. */
static bool basis_open_regular(const char* path, unsigned long long expected_size, int* out_fd,
                               struct stat* out_st) {
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(path, &leaf, false);
  if (parent_fd < 0)
    return false;
  int fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  free(leaf);
  close(parent_fd);
  if (fd < 0)
    return false;
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
      (unsigned long long)st.st_size != expected_size) {
    close(fd);
    return false;
  }
  *out_fd = fd;
  *out_st = st;
  return true;
}

/* Read the whole remaining content of an open descriptor.  A zero-length file
   yields an empty Data (data pointer NULL). */
static Data* basis_read_content(int fd, unsigned long long size) {
  if (size == 0)
    return data_create_reserve(0);
  if (size > MAX_RECEIVE_WHOLE_FILE_SIZE || size > SIZE_MAX)
    return NULL;
  void* buf = protocol_alloc((size_t)size);
  if (!buf)
    return NULL;
  size_t got = 0;
  while (got < (size_t)size) {
    ssize_t n = read(fd, (char*)buf + got, (size_t)size - got);
    if (n <= 0) {
      free(buf);
      return NULL;
    }
    got += (size_t)n;
  }
  return data_create(buf, (size_t)size);
}

/* --ignore-times forces every file to be updated, so no basis hit is ever
   declared (matching rsync, where -I prevents link-dest from linking). */
static bool basis_quick_matches(const Config* config, const struct stat* st, time_t check_mtime,
                                long check_mtime_nsec) {
  if (config->size_only)
    return true;
  long mtime_nsec = 0;
#ifdef __linux__
  mtime_nsec = st->st_mtim.tv_nsec;
#endif
  return metadata_mtime_matches(st->st_mtime, mtime_nsec, check_mtime, check_mtime_nsec,
                                config->modify_window);
}

/* Search the basis-dir list in command-line order and return the first exact
   match.  When load_content is true the matched bytes are kept in out->content
   so the caller can materialize the file without re-reading it. */
static bool basis_match_find(const Config* config, const char* check_path,
                             unsigned long long check_size, time_t check_mtime,
                             long check_mtime_nsec, const uint8_t* check_digest,
                             size_t check_digest_len, bool load_content, BasisMatch* out) {
  memset(out, 0, sizeof(*out));
  if (!config || !config_has_basis(config) || config->ignore_times)
    return false;
  for (int i = 0; i < config->basis_count; i++) {
    const BasisDest* entry = &config->basis_dirs[i];
    char* basis_dir = path_cat(config->receive_root_directory, entry->path);
    if (!basis_dir)
      continue;
    char* candidate = path_cat(basis_dir, check_path);
    free(basis_dir);
    if (!candidate)
      continue;

    int fd;
    struct stat st;
    if (basis_open_regular(candidate, check_size, &fd, &st)) {
      if (basis_quick_matches(config, &st, check_mtime, check_mtime_nsec)) {
        Data* content = basis_read_content(fd, check_size);
        if (content) {
          uint8_t basis_digest[CHECKSUM_MAX_DIGEST_LEN];
          size_t basis_len = 0;
          bool hashed = checksum_digest((ChecksumAlgo)config->checksum_algo, config->checksum_seed,
                                        content->data, content->size, basis_digest,
                                        sizeof(basis_digest), &basis_len);
          if (hashed && basis_len == check_digest_len && check_digest_len > 0 &&
              memcmp(basis_digest, check_digest, check_digest_len) == 0) {
            out->hit = true;
            out->type = entry->type;
            out->basis_path = candidate;
            candidate = NULL; /* ownership transferred to out */
            out->st = st;
            out->content = load_content ? content : NULL;
            if (!load_content)
              data_destroy(content);
            close(fd);
            return true;
          }
        }
        data_destroy(content);
      }
      close(fd);
    }
    free(candidate);
  }
  return false;
}

/* ---------------------------------------------------------------------------
 * -y/--fuzzy similar-file delta basis.
 *
 * When a file must be transferred and the destination holds no usable content
 * at the exact path (the destination file is absent, or is outside the delta
 * engine's size bounds), --fuzzy lets the receiver reuse an EXISTING regular
 * file in the SAME destination directory as the delta basis, so the sender
 * transmits only the differences instead of the whole file.  This is the
 * rsync "find a similar file to use as a basis for a transfer" case (e.g. a
 * file recreated under a new name whose old-named sibling is still present).
 *
 * The delta handshake is unchanged and receiver-driven, so the sender never
 * learns the basis was a different file and needs no new protocol.  Byte
 * exactness never depends on which bytes the basis holds: the delta protocol
 * only references basis blocks whose Adler-32 + xxHash32 checksums match the
 * source, delta_apply validates every reference against the basis size, and a
 * basis that shares nothing simply makes the sender reply STATUS_NEXT (full
 * transfer).  A fuzzy basis can therefore waste bandwidth but never corrupt a
 * file.
 *
 * Similarity heuristic (deterministic, deliberately simpler than rsync's):
 *   * candidates are the target's sibling entries in its destination
 *     directory, opened through the confined root (file_open_secure_parent +
 *     openat O_NOFOLLOW, fstatat AT_SYMLINK_NOFOLLOW) -- symlinks are never
 *     followed and nothing outside the destination root is ever read;
 *   * dotfiles, directories, the target's own name, and the .fastsync-stage /
 *     temp scratch names are never candidates;
 *   * size gate = the delta engine's own bounds (delta_should_attempt: both
 *     files >= DELTA_MIN_FILE_SIZE, <= delta_max_file_size, ratio <= 10x),
 *     NOT rsync's ~1.5x size window;
 *   * name gate = Levenshtein edit distance between the basenames, accepted
 *     only when distance <= half the length of the longer basename;
 *   * the single best candidate (smallest distance; tie-break: size closest
 *     to the incoming file, then lexicographically smaller basename) is read
 *     and returned as the basis.
 * ------------------------------------------------------------------------- */

/* A directory scan is linear in the number of entries; the fuzzy search stops
 * after this many so a pathological huge directory cannot stall a transfer.
 * The cap bounds the readdir() ITERATIONS, not the per-entry work: every
 * entry that survives the (cheap) size and pre-name gates still runs an
 * edit-distance DP, so the per-entry DP cost is separately bounded below by
 * pre-pruning on the name length gap and the absent-character bound, and by
 * trimming the common prefix/suffix before the DP runs on the middles only. */
#define FUZZY_MAX_DIRECTORY_SCAN 4096
/* Names longer than this never take part in fuzzy matching: the edit-distance
 * DP below is O(len^2), so over-long names are bounded out of the search. */
#define FUZZY_NAME_LIMIT 192

typedef struct {
  char name[FUZZY_NAME_LIMIT + 1];
  unsigned long long size;
  size_t distance;
  unsigned long long size_gap;
} FuzzyCandidate;

/* Two-row DP scratch, allocated once per directory scan (not per candidate) so
 * a 4096-entry directory never performs 4096 malloc/free pairs. */
typedef struct {
  size_t* prev;
  size_t* cur;
} FuzzyEditBuffer;

static bool fuzzy_edit_buffer_init(FuzzyEditBuffer* buf) {
  buf->prev = malloc((FUZZY_NAME_LIMIT + 1) * sizeof(size_t));
  buf->cur = malloc((FUZZY_NAME_LIMIT + 1) * sizeof(size_t));
  if (!buf->prev || !buf->cur) {
    free(buf->prev);
    free(buf->cur);
    buf->prev = NULL;
    buf->cur = NULL;
    return false;
  }
  return true;
}

static void fuzzy_edit_buffer_destroy(FuzzyEditBuffer* buf) {
  free(buf->prev);
  free(buf->cur);
  buf->prev = NULL;
  buf->cur = NULL;
}

/* Cheap lower bounds used to reject a candidate BEFORE the DP:
 *  - any edit script must at least absorb the length gap: d >= |la - lb|;
 *  - any character of `a` that does not occur in `b` at all must be deleted or
 *    substituted at its own position: d >= (count of such characters).
 * The acceptance gate is d*2 <= longer, so a candidate whose max of these two
 * bounds already violates it can be skipped without computing the distance. */
static size_t fuzzy_absent_char_bound(const char* a, size_t la, const char* b, size_t lb) {
  if (lb == 0)
    return la;
  bool present[256] = {false};
  for (size_t i = 0; i < lb; i++)
    present[(uint8_t)b[i]] = true;
  size_t absent = 0;
  for (size_t i = 0; i < la; i++)
    if (!present[(uint8_t)a[i]])
      absent++;
  return absent;
}

/* Levenshtein edit distance between the two basenames.  A shared prefix and a
 * (non-overlapping) shared suffix can always be aligned at no cost, so the DP
 * only runs over the differing middles; its two rows come from `buf` (allocated
 * once by the caller).  Callers enforce la, lb <= FUZZY_NAME_LIMIT. */
static size_t fuzzy_edit_distance(FuzzyEditBuffer* buf, const char* a, size_t la, const char* b,
                                  size_t lb) {
  size_t p = 0;
  while (p < la && p < lb && a[p] == b[p])
    p++;
  /* Trim the common suffix (never overlapping the prefix).  Working with two
     moving end indices keeps the region arithmetic explicit and safe. */
  size_t ae = la;
  size_t be = lb;
  while (ae > p && be > p && a[ae - 1] == b[be - 1]) {
    ae--;
    be--;
  }
  size_t ma = ae - p;
  size_t mb = be - p;
  /* cppcheck-suppress knownConditionTrueFalse -- the prefix/suffix trims above
     only run while the corresponding ends match, so a middle can remain; the
     analysis unsoundly concludes the trims always consume everything. */
  if (ma == 0)
    return mb;
  if (mb == 0)
    return ma;
  const char* A = a + p;
  const char* B = b + p;
  size_t* prev = buf->prev;
  size_t* cur = buf->cur;
  for (size_t j = 0; j <= mb; j++)
    prev[j] = j;
  for (size_t i = 1; i <= ma; i++) {
    cur[0] = i;
    for (size_t j = 1; j <= mb; j++) {
      size_t cost = A[i - 1] == B[j - 1] ? 0 : 1;
      size_t del = prev[j] + 1;
      size_t ins = cur[j - 1] + 1;
      size_t sub = prev[j - 1] + cost;
      size_t m = del < ins ? del : ins;
      cur[j] = m < sub ? m : sub;
    }
    size_t* tmp = prev;
    prev = cur;
    cur = tmp;
  }
  return prev[mb];
}

/* Deterministic ordering of two fuzzy candidates: smallest edit distance,
 * then the size closest to the incoming file, then the lexical basename. */
static bool fuzzy_candidate_better(const FuzzyCandidate* cand, const FuzzyCandidate* best) {
  if (!best->name[0])
    return true;
  if (cand->distance != best->distance)
    return cand->distance < best->distance;
  if (cand->size_gap != best->size_gap)
    return cand->size_gap < best->size_gap;
  return strcmp(cand->name, best->name) < 0;
}

/* Search the destination directory that will contain `check_path` for a
 * similar regular file usable as a --fuzzy delta basis and return its full
 * content in a malloc'd (protocol_alloc) buffer.  Returns NULL (with *out_size
 * = 0) when no candidate qualifies, which means the caller performs the normal
 * whole-file transfer. */
static void* fuzzy_basis_find_and_load(const Config* config, const char* check_path,
                                       unsigned long long check_size,
                                       unsigned long long* out_size) {
  *out_size = 0;
  if (!config || !config->receive_root_directory || !config->fuzzy || !config->use_delta ||
      !check_path || check_size < DELTA_MIN_FILE_SIZE || check_size > config->delta_max_file_size ||
      check_size > MAX_RECEIVE_WHOLE_FILE_SIZE)
    return NULL;

  char* full_path = path_cat(config->receive_root_directory, check_path);
  if (!full_path)
    return NULL;
  char* leaf = NULL;
  int dir_fd = file_open_secure_parent(full_path, &leaf, false);
  if (dir_fd < 0 || !leaf) {
    free(leaf);
    free(full_path);
    return NULL;
  }
  size_t target_len = strlen(leaf);
  /* A target basename longer than FUZZY_NAME_LIMIT can never pass the name gate
     (every candidate name is bounded by the same limit), so skip the scan. */
  if (target_len > FUZZY_NAME_LIMIT) {
    close(dir_fd);
    free(leaf);
    free(full_path);
    return NULL;
  }

  int scanfd = dup(dir_fd);
  if (scanfd < 0) {
    close(dir_fd);
    free(leaf);
    free(full_path);
    return NULL;
  }
  DIR* dir = fdopendir(scanfd);
  if (!dir) {
    close(scanfd);
    close(dir_fd);
    free(leaf);
    free(full_path);
    return NULL;
  }

  /* The DP scratch rows are allocated once per scan (not once per candidate). */
  FuzzyEditBuffer ebuf;
  if (!fuzzy_edit_buffer_init(&ebuf)) {
    closedir(dir);
    close(dir_fd);
    free(leaf);
    free(full_path);
    return NULL;
  }

  FuzzyCandidate best;
  memset(&best, 0, sizeof(best));
  const struct dirent* entry;
  size_t scanned = 0;
  /* readdir() yields entries in filesystem-dependent order, so the SET of
     candidates seen is order-dependent; the winner is still deterministic
     because every candidate is compared with the total ordering in
     fuzzy_candidate_better (acceptable for a heuristic). */
  while (scanned < FUZZY_MAX_DIRECTORY_SCAN && (entry = readdir(dir)) != NULL) {
    scanned++;
    const char* name = entry->d_name;
    size_t name_len = strlen(name);
    if (name[0] == '.' || name_len == 0 || name_len > FUZZY_NAME_LIMIT || strcmp(name, leaf) == 0)
      continue;
    struct stat st;
    if (fstatat(dir_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode))
      continue;
    unsigned long long cand_size = (unsigned long long)st.st_size;
    if (cand_size == 0 || cand_size > MAX_RECEIVE_WHOLE_FILE_SIZE ||
        !delta_should_attempt(cand_size, check_size, config->delta_max_file_size))
      continue;
    /* Cheap pre-name gates run BEFORE the edit-distance DP.  The edit distance
       is bounded below by the length gap |la-lb| and by the number of
       characters of one basename that are absent from the other (each such
       position costs at least one op), so a candidate whose acceptance gate
       (distance*2 <= longer) already fails on the max of those bounds is
       skipped without running the DP. */
    size_t longer = target_len > name_len ? target_len : name_len;
    size_t bound = longer - (target_len < name_len ? target_len : name_len);
    size_t absent = fuzzy_absent_char_bound(leaf, target_len, name, name_len);
    if (absent > bound)
      bound = absent;
    if (bound * 2 > longer)
      continue;
    size_t distance = fuzzy_edit_distance(&ebuf, leaf, target_len, name, name_len);
    if (distance * 2 > longer)
      continue;
    FuzzyCandidate cand;
    memcpy(cand.name, name, name_len + 1);
    cand.size = cand_size;
    cand.distance = distance;
    cand.size_gap = cand_size > check_size ? cand_size - check_size : check_size - cand_size;
    if (fuzzy_candidate_better(&cand, &best))
      best = cand;
  }
  closedir(dir);
  free(leaf);
  fuzzy_edit_buffer_destroy(&ebuf);

  void* basis = NULL;
  if (best.name[0]) {
    /* O_NONBLOCK: a name raced to a FIFO between the fstatat gate and this open
       would otherwise block the receive thread forever on open(2); with it the
       open fails (ENXIO) and the fstat/S_ISREG gate below would reject it too.
       A regular file opened with O_NONBLOCK is unaffected. */
    int fd = openat(dir_fd, best.name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) {
      struct stat st;
      if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
          (unsigned long long)st.st_size == best.size && best.size <= SIZE_MAX) {
        basis = protocol_alloc((size_t)best.size);
        if (basis) {
          size_t got = 0;
          while (got < (size_t)best.size) {
            ssize_t n = read(fd, (char*)basis + got, (size_t)best.size - got);
            if (n <= 0) {
              free(basis);
              basis = NULL;
              break;
            }
            got += (size_t)n;
          }
        }
      }
      close(fd);
    }
  }
  close(dir_fd);
  free(full_path);
  if (basis)
    *out_size = best.size;
  return basis;
}

File* receive_incremental_check(int fd, const Config* config, bool* skipped) {
  if (!config || !skipped) {
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  *skipped = false;
  char* check_path = receive_str(fd);
  if (check_path == NULL) {
    return NULL;
  }

  unsigned long long check_size;
  long long check_mtime;
  long long check_mtime_nsec;
  uint8_t check_digest[CHECKSUM_MAX_DIGEST_LEN];
  size_t check_digest_len = 0;
  if (!receive_n_data(fd, &check_size, sizeof(check_size)) ||
      !receive_n_data(fd, &check_mtime, sizeof(check_mtime))) {
    free(check_path);
    return NULL;
  }
  if (!receive_n_data(fd, &check_mtime_nsec, sizeof(check_mtime_nsec)) || check_mtime_nsec < 0 ||
      check_mtime_nsec >= 1000000000LL) {
    free(check_path);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  if ((config->checksum || config_has_basis(config))) {
    uint8_t wire_len;
    if (!receive_n_data(fd, &wire_len, sizeof(wire_len)) || wire_len == 0 ||
        wire_len > CHECKSUM_MAX_DIGEST_LEN ||
        wire_len != checksum_digest_len((ChecksumAlgo)config->checksum_algo)) {
      free(check_path);
      send_status(fd, STATUS_ERROR);
      return NULL;
    }
    check_digest_len = wire_len;
    if (!receive_n_data(fd, check_digest, check_digest_len)) {
      free(check_path);
      return NULL;
    }
  }

  if (check_size > MAX_RECEIVE_WHOLE_FILE_SIZE) {
    free(check_path);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }

  if (has_path_traversal(check_path)) {
    char* escaped_path = output_escape(check_path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Path traversal detected: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    free(check_path);
    return NULL;
  }

  char* full_path = path_cat(config->receive_root_directory, check_path);
  if (!full_path) {
    free(check_path);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }

  /* Open the existing destination entry (if any) once and keep the descriptor
     until the quick-check below decides whether the old contents are needed. */
  struct stat st;
  bool has_old_file = false;
  int old_fd = -1;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(full_path, &leaf, false);
  if (parent_fd >= 0) {
    old_fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    free(leaf);
    close(parent_fd);
    has_old_file = old_fd >= 0 && fstat(old_fd, &st) == 0 && S_ISREG(st.st_mode);
  }
  if (!has_old_file && old_fd >= 0) {
    close(old_fd);
    old_fd = -1;
  }
  unsigned long long old_size = has_old_file ? (unsigned long long)st.st_size : 0;

  /* Decide from metadata alone whether the receiver already holds the file
     the sender is offering.  The old contents are only read into memory when
     a checksum comparison or a delta transfer actually requires them. */
  bool size_equal = has_old_file && old_size == check_size;
  bool match_by_metadata = false;
  if (size_equal && !config->ignore_times && !config->size_only) {
    long long old_mtime_nsec = 0;
#ifdef __linux__
    old_mtime_nsec = st.st_mtim.tv_nsec;
#endif
    match_by_metadata = metadata_mtime_matches(st.st_mtime, old_mtime_nsec, (time_t)check_mtime,
                                               (long)check_mtime_nsec, config->modify_window);
  }

  bool try_delta = config->use_delta && !config->whole_file && has_old_file &&
                   delta_should_attempt(old_size, check_size, config->delta_max_file_size);
  bool checksum_needs_read = size_equal && !config->ignore_times && config->checksum;
  bool need_old_data = checksum_needs_read || try_delta;

  void* old_data = NULL;
  if (need_old_data && has_old_file && old_size > 0 && old_size <= MAX_RECEIVE_WHOLE_FILE_SIZE &&
      old_size <= SIZE_MAX) {
    old_data = protocol_alloc((size_t)old_size);
    if (old_data) {
      size_t got = 0;
      while (got < (size_t)old_size) {
        ssize_t n = read(old_fd, (char*)old_data + got, (size_t)old_size - got);
        if (n <= 0) {
          free(old_data);
          old_data = NULL;
          break;
        }
        got += (size_t)n;
      }
    }
  }

  /* Quick-skip decision.  If no content comparison is required this is final
     and the old file was never read; if the read failed the file is not
     skipped and the transfer proceeds with the full new contents. */
  bool match = false;
  if (checksum_needs_read) {
    uint8_t old_digest[CHECKSUM_MAX_DIGEST_LEN];
    size_t old_len = 0;
    bool hashed = checksum_digest((ChecksumAlgo)config->checksum_algo, config->checksum_seed,
                                  old_size == 0 ? "" : old_data, (size_t)old_size, old_digest,
                                  sizeof(old_digest), &old_len);
    match = hashed && old_len == check_digest_len && check_digest_len > 0 &&
            memcmp(old_digest, check_digest, check_digest_len) == 0;
  } else if (size_equal && !config->ignore_times) {
    match = config->size_only || match_by_metadata;
  }

  if (match) {
    free(old_data);
    if (!send_status(fd, STATUS_OK)) {
      close(old_fd);
      free(full_path);
      free(check_path);
      return NULL;
    }
    close(old_fd);
    free(full_path);
    free(check_path);
    *skipped = true;
    return NULL;
  }

  /* ---- Alternate basis directories ---- */
  if (config_has_basis(config)) {
    BasisMatch basis;
    basis_match_find(config, check_path, check_size, (time_t)check_mtime, (long)check_mtime_nsec,
                     check_digest, check_digest_len, true, &basis);
    if (basis.hit) {
      if (basis.type == BASIS_DEST_COMPARE) {
        /* compare-dest never copies: an exact match only suppresses the data
           for a file the destination does not already hold (sparse backup).
           When the destination holds a DIFFERENT version FastSync falls back to
           a normal transfer rather than deleting the stale entry the way rsync
           does (see RSYNC_COMPAT.md). */
        basis_match_free(&basis);
        if (!has_old_file) {
          if (!send_status(fd, STATUS_OK)) {
            close(old_fd);
            free(full_path);
            free(check_path);
            return NULL;
          }
          free(old_data);
          close(old_fd);
          free(full_path);
          free(check_path);
          *skipped = true;
          return NULL;
        }
      } else {
        /* copy-dest / link-dest: materialize the unchanged file locally so the
           sender can skip the data.  The store engine re-applies the normal
           existing/ignore-existing/update/backup/delay-updates policy. */
        File* materialized = file_create(check_path);
        if (materialized && basis.content) {
          materialized->data = basis.content;
          basis.content = NULL;
          materialized->metadata = file_metadata_create(&basis.st);
          materialized->skip = true; /* receiver must not ack this as a data file */
          if (basis.type == BASIS_DEST_LINK) {
            materialized->basis_link = basis.basis_path;
            basis.basis_path = NULL;
          }
          if (!materialized->metadata) {
            file_destroy(materialized);
            materialized = NULL;
          }
        } else {
          file_destroy(materialized);
          materialized = NULL;
        }
        if (materialized) {
          if (!send_status(fd, STATUS_OK)) {
            basis_match_free(&basis);
            file_destroy(materialized);
            close(old_fd);
            free(full_path);
            free(check_path);
            return NULL;
          }
          basis_match_free(&basis);
          free(old_data);
          close(old_fd);
          free(full_path);
          free(check_path);
          *skipped = false;
          return materialized;
        }
        /* Materialization setup failed: fall through to the normal transfer. */
      }
    }
    basis_match_free(&basis);
  }

  if (try_delta && old_data != NULL) {
    bool delta_failed = false;
    File* delta_file =
        receive_delta_file(fd, config, check_path, old_data, old_size, &delta_failed);
    old_data = NULL; /* receive_delta_file consumes the snapshot on every path */
    if (delta_file) {
      close(old_fd);
      free(full_path);
      free(check_path);
      return delta_file;
    }
    if (delta_failed) {
      close(old_fd);
      free(full_path);
      free(check_path);
      return NULL;
    }
  }
  free(old_data);
  old_data = NULL;

  /* ---- -y/--fuzzy similar-file delta basis ----
   * Reaching this point means the file must be transferred and the
   * destination's own content at the exact path could not serve as a delta
   * basis (it is absent, outside the delta size bounds, or unreadable).  With
   * --fuzzy the receiver tries an existing similar-named file in the same
   * destination directory instead.  receive_delta_file performs the whole
   * handshake: when the sender judges the delta not worthwhile it replies
   * STATUS_NEXT and the full content is received there, so a fuzzy attempt
   * can only improve bandwidth, never fall through into the plain transfer
   * below (that path is reserved for "no usable candidate was found"). */
  if (config->fuzzy && config->use_delta) {
    unsigned long long fuzzy_size = 0;
    void* fuzzy_basis = fuzzy_basis_find_and_load(config, check_path, check_size, &fuzzy_size);
    if (fuzzy_basis != NULL) {
      bool fuzzy_failed = false;
      File* fuzzy_file =
          receive_delta_file(fd, config, check_path, fuzzy_basis, fuzzy_size, &fuzzy_failed);
      fuzzy_basis = NULL; /* receive_delta_file consumes the buffer on every path */
      if (fuzzy_file) {
        close(old_fd);
        free(full_path);
        free(check_path);
        return fuzzy_file;
      }
      if (fuzzy_failed) {
        close(old_fd);
        free(full_path);
        free(check_path);
        return NULL;
      }
    }
    free(fuzzy_basis);
  }

  if (!send_status(fd, STATUS_NEXT)) {
    close(old_fd);
    free(full_path);
    free(check_path);
    return NULL;
  }
  close(old_fd);

  File* file = file_create(check_path);
  free(check_path);
  free(full_path);
  if (file == NULL) {
    return NULL;
  }

  if (config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(fd, &meta_ok);
    if (!meta_ok) {
      file_destroy(file);
      return NULL;
    }
  }

  Data* file_data = receive_data_limited(fd, MAX_RECEIVE_WHOLE_FILE_SIZE);
  if (file_data == NULL) {
    file_destroy(file);
    return NULL;
  }

  if (config->use_compression &&
      !compression_should_skip_with_suffixes(file->path, config->skip_compress_suffixes,
                                             config->skip_compress_set ? config->skip_compress_count
                                                                       : -1)) {
    Data* uncompressed = data_decompress_limited(file_data, MAX_RECEIVE_WHOLE_FILE_SIZE);
    data_destroy(file_data);
    if (uncompressed == NULL) {
      file_destroy(file);
      return NULL;
    }
    if (uncompressed->size > MAX_FILE_DATA_SIZE) {
      data_destroy(uncompressed);
      file_destroy(file);
      return NULL;
    }
    file_data = uncompressed;
  }

  data_destroy(file->data);
  file->data = file_data;
  return file;
}

File* file_receive(const Config* config, int file_descriptor) {
  char* path = receive_str(file_descriptor);
  if (path == NULL)
    return NULL;
  if (path[0] == '\0' || has_path_traversal(path)) {
    char* escaped_path = output_escape(path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid received file path: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    free(path);
    return NULL;
  }
  File* file = file_create(path);
  free(path);
  if (file == NULL)
    return NULL;
  if (config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(file_descriptor, &meta_ok);
    if (!meta_ok) {
      file_destroy(file);
      return NULL;
    }
  }
  Data* file_data = receive_data_limited(file_descriptor, MAX_RECEIVE_WHOLE_FILE_SIZE);
  if (file_data == NULL) {
    file_destroy(file);
    return NULL;
  }
  if (config->use_compression &&
      !compression_should_skip_with_suffixes(file->path, config->skip_compress_suffixes,
                                             config->skip_compress_set ? config->skip_compress_count
                                                                       : -1)) {
    Data* file_data_uncompressed = data_decompress_limited(file_data, MAX_RECEIVE_WHOLE_FILE_SIZE);
    data_destroy(file_data);
    if (file_data_uncompressed == NULL) {
      file_destroy(file);
      return NULL;
    }
    if (file_data_uncompressed->size > MAX_FILE_DATA_SIZE) {
      data_destroy(file_data_uncompressed);
      file_destroy(file);
      return NULL;
    }
    file_data = file_data_uncompressed;
  }
  data_destroy(file->data);
  file->data = file_data;
  return file;
}

/* Receive an explicit directory entry (--dirs): a STATUS_MKDIR frame carries
   only the destination path; the entry carries no payload.  The same path
   validation as a regular file applies (non-empty, relative-or-mirrored, no
   traversal), and the created File is routed through the regular store_file
   sink so single-threaded and -m receivers handle directories identically. */
File* file_receive_directory(int file_descriptor) {
  char* path = receive_str(file_descriptor);
  if (path == NULL)
    return NULL;
  if (path[0] == '\0' || has_path_traversal(path)) {
    char* escaped_path = output_escape(path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid received directory path: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    free(path);
    return NULL;
  }
  File* file = file_create(path);
  free(path);
  if (file == NULL)
    return NULL;
  file->is_dir = true;
  return file;
}

/* Read a delete-manifest frame (the STATUS_MANIFEST leading code has already
   been consumed): a keep-set entry count followed by that many
   destination-relative paths, then a protected-prefix count followed by that
   many destination-relative prefixes.  The frame is self-delimiting (the counts
   are authoritative), so the caller decides what to do next and continues
   reading the following STATUS_* frame.  Returns an owned DeleteManifest, or
   NULL after sending STATUS_ERROR when the frame is malformed (bad count,
   empty/absolute path, path traversal, or an aggregate size beyond
   MAX_MANIFEST_BYTES). */
static bool receive_manifest_section(int fd, ArrayList* list, size_t* manifest_bytes) {
  int count;
  if (!receive_int(fd, &count)) {
    send_status(fd, STATUS_ERROR);
    return false;
  }
  if (count < 0 || count > MAX_MANIFEST_ENTRIES) {
    send_status(fd, STATUS_ERROR);
    return false;
  }
  for (int i = 0; i < count; i++) {
    char* s = receive_str(fd);
    size_t entry_size = s ? strlen(s) : 0;
    if (!s || s[0] == '\0' || s[0] == '/' || has_path_traversal(s) ||
        entry_size > MAX_MANIFEST_BYTES - *manifest_bytes ||
        (*manifest_bytes += entry_size) > MAX_MANIFEST_BYTES || !array_list_add(list, s)) {
      free(s);
      send_status(fd, STATUS_ERROR);
      return false;
    }
  }
  return true;
}

DeleteManifest* receive_manifest_entries(int fd) {
  DeleteManifest* manifest = calloc(1, sizeof(DeleteManifest));
  if (!manifest) {
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  manifest->keeps = array_list_create(free);
  manifest->protected = array_list_create(free);
  if (!manifest->keeps || !manifest->protected) {
    delete_manifest_free(manifest);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  size_t manifest_bytes = 0;
  if (!receive_manifest_section(fd, manifest->keeps, &manifest_bytes) ||
      !receive_manifest_section(fd, manifest->protected, &manifest_bytes)) {
    delete_manifest_free(manifest);
    return NULL;
  }
  return manifest;
}

void delete_manifest_free(DeleteManifest* manifest) {
  if (!manifest)
    return;
  array_list_delete(manifest->keeps);
  array_list_delete(manifest->protected);
  free(manifest);
}

/* Remove every destination entry under the receive root that is not in the
   keep-set, bounded by MAX_SERVER_DELETE_COUNT (or a smaller client
   --max-delete=NUM, which is all-or-nothing), using the symlink-safe delete
   walker.  With --delay-updates the not-yet-published staging directory is a
   direct child of the receive root and must not be treated as a set of extras;
   the manifest's protected prefixes (paths excluded on the source) and the
   alternate basis directories are never destination content and are skipped at
   any depth.  Prints a notice and returns true on success. */
bool manifest_delete_extras(const Config* config, DeleteManifest* manifest) {
  if (!config || !manifest || !manifest->keeps)
    return false;
  fprintf(stderr, "Deleting files not in manifest...\n");
  /* Protected entries:
     - the --delay-updates staging name, protected only as a DIRECT child of the
       receive root (a nested destination directory that happens to be named
       .fastsync-stage is ordinary content);
     - alternate basis directories (--compare-dest / --copy-dest / --link-dest)
       at any depth: they are extra comparison snapshots the user pointed at,
       not destination content, and deleting them would destroy the very files a
       --link-dest run just linked into place;
     - the sender-side protected prefixes (source paths excluded by filters), at
       any depth, so an excluded destination mirror survives --delete unless
       --delete-excluded opts back into removing it. */
  int skip_count = (config->delay_updates ? 1 : 0) + config->basis_count +
                   (manifest->protected ? manifest->protected->size : 0);
  DeleteSkipEntry* skips = NULL;
  if (skip_count > 0) {
    skips = calloc((size_t)skip_count, sizeof(DeleteSkipEntry));
    if (!skips)
      return false;
    int idx = 0;
    if (config->delay_updates) {
      skips[idx].prefix = DELAY_UPDATES_STAGING_DIR;
      skips[idx].top_level_only = true;
      idx++;
    }
    for (int i = 0; i < config->basis_count; i++) {
      skips[idx].prefix = config->basis_dirs[i].path;
      skips[idx].top_level_only = false;
      idx++;
    }
    for (int i = 0; i < manifest->protected->size; i++) {
      skips[idx].prefix = (const char*)manifest->protected->items[i];
      skips[idx].top_level_only = false;
      idx++;
    }
  }
  /* A client --max-delete=NUM smaller than the server's hard bound replaces it
     for this run; both still bound the walk.  The walker is all-or-nothing, so
     a run that would delete more than the bound removes nothing and fails with
     an error that names the bound that was hit. */
  bool user_limited =
      config->max_delete >= 0 && (size_t)config->max_delete < MAX_SERVER_DELETE_COUNT;
  size_t cap = user_limited ? (size_t)config->max_delete : MAX_SERVER_DELETE_COUNT;
  size_t deleted_count = 0;
  DeleteWalkResult result = delete_extras_limited(config->receive_root_directory, manifest->keeps,
                                                  cap, skips, skip_count, &deleted_count);
  free(skips);
  if (result == DELETE_WALK_LIMIT_EXCEEDED) {
    if (user_limited) {
      log_message(LOG_LEVEL_ERROR,
                  "deletion stopped: the destination holds more than --max-delete=%d extraneous "
                  "entries; no files were deleted",
                  config->max_delete);
    } else {
      log_message(LOG_LEVEL_ERROR,
                  "deletion stopped: the destination holds more than %u extraneous entries "
                  "(server deletion limit); no files were deleted",
                  (unsigned)MAX_SERVER_DELETE_COUNT);
    }
    return false;
  }
  if (result != DELETE_WALK_OK) {
    log_message(LOG_LEVEL_ERROR, "deletion failed while removing extraneous files");
    return false;
  }
  return true;
}
