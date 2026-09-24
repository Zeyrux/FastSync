#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "array_list.h"
#include "charset.h"
#include "chmod.h"
#include "chunk.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delay_updates.h"
#include "delta.h"
#include "file.h"
#include "file_receive.h"
#include "format.h"
#include "identity.h"
#include "incremental_check.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"
#include "xattr.h"

File* file_receive(const Config* config, int file_descriptor) {
  char* path = receive_wire_str(file_descriptor);
  if (path == NULL)
    return NULL;
  if (path[0] == '\0' || (!file_get_trust_sender() && has_path_traversal(path))) {
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
  if (!receive_file_xattrs(file, file_descriptor, config)) {
    file_destroy(file);
    return NULL;
  }
  bool compress =
      config->use_compression && !compression_should_skip_with_suffixes(
                                     file->path, config->skip_compress_suffixes,
                                     config->skip_compress_set ? config->skip_compress_count : -1);
  char* dest_path = path_cat(config->receive_root_directory, file->path);
  if (!dest_path) {
    file_destroy(file);
    return NULL;
  }
  Data* buffer = NULL;
  char* spool = NULL;
  unsigned long long size = 0;
  bool ok = file_receive_payload(file_descriptor, compress, 0, dest_path,
                                 protocol_whole_file_receive_limit(), &buffer, &spool, &size);
  free(dest_path);
  if (!ok) {
    file_destroy(file);
    return NULL;
  }
  if (spool) {
    Data* reserved = data_create_reserve((size_t)size);
    if (!reserved) {
      unlink(spool);
      free(spool);
      file_destroy(file);
      return NULL;
    }
    data_destroy(file->data);
    file->data = reserved;
    file->basis_copy = spool;
    file->data_spool = true;
  } else {
    data_destroy(file->data);
    file->data = buffer;
  }
  return file;
}

/* ---- P7 Wave D: deferred directory metadata ---- */

bool dir_metadata_should_capture(const Config* config) {
  /* Directory metadata is captured when a directory attribute is actually
   * requested: -p/--perms (directory modes), -t/--times (directory mtimes,
   * unless -O/--omit-dir-times suppresses them), -o/-g (directory ownership),
   * -X/-A (directory xattrs/ACLs), or --fake-super (whose reserved %stat record
   * is written on the directory itself, so its metadata must travel).
   * --atimes/-U alone does not pull directory metadata (matching the original
   * dir-time bundle). */
  return config && config->use_metadata &&
         (config->preserve_perms || (config->preserve_times && !config->omit_dir_times) ||
          config->preserve_owner || config->preserve_group || config->preserve_xattrs ||
          config->preserve_acls || config->fake_super);
}

void dir_time_list_init(DirTimeList* list) {
  if (!list)
    return;
  list->paths = NULL;
  list->entries = NULL;
  list->xattrs = NULL;
  list->count = 0;
  list->capacity = 0;
  list->bytes = 0;
}

void dir_time_list_free(DirTimeList* list) {
  if (!list)
    return;
  for (size_t i = 0; i < list->count; i++) {
    free(list->paths[i]);
    xattr_list_free(list->xattrs ? list->xattrs[i] : NULL);
  }
  free(list->paths);
  free(list->entries);
  free(list->xattrs);
  list->paths = NULL;
  list->entries = NULL;
  list->xattrs = NULL;
  list->count = 0;
  list->capacity = 0;
  list->bytes = 0;
}

bool dir_time_list_add(DirTimeList* list, const char* wire_path, const FileMetadata* metadata,
                       const FileXattrList* xattrs) {
  if (!list || !wire_path || !metadata)
    return true; /* nothing to remember; never a hard error */
  /* Cumulative, not per-frame: the sender may stream a tree across unbounded
     STATUS_DIR_TIMES frames, so bound the TOTAL retained here.  Reject before
     touching the list, leaving it exactly as it was (the caller fails the
     transfer, which becomes a clean protocol error). */
  size_t path_len = strlen(wire_path);
  /* Charge the whole per-entry cost (path copy + pointer slot + metadata
     struct + captured xattrs), not just the path, so the array growth is
     bounded by the same cumulative budget. */
  size_t xattr_cost = 0;
  if (xattrs) {
    for (int i = 0; i < xattrs->count; i++)
      xattr_cost += strlen(xattrs->items[i].name) + xattrs->items[i].value_len + sizeof(FileXattr);
  }
  size_t entry_cost = path_len + sizeof(FileMetadata) + 2 * sizeof(char*) + xattr_cost;
  if (list->count >= MAX_DIR_TIME_ENTRIES || entry_cost > MAX_DIR_TIME_BYTES - list->bytes)
    return false;
  if (list->count == list->capacity) {
    size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
    if (new_capacity < list->capacity)
      return false;
    /* Assign each grown array as soon as its realloc succeeds: the old block is
       already freed by then, so discarding the pointer would dangle.  capacity
       is advanced only after ALL reallocs succeed, so a partial failure leaves
       capacity no larger than the smallest allocation -- never a mismatched
       list the next add could write past. */
    char** grown_paths = realloc(list->paths, new_capacity * sizeof(char*));
    if (!grown_paths)
      return false;
    list->paths = grown_paths;
    FileMetadata* grown_entries = realloc(list->entries, new_capacity * sizeof(FileMetadata));
    if (!grown_entries)
      return false;
    list->entries = grown_entries;
    FileXattrList** grown_xattrs = realloc(list->xattrs, new_capacity * sizeof(FileXattrList*));
    if (!grown_xattrs)
      return false;
    list->xattrs = grown_xattrs;
    list->capacity = new_capacity;
  }
  char* copy = str_dup(wire_path);
  if (!copy)
    return false;
  FileXattrList* xattr_copy = xattr_list_clone(xattrs);
  if (xattrs && !xattr_copy) {
    free(copy);
    return false;
  }
  list->paths[list->count] = copy;
  list->entries[list->count] = *metadata;
  list->xattrs[list->count] = xattr_copy;
  list->count++;
  list->bytes += entry_cost;
  return true;
}

void dir_metadata_list_apply(const DirTimeList* list, const char* root_directory,
                             const Config* config) {
  if (!list || !root_directory || !config)
    return;
  bool apply_times = config->preserve_times && !config->omit_dir_times;
  bool apply_mode = config->preserve_perms;
  bool apply_xattrs = config->use_xattrs;
  bool apply_fake_super = config->fake_super;
  /* Ownership is applied through the active identity snapshot (which no-ops
   * unless an ownership request is active), xattrs only when -X/-A was
   * negotiated, and the --fake-super record whenever the flag is active.
   * Times/mode keep their own per-attribute gates. */
  bool have_any =
      apply_times || apply_mode || apply_xattrs || apply_fake_super || identity_active_enabled();
  if (!have_any)
    return;
  /* Built once: the --fake-super replay uses it to apply only the recorded
   * permission bits (the special bits stay in the record, exactly like the
   * regular-file fake-super receiver). */
  FileAttrPolicy policy = file_attr_policy_from_config(config);
  for (size_t i = 0; i < list->count; i++) {
    char* dir_path = path_cat(root_directory, list->paths[i]);
    if (!dir_path)
      continue;
    char* leaf = NULL;
    /* The parent walk is fd-relative and O_NOFOLLOW, so a symlink planted in a
       parent component can never redirect the utimensat/chmod outside the
       root. */
    int parent_fd = file_open_secure_parent(dir_path, &leaf, false);
    if (parent_fd < 0) {
      free(dir_path);
      continue;
    }
    /* A dir-time entry only records metadata: the directory is (deliberately)
       not created from it, so an empty source directory (or one pruned by
       -m/--prune-empty-dirs) may well not exist here.  Skip absent paths
       QUIETLY rather than warning for every one, and apply the metadata only to
       a real directory that does exist.  AT_SYMLINK_NOFOLLOW keeps a same-named
       symlink from being followed; a pre-existing regular file/symlink is not a
       directory, so it is left completely untouched. */
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(st.st_mode)) {
      close(parent_fd);
      free(leaf);
      free(dir_path);
      continue;
    }
    /* One O_DIRECTORY|O_NOFOLLOW fd drives ownership/mode/xattr application so
       none of them can follow a same-named symlink planted after the fstatat. */
    int dir_fd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    /* Ownership first: a chown clears setuid/setgid, so it must precede mode. */
    if (dir_fd >= 0)
      identity_apply_ownership(dir_fd, (int32_t)list->entries[i].uid,
                               (int32_t)list->entries[i].gid);
    if (apply_times) {
      struct timespec times[2] = {
          {.tv_sec = 0, .tv_nsec = UTIME_OMIT},
          {.tv_sec = list->entries[i].mtime_sec, .tv_nsec = list->entries[i].mtime_nsec}};
      if (config->preserve_atimes && list->entries[i].atime_valid) {
        times[0].tv_sec = list->entries[i].atime_sec;
        times[0].tv_nsec = list->entries[i].atime_nsec;
      }
      if (utimensat(parent_fd, leaf, times, AT_SYMLINK_NOFOLLOW) != 0) {
        char* escaped_path = output_escape(dir_path, log_get_8_bit_output());
        log_message(LOG_LEVEL_WARNING, "Failed to set directory timestamps on %s: %s",
                    escaped_path ? escaped_path : "<allocation failed>", strerror(errno));
        free(escaped_path);
      }
    }
    /* The final directory mode (after any --chmod) is computed once so the
       --fake-super record can carry it even when the on-disk replay is
       restricted to the permission bits below. */
    mode_t dir_mode = list->entries[i].mode;
    bool mode_ready = true;
    if (apply_mode && config->chmod_spec && *config->chmod_spec &&
        !chmod_apply(dir_mode, config->chmod_spec, &dir_mode)) {
      char* escaped_path = output_escape(dir_path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING, "Failed to apply --chmod to directory %s",
                  escaped_path ? escaped_path : "<allocation failed>");
      free(escaped_path);
      mode_ready = false;
    }
    /* Under --fake-super the normal fchmod below still applies the mode, but
       the fake-super replay that follows narrows the on-disk result to the
       recorded permission bits (the full mode, including setuid/setgid/sticky,
       lives only in the record).  Keeping the normal fchmod first means a
       filesystem without xattr support still gets the directory mode rather than
       silently losing it. */
    if (apply_mode && mode_ready) {
      /* rsync -p copies the source directory mode exactly, including
       * group/other write and the setgid/sticky bits.  Setuid/setgid/sticky
       * are super-user activities: when the connection forbade them
       * (SUPER_MODE_OFF / --no-super), strip them even under -p. */
      mode_t safe_mode = dir_mode & (mode_t)(S_ISUID | S_ISGID | S_ISVTX | 0777);
      if (!privilege_super_mode_permitted(config->super_mode))
        safe_mode &= ~(mode_t)(S_ISUID | S_ISGID | S_ISVTX);
      if (dir_fd < 0) {
        char* escaped_path = output_escape(dir_path, log_get_8_bit_output());
        log_message(LOG_LEVEL_WARNING, "Failed to open directory %s to set its mode: %s",
                    escaped_path ? escaped_path : "<allocation failed>", strerror(errno));
        free(escaped_path);
      } else if (fchmod(dir_fd, safe_mode) != 0) {
        char* escaped_path = output_escape(dir_path, log_get_8_bit_output());
        log_message(LOG_LEVEL_WARNING, "Failed to set directory mode on %s: %s",
                    escaped_path ? escaped_path : "<allocation failed>", strerror(errno));
        free(escaped_path);
      }
    }
    /* --fake-super: park the directory's full stat (rsync 3.4.1's exact
       grammar) on the directory ITSELF, then replay only the recorded
       permission bits fd-relative.  The special bits live only in the record
       and the recorded ownership is never real-chowned: the resolved ids are
       stored for a later privileged restore, exactly like the file path.  Runs
       before the xattr apply so a mode change cannot clobber the ACL mask. */
    if (apply_fake_super && dir_fd >= 0) {
      uint32_t store_uid = 0;
      uint32_t store_gid = 0;
      identity_resolve_storage_ids((int32_t)list->entries[i].uid, (int32_t)list->entries[i].gid,
                                   &store_uid, &store_gid);
      fake_super_store_fd(dir_fd, store_uid, store_gid, (uint32_t)dir_mode, 0, 0);
      fake_super_restore_fd(dir_fd, policy);
    }
    /* xattrs/ACLs last: a mode change can rewrite the ACL mask, so the ACL
       xattrs must be (re)applied after fchmod. */
    if (apply_xattrs && dir_fd >= 0 && list->xattrs)
      xattr_apply_fd(dir_fd, list->xattrs[i]);
    if (dir_fd >= 0)
      close(dir_fd);
    close(parent_fd);
    free(leaf);
    free(dir_path);
  }
}

/* Receive an explicit directory entry (--dirs): a STATUS_MKDIR frame carries
   the destination path and, when metadata is negotiated, the directory's
   metadata frame.  The same path validation as a regular file applies
   (non-empty, relative-or-mirrored, no traversal), and the created File is
   routed through the regular store_file sink so single-threaded and -m
   receivers handle directories identically.  The metadata is NOT applied here:
   the sink accumulates it into a DirTimeList that is applied only after the
   whole transfer (children would otherwise clobber the directory mtime). */
File* file_receive_directory(int file_descriptor, const Config* config) {
  char* path = receive_wire_str(file_descriptor);
  if (path == NULL)
    return NULL;
  if (path[0] == '\0' || (!file_get_trust_sender() && has_path_traversal(path))) {
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
  if (config && config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(file_descriptor, &meta_ok);
    if (!meta_ok) {
      file_destroy(file);
      return NULL;
    }
  }
  /* Directory xattrs/ACLs (-X/-A) ride after the metadata when negotiated. */
  if (config && !receive_file_xattrs(file, file_descriptor, config)) {
    file_destroy(file);
    return NULL;
  }
  return file;
}

/* Receive one directory-time entry from a STATUS_DIR_TIMES frame: the
 * destination-relative wire path and (when metadata is negotiated) the
 * directory's metadata frame.  The created File is an is_dir, dir_time_only
 * entry routed through the regular store_file sink: the sink records its
 * metadata into the deferred DirTimeList but never creates the directory (the
 * scanner captures every traversed directory, including empty ones).  Unlike a
 * STATUS_MKDIR entry, this one must not create anything. */
File* file_receive_dir_time(int file_descriptor, const Config* config) {
  char* path = receive_wire_str(file_descriptor);
  if (path == NULL)
    return NULL;
  if (path[0] == '\0' || (!file_get_trust_sender() && has_path_traversal(path))) {
    char* escaped_path = output_escape(path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid received directory-time path: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    free(path);
    return NULL;
  }
  File* file = file_create(path);
  free(path);
  if (!file)
    return NULL;
  file->is_dir = true;
  file->dir_time_only = true;
  if (config && config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(file_descriptor, &meta_ok);
    if (!meta_ok) {
      file_destroy(file);
      return NULL;
    }
  }
  /* Directory xattrs/ACLs (-X/-A) ride after the metadata, mirroring the
     sender's send_dir_times(). */
  if (config && !receive_file_xattrs(file, file_descriptor, config)) {
    file_destroy(file);
    return NULL;
  }
  return file;
}

/* Receive a --hard-links/-H sibling frame (the leading STATUS_HARDLINK code has
   already been consumed): the destination path, the run-local link-group id,
   and the first (data-carrying) member's destination-relative wire path.  The
   created File carries no payload; it is installed beneath the receive root as
   a hard link to (or, on link failure, a byte-identical copy of) the first
   member.  All paths are validated like every other received path (non-empty,
   relative, no traversal). */
File* file_receive_hardlink(int file_descriptor) {
  char* path = receive_wire_str(file_descriptor);
  if (path == NULL)
    return NULL;
  if (path[0] == '\0' || (!file_get_trust_sender() && has_path_traversal(path))) {
    char* escaped_path = output_escape(path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid received hard-link path: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    free(path);
    send_error_detail(file_descriptor, "invalid hard-link path");
    return NULL;
  }
  int gid;
  if (!receive_int(file_descriptor, &gid) || gid <= 0) {
    free(path);
    return NULL;
  }
  char* target = receive_wire_str(file_descriptor);
  if (!target) {
    free(path);
    return NULL;
  }
  if (target[0] == '\0' || (!file_get_trust_sender() && has_path_traversal(target))) {
    char* escaped = output_escape(target, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid hard-link target path: %s",
                escaped ? escaped : "<allocation failed>");
    free(escaped);
    free(target);
    free(path);
    send_error_detail(file_descriptor, "invalid hard-link target path");
    return NULL;
  }
  File* file = file_create(path);
  free(path);
  if (file == NULL) {
    free(target);
    return NULL;
  }
  file->link_group = gid;
  file->link_first = false;
  file->hardlink_target = target;
  return file;
}

/* Receive a symlink entry (the leading STATUS_SYMLINK code has already been
   consumed): the destination path and the (sender-munged, if --munge-links)
   symlink target string, then metadata when negotiated.  The created File is
   routed through the regular store_file sink, which creates the link beneath
   the receive root (unmungeing the target first). */
File* file_receive_symlink(int file_descriptor, const Config* config) {
  char* path = receive_wire_str(file_descriptor);
  if (path == NULL)
    return NULL;
  if (path[0] == '\0' || (!file_get_trust_sender() && has_path_traversal(path))) {
    char* escaped_path = output_escape(path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid received symlink path: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    free(path);
    send_error_detail(file_descriptor, "invalid symlink path");
    return NULL;
  }
  char* target = receive_wire_str(file_descriptor);
  if (!target) {
    free(path);
    return NULL;
  }
  if (target[0] == '\0') {
    char* escaped = output_escape(target, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid received symlink target: %s",
                escaped ? escaped : "<allocation failed>");
    free(escaped);
    free(target);
    free(path);
    send_error_detail(file_descriptor, "invalid symlink target");
    return NULL;
  }
  File* file = file_create(path);
  free(path);
  if (!file) {
    free(target);
    return NULL;
  }
  if (config && config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(file_descriptor, &meta_ok);
    if (!meta_ok) {
      file_destroy(file);
      free(target);
      return NULL;
    }
  }
  /* Symlink xattrs/ACLs (-X/-A) arrive in the same trailing block as the other
     entry kinds; the block is present iff use_xattrs (which itself implies
     use_metadata, so the metadata frame above is always consumed first). */
  if (config && !receive_file_xattrs(file, file_descriptor, config)) {
    file_destroy(file);
    free(target);
    return NULL;
  }
  file->is_symlink = true;
  file->symlink_target = target;
  return file;
}

/* Receive a device/special node frame (--devices/--specials): the leading
 * STATUS_SPECIAL code has already been consumed.  Payload: the destination path,
 * the metadata frame (whose mode's S_IFMT bits carry the node kind), and two
 * int32 rdev major/minor fields.  The created File carries no payload and is
 * recreated by file_save_to_disk_full (mknod/mkfifo, privilege-gated and
 * confined).  rdev is validated here (non-negative, range-checked) so a bogus
 * value cannot drive a dangerous node on the receiver. */
File* file_receive_special(int file_descriptor) {
  char* path = receive_wire_str(file_descriptor);
  if (path == NULL)
    return NULL;
  if (path[0] == '\0' || (!file_get_trust_sender() && has_path_traversal(path))) {
    char* escaped_path = output_escape(path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid received special path: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    free(path);
    send_error_detail(file_descriptor, "invalid special path");
    return NULL;
  }
  int meta_ok = 1;
  FileMetadata* metadata = metadata_receive(file_descriptor, &meta_ok);
  if (!meta_ok) {
    free(path);
    send_status(file_descriptor, STATUS_ERROR);
    return NULL;
  }
  int32_t major = 0;
  int32_t minor = 0;
  if (!receive_n_data(file_descriptor, &major, sizeof(major)) ||
      !receive_n_data(file_descriptor, &minor, sizeof(minor))) {
    free(path);
    file_metadata_destroy(metadata);
    send_status(file_descriptor, STATUS_ERROR);
    return NULL;
  }
  /* A node kind must be present; without metadata mode there is no S_IFMT to
     recreate from. */
  if (!metadata) {
    log_message(LOG_LEVEL_ERROR, "Special node sent without metadata (mode)");
    free(path);
    send_error_detail(file_descriptor, "special node sent without metadata");
    return NULL;
  }
  if (!file_special_rdev_valid(major, minor, metadata->mode)) {
    log_message(LOG_LEVEL_ERROR, "Invalid special rdev received (%d:%d)", (int)major, (int)minor);
    free(path);
    file_metadata_destroy(metadata);
    send_error_detail(file_descriptor, "invalid special device rdev");
    return NULL;
  }
  File* file = file_create(path);
  free(path);
  if (file == NULL) {
    file_metadata_destroy(metadata);
    return NULL;
  }
  file->metadata = metadata;
  file->is_special = true;
  file->rdev_major = major;
  file->rdev_minor = minor;
  return file;
}
