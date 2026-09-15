#include <errno.h>
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
#include "identity.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"
#include "xattr.h"

#define MAX_SERVER_DELETE_COUNT 100000U
#define MAX_FILE_DATA_SIZE MAX_RECEIVE_WHOLE_FILE_SIZE
/* Retained cost of one delete-manifest entry beyond its path bytes: the
   ArrayList pointer slot plus an approximate malloc header/rounding for the
   heap copy.  Charged against MAX_MANIFEST_BYTES so a frame full of tiny paths
   cannot retain far more than the byte budget (B5). */
#define MANIFEST_ENTRY_OVERHEAD (sizeof(char*) + 16)

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
  FileAttrPolicy policy = file_attr_policy_from_config(config);

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
                                  config->preallocate, metadata, policy, config->use_fsync, NULL);
  } else {
    ok =
        file_to_disk_secure_attrs(staged_path, file->data->data, file->data->size, false, sparse,
                                  config->preallocate, metadata, policy, false, false,
                                  config->use_fsync, file->xattrs, config->fake_super, false, NULL);
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

/* Read the whole content of a confined regular file (used to fall back to a
   byte-identical copy when a hard-link sibling's link() fails).  Symlink-safe
   (parent resolved via file_open_secure_parent + O_NOFOLLOW).  A zero-length
   file yields *out_size 0 and *out_buf NULL as a SUCCESS.  Returns false only
   on a real error/read failure, setting *source_absent to true when the reason
   was that the path does not exist (ENOENT/ENOTDIR), so the caller can decide
   between an abort and a graceful skip. */
static bool hardlink_read_source(const char* path, void** out_buf, unsigned long long* out_size,
                                 bool* source_absent) {
  *out_buf = NULL;
  *out_size = 0;
  *source_absent = false;
  if (!path)
    return false;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(path, &leaf, false);
  if (parent_fd < 0) {
    *source_absent = errno == ENOENT || errno == ENOTDIR;
    return false;
  }
  /* O_NONBLOCK is a no-op for a regular file but makes openat() fail/succeed
     immediately for a client-planted FIFO instead of blocking the receive
     thread forever; the post-open S_ISREG gate below is the actual type check. */
  int fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  int saved_errno = errno;
  free(leaf);
  close(parent_fd);
  if (fd < 0) {
    *source_absent = saved_errno == ENOENT || saved_errno == ENOTDIR;
    return false;
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return false;
  }
  unsigned long long size = (unsigned long long)st.st_size;
  if (size > MAX_RECEIVE_WHOLE_FILE_SIZE || size > SIZE_MAX) {
    close(fd);
    return false;
  }
  if (size == 0) {
    close(fd);
    return true;
  }
  void* buf = protocol_alloc((size_t)size);
  if (!buf) {
    close(fd);
    return false;
  }
  size_t got = 0;
  while (got < (size_t)size) {
    ssize_t n = read(fd, (char*)buf + got, (size_t)size - got);
    if (n <= 0) {
      free(buf);
      close(fd);
      return false;
    }
    got += (size_t)n;
  }
  close(fd);
  *out_buf = buf;
  *out_size = size;
  return true;
}

/* The group's first member's installed file is absent, but its destination
   path was validated (a sibling is only ever processed after its group's first
   member).  When the sibling's OWN destination already exists it should be
   left alone -- a clean skip -- rather than aborting the whole transfer (the
   asymmetric --existing case: the first member was skipped because its
   destination was missing, while the sibling already has one).  Only when the
   sibling's destination is missing too is this a genuine failure to
   link/copy, which aborts. */
static FileSaveResult hardlink_sibling_absent_first(const char* destination_path) {
  if (destination_path && file_path_exists_secure(destination_path))
    return FILE_SAVE_SKIPPED;
  return FILE_SAVE_ERROR;
}

/* Install a --hard-links/-H sibling: the destination entry is atomically
   replaced (temp + rename) with a hard link to the group's first member.  The
   first member is guaranteed already installed at `hardlink_target` under the
   root because -H relies on the receiver's single-FIFO-writer pipeline (one
   receive thread, one write thread, FIFO queue => wire order == write order)
   plus the sender's forced sequential scan, so a sibling is always processed
   after its group's first member.  When link() fails (different filesystem,
   filesystem refuses links) a byte-identical copy of the first member is
   written instead, so the result is never partial or corrupt.  With
   --delay-updates the sibling is staged as a hard link to the first member's
   STAGED file (publication's renames preserve the shared inode).  The final
   --existing/--ignore-existing/--update policies are decided against the final
   destination like every normal write. */
static FileSaveResult file_save_hardlink_sibling(const char* root_directory, const File* file,
                                                 const Config* config) {
  Config* cfg = (Config*)config;
  if (!root_directory || !file || !file->path || !file->hardlink_target)
    return FILE_SAVE_ERROR;
  char* destination_path = path_cat(root_directory, file->path);
  if (!destination_path)
    return FILE_SAVE_ERROR;

  if (cfg->existing && !file_path_exists_secure(destination_path)) {
    free(destination_path);
    return FILE_SAVE_SKIPPED;
  }
  if (cfg->ignore_existing && file_path_exists_secure(destination_path)) {
    free(destination_path);
    return FILE_SAVE_SKIPPED;
  }
  if (cfg->update && file_destination_is_newer_secure(destination_path, file->metadata)) {
    free(destination_path);
    return FILE_SAVE_SKIPPED;
  }

  bool preallocate = cfg && cfg->preallocate;
  FileAttrPolicy policy = file_attr_policy_from_config(cfg);
  bool use_fsync = cfg && cfg->use_fsync;

  if (cfg->delay_updates) {
    if (!cfg->delay_context) {
      cfg->delay_context = delay_updates_context_create(root_directory);
      if (!cfg->delay_context) {
        free(destination_path);
        return FILE_SAVE_ERROR;
      }
    }
    if (!delay_updates_prepare(cfg->delay_context)) {
      free(destination_path);
      return FILE_SAVE_ERROR;
    }
    char* staged_first = path_cat(cfg->delay_context->staging_root, file->hardlink_target);
    char* staged_sibling = path_cat(cfg->delay_context->staging_root, file->path);
    if (!staged_first || !staged_sibling) {
      free(staged_first);
      free(staged_sibling);
      free(destination_path);
      return FILE_SAVE_ERROR;
    }
    void* content = NULL;
    unsigned long long content_size = 0;
    bool source_absent = false;
    if (!hardlink_read_source(staged_first, &content, &content_size, &source_absent)) {
      FileSaveResult absent_result =
          source_absent ? hardlink_sibling_absent_first(destination_path) : FILE_SAVE_ERROR;
      free(staged_first);
      free(staged_sibling);
      free(destination_path);
      return absent_result;
    }
    FileXattrList* sibling_xattrs =
        cfg->use_xattrs ? xattr_capture_path(staged_first, cfg->preserve_acls) : NULL;
    bool ok = file_to_disk_secure_link_attrs(staged_sibling, staged_first, content, content_size,
                                             preallocate, file->metadata, policy, use_fsync,
                                             sibling_xattrs, cfg ? cfg->fake_super : false, NULL);
    xattr_list_free(sibling_xattrs);
    free(content);
    if (ok)
      ok = delay_updates_record(cfg->delay_context, staged_sibling, destination_path, file->path);
    if (!ok)
      unlink(staged_sibling);
    free(staged_first);
    free(staged_sibling);
    free(destination_path);
    return ok ? FILE_SAVE_WRITTEN : FILE_SAVE_ERROR;
  }

  char* first_disk = path_cat(root_directory, file->hardlink_target);
  if (!first_disk) {
    free(destination_path);
    return FILE_SAVE_ERROR;
  }
  void* content = NULL;
  unsigned long long content_size = 0;
  bool source_absent = false;
  if (!hardlink_read_source(first_disk, &content, &content_size, &source_absent)) {
    FileSaveResult absent_result =
        source_absent ? hardlink_sibling_absent_first(destination_path) : FILE_SAVE_ERROR;
    free(first_disk);
    free(destination_path);
    return absent_result;
  }
  /* Resolve a relative --temp-dir against the destination root, exactly as the
   * primary save path does; an absolute one is used verbatim. */
  char* resolved_temp = NULL;
  if (cfg->temp_dir) {
    resolved_temp =
        cfg->temp_dir[0] == '/' ? str_dup(cfg->temp_dir) : path_cat(root_directory, cfg->temp_dir);
    if (!resolved_temp) {
      free(content);
      free(first_disk);
      free(destination_path);
      return FILE_SAVE_ERROR;
    }
  }
  FileXattrList* sibling_xattrs =
      cfg->use_xattrs ? xattr_capture_path(first_disk, cfg->preserve_acls) : NULL;
  bool ok = file_to_disk_secure_link_attrs(
      destination_path, first_disk, content, content_size, preallocate, file->metadata, policy,
      use_fsync, sibling_xattrs, cfg ? cfg->fake_super : false, resolved_temp);
  xattr_list_free(sibling_xattrs);
  free(resolved_temp);
  free(content);
  free(first_disk);
  free(destination_path);
  return ok ? FILE_SAVE_WRITTEN : FILE_SAVE_ERROR;
}

/* Validate a transmitted special rdev against the node kind implied by `mode`'s
 * S_IFMT bits.  Char/block devices require a legal major/minor pair (non-negative,
 * range-checked); a non-device special (FIFO/socket) must carry an empty rdev.
 * Used identically on the wire path and at the secure recreation site so a
 * malicious/bogus rdev can never drive a dangerous node. */
bool file_special_rdev_valid(int32_t major, int32_t minor, mode_t mode) {
  bool is_device = S_ISCHR(mode) || S_ISBLK(mode);
  if (is_device)
    return major >= 0 && minor >= 0 && major <= 0xffff && minor <= 0x00ffffff;
  /* A non-device entry must actually be a special (FIFO/socket) and carry no
     rdev; a regular/dir mode is never a valid special node. */
  return (S_ISFIFO(mode) || S_ISSOCK(mode)) && major == 0 && minor == 0;
}

/* ---- Device/special node RECREATION (--devices/--specials), receiver side ----
 *
 * Privilege gating: making a real device node requires CAP_MKNOD (root); making
 * a FIFO works unprivileged (mkfifo).  When the receiver lacks the capability,
 * mknodat() fails with EPERM and the entry is SKIPPED with a warning -- the
 * whole transfer must NOT abort just because the environment cannot make the
 * node.  CI runs non-root, so device creation is expected to skip there and
 * only a FIFO is honestly assertable unprivileged.
 *
 * Confinement: the parent directory is opened fd-relative below the receive
 * root (file_open_secure_parent: O_NOFOLLOW, no "..", root-checked) and the
 * node is created with mknodat()/mkfifoat(), so it can never be placed outside
 * the confined root and never follows a symlink.
 *
 * rdev validation: a malicious/bogus rdev (negative, out-of-range) is rejected
 * here as well as on the wire (file_receive_special / chunk_deserialize), and a
 * non-device entry must carry an empty rdev.
 */
static FileSaveResult file_save_special_to_disk(const char* root_directory, const File* file,
                                                const Config* config) {
  /* The empty-path and structural checks stay unconditional; the redundant
     ".." list-path re-check is skipped under --trust-sender exactly like the
     receive layer (confinement is deferred to the secure parent walk below,
     which is never disabled). */
  if (!root_directory || !file || !file->path || file->path[0] == '\0' ||
      (!file_get_trust_sender() && has_path_traversal(file->path)) || !file->metadata)
    return FILE_SAVE_ERROR;

  mode_t mode = file->metadata->mode;
  bool is_char = S_ISCHR(mode);
  bool is_blk = S_ISBLK(mode);
  bool is_fifo = S_ISFIFO(mode);
  bool is_sock = S_ISSOCK(mode);
  if (!is_char && !is_blk && !is_fifo && !is_sock) {
    log_message(LOG_LEVEL_ERROR, "Special node has no device/FIFO/socket mode");
    return FILE_SAVE_ERROR;
  }
  if (is_char || is_blk) {
    if (!config || !config->preserve_devices)
      return FILE_SAVE_SKIPPED;
    /* --super / --no-super (P7 Wave E): char/block device-node creation is a
       super-user activity.  --no-super forbids it even for a root receiver;
       AUTO and --super attempt it (an unprivileged attempt is refused by the
       kernel and skipped).  The helper is evaluated against THIS config's mode
       so the policy does not depend on a prior identity_set_active().  Pure
       FIFO creation is unprivileged and deliberately NOT gated here. */
    if (!privilege_super_mode_permitted(config->super_mode)) {
      char* escaped_path = output_escape(file->path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING,
                  "skipping %s: super-user device-node creation is not permitted on this receiver",
                  escaped_path ? escaped_path : "<allocation failed>");
      free(escaped_path);
      return FILE_SAVE_SKIPPED;
    }
  } else if (is_fifo || is_sock) {
    /* FIFOs and unix sockets are recreated by --specials.  mknod(S_IFSOCK)
       works unprivileged on Linux (the node carries no live socket), so unlike
       a socket bound to a live fd it can be materialized. */
    if (!config || !config->preserve_specials)
      return FILE_SAVE_SKIPPED;
  }
  /* Defense-in-depth rdev/type validation (also done on the wire path). */
  if (!file_special_rdev_valid(file->rdev_major, file->rdev_minor, mode)) {
    log_message(LOG_LEVEL_ERROR, "Rejected out-of-range device rdev %d:%d", file->rdev_major,
                file->rdev_minor);
    return FILE_SAVE_ERROR;
  }

  char* destination = path_cat(root_directory, file->path);
  if (!destination)
    return FILE_SAVE_ERROR;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(destination, &leaf, true);
  if (parent_fd < 0) {
    free(destination);
    return FILE_SAVE_ERROR;
  }

  /* --existing / --ignore-existing / --update decide against the node that
     would be replaced, mirroring the regular-file path. */
  if (config->existing && !file_path_exists_secure(destination)) {
    close(parent_fd);
    free(leaf);
    free(destination);
    return FILE_SAVE_SKIPPED;
  }
  if (config->ignore_existing && file_path_exists_secure(destination)) {
    close(parent_fd);
    free(leaf);
    free(destination);
    return FILE_SAVE_SKIPPED;
  }
  if (config->update && file_destination_is_newer_secure(destination, file->metadata)) {
    close(parent_fd);
    free(leaf);
    free(destination);
    return FILE_SAVE_SKIPPED;
  }

  dev_t rdev = 0;
  mode_t create_mode;
  if (is_char) {
    create_mode = S_IFCHR;
    rdev = makedev((unsigned)file->rdev_major, (unsigned)file->rdev_minor);
  } else if (is_blk) {
    create_mode = S_IFBLK;
    rdev = makedev((unsigned)file->rdev_major, (unsigned)file->rdev_minor);
  } else if (is_sock) {
    create_mode = S_IFSOCK;
  } else {
    create_mode = S_IFIFO;
  }
  const char* node_kind = (is_char || is_blk) ? "device" : (is_fifo ? "FIFO" : "socket");
  /* The creation permission bits come from the source only under -p/--perms;
   * otherwise a safe default (0644, group/other write never granted) keeps an
   * unprivileged no--p run from materializing a world-writable node. */
  mode_t perms = config->preserve_perms ? (mode & 0777 & ~(S_IWGRP | S_IWOTH)) : 0644;

  int rc = is_fifo ? mkfifoat(parent_fd, leaf, perms)
                   : mknodat(parent_fd, leaf, create_mode | perms, rdev);
  if (rc != 0) {
    if (errno == EEXIST) {
      /* An entry already exists: only skip when it already is a matching node;
         never replace an existing directory or unrelated entry with the node. */
      struct stat st;
      if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
          ((is_char && S_ISCHR(st.st_mode)) || (is_blk && S_ISBLK(st.st_mode)) ||
           (is_fifo && S_ISFIFO(st.st_mode)) || (is_sock && S_ISSOCK(st.st_mode)))) {
        close(parent_fd);
        free(leaf);
        free(destination);
        return FILE_SAVE_SKIPPED;
      }
      char* escaped_path = output_escape(file->path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING, "refusing to replace existing entry with %s: %s (skipped)",
                  node_kind, escaped_path ? escaped_path : "<allocation failed>");
      free(escaped_path);
    } else if (errno == EPERM || errno == EACCES) {
      /* Missing CAP_MKNOD / parent write permission: the environment cannot
         create the node, so skip instead of failing the whole run. */
      char* escaped_path = output_escape(file->path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING,
                  "skipping %s: cannot create %s node (%s)\n"
                  "  --devices/--specials node creation needs privilege (CAP_MKNOD)",
                  escaped_path ? escaped_path : "<allocation failed>", node_kind, strerror(errno));
      free(escaped_path);
    } else {
      char* escaped_path = output_escape(file->path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING, "failed to create %s %s: %s (skipped)", node_kind,
                  escaped_path ? escaped_path : "<allocation failed>", strerror(errno));
      free(escaped_path);
    }
    close(parent_fd);
    free(leaf);
    free(destination);
    return FILE_SAVE_SKIPPED;
  }

  /* Apply times on the fresh node (utimensat, no-follow) per the negotiated
   * per-attribute policy: mtime only under -t, atime only under -U.  The slot
   * not requested stays UTIME_OMIT so it is left untouched. */
  FileAttrPolicy policy = file_attr_policy_from_config(config);
  if (policy.times || (policy.atimes && file->metadata->atime_valid)) {
    struct timespec times[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT},
                                {.tv_sec = 0, .tv_nsec = UTIME_OMIT}};
    if (policy.times) {
      times[1].tv_sec = file->metadata->mtime_sec;
      times[1].tv_nsec = file->metadata->mtime_nsec;
    }
    if (policy.atimes && file->metadata->atime_valid) {
      times[0].tv_sec = file->metadata->atime_sec;
      times[0].tv_nsec = file->metadata->atime_nsec;
    }
    utimensat(parent_fd, leaf, times, AT_SYMLINK_NOFOLLOW);
  }
  /* P7 Wave E: apply the negotiated ownership to the node ITSELF.  A FIFO is
     created unprivileged, but --copy-as and explicit identity policies own
     every entry (a char/block node path is already privilege-gated above).  The
     no-follow helper changes the node's own ownership without dereferencing it;
     it is a no-op unless an identity policy is active. */
  bool owner_ok = true;
  if (identity_active_enabled())
    owner_ok = identity_apply_ownership_link(parent_fd, leaf, (int32_t)file->metadata->uid,
                                             (int32_t)file->metadata->gid);
  close(parent_fd);
  free(leaf);
  free(destination);
  /* A failed required --copy-as ownership marks the node as failed; every other
   * identity policy stays best-effort. */
  return owner_ok ? FILE_SAVE_WRITTEN : FILE_SAVE_ERROR;
}

/* --write-devices (receiver): write the received data directly into an EXISTING
 * device node on the destination instead of creating a regular file.  The node
 * must already exist and be a char/block device (the device itself is opened and
 * followed); it is confined to the receive root via file_open_secure_parent.
 * Dangerous by nature, so deliberately restricted: a missing/non-device
 * destination, or a write failure, is SKIPPED with a warning rather than
 * allowed.  On environments without device access the run still succeeds (the
 * entry is skipped), never aborts. */
static FileSaveResult file_save_write_device(const char* root_directory, const File* file) {
  if (!root_directory || !file || !file->path || file->path[0] == '\0' ||
      (!file_get_trust_sender() && has_path_traversal(file->path)))
    return FILE_SAVE_ERROR;
  if (!file->data)
    return FILE_SAVE_ERROR;
  char* destination = path_cat(root_directory, file->path);
  if (!destination)
    return FILE_SAVE_ERROR;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(destination, &leaf, false);
  if (parent_fd < 0) {
    free(destination);
    return FILE_SAVE_SKIPPED;
  }
  /* O_NONBLOCK: a pre-existing FIFO at the target would otherwise block the
       receive thread forever on open(2).  With it the open only succeeds for a
       readerless FIFO with O_RDWR (which the device fstat gate rejects anyway)
       or fails with ENXIO/EAGAIN, both treated as a normal skip below. */
  int fd = openat(parent_fd, leaf, O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  int saved_errno = errno;
  free(leaf);
  close(parent_fd);
  if (fd < 0) {
    free(destination);
    char* escaped_path = output_escape(file->path, log_get_8_bit_output());
    const char* shown_path = escaped_path ? escaped_path : "<allocation failed>";
    if (saved_errno == ENXIO || saved_errno == EAGAIN) {
      /* A FIFO with no reader / an unreadable special: skip like every other
         unusable write-devices target instead of blocking or failing. */
      log_message(LOG_LEVEL_WARNING, "write-devices: %s not writable (%s); skipped", shown_path,
                  strerror(saved_errno));
    } else {
      log_message(LOG_LEVEL_WARNING, "write-devices: cannot open %s (%s); skipped", shown_path,
                  strerror(saved_errno));
    }
    free(escaped_path);
    return FILE_SAVE_SKIPPED;
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || !(S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))) {
    close(fd);
    free(destination);
    char* escaped_path = output_escape(file->path, log_get_8_bit_output());
    log_message(LOG_LEVEL_WARNING, "write-devices: %s is not a device node; skipped",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    return FILE_SAVE_SKIPPED;
  }
  bool ok = true;
  if (file->data->size > 0) {
    size_t total = (size_t)file->data->size;
    size_t written = 0;
    while (written < total) {
      ssize_t n = write(fd, (char*)file->data->data + written, total - written);
      if (n <= 0) {
        ok = false;
        break;
      }
      written += (size_t)n;
    }
  }
  close(fd);
  free(destination);
  return ok ? FILE_SAVE_WRITTEN : FILE_SAVE_SKIPPED;
}

FileSaveResult file_save_to_disk_full(const char* root_directory, const File* file,
                                      const Config* config) {
  /* Central no-mutation guard: a server-contacting --dry-run (or a local batch
     apply that somehow carries dry_run) must never touch the destination, no
     matter which caller reached this primitive.  The per-caller guards remain,
     but this is the last line of defense for every save path.  Report SKIPPED
     so a --remove-source-files sender correctly keeps its source. */
  if (config && config->dry_run)
    return FILE_SAVE_SKIPPED;
  /* Backups are incompatible with ignore-existing: moving the entry first
     would make a concurrent no-replace commit overwrite its old name. */
  bool backup_enabled = config && config->backup && !config->ignore_existing;
  bool inplace = config && config->inplace;
  bool sparse = config && config->preserve_sparse;
  FileAttrPolicy policy = file_attr_policy_from_config(config);
  const char* backup_suffix = (config && config->suffix) ? config->suffix : "~";
  const char* backup_dir = (config && config->backup_dir) ? config->backup_dir : NULL;
  const char* partial_dir = (config && config->partial_dir) ? config->partial_dir : NULL;
  const char* temp_dir = (config && config->temp_dir) ? config->temp_dir : NULL;
  bool use_partial_root = partial_dir && config && config->partial;
  char *confined_backup = NULL, *confined_partial = NULL, *disk_path = NULL;
  char* destination_path = NULL;
  char *backup_path = NULL, *parent_copy = NULL;

  if (!file || !file->path || !file->data || (file->data->size != 0 && !file->data->data) ||
      (!file_get_trust_sender() && has_path_traversal(file->path)) ||
      (backup_enabled &&
       (!backup_suffix || backup_suffix[0] == '\0' || strchr(backup_suffix, '/') != NULL ||
        strcmp(backup_suffix, ".") == 0 || strcmp(backup_suffix, "..") == 0))) {
    log_message(LOG_LEVEL_ERROR, "Invalid file or path received");
    return FILE_SAVE_ERROR;
  }

  /* P7 Wave D #1: a STATUS_DIR_TIMES entry is RECORD-ONLY.  The scanner
     captures every traversed directory -- including empty ones whose parents
     were never created by a child write and directories pruned by
     -m/--prune-empty-dirs.  Creating them here would resurrect empty
     directories (an -a behavior change) and could abort the whole transfer on a
     pre-existing regular file/symlink at the mirror path.  Short-circuit before
     any device/write-devices/directory branch and report it as skipped so the
     sink still accumulates its metadata for the deferred DirTimeList
     application, but create nothing. */
  if (file->dir_time_only)
    return FILE_SAVE_SKIPPED;

  /* Device/special node (--devices/--specials): recreate the node instead of
     writing content (privilege-gated, confined, rdev-validated). */
  if (file->is_special)
    return file_save_special_to_disk(root_directory, file, config);
  /* --write-devices: write straight into an existing device node.  Writing
     into a device is a super-user activity, so --no-super must suppress it just
     like device-node creation; the default AUTO/--super attempt it (the wide
     open below keeps its own confinement and best-effort skip semantics). */
  if (config && config->write_devices) {
    if (!privilege_super_mode_permitted(config->super_mode)) {
      char* escaped_path = output_escape(file->path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING,
                  "write-devices: %s skipped: super-user activities are not permitted on this "
                  "receiver",
                  escaped_path ? escaped_path : "(null)");
      free(escaped_path);
      return FILE_SAVE_SKIPPED;
    }
    return file_save_write_device(root_directory, file);
  }

  /* Explicit directory entries (--dirs) carry an empty payload; the entry is
     created as a directory under the receive root, applying the same secure
     mkdir-parent semantics as regular writes.  Directories are created
     immediately (they are never staged by --delay-updates, matching rsync,
     where directory creation is not delayed). */
  if (file->is_dir) {
    if (file->path[0] == '\0' || (!file_get_trust_sender() && has_path_traversal(file->path))) {
      log_message(LOG_LEVEL_ERROR, "Invalid directory path received");
      return FILE_SAVE_ERROR;
    }
    char* dir_path = path_cat(root_directory, file->path);
    if (!dir_path)
      return FILE_SAVE_ERROR;
    bool ok = file_ensure_directory_secure(dir_path);
    /* P7 Wave E: apply the negotiated ownership to the directory ITSELF (not
       just the files inside it).  --copy-as and every explicit identity policy
       own every entry, so a directory must not keep the receiver's owner while
       its children get the policy owner.  Applied no-follow on the confined
       parent fd after the mkdir; identity_apply_ownership_link() is itself a
       no-op unless an identity policy is active. */
    if (ok && file->metadata && identity_active_enabled()) {
      char* leaf = NULL;
      int parent_fd = file_open_secure_parent(dir_path, &leaf, false);
      if (parent_fd >= 0) {
        if (!identity_apply_ownership_link(parent_fd, leaf, (int32_t)file->metadata->uid,
                                           (int32_t)file->metadata->gid))
          ok = false;
        close(parent_fd);
      } else if (identity_copy_as_active()) {
        /* The directory exists (ok) but its required --copy-as ownership could
           not be applied because the confined parent could not be opened. */
        ok = false;
      }
      free(leaf);
    }
    free(dir_path);
    return ok ? FILE_SAVE_WRITTEN : FILE_SAVE_ERROR;
  }

  /* Symlink entry.  (The process-wide --keep-dirlinks policy is set once by the
     connection handler from the negotiated config, before any receiver/writer
     threads start, so it is stable throughout this walk.) */

  if (file->is_symlink) {
    if (!file->symlink_target || file->path[0] == '\0' ||
        (!file_get_trust_sender() && has_path_traversal(file->path))) {
      log_message(LOG_LEVEL_ERROR, "Invalid symlink entry received");
      return FILE_SAVE_ERROR;
    }
    char* link_path = path_cat(root_directory, file->path);
    if (!link_path)
      return FILE_SAVE_ERROR;
    /* The link value is stored verbatim (rsync -l parity: absolute and
       ".."-bearing targets are preserved; the scanner's --safe-links /
       --copy-unsafe-links decide which links are sent at all).  --munge-links
       is a RECEIVER-side rewrite: the stored target is prefixed with
       /rsyncd-munged/, making the link unusable while the referenced directory
       does not exist -- exactly as rsync's receiver munges.  Only the link's
       own placement path is confined below the receive root. */
    bool munge = config && config->munge_links;
    char* target = str_dup(file->symlink_target);
    bool ok = target != NULL;
    if (ok && munge) {
      char* munged = file_symlink_munge(target);
      free(target);
      target = munged;
      ok = target != NULL;
    }
    if (!ok) {
      free(target);
      free(link_path);
      return FILE_SAVE_SKIPPED;
    }
    char* parent = str_dup(link_path);
    if (parent) {
      /* Propagate a failed --copy-as ownership of the parent directory this
         creates; every other failure mode stays best-effort as before. */
      ok = file_ensure_directory_secure(dirname(parent));
      free(parent);
    }
    if (ok)
      ok = file_symlink_at_secure(link_path, target);
    free(target);
    /* P7 Wave D: apply the symlink's own metadata with no-follow primitives
       (utimensat/lchown/fchmodat AT_SYMLINK_NOFOLLOW).  -J/--omit-link-times
       suppresses the timestamps; ownership stays gated by the identity policy.
       A symlink has no children, so this can be applied immediately. */
    if (ok && config && config->use_metadata) {
      FileAttrPolicy link_policy = file_attr_policy_from_config(config);
      ok = file_restore_symlink_metadata(link_path, file->metadata, link_policy,
                                         config->omit_link_times);
    }
    free(link_path);
    return ok ? FILE_SAVE_WRITTEN : FILE_SAVE_ERROR;
  }

  /* --hard-links/-H sibling: a later member of a link group arrives with no
     payload and is installed as a hard link to (or, on link() failure, a
     byte-identical copy of) the group's first member.  Handled entirely here,
     before the normal data-write paths (which would create an empty file). */
  if (file->link_group != 0 && !file->link_first && file->hardlink_target != NULL) {
    return file_save_hardlink_sibling(root_directory, file, config);
  }

  /* These options arrive from the client.  --backup-dir and --partial-dir are
     names below the server root, never independent filesystem roots: an
     absolute or `..`-escaping value is rejected outright.  --temp-dir is
     deliberately NOT confined: rsync accepts any temp dir (absolute, or
     relative to the destination root), including one outside the destination
     tree or on another filesystem, and falls back to a non-atomic copy when
     the install rename hits EXDEV. */
  if ((backup_dir && (backup_dir[0] == '/' || has_path_traversal(backup_dir))) ||
      (partial_dir && (partial_dir[0] == '/' || has_path_traversal(partial_dir))))
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
     directory; the engine then atomically renames the completed file into the
     final destination directory.  rsync resolves a relative temp dir against
     the destination directory and uses an absolute one verbatim, requiring
     that it already exist; the engine falls back to a non-atomic copy on
     EXDEV.  The partial-dir flow already keeps its working copy in a separate
     directory and --inplace writes directly, so neither diverts through the
     scratch dir (matching rsync, where --inplace/--partial-dir supersede
     --temp-dir). */
  char* confined_temp = NULL;
  bool use_temp_dir = temp_dir != NULL && !inplace && !use_partial_root;
  if (use_temp_dir) {
    if (temp_dir[0] == '/')
      confined_temp = str_dup(temp_dir);
    else
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
    ok = file_to_disk_secure_link_attrs(
        disk_path, file->basis_link, file->data->data, file->data->size, config->preallocate,
        metadata, policy, config->use_fsync, file->xattrs, config->fake_super, confined_temp);
  } else {
    /* The plain no-replace / update / with-fsync engines, plus per-file xattr
       (-X/-A) and --fake-super application on the written fd. */
    ok = file_to_disk_secure_attrs(
        disk_path, file->data->data, file->data->size, inplace, sparse,
        config && config->preallocate, metadata, policy, config && config->update,
        config && config->ignore_existing, config && config->use_fsync, file->xattrs,
        config ? config->fake_super : false, config ? config->partial : false, confined_temp);
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

/* Receive a file's xattr block (when the config enables xattr transport) and
 * attach it to `file`.  Returns false on a malformed/oversized frame. */
static bool receive_file_xattrs(File* file, int fd, const Config* config) {
  if (!config->use_xattrs)
    return true;
  int xok = 0;
  FileXattrList* list = xattr_receive(fd, &xok, config->preserve_acls);
  if (!xok) {
    xattr_list_free(list);
    return false;
  }
  file->xattrs = list;
  return true;
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
      ProtocolSession* owner = delta_data->owner;
      raw_delta = data_decompress_limited(delta_data, MAX_RECEIVE_WHOLE_FILE_SIZE);
      data_destroy(delta_data);
      if (!raw_delta) {
        free(old_data);
        delta_signature_destroy(sig);
        *failed = true;
        return NULL;
      }
      /* Charge the decompressed delta to the connection budget (the paired
         wire buffer's charge was just released). */
      if (!data_charge_session(raw_delta, owner, raw_delta->size)) {
        data_destroy(raw_delta);
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
    if (!receive_file_xattrs(file, fd, config)) {
      file_destroy(file);
      free(new_data);
      free(old_data);
      delta_signature_destroy(sig);
      *failed = true;
      return NULL;
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
    if (!receive_file_xattrs(file, fd, config)) {
      file_destroy(file);
      *failed = true;
      return NULL;
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
      ProtocolSession* owner = file_data->owner;
      data_destroy(file_data);
      if (uncompressed == NULL) {
        file_destroy(file);
        *failed = true;
        return NULL;
      }
      if (!data_charge_session(uncompressed, owner, uncompressed->size)) {
        data_destroy(uncompressed);
        file_destroy(file);
        send_status(fd, STATUS_ERROR);
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
  /* O_NONBLOCK: a client-planted FIFO must not block the receiver's openat()
     forever; the fstat()/S_ISREG gate below rejects it immediately. */
  int fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
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
   so the caller can materialize the file without re-reading it.

   An exact match ALSO requires the basis bytes' digest to equal the source's,
   so `hash_content` gates the content read/hash itself.  A server-contacting
   --dry-run passes hash_content=false: no basis file may be read or hashed
   (that would be a 1-bit content oracle against a client-supplied digest), so a
   metadata-only pass can never confirm a hit and declines it.  The real path
   always passes hash_content=true, keeping its behavior byte-for-byte. */
static bool basis_match_find(const Config* config, const char* check_path,
                             unsigned long long check_size, time_t check_mtime,
                             long check_mtime_nsec, const uint8_t* check_digest,
                             size_t check_digest_len, bool load_content, bool hash_content,
                             BasisMatch* out) {
  memset(out, 0, sizeof(*out));
  if (!config || !config_has_basis(config) || config->ignore_times)
    return false;
  /* Dry-run: never read/hash basis content.  A hit cannot be decided from
     metadata alone, so report no match (the caller treats it as would-transfer)
     without touching the file's contents. */
  if (!hash_content)
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

/* Read the remainder of a full-file transfer after the receiver has already
 * sent STATUS_NEXT: receive the metadata frame (when enabled) followed by the
 * data frame, and return an owned File.  Shared by the plain full-transfer path
 * and the --append-verify prefix-mismatch fallback (a clean full transfer
 * instead of a corrupt prefix+tail blend). */
static File* receive_full_file(int fd, const Config* config, const char* path) {
  File* file = file_create(path);
  if (!file)
    return NULL;
  if (config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(fd, &meta_ok);
    if (!meta_ok) {
      file_destroy(file);
      return NULL;
    }
  }
  if (!receive_file_xattrs(file, fd, config)) {
    file_destroy(file);
    return NULL;
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
    ProtocolSession* owner = file_data->owner;
    data_destroy(file_data);
    if (uncompressed == NULL) {
      file_destroy(file);
      return NULL;
    }
    if (!data_charge_session(uncompressed, owner, uncompressed->size)) {
      data_destroy(uncompressed);
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

/* ---------------------------------------------------------------------------
 * receive_incremental_check() decomposition.
 *
 * The per-file STATUS_CHECK fast path is split into the small helpers below,
 * called in order by a short linear orchestrator (receive_incremental_check_ex).
 * Each helper owns one decision: request validation, secure destination open,
 * metadata-only skip, server-contacting --dry-run no-mutation short-circuit,
 * alternate-basis match, --append tail resume, block delta, --fuzzy basis, and
 * the final "send the whole file" fallback.  Every protocol send/receive and
 * every resource cleanup is preserved exactly; the non-dry-run wire is
 * byte-for-byte unchanged.  receive_incremental_check_ex additionally exposes a
 * `would_transfer` out-param for the dry-run caller; the 3-arg
 * receive_incremental_check wrapper passes NULL.
 * ------------------------------------------------------------------------- */

/* Owned state threaded through the helpers below. */
typedef struct {
  int fd;
  const Config* config;
  char* check_path; /* received destination-relative path */
  char* full_path;  /* receive-root-prefixed destination path */
  unsigned long long check_size;
  long long check_mtime;
  long long check_mtime_nsec;
  uint8_t check_digest[CHECKSUM_MAX_DIGEST_LEN];
  size_t check_digest_len;
  bool has_old_file;
  int old_fd;
  struct stat old_st;
  unsigned long long old_size;
  void* old_data; /* snapshot of the existing destination, or NULL */
} IncrementalCheckState;

typedef enum {
  INCREMENTAL_CONTINUE, /* proceed to the next helper */
  INCREMENTAL_ERROR,    /* protocol/validation failure: return NULL */
  INCREMENTAL_SKIP,     /* up to date: *skipped = true, return NULL */
  INCREMENTAL_DRY_RUN,  /* --dry-run resolved: flags set, return NULL */
  INCREMENTAL_FILE,     /* a File* was produced (out_file) */
} IncrementalCheckOutcome;

static void incremental_check_state_init(IncrementalCheckState* state, int fd,
                                         const Config* config) {
  memset(state, 0, sizeof(*state));
  state->fd = fd;
  state->config = config;
  state->old_fd = -1;
}

/* Release every resource the helpers may have acquired.  Idempotent, so it is
   safe on every exit path exactly the way the original inline cleanup was. */
static void incremental_check_state_cleanup(IncrementalCheckState* state) {
  free(state->old_data);
  state->old_data = NULL;
  if (state->old_fd >= 0)
    close(state->old_fd);
  state->old_fd = -1;
  free(state->full_path);
  state->full_path = NULL;
  free(state->check_path);
  state->check_path = NULL;
}

/* Receive and validate the STATUS_CHECK request frame: path, size, mtime,
   nanosecond mtime, and (when negotiated) the source digest. */
static IncrementalCheckOutcome incremental_check_receive_request(IncrementalCheckState* state) {
  int fd = state->fd;
  const Config* config = state->config;
  char* check_path = receive_wire_str(fd);
  if (check_path == NULL)
    return INCREMENTAL_ERROR;
  state->check_path = check_path;

  if (!receive_n_data(fd, &state->check_size, sizeof(state->check_size)) ||
      !receive_n_data(fd, &state->check_mtime, sizeof(state->check_mtime)))
    return INCREMENTAL_ERROR;
  if (!receive_n_data(fd, &state->check_mtime_nsec, sizeof(state->check_mtime_nsec)) ||
      state->check_mtime_nsec < 0 || state->check_mtime_nsec >= 1000000000LL) {
    send_error_detail(fd, "invalid check mtime nanoseconds");
    return INCREMENTAL_ERROR;
  }
  if ((config->checksum || config_has_basis(config))) {
    uint8_t wire_len;
    if (!receive_n_data(fd, &wire_len, sizeof(wire_len)) || wire_len == 0 ||
        wire_len > CHECKSUM_MAX_DIGEST_LEN ||
        wire_len != checksum_digest_len((ChecksumAlgo)config->checksum_algo)) {
      send_error_detail(fd, "invalid check digest length");
      return INCREMENTAL_ERROR;
    }
    state->check_digest_len = wire_len;
    if (!receive_n_data(fd, state->check_digest, state->check_digest_len))
      return INCREMENTAL_ERROR;
  }

  if (state->check_size > MAX_RECEIVE_WHOLE_FILE_SIZE) {
    send_error_detail(fd, "check size exceeds receiver limit");
    return INCREMENTAL_ERROR;
  }

  if (check_path[0] == '\0' || has_path_traversal(check_path)) {
    char* escaped_path = output_escape(check_path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid received check path: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    return INCREMENTAL_ERROR;
  }
  return INCREMENTAL_CONTINUE;
}

/* Open the existing destination entry once, confined below the receive root,
   and record its stat. */
static IncrementalCheckOutcome incremental_check_open_destination(IncrementalCheckState* state) {
  char* full_path = path_cat(state->config->receive_root_directory, state->check_path);
  if (!full_path) {
    send_error_detail(state->fd, "could not build destination path");
    return INCREMENTAL_ERROR;
  }
  state->full_path = full_path;

  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(full_path, &leaf, false);
  if (parent_fd >= 0) {
    /* O_NONBLOCK: an existing FIFO at the destination must not block this
       openat(); the S_ISREG gate below rejects the non-regular entry. */
    state->old_fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    free(leaf);
    close(parent_fd);
    state->has_old_file = state->old_fd >= 0 && fstat(state->old_fd, &state->old_st) == 0 &&
                          S_ISREG(state->old_st.st_mode);
  }
  if (!state->has_old_file && state->old_fd >= 0) {
    close(state->old_fd);
    state->old_fd = -1;
  }
  state->old_size = state->has_old_file ? (unsigned long long)state->old_st.st_size : 0;
  return INCREMENTAL_CONTINUE;
}

/* Metadata-only (and, when --checksum forces it, content) up-to-date decision.
   Loads the old contents only when a checksum comparison or delta needs them. */
static IncrementalCheckOutcome incremental_check_quick_skip(IncrementalCheckState* state,
                                                            bool* out_try_delta) {
  int fd = state->fd;
  const Config* config = state->config;
  bool has_old_file = state->has_old_file;
  unsigned long long old_size = state->old_size;
  struct stat st = state->old_st;

  bool size_equal = has_old_file && old_size == state->check_size;
  bool match_by_metadata = false;
  if (size_equal && !config->ignore_times && !config->size_only) {
    long long old_mtime_nsec = 0;
#ifdef __linux__
    old_mtime_nsec = st.st_mtim.tv_nsec;
#endif
    match_by_metadata =
        metadata_mtime_matches(st.st_mtime, old_mtime_nsec, (time_t)state->check_mtime,
                               (long)state->check_mtime_nsec, config->modify_window);
  }

  bool try_delta = config->use_delta && !config->whole_file && has_old_file &&
                   delta_should_attempt(old_size, state->check_size, config->delta_max_file_size);
  bool checksum_needs_read = size_equal && !config->ignore_times && config->checksum;
  /* --dry-run must never read the destination file's CONTENTS: a client could
     otherwise use `--dry-run --checksum` against a read-only module as a
     1-bit content oracle (hash match / mismatch) and force arbitrary reads.
     Decide from metadata alone; when metadata is inconclusive (checksum or
     delta would have required the body) report would-transfer.  The real
     (non-dry-run) behavior below is unchanged. */
  bool need_old_data = !config->dry_run && (checksum_needs_read || try_delta);
  if (config->dry_run)
    try_delta = false;
  *out_try_delta = try_delta;

  if (need_old_data && has_old_file && old_size > 0 && old_size <= MAX_RECEIVE_WHOLE_FILE_SIZE &&
      old_size <= SIZE_MAX) {
    state->old_data = protocol_alloc((size_t)old_size);
    if (state->old_data) {
      size_t got = 0;
      while (got < (size_t)old_size) {
        ssize_t n = read(state->old_fd, (char*)state->old_data + got, (size_t)old_size - got);
        if (n <= 0) {
          free(state->old_data);
          state->old_data = NULL;
          break;
        }
        got += (size_t)n;
      }
    }
  }

  bool match = false;
  if (config->dry_run) {
    /* Metadata-only decision: a size match plus a matching mtime is treated as
       up to date; --checksum/--delta cannot be verified without reading, so an
       otherwise inconclusive comparison is a would-transfer. */
    match = size_equal && !config->ignore_times && (config->size_only || match_by_metadata);
  } else if (checksum_needs_read) {
    uint8_t old_digest[CHECKSUM_MAX_DIGEST_LEN];
    size_t old_len = 0;
    bool hashed = checksum_digest((ChecksumAlgo)config->checksum_algo, config->checksum_seed,
                                  old_size == 0 ? "" : state->old_data, (size_t)old_size,
                                  old_digest, sizeof(old_digest), &old_len);
    match = hashed && old_len == state->check_digest_len && state->check_digest_len > 0 &&
            memcmp(old_digest, state->check_digest, state->check_digest_len) == 0;
  } else if (size_equal && !config->ignore_times) {
    match = config->size_only || match_by_metadata;
  }

  if (match) {
    if (!send_status(fd, STATUS_OK))
      return INCREMENTAL_ERROR;
    return INCREMENTAL_SKIP;
  }
  return INCREMENTAL_CONTINUE;
}

/* Server-contacting --dry-run no-mutation short-circuit.  Runs after the
   quick-skip decision and before any path that could touch the destination.
   When dry_run is set and the file is not already up to date the receiver must
   materialize nothing (no basis link/copy, no append/delta/full transfer) and
   the sender must send no data, so answer STATUS_DRY_RUN_TRANSFER and stop.

   The basis lookup is deliberately content-blind: a real run would only accept
   a --compare-dest exact hit after hashing the basis file and comparing it with
   the client-supplied digest, which in a dry-run is a 1-bit content oracle.
   Under dry_run no basis bytes may be read, so an otherwise-matching entry is
   treated as would-transfer instead of a skip.  Everything read here (the
   destination file's metadata, basis candidates' metadata) is read-only. */
static IncrementalCheckOutcome incremental_check_dry_run_shortcut(IncrementalCheckState* state,
                                                                  bool* skipped,
                                                                  bool* would_transfer) {
  const Config* config = state->config;
  if (!config->dry_run)
    return INCREMENTAL_CONTINUE;

  bool skip_via_compare = false;
  if (config_has_basis(config) && !config->ignore_times) {
    BasisMatch basis;
    /* hash_content=false: a dry-run must not read or hash the basis file.  No
       content comparison is possible, so no compare-dest hit can be confirmed
       and an otherwise-matching file is reported as would-transfer. */
    basis_match_find(config, state->check_path, state->check_size, (time_t)state->check_mtime,
                     (long)state->check_mtime_nsec, state->check_digest, state->check_digest_len,
                     false, false, &basis);
    if (basis.hit && basis.type == BASIS_DEST_COMPARE && !state->has_old_file)
      skip_via_compare = true;
    basis_match_free(&basis);
  }
  Status reply = skip_via_compare ? STATUS_OK : STATUS_DRY_RUN_TRANSFER;
  if (!send_status(state->fd, reply))
    return INCREMENTAL_ERROR;
  if (skip_via_compare)
    *skipped = true;
  else if (would_transfer)
    *would_transfer = true;
  return INCREMENTAL_DRY_RUN;
}

/* Alternate basis directories (--compare-dest/--copy-dest/--link-dest): a hit
   either suppresses the transfer (compare-dest) or materializes the file from
   the basis without a data frame. */
static IncrementalCheckOutcome incremental_check_try_basis(IncrementalCheckState* state,
                                                           File** out_file) {
  int fd = state->fd;
  const Config* config = state->config;
  if (!config_has_basis(config))
    return INCREMENTAL_CONTINUE;

  BasisMatch basis;
  basis_match_find(config, state->check_path, state->check_size, (time_t)state->check_mtime,
                   (long)state->check_mtime_nsec, state->check_digest, state->check_digest_len,
                   true, true, &basis);
  if (basis.hit) {
    if (basis.type == BASIS_DEST_COMPARE) {
      basis_match_free(&basis);
      if (!state->has_old_file) {
        if (!send_status(fd, STATUS_OK))
          return INCREMENTAL_ERROR;
        return INCREMENTAL_SKIP;
      }
    } else {
      File* materialized = file_create(state->check_path);
      if (materialized && basis.content) {
        data_destroy(materialized->data);
        materialized->data = basis.content;
        basis.content = NULL;
        materialized->metadata = file_metadata_create(NULL, &basis.st, false, false);
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
          return INCREMENTAL_ERROR;
        }
        basis_match_free(&basis);
        *out_file = materialized;
        return INCREMENTAL_FILE;
      }
      /* Materialization setup failed: fall through to the normal transfer. */
    }
  }
  basis_match_free(&basis);
  return INCREMENTAL_CONTINUE;
}

/* --append / --append-verify tail resume: when the destination is a SHORTER
   file in an append mode, negotiate the resume offset and receive only the
   tail.  Produces the reconstructed file, or falls through to delta/full. */
static IncrementalCheckOutcome incremental_check_try_append_resume(IncrementalCheckState* state,
                                                                   File** out_file) {
  int fd = state->fd;
  const Config* config = state->config;
  const char* check_path = state->check_path;
  unsigned long long old_size = state->old_size;
  unsigned long long check_size = state->check_size;

  bool append_resume = (config->append || config->append_verify) && state->has_old_file &&
                       append_resume_eligible(old_size, check_size);
  if (!append_resume)
    return INCREMENTAL_CONTINUE;

  /* Ensure the retained prefix (== the whole, shorter destination file) is in
     memory; it is needed both to rebuild the full file and, for
     --append-verify, to checksum it.  A load failure is not fatal: the resume is
     simply not possible and we fall through to the other paths. */
  if (state->old_data == NULL && old_size > 0 && old_size <= MAX_RECEIVE_WHOLE_FILE_SIZE &&
      old_size <= SIZE_MAX) {
    state->old_data = protocol_alloc((size_t)old_size);
    if (state->old_data) {
      size_t got = 0;
      while (got < (size_t)old_size) {
        ssize_t n = read(state->old_fd, (char*)state->old_data + got, (size_t)old_size - got);
        if (n <= 0) {
          free(state->old_data);
          state->old_data = NULL;
          break;
        }
        got += (size_t)n;
      }
    }
  }
  if (state->old_data == NULL && old_size != 0)
    return INCREMENTAL_CONTINUE;

  if (!send_status(fd, STATUS_APPEND) || !send_n_data(fd, &old_size, sizeof(old_size)))
    return INCREMENTAL_ERROR;
  bool verify = config->append_verify;
  bool full_fallback = false;
  if (verify) {
    Status sig_status;
    if (!receive_status(fd, &sig_status))
      return INCREMENTAL_ERROR;
    if (sig_status != STATUS_APPEND_SIG) {
      send_status(fd, STATUS_ERROR);
      return INCREMENTAL_ERROR;
    }
    uint64_t src_prefix_hash;
    if (!receive_n_data(fd, &src_prefix_hash, sizeof(src_prefix_hash)))
      return INCREMENTAL_ERROR;
    /* Compare the retained prefix against the source prefix.  A mismatch must
       never be silently appended to: fall back to a full transfer so the result
       is a byte-identical source copy. */
    uint64_t dst_prefix_hash =
        old_size == 0 ? delta_xxhash64("", 0) : delta_xxhash64(state->old_data, (size_t)old_size);
    if (dst_prefix_hash == src_prefix_hash) {
      if (!send_status(fd, STATUS_APPEND_OK))
        return INCREMENTAL_ERROR;
    } else {
      if (!send_status(fd, STATUS_NEXT))
        return INCREMENTAL_ERROR;
      full_fallback = true;
    }
  }

  if (full_fallback) {
    /* Retained prefix differed: receive the sender's full transfer. */
    free(state->old_data);
    state->old_data = NULL;
    if (state->old_fd >= 0) {
      close(state->old_fd);
      state->old_fd = -1;
    }
    *out_file = receive_full_file(fd, config, check_path);
    return INCREMENTAL_FILE;
  }

  /* Receive the tail (STATUS_APPEND_DATA + metadata + tail bytes). */
  Status tail_status;
  if (!receive_status(fd, &tail_status))
    return INCREMENTAL_ERROR;
  if (tail_status != STATUS_APPEND_DATA) {
    send_status(fd, STATUS_ERROR);
    return INCREMENTAL_ERROR;
  }
  FileMetadata* meta = NULL;
  FileXattrList* append_xattrs = NULL;
  if (config->use_metadata) {
    int meta_ok = 1;
    meta = metadata_receive(fd, &meta_ok);
    if (!meta_ok)
      return INCREMENTAL_ERROR;
  }
  if (config->use_xattrs) {
    int xok = 0;
    append_xattrs = xattr_receive(fd, &xok, config->preserve_acls);
    if (!xok) {
      xattr_list_free(append_xattrs);
      return INCREMENTAL_ERROR;
    }
  }
  Data* tail = receive_data_limited(fd, MAX_RECEIVE_WHOLE_FILE_SIZE);
  if (tail == NULL) {
    xattr_list_free(append_xattrs);
    return INCREMENTAL_ERROR;
  }
  if (config->use_compression &&
      !compression_should_skip_with_suffixes(check_path, config->skip_compress_suffixes,
                                             config->skip_compress_set ? config->skip_compress_count
                                                                       : -1)) {
    Data* uncompressed = data_decompress_limited(tail, MAX_RECEIVE_WHOLE_FILE_SIZE);
    ProtocolSession* owner = tail->owner;
    data_destroy(tail);
    if (uncompressed == NULL) {
      xattr_list_free(append_xattrs);
      return INCREMENTAL_ERROR;
    }
    if (!data_charge_session(uncompressed, owner, uncompressed->size)) {
      data_destroy(uncompressed);
      xattr_list_free(append_xattrs);
      return INCREMENTAL_ERROR;
    }
    if (uncompressed->size > MAX_FILE_DATA_SIZE) {
      data_destroy(uncompressed);
      xattr_list_free(append_xattrs);
      return INCREMENTAL_ERROR;
    }
    tail = uncompressed;
  }
  /* The tail must complete the file exactly; anything else is a protocol
     violation (never a truncated or overrun file). */
  unsigned long long expected_tail;
  if (!append_tail_length(old_size, check_size, &expected_tail) ||
      tail->size != (size_t)expected_tail) {
    send_status(fd, STATUS_ERROR);
    data_destroy(tail);
    xattr_list_free(append_xattrs);
    return INCREMENTAL_ERROR;
  }
  size_t full_size = (size_t)check_size;
  void* full = protocol_alloc(full_size ? full_size : 1);
  if (!full) {
    data_destroy(tail);
    xattr_list_free(append_xattrs);
    return INCREMENTAL_ERROR;
  }
  if (old_size > 0 && state->old_data)
    memcpy(full, state->old_data, (size_t)old_size);
  if (tail->size > 0)
    memcpy((char*)full + old_size, tail->data, tail->size);
  data_destroy(tail);
  free(state->old_data);
  state->old_data = NULL;

  File* file = file_create(check_path);
  if (!file) {
    free(full);
    xattr_list_free(append_xattrs);
    return INCREMENTAL_ERROR;
  }
  file->metadata = meta;
  file->xattrs = append_xattrs;
  append_xattrs = NULL;
  data_destroy(file->data);
  file->data = data_create(full, full_size);
  if (!file->data) { /* data_create already freed full on failure */
    file_destroy(file);
    return INCREMENTAL_ERROR;
  }
  *out_file = file;
  return INCREMENTAL_FILE;
}

/* Block delta transfer against the existing destination content. */
static IncrementalCheckOutcome incremental_check_try_delta(IncrementalCheckState* state,
                                                           bool try_delta, File** out_file) {
  if (try_delta && state->old_data != NULL) {
    bool delta_failed = false;
    File* delta_file = receive_delta_file(state->fd, state->config, state->check_path,
                                          state->old_data, state->old_size, &delta_failed);
    state->old_data = NULL; /* receive_delta_file consumes the snapshot on every path */
    if (delta_file) {
      *out_file = delta_file;
      return INCREMENTAL_FILE;
    }
    if (delta_failed)
      return INCREMENTAL_ERROR;
  }
  free(state->old_data);
  state->old_data = NULL;
  return INCREMENTAL_CONTINUE;
}

/* -y/--fuzzy similar-file delta basis.  Reaching this point means the file
   must be transferred and the destination's own content could not serve as a
   delta basis; try an existing similar-named sibling in the same directory. */
static IncrementalCheckOutcome incremental_check_try_fuzzy(IncrementalCheckState* state,
                                                           File** out_file) {
  const Config* config = state->config;
  if (!config->fuzzy || !config->use_delta)
    return INCREMENTAL_CONTINUE;
  unsigned long long fuzzy_size = 0;
  void* fuzzy_basis =
      fuzzy_basis_find_and_load(config, state->check_path, state->check_size, &fuzzy_size);
  if (fuzzy_basis != NULL) {
    bool fuzzy_failed = false;
    File* fuzzy_file = receive_delta_file(state->fd, config, state->check_path, fuzzy_basis,
                                          fuzzy_size, &fuzzy_failed);
    fuzzy_basis = NULL; /* receive_delta_file consumes the buffer on every path */
    if (fuzzy_file) {
      *out_file = fuzzy_file;
      return INCREMENTAL_FILE;
    }
    if (fuzzy_failed)
      return INCREMENTAL_ERROR;
  }
  free(fuzzy_basis);
  return INCREMENTAL_CONTINUE;
}

/* Final fallback: tell the sender to transmit the whole file and receive it. */
static File* incremental_check_receive_full(IncrementalCheckState* state) {
  if (!send_status(state->fd, STATUS_NEXT))
    return NULL;
  if (state->old_fd >= 0) {
    close(state->old_fd);
    state->old_fd = -1;
  }
  return receive_full_file(state->fd, state->config, state->check_path);
}

/* Core implementation.  `would_transfer` (may be NULL) is set true only on the
 * server-contacting --dry-run path, when the file is not up to date and the
 * receiver answered STATUS_DRY_RUN_TRANSFER; the caller then knows no File is
 * returned and nothing was stored. */
File* receive_incremental_check_ex(int fd, const Config* config, bool* skipped,
                                   bool* would_transfer) {
  if (would_transfer)
    *would_transfer = false;
  if (!config || !skipped) {
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  *skipped = false;

  IncrementalCheckState state;
  incremental_check_state_init(&state, fd, config);

  File* result = NULL;
  bool try_delta = false;
  IncrementalCheckOutcome outcome;

  outcome = incremental_check_receive_request(&state);
  if (outcome == INCREMENTAL_ERROR)
    goto done;

  outcome = incremental_check_open_destination(&state);
  if (outcome == INCREMENTAL_ERROR)
    goto done;

  outcome = incremental_check_quick_skip(&state, &try_delta);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_SKIP) {
    *skipped = true;
    goto done;
  }

  /* Dry-run resolves here (no mutation) or falls through to the normal path. */
  outcome = incremental_check_dry_run_shortcut(&state, skipped, would_transfer);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome != INCREMENTAL_CONTINUE)
    goto done;

  outcome = incremental_check_try_basis(&state, &result);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_SKIP) {
    *skipped = true;
    goto done;
  }
  if (outcome == INCREMENTAL_FILE)
    goto done;

  outcome = incremental_check_try_append_resume(&state, &result);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_FILE)
    goto done;

  outcome = incremental_check_try_delta(&state, try_delta, &result);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_FILE)
    goto done;

  outcome = incremental_check_try_fuzzy(&state, &result);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_FILE)
    goto done;

  result = incremental_check_receive_full(&state);

done:
  incremental_check_state_cleanup(&state);
  return result;
}

File* receive_incremental_check(int fd, const Config* config, bool* skipped) {
  return receive_incremental_check_ex(fd, config, skipped, NULL);
}

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
    ProtocolSession* owner = file_data->owner;
    data_destroy(file_data);
    if (file_data_uncompressed == NULL) {
      file_destroy(file);
      return NULL;
    }
    if (!data_charge_session(file_data_uncompressed, owner, file_data_uncompressed->size)) {
      data_destroy(file_data_uncompressed);
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

/* ---- P7 Wave D: deferred directory metadata ---- */

bool dir_metadata_should_capture(const Config* config) {
  /* Directory metadata is captured when a directory attribute is actually
   * requested: -p/--perms (directory modes) or -t/--times (directory mtimes,
   * unless -O/--omit-dir-times suppresses them).  --atimes/-U alone does not
   * pull directory metadata (matching the original dir-time bundle). */
  return config && config->use_metadata &&
         (config->preserve_perms || (config->preserve_times && !config->omit_dir_times));
}

void dir_time_list_init(DirTimeList* list) {
  if (!list)
    return;
  list->paths = NULL;
  list->entries = NULL;
  list->count = 0;
  list->capacity = 0;
  list->bytes = 0;
}

void dir_time_list_free(DirTimeList* list) {
  if (!list)
    return;
  for (size_t i = 0; i < list->count; i++)
    free(list->paths[i]);
  free(list->paths);
  free(list->entries);
  list->paths = NULL;
  list->entries = NULL;
  list->count = 0;
  list->capacity = 0;
  list->bytes = 0;
}

bool dir_time_list_add(DirTimeList* list, const char* wire_path, const FileMetadata* metadata) {
  if (!list || !wire_path || !metadata)
    return true; /* nothing to remember; never a hard error */
  /* Cumulative, not per-frame: the sender may stream a tree across unbounded
     STATUS_DIR_TIMES frames, so bound the TOTAL retained here.  Reject before
     touching the list, leaving it exactly as it was (the caller fails the
     transfer, which becomes a clean protocol error). */
  size_t path_len = strlen(wire_path);
  /* Charge the whole per-entry cost (path copy + pointer slot + metadata
     struct), not just the path, so the array growth is bounded by the same
     cumulative budget. */
  size_t entry_cost = path_len + sizeof(FileMetadata) + sizeof(char*);
  if (list->count >= MAX_DIR_TIME_ENTRIES || entry_cost > MAX_DIR_TIME_BYTES - list->bytes)
    return false;
  if (list->count == list->capacity) {
    size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
    if (new_capacity < list->capacity)
      return false;
    /* Assign each grown array as soon as its realloc succeeds: the old block is
       already freed by then, so discarding the pointer would dangle.  capacity
       is advanced only after BOTH reallocs succeed, so a partial failure leaves
       capacity no larger than the entries allocation (the paths array may be
       over-allocated, which is harmless) -- never a mismatched list the next
       add could write past. */
    char** grown_paths = realloc(list->paths, new_capacity * sizeof(char*));
    if (!grown_paths)
      return false;
    list->paths = grown_paths;
    FileMetadata* grown_entries = realloc(list->entries, new_capacity * sizeof(FileMetadata));
    if (!grown_entries)
      return false;
    list->entries = grown_entries;
    list->capacity = new_capacity;
  }
  char* copy = str_dup(wire_path);
  if (!copy)
    return false;
  list->paths[list->count] = copy;
  list->entries[list->count] = *metadata;
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
  if (!apply_times && !apply_mode)
    return;
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
    if (apply_mode) {
      mode_t dir_mode = list->entries[i].mode;
      bool mode_ready = true;
      if (config->chmod_spec && *config->chmod_spec &&
          !chmod_apply(dir_mode, config->chmod_spec, &dir_mode)) {
        char* escaped_path = output_escape(dir_path, log_get_8_bit_output());
        log_message(LOG_LEVEL_WARNING, "Failed to apply --chmod to directory %s",
                    escaped_path ? escaped_path : "<allocation failed>");
        free(escaped_path);
        mode_ready = false;
      }
      if (mode_ready) {
        /* Route the directory mode through the SAME sanitization as the
         * regular-file policy: a client-supplied mode never grants group/other
         * write.  Open the directory with O_DIRECTORY|O_NOFOLLOW (never
         * following a same-named symlink) and fchmod the fd, avoiding the
         * fchmodat(..., 0) TOCTOU/symlink-follow hole. */
        mode_t safe_mode =
            (dir_mode & 0777 & ~(S_IWGRP | S_IWOTH)) | (dir_mode & (S_ISGID | S_ISVTX));
        int dir_fd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dir_fd < 0) {
          char* escaped_path = output_escape(dir_path, log_get_8_bit_output());
          log_message(LOG_LEVEL_WARNING, "Failed to open directory %s to set its mode: %s",
                      escaped_path ? escaped_path : "<allocation failed>", strerror(errno));
          free(escaped_path);
        } else {
          if (fchmod(dir_fd, safe_mode) != 0) {
            char* escaped_path = output_escape(dir_path, log_get_8_bit_output());
            log_message(LOG_LEVEL_WARNING, "Failed to set directory mode on %s: %s",
                        escaped_path ? escaped_path : "<allocation failed>", strerror(errno));
            free(escaped_path);
          }
          close(dir_fd);
        }
      }
    }
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

/* Read a delete-manifest frame (the STATUS_MANIFEST leading code has already
   been consumed): a keep-set entry count followed by that many
   destination-relative paths, then a protected-prefix count followed by that
   many destination-relative prefixes, then (protocol 2.10.0+) a missing-args
   count followed by that many destination-relative delete paths.  The frame is
   self-delimiting (the counts are authoritative), so the caller decides what to
   do next and continues reading the following STATUS_* frame.  Every section is
   validated identically: an entry must be non-empty, relative and traversal-free
   and the aggregate length across ALL sections is capped by MAX_MANIFEST_BYTES
   (so the missing-args deletion requests are confined like the rest of the
   manifest).  Returns an owned DeleteManifest, or NULL after sending STATUS_ERROR
   when the frame is malformed (bad count, empty/absolute path, path traversal,
   or an aggregate size beyond MAX_MANIFEST_BYTES). */
static bool receive_manifest_section(int fd, ArrayList* list, size_t* manifest_bytes,
                                     size_t* manifest_entries) {
  int count;
  if (!receive_int(fd, &count)) {
    send_status(fd, STATUS_ERROR);
    return false;
  }
  if (count < 0 || count > MAX_MANIFEST_ENTRIES ||
      (size_t)count > MAX_MANIFEST_ENTRIES - *manifest_entries) {
    send_status(fd, STATUS_ERROR);
    return false;
  }
  for (int i = 0; i < count; i++) {
    char* s = receive_wire_str(fd);
    size_t entry_size = s ? strlen(s) + MANIFEST_ENTRY_OVERHEAD : 0;
    if (!s || s[0] == '\0' || s[0] == '/' || has_path_traversal(s) ||
        entry_size > MAX_MANIFEST_BYTES - *manifest_bytes ||
        (*manifest_bytes += entry_size) > MAX_MANIFEST_BYTES || !array_list_add(list, s)) {
      free(s);
      send_status(fd, STATUS_ERROR);
      return false;
    }
  }
  *manifest_entries += (size_t)count;
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
  manifest->missing = array_list_create(free);
  if (!manifest->keeps || !manifest->protected || !manifest->missing) {
    delete_manifest_free(manifest);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  size_t manifest_bytes = 0;
  size_t manifest_entries = 0;
  if (!receive_manifest_section(fd, manifest->keeps, &manifest_bytes, &manifest_entries) ||
      !receive_manifest_section(fd, manifest->protected, &manifest_bytes, &manifest_entries) ||
      !receive_manifest_section(fd, manifest->missing, &manifest_bytes, &manifest_entries)) {
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
  array_list_delete(manifest->missing);
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

/* --delete-missing-args exact-path deletions: each destination mirror in
   manifest->missing is an explicit user request, so it is removed even when the
   ordinary extras walk (with its protected prefixes) would leave it alone.  The
   --delay-updates staging directory and basis snapshots are receiver artifacts
   and stay protected exactly as in the extras walker.  A regular file or
   symlink is unlinked, an empty directory removed, and a NON-empty directory is
   removed recursively only when --delete or --force is in effect (rsync parity:
   the man page says a non-empty directory mirror is only deleted with --force
   or --delete); otherwise it is left with a warning and the run continues.  A
   mirror that does not exist is a no-op.  Returns false only on a genuine error
   (a confinement failure on a validated path or an I/O error), which fails the
   run. */
bool manifest_delete_missing_args(const Config* config, DeleteManifest* manifest) {
  if (!config || !manifest)
    return false;
  if (!manifest->missing || manifest->missing->size == 0)
    return true;
  fprintf(stderr, "Deleting destination mirrors of missing source arguments...\n");
  int skip_count = (config->delay_updates ? 1 : 0) + config->basis_count;
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
  }
  bool ok = true;
  for (int i = 0; i < manifest->missing->size; i++) {
    const char* rel = (const char*)manifest->missing->items[i];
    if (!rel || *rel == '\0' || *rel == '/' || has_path_traversal(rel)) {
      /* Defensive only: receive_manifest_entries already validated every
         section identically, so a controlled peer never reaches this branch. */
      log_message(LOG_LEVEL_ERROR, "invalid missing-args delete path");
      ok = false;
      continue;
    }
    bool at_root = strchr(rel, '/') == NULL;
    if (path_under_skip_prefix(rel, at_root, skips, skip_count)) {
      char* escaped = output_escape(rel, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING,
                  "missing-args path '%s' is protected (staging directory or basis snapshot); "
                  "not deleting",
                  escaped ? escaped : "<allocation failed>");
      free(escaped);
      continue;
    }
    char* full = path_cat(config->receive_root_directory, rel);
    if (!full) {
      ok = false;
      continue;
    }
    char* leaf = NULL;
    int parent_fd = file_open_secure_parent(full, &leaf, false);
    if (parent_fd < 0) {
      /* The mirror's parent directory may itself not exist on the destination
         (a deeper missing entry whose leading directories were never created).
         That is a no-op -- there is nothing to delete -- matching
         file_remove_tree_secure's absent-path handling; only a genuine I/O
         error (EACCES, a symlink loop, ...) fails the run. */
      bool absent = errno == ENOENT || errno == ENOTDIR;
      free(full);
      free(leaf);
      if (!absent)
        ok = false;
      continue;
    }
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) {
      /* Already absent: nothing to delete (a no-op, not a deletion). */
      if (errno != ENOENT)
        ok = false;
      close(parent_fd);
      free(leaf);
      free(full);
      continue;
    }
    bool removed = false;
    if (S_ISDIR(st.st_mode)) {
      if (unlinkat(parent_fd, leaf, AT_REMOVEDIR) == 0) {
        removed = true;
      } else if (errno == ENOTEMPTY || errno == EEXIST) {
        close(parent_fd);
        parent_fd = -1;
        free(leaf);
        leaf = NULL;
        if (config->use_delete || config->force_delete) {
          if (!file_remove_tree_secure(full))
            ok = false;
          else
            removed = true;
        } else {
          char* escaped = output_escape(rel, log_get_8_bit_output());
          log_message(LOG_LEVEL_WARNING,
                      "missing-args destination '%s' is a non-empty directory; use --force or "
                      "--delete to remove it",
                      escaped ? escaped : "<allocation failed>");
          free(escaped);
        }
      } else if (errno != ENOENT) {
        ok = false;
      }
    } else {
      if (unlinkat(parent_fd, leaf, 0) == 0) {
        removed = true;
      } else if (errno != ENOENT) {
        ok = false;
      }
    }
    if (removed) {
      char* escaped = output_escape(rel, log_get_8_bit_output());
      fprintf(stderr, "  Deleted: %s\n", escaped ? escaped : "<allocation failed>");
      free(escaped);
    }
    if (parent_fd >= 0)
      close(parent_fd);
    free(leaf);
    free(full);
    if (!ok)
      break;
  }
  free(skips);
  return ok;
}

/* Commit every deletion family the manifest carries.  The --delete-missing-args
   exact-path deletions run FIRST: they are explicit user requests and must not
   be blocked by the extras walker's filter-exclusion protection (a protected
   leftover inside a missing-argument directory must not make that user-requested
   removal fail).  The ordinary extras walk then runs when --delete is active.
   Returns true when there was nothing to do or every requested deletion
   committed. */
bool manifest_delete_all(const Config* config, DeleteManifest* manifest) {
  if (!config || !manifest)
    return false;
  /* Central no-mutation guard: a dry-run never deletes.  No manifest is sent on
     the dry-run path, but a hostile/buggy peer could; treat it as a no-op so
     the receiver can never remove anything. */
  if (config->dry_run)
    return true;
  if (config->delete_missing_args && !manifest_delete_missing_args(config, manifest))
    return false;
  if (config->use_delete && !manifest_delete_extras(config, manifest))
    return false;
  return true;
}
