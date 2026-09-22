#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
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
#include "file_save.h"
#include "format.h"
#include "identity.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"
#include "xattr.h"

bool file_save_to_disk(const char* root_directory, const File* file, const Config* config) {
  return file_save_to_disk_full_ex(root_directory, file, config, NULL, NULL) != FILE_SAVE_ERROR;
}

FileSaveResult file_save_to_disk_full(const char* root_directory, const File* file,
                                      const Config* config) {
  return file_save_to_disk_full_ex(root_directory, file, config, NULL, NULL);
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
  } else if (file->basis_copy) {
    /* --copy-dest basis hit: stream the basis into the staging tree (bounded
       buffers, so an over-limit basis still stages). */
    ok = file_copy_basis_stream_attrs(staged_path, file->basis_copy, file->data->size,
                                      config->preallocate, metadata, policy, config->update,
                                      config->use_fsync, file->xattrs, config->fake_super, NULL);
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

/* Resolve a user-supplied --temp-dir against the receive `root`.
 *
 * A relative, traversal-free name is joined below the root (the historical
 * behavior).  An absolute path is canonicalized with realpath(3) and accepted
 * only when it lies inside the canonicalized receive root; this is the parity
 * win over rejecting every absolute path, without weakening the confinement
 * invariant: an absolute path that escapes the root (including one reached
 * through a symlinked component) is still refused.  A `..` component in a
 * relative name is likewise refused.  The root itself is treated as an
 * absolute path free of `..`; its realpath() resolves any symlinks so the
 * prefix comparison is against one canonical form.
 *
 * Logs a clear error on rejection (the scratch dir must stay confined) and
 * returns a newly allocated scratch path, or NULL on rejection/allocation
 * failure. */
static char* file_save_resolve_temp_dir(const char* root, const char* temp_dir) {
  if (temp_dir[0] != '/') {
    if (has_path_traversal(temp_dir)) {
      log_message(
          LOG_LEVEL_ERROR,
          "receiver rejected --temp-dir '%s': a '..' component would escape the receive root",
          temp_dir);
      return NULL;
    }
    return path_cat(root, temp_dir);
  }
  char canonical_temp[PATH_MAX];
  char canonical_root[PATH_MAX];
  if (!realpath(temp_dir, canonical_temp)) {
    log_message(LOG_LEVEL_ERROR,
                "receiver rejected --temp-dir '%s': could not resolve the absolute path (%s)",
                temp_dir, strerror(errno));
    return NULL;
  }
  if (!realpath(root, canonical_root)) {
    log_message(LOG_LEVEL_ERROR,
                "receiver rejected --temp-dir '%s': could not resolve the receive root (%s)",
                temp_dir, strerror(errno));
    return NULL;
  }
  if (strcmp(canonical_root, "/") != 0 && !path_is_within_root(canonical_root, canonical_temp)) {
    log_message(LOG_LEVEL_ERROR,
                "receiver rejected --temp-dir '%s': an absolute temp dir must be inside the "
                "receive root '%s'",
                temp_dir, canonical_root);
    return NULL;
  }
  return str_dup(canonical_temp);
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
                                                 const Config* config, bool* created) {
  Config* cfg = (Config*)config;
  if (!root_directory || !file || !file->path || !file->hardlink_target)
    return FILE_SAVE_ERROR;
  char* destination_path = path_cat(root_directory, file->path);
  if (!destination_path)
    return FILE_SAVE_ERROR;
  bool existed = file_path_exists_secure(destination_path);

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
    if (ok && created && !existed)
      *created = true;
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
  /* Resolve the --temp-dir under the destination root, exactly as the primary
   * save path does: a relative dir joins below the root, an absolute dir is
   * accepted only when it canonicalizes inside the root, and any escaping value
   * is rejected. */
  char* resolved_temp = NULL;
  if (cfg->temp_dir) {
    resolved_temp = file_save_resolve_temp_dir(root_directory, cfg->temp_dir);
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
  if (ok && created && !existed)
    *created = true;
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
                                                const Config* config, bool* created) {
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
  bool existed = file_path_exists_secure(destination);
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
  /* Under -p/--perms rsync copies the source's permission and special bits; a
   * kernel that denies setuid/setgid/sticky reports the failure rather than
   * having them masked here.  Without -p the node is created like any other new
   * entry: source_mode & 0777 & ~umask.  When super-user activities are
   * forbidden, the special bits are stripped even under -p (they are
   * super-user activities just like device-node creation). */
  mode_t perms = config->preserve_perms ? (mode & (mode_t)(S_ISUID | S_ISGID | S_ISVTX | 0777))
                                        : (mode & 0777 & ~(mode_t)file_process_umask());
  if (!privilege_super_mode_permitted(config->super_mode))
    perms &= ~(mode_t)(S_ISUID | S_ISGID | S_ISVTX);

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
  if (owner_ok && created && !existed)
    *created = true;
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

/* ---- file_save_to_disk_full_ex decomposition ----
 *
 * The regular-file install path is split into small static helpers that share
 * one FileSavePlan (the owned path-set) and route every exit through a single
 * cleanup epilogue so the path-set is released exactly once.  Each helper owns
 * one decision: request validation, special/device dispatch, directory and
 * symlink creation, path resolution, the --existing/--ignore-existing/--update/
 * --force/--backup pre-write policies, and the data install.  The ordering of
 * every check and every protocol/write operation is unchanged.
 */

/* Owned state for one regular-file install.  The path-set pointers are owned by
 * the plan and freed together by file_save_plan_dispose(). */
typedef struct {
  const char* root_directory;
  const File* file;
  const Config* config;
  bool backup_enabled;
  bool inplace;
  bool sparse;
  FileAttrPolicy policy;
  const char* backup_suffix;
  const char* backup_dir;
  const char* partial_dir;
  const char* temp_dir;
  bool use_partial_root;
  bool dest_existed;
  char* confined_backup;
  char* confined_partial;
  char* disk_path;
  char* destination_path;
  char* backup_path;
  char* parent_copy;
  char* confined_temp;
} FileSavePlan;

static void file_save_plan_init(FileSavePlan* plan, const char* root_directory, const File* file,
                                const Config* config) {
  memset(plan, 0, sizeof(*plan));
  plan->root_directory = root_directory;
  plan->file = file;
  plan->config = config;
  plan->backup_enabled = config && config->backup && !config->ignore_existing;
  plan->inplace = config && config->inplace;
  plan->sparse = config && config->preserve_sparse;
  plan->policy = file_attr_policy_from_config(config);
  plan->backup_suffix = (config && config->suffix) ? config->suffix : "~";
  plan->backup_dir = (config && config->backup_dir) ? config->backup_dir : NULL;
  plan->partial_dir = (config && config->partial_dir) ? config->partial_dir : NULL;
  plan->temp_dir = (config && config->temp_dir) ? config->temp_dir : NULL;
  plan->use_partial_root = plan->partial_dir && config && config->partial;
}

/* Single cleanup epilogue: release the whole owned path-set exactly once. */
static void file_save_plan_dispose(FileSavePlan* plan) {
  free(plan->parent_copy);
  free(plan->backup_path);
  free(plan->confined_backup);
  free(plan->confined_partial);
  free(plan->destination_path);
  free(plan->disk_path);
  free(plan->confined_temp);
}

/* Structural validation of the received entry. */
static bool file_save_validate(const FileSavePlan* plan) {
  const File* file = plan->file;
  const char* backup_suffix = plan->backup_suffix;
  return file && file->path && file->data &&
         (file->data->size == 0 || file->data->data || file->basis_link || file->basis_copy) &&
         (file_get_trust_sender() || !has_path_traversal(file->path)) &&
         (!plan->backup_enabled ||
          (backup_suffix && backup_suffix[0] != '\0' && strchr(backup_suffix, '/') == NULL &&
           strcmp(backup_suffix, ".") != 0 && strcmp(backup_suffix, "..") != 0));
}

/* Explicit directory entry (--dirs). */
static FileSaveResult file_save_directory_to_disk(const FileSavePlan* plan, bool* created) {
  const File* file = plan->file;
  if (file->path[0] == '\0' || (!file_get_trust_sender() && has_path_traversal(file->path))) {
    log_message(LOG_LEVEL_ERROR, "Invalid directory path received");
    return FILE_SAVE_ERROR;
  }
  char* dir_path = path_cat(plan->root_directory, file->path);
  if (!dir_path)
    return FILE_SAVE_ERROR;
  bool dir_existed = file_path_exists_secure(dir_path);
  bool ok = file_ensure_directory_secure(dir_path);
  /* One confined, no-follow descriptor drives ownership/mode/xattr/timestamp
     application so none of them can follow a same-named symlink planted after
     the mkdir.  This mirrors the O_DIRECTORY|O_NOFOLLOW fd that
     dir_metadata_list_apply() opens for the recursive path; the fd is reached
     through the already-confined parent. */
  char* leaf = NULL;
  int parent_fd = -1;
  int dir_fd = -1;
  if (ok) {
    parent_fd = file_open_secure_parent(dir_path, &leaf, false);
    if (parent_fd >= 0)
      dir_fd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  }
  /* P7 Wave E: apply the negotiated ownership to the directory ITSELF (not
     just the files inside it).  --copy-as and every explicit identity policy
     own every entry, so a directory must not keep the receiver's owner while
     its children get the policy owner.  Applied no-follow on the confined
     parent fd; identity_apply_ownership_link() is itself a no-op unless an
     identity policy is active.  Ownership runs before the mode because a chown
     clears setuid/setgid.  A failed REQUIRED --copy-as ownership fails the
     entry; every other policy stays best-effort. */
  if (ok && file->metadata && identity_active_enabled()) {
    if (parent_fd >= 0) {
      if (!identity_apply_ownership_link(parent_fd, leaf, (int32_t)file->metadata->uid,
                                         (int32_t)file->metadata->gid))
        ok = false;
    } else if (identity_copy_as_active()) {
      /* The directory exists (ok) but its required --copy-as ownership could
         not be applied because the confined parent could not be opened. */
      ok = false;
    }
  } else if (ok && identity_copy_as_active()) {
    ok = false;
  }
  /* The final source MODE is deliberately NOT applied inline.  A restrictive
     source mode (for example 0555) would make the directory unwritable before
     its children are created, so a non-root receiver fails each child with
     EACCES.  The receiver feeds every is_dir entry -- including this explicit
     --dirs/STATUS_MKDIR one -- into the deferred DirTimeList, and
     dir_metadata_list_apply() stamps the exact mode once the whole transfer has
     finished, exactly as it does for the recursive path.  Leaving the directory
     at its creation mode keeps it writable for the children until then.

     The xattrs below are still applied inline so a direct
     file_save_to_disk_full() caller (which has no deferred pass) also gets
     --dirs directory xattrs.  Because the inline mode is absent, the inline
     order here is ownership, then xattrs, then timestamps; the recursive path
     (which DOES apply a mode) orders them times, mode, xattrs -- the difference
     is intentional, and the deferred pass re-stamps mode and xattrs last.
     Best-effort: a per-attribute failure is logged and skipped by
     xattr_apply_fd(), never fatal. */
  if (ok && plan->config && plan->config->use_xattrs && dir_fd >= 0 && file->xattrs)
    xattr_apply_fd(dir_fd, file->xattrs);
  /* Timestamps last so no later inline ownership/xattr change is mistaken for a
     content update; the deferred pass re-stamps them after every child write.
     -J/--omit-dir-times suppresses the directory mtime; --atimes/-U applies
     only when the source atime is valid, exactly as the recursive path. */
  if (ok && file->metadata && plan->config && plan->config->preserve_times &&
      !plan->config->omit_dir_times) {
    struct timespec times[2] = {
        {.tv_sec = 0, .tv_nsec = UTIME_OMIT},
        {.tv_sec = file->metadata->mtime_sec, .tv_nsec = file->metadata->mtime_nsec}};
    if (plan->config->preserve_atimes && file->metadata->atime_valid) {
      times[0].tv_sec = file->metadata->atime_sec;
      times[0].tv_nsec = file->metadata->atime_nsec;
    }
    if (parent_fd >= 0 && utimensat(parent_fd, leaf, times, AT_SYMLINK_NOFOLLOW) != 0) {
      int saved_errno = errno;
      char* escaped_path = output_escape(dir_path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING, "Failed to set directory timestamps on %s: %s",
                  escaped_path ? escaped_path : "<allocation failed>", strerror(saved_errno));
      free(escaped_path);
    }
  }
  if (dir_fd >= 0)
    close(dir_fd);
  if (parent_fd >= 0)
    close(parent_fd);
  free(leaf);
  free(dir_path);
  if (ok && created && !dir_existed)
    *created = true;
  return ok ? FILE_SAVE_WRITTEN : FILE_SAVE_ERROR;
}

/* Symlink entry.  (The process-wide --keep-dirlinks policy is set once by the
   connection handler from the negotiated config, before any receiver/writer
   threads start, so it is stable throughout this walk.) */
static FileSaveResult file_save_symlink_to_disk(const FileSavePlan* plan, bool* created) {
  const File* file = plan->file;
  const Config* config = plan->config;
  if (!file->symlink_target || file->path[0] == '\0' ||
      (!file_get_trust_sender() && has_path_traversal(file->path))) {
    log_message(LOG_LEVEL_ERROR, "Invalid symlink entry received");
    return FILE_SAVE_ERROR;
  }
  char* link_path = path_cat(plan->root_directory, file->path);
  if (!link_path)
    return FILE_SAVE_ERROR;
  bool link_existed = file_path_exists_secure(link_path);
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
  if (ok && created && !link_existed)
    *created = true;
  free(link_path);
  return ok ? FILE_SAVE_WRITTEN : FILE_SAVE_ERROR;
}

/* Device/special node (--devices/--specials) and --write-devices dispatch. */
static bool file_save_try_special_dispatch(const FileSavePlan* plan, bool* created,
                                           FileSaveResult* out) {
  const File* file = plan->file;
  const Config* config = plan->config;
  /* Device/special node (--devices/--specials): recreate the node instead of
     writing content (privilege-gated, confined, rdev-validated). */
  if (file->is_special) {
    *out = file_save_special_to_disk(plan->root_directory, file, config, created);
    return true;
  }
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
      *out = FILE_SAVE_SKIPPED;
      return true;
    }
    *out = file_save_write_device(plan->root_directory, file);
    return true;
  }
  return false;
}

/* Resolve and confine the backup/partial/temp directories and the destination
   and disk paths.  Returns false on an invalid/escaping option or an
   allocation failure (the caller routes to the cleanup epilogue). */
static bool file_save_resolve_paths(FileSavePlan* plan) {
  /* These options arrive from the client.  --backup-dir and --partial-dir are
     names below the server root, never independent filesystem roots: an
     absolute or `..`-escaping value is rejected outright.  --temp-dir is
     resolved by file_save_resolve_temp_dir below: a relative name joins below
     the root, an absolute name is accepted only when it canonicalizes inside
     the root, and any escaping value is rejected.  If the resolved scratch dir
     still lands on a different filesystem than the destination the install
     falls back to a non-atomic copy (see file_to_disk_secure_impl), never an
     abort. */
  if ((plan->backup_dir && (plan->backup_dir[0] == '/' || has_path_traversal(plan->backup_dir))) ||
      (plan->partial_dir && (plan->partial_dir[0] == '/' || has_path_traversal(plan->partial_dir))))
    return false;
  if (plan->backup_dir &&
      !(plan->confined_backup = path_cat(plan->root_directory, plan->backup_dir)))
    return false;
  if (plan->partial_dir &&
      !(plan->confined_partial = path_cat(plan->root_directory, plan->partial_dir)))
    return false;
  if (plan->temp_dir &&
      !(plan->confined_temp = file_save_resolve_temp_dir(plan->root_directory, plan->temp_dir)))
    return false;

  const char* actual_root = plan->use_partial_root ? plan->confined_partial : plan->root_directory;
  plan->destination_path = path_cat(plan->root_directory, plan->file->path);
  plan->disk_path = path_cat(actual_root, plan->file->path);
  if (plan->destination_path == NULL || plan->disk_path == NULL)
    return false;
  /* Snapshot the final destination's existence BEFORE any backup/force/partial
     step can move or remove it, so the receiver can report rsync's
     `Number of created files` (protocol 2.28.0). */
  plan->dest_existed = file_path_exists_secure(plan->destination_path);
  return true;
}

typedef enum {
  FILE_SAVE_POLICY_CONTINUE, /* proceed to the install */
  FILE_SAVE_POLICY_SKIP,     /* --existing/--ignore-existing/--update skip */
  FILE_SAVE_POLICY_ERROR,    /* --force/--backup failure */
} FileSavePolicyOutcome;

/* The immediate-install pre-write policies: --existing, --ignore-existing,
   --update, --force and --backup, in that order. */
static FileSavePolicyOutcome file_save_apply_prewrite_policies(FileSavePlan* plan) {
  const Config* config = plan->config;
  const File* file = plan->file;

  /* --existing checks the final destination, not a temporary partial path. */
  if (config && config->existing && !file_path_exists_secure(plan->destination_path))
    return FILE_SAVE_POLICY_SKIP;

  /* --ignore-existing checks the final destination before partial files or
     overwrite policies can modify it. */
  if (config && config->ignore_existing) {
    bool exists = file_path_exists_secure(plan->destination_path);
    if (exists)
      return FILE_SAVE_POLICY_SKIP;
  }

  /* --update is receiver-side policy: never replace a newer destination.
     In partial-dir mode the entry that would be replaced is the real
     destination, not the temporary partial file.  The secure stat does not
     require read permission on the destination. */
  const char* update_target = plan->use_partial_root ? plan->destination_path : plan->disk_path;
  if (config && config->update && file_destination_is_newer_secure(update_target, file->metadata))
    return FILE_SAVE_POLICY_SKIP;

  /* --force (rsync semantics): an incoming regular file may replace a
     destination DIRECTORY by removing that (possibly non-empty, symlink-safe)
     tree first, so the atomic temp+rename below can install the file.  Only the
     immediate-install path does this: a --delay-updates run stages into its own
     tree and is unaffected here (its publication renames over regular files
     only).  The blocking directory is removed only after the --update /
     --existing / --ignore-existing decisions above, which see it as an existing
     destination entry. */
  if (config && config->force_delete && !file->is_dir &&
      file_directory_exists_secure(plan->destination_path)) {
    if (!file_remove_tree_secure(plan->destination_path))
      return FILE_SAVE_POLICY_ERROR;
  }

  if (plan->backup_enabled) {
    /* Back up the entry that the incoming write will replace.  When writing
       through a partial dir the pre-existing destination file is the one to
       preserve; any stale partial file is overwritten without a backup. */
    const char* replace_target = plan->use_partial_root ? plan->destination_path : plan->disk_path;
    struct stat backup_stat;
    if (file_stat_secure(replace_target, &backup_stat)) {
      if (plan->backup_dir) {
        plan->backup_path = path_cat(plan->confined_backup, file->path);
      } else {
        size_t path_len = strlen(replace_target);
        size_t suffix_len = strlen(plan->backup_suffix);
        if (path_len > SIZE_MAX - suffix_len - 1)
          return FILE_SAVE_POLICY_ERROR;
        plan->backup_path = malloc(path_len + suffix_len + 1);
        if (plan->backup_path) {
          memcpy(plan->backup_path, replace_target, path_len);
          memcpy(plan->backup_path + path_len, plan->backup_suffix, suffix_len + 1);
        }
      }
      if (!plan->backup_path)
        return FILE_SAVE_POLICY_ERROR;
      plan->parent_copy = str_dup(plan->backup_path);
      if (!plan->parent_copy || !file_ensure_directory_secure(dirname(plan->parent_copy)))
        return FILE_SAVE_POLICY_ERROR;
      free(plan->parent_copy);
      plan->parent_copy = NULL;
      if (!file_rename_secure(replace_target, plan->backup_path))
        return FILE_SAVE_POLICY_ERROR;
      free(plan->backup_path);
      plan->backup_path = NULL;
    }
  }
  return FILE_SAVE_POLICY_CONTINUE;
}

/* Install the file data into the destination (or staging/partial path):
   --link-dest hard link, --copy-dest streamed copy, or the plain atomic
   temp+rename engine with per-file xattr/--fake-super application. */
static bool file_save_install_data(FileSavePlan* plan, const FileMetadata* metadata,
                                   unsigned* created_dirs) {
  const File* file = plan->file;
  const Config* config = plan->config;
  char* count_floor = file_transfer_root_floor(config);
  bool ok;
  if (config && file->basis_link) {
    ok = file_to_disk_secure_link_attrs_counted(
        plan->disk_path, file->basis_link, file->data->data, file->data->size, config->preallocate,
        metadata, plan->policy, config->use_fsync, file->xattrs, config->fake_super,
        plan->confined_temp, created_dirs, count_floor);
  } else if (config && file->basis_copy) {
    /* --copy-dest: stream the basis bytes through a bounded buffer so a basis
       larger than any whole-file bound still materializes.  The source
       metadata was transmitted with the check frame. */
    ok = file_copy_basis_stream_attrs(plan->disk_path, file->basis_copy, file->data->size,
                                      config->preallocate, metadata, plan->policy, config->update,
                                      config->use_fsync, file->xattrs, config->fake_super,
                                      plan->confined_temp);
  } else {
    /* The plain no-replace / update / with-fsync engines, plus per-file xattr
       (-X/-A) and --fake-super application on the written fd. */
    ok = file_to_disk_secure_attrs_counted(
        plan->disk_path, file->data->data, file->data->size, plan->inplace, plan->sparse,
        config && config->preallocate, metadata, plan->policy, config && config->update,
        config && config->ignore_existing, config && config->use_fsync, file->xattrs,
        config ? config->fake_super : false, config ? config->partial : false, plan->confined_temp,
        created_dirs, count_floor);
  }
  free(count_floor);
  return ok;
}

FileSaveResult file_save_to_disk_full_ex(const char* root_directory, const File* file,
                                         const Config* config, bool* created,
                                         unsigned* created_dirs) {
  if (created)
    *created = false;
  if (created_dirs)
    *created_dirs = 0;
  /* Central no-mutation guard: a server-contacting --dry-run (or a local batch
     apply that somehow carries dry_run) must never touch the destination, no
     matter which caller reached this primitive.  The per-caller guards remain,
     but this is the last line of defense for every save path.  Report SKIPPED
     so a --remove-source-files sender correctly keeps its source. */
  if (config && config->dry_run)
    return FILE_SAVE_SKIPPED;

  FileSavePlan plan;
  file_save_plan_init(&plan, root_directory, file, config);
  FileSaveResult result = FILE_SAVE_ERROR;

  if (!file_save_validate(&plan)) {
    log_message(LOG_LEVEL_ERROR, "Invalid file or path received");
    goto out;
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
  if (file->dir_time_only) {
    result = FILE_SAVE_SKIPPED;
    goto out;
  }

  FileSaveResult dispatched;
  if (file_save_try_special_dispatch(&plan, created, &dispatched)) {
    result = dispatched;
    goto out;
  }

  /* Explicit directory entries (--dirs) carry an empty payload; the entry is
     created as a directory under the receive root, applying the same secure
     mkdir-parent semantics as regular writes.  Directories are created
     immediately (they are never staged by --delay-updates, matching rsync,
     where directory creation is not delayed). */
  if (file->is_dir) {
    result = file_save_directory_to_disk(&plan, created);
    goto out;
  }

  if (file->is_symlink) {
    result = file_save_symlink_to_disk(&plan, created);
    goto out;
  }

  /* --hard-links/-H sibling: a later member of a link group arrives with no
     payload and is installed as a hard link to (or, on link() failure, a
     byte-identical copy of) the group's first member.  Handled entirely here,
     before the normal data-write paths (which would create an empty file). */
  if (file->link_group != 0 && !file->link_first && file->hardlink_target != NULL) {
    result = file_save_hardlink_sibling(root_directory, file, config, created);
    goto out;
  }

  if (!file_save_resolve_paths(&plan))
    goto out;

  /* --delay-updates diverts the whole write into the staging tree; the rest of
     this function is the immediate-install path. */
  if (config && config->delay_updates) {
    FileSaveResult staged =
        file_stage_delayed_update(root_directory, plan.destination_path, file, (Config*)config);
    if (staged == FILE_SAVE_WRITTEN && created && !plan.dest_existed)
      *created = true;
    result = staged;
    goto out;
  }

  FileSavePolicyOutcome policy_outcome = file_save_apply_prewrite_policies(&plan);
  if (policy_outcome == FILE_SAVE_POLICY_SKIP) {
    result = FILE_SAVE_SKIPPED;
    goto out;
  }
  if (policy_outcome == FILE_SAVE_POLICY_ERROR)
    goto out;

  FileMetadata adjusted_metadata;
  const FileMetadata* metadata = file->metadata;
  if (metadata && config && config->chmod_spec && *config->chmod_spec) {
    adjusted_metadata = *metadata;
    if (!chmod_apply(adjusted_metadata.mode, config->chmod_spec, &adjusted_metadata.mode))
      goto out;
    metadata = &adjusted_metadata;
  }

  /* A configured --temp-dir sends the temporary working copy to a scratch
     directory; the engine then atomically renames the completed file into the
     final destination directory.  The scratch path was confined to the receive
     root (and canonicalized) in file_save_resolve_paths and must already exist;
     the engine falls back to a non-atomic copy on EXDEV.  The partial-dir flow
     already keeps its working copy in a separate directory and --inplace writes
     directly, so neither diverts through the scratch dir (matching rsync, where
     --inplace/--partial-dir supersede --temp-dir). */
  /* --inplace and --partial-dir supersede --temp-dir in rsync, so the scratch
     dir is not used on those paths.  The value was still validated/confined by
     file_save_resolve_paths; drop the resolved path so it is never handed to the
     install engine. */
  if (plan.confined_temp && (plan.inplace || plan.use_partial_root)) {
    free(plan.confined_temp);
    plan.confined_temp = NULL;
  }
  bool use_temp_dir = plan.confined_temp != NULL;
  if (use_temp_dir) {
    /* A user-supplied trailing slash would leave the scratch path ending in
       "/", which has no final component to create/open.  Normalize it away. */
    size_t temp_len = strlen(plan.confined_temp);
    while (temp_len > 1 && plan.confined_temp[temp_len - 1] == '/')
      plan.confined_temp[--temp_len] = '\0';
  }

  /* A --link-dest basis hit installs an atomic hard link (with a byte-copy
     fallback); --inplace and the update/no-replace write variants do not
     apply to a fresh hard link, whose inode attributes already match.  The
     existing/ignore-existing/update/backup preamble above has already made the
     policy decision. */
  if (!file_save_install_data(&plan, metadata, created_dirs))
    goto out;

  /* --partial --partial-dir writes the complete file under the partial dir so
     interrupted transfers leave a resumable copy there.  Once the file is
     fully written it must be atomically installed at the real destination;
     otherwise completed transfers would linger under the partial dir. */
  if (plan.use_partial_root) {
    if (!file_rename_secure(plan.disk_path, plan.destination_path))
      goto out;
  }

  if (created && !plan.dest_existed)
    *created = true;
  result = FILE_SAVE_WRITTEN;

out:
  file_save_plan_dispose(&plan);
  return result;
}

void receiver_stats_note_saved(ReceiverStats* stats, const File* file, bool created,
                               unsigned created_dirs) {
  if (!stats || !file)
    return;
  /* A basis-dir hit (--link-dest/--copy-dest) materializes bytes the sender
   * never transferred.  rsync reports no literal data and no created entry for
   * such a file, and does not count the parent directories it creates only to
   * hold it, so exclude the whole entry from the receiver tallies. */
  bool basis_sourced = file->basis_link != NULL || file->basis_copy != NULL;
  if (basis_sourced)
    return;
  bool is_sibling = file->link_group != 0 && !file->link_first;
  if (!file->is_dir && !file->is_symlink && !file->is_special && !is_sibling) {
    unsigned long long literal = file->literal_bytes;
    if (literal == 0 && file->matched_bytes == 0)
      literal = file->data ? file->data->size : 0;
    stats->literal_bytes += literal;
  }
  stats->created_dir += created_dirs;
  if (!created)
    return;
  if (file->is_dir)
    stats->created_dir++;
  else if (file->is_symlink)
    stats->created_link++;
  else if (file->is_special)
    stats->created_special++;
  else
    stats->created_reg++;
}
