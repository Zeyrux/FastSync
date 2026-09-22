#define _GNU_SOURCE
#include "xattr.h"
#include "identity.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"
#include "file_types.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

/* ---- lifecycle ---- */

FileXattrList* xattr_list_new(void) {
  FileXattrList* list = protocol_alloc(sizeof(FileXattrList));
  if (!list)
    return NULL;
  list->items = NULL;
  list->count = 0;
  return list;
}

void xattr_list_free(FileXattrList* list) {
  if (!list)
    return;
  for (int i = 0; i < list->count; i++) {
    free(list->items[i].name);
    free(list->items[i].value);
  }
  free(list->items);
  free(list);
}

FileXattrList* xattr_list_clone(const FileXattrList* list) {
  if (!list)
    return NULL;
  FileXattrList* clone = xattr_list_new();
  if (!clone)
    return NULL;
  for (int i = 0; i < list->count; i++) {
    if (!xattr_list_append(clone, list->items[i].name, list->items[i].value,
                           list->items[i].value_len)) {
      xattr_list_free(clone);
      return NULL;
    }
  }
  return clone;
}

bool xattr_list_append(FileXattrList* list, const char* name, const void* value, size_t value_len) {
  if (!list || !name || (!value && value_len != 0))
    return false;
  if (list->count >= XATTR_MAX_COUNT)
    return false;
  FileXattr* grown = realloc(list->items, ((size_t)list->count + 1) * sizeof(FileXattr));
  if (!grown)
    return false;
  list->items = grown;
  size_t name_len = strlen(name);
  char* name_copy = malloc(name_len + 1);
  if (!name_copy) {
    return false;
  }
  unsigned char* value_copy = NULL;
  if (value_len > 0) {
    value_copy = malloc(value_len);
    if (!value_copy) {
      free(name_copy);
      return false;
    }
    memcpy(value_copy, value, value_len);
  }
  memcpy(name_copy, name, name_len);
  name_copy[name_len] = '\0';
  list->items[list->count].name = name_copy;
  list->items[list->count].value = value_copy;
  list->items[list->count].value_len = value_len;
  list->count++;
  return true;
}

/* ---- namespace / length validation ---- */

/* A Linux xattr name is "namespace.name" with an optional leading "trusted.",
 * "system.", "security.", "user.", or "trusted." prefix.  We only ever touch
 * the unprivileged "user.*" namespace and, only when --acls/-A was negotiated,
 * the two POSIX ACL xattrs carried in the "system." namespace.  Everything else
 * -- especially "security.*" (ACLs, capabilities, SELinux labels) and
 * "trusted.*" -- is refused so a client can never compel the receiver to apply a
 * privileged attribute it would not otherwise be able to set (and which would be
 * a local privilege escalation if it could).
 *
 * The ACL gate is deliberate: --xattrs/-X alone derives use_xattrs but must NOT
 * authorize the ACL names, otherwise a -X client could plant an ACL the
 * receiver never opted into (B4). */
bool xattr_name_appliable(const char* name, bool preserve_acls) {
  if (!name || name[0] == '\0')
    return false;
  size_t len = strlen(name);
  if (len > XATTR_NAME_MAX)
    return false;
  /* The reserved --fake-super key is exclusively the RECEIVER's: it records the
   * source stat for a later privileged restore.  A plain -X run must never
   * forward a source file that already carries this key (spoofable) onto the
   * destination, so it is excluded from capture AND from application.  Only
   * fake_super_store_fd() writes it. */
  if (strcmp(name, FAKESUPER_XATTR) == 0)
    return false;
  if (strncmp(name, "user.", 5) == 0)
    return name[5] != '\0';
  if (strcmp(name, "system.posix_acl_access") == 0)
    return preserve_acls;
  if (strcmp(name, "system.posix_acl_default") == 0)
    return preserve_acls;
  return false;
}

/* The two POSIX ACL xattr names: the only names whose applicablity is
 * conditional (they require --acls).  Used by the receiver to distinguish "not
 * negotiated" (drop the entry, keep user.* working for -X) from a genuinely
 * disallowed namespace (hard reject). */
static bool xattr_name_is_posix_acl(const char* name) {
  return name != NULL && (strcmp(name, "system.posix_acl_access") == 0 ||
                          strcmp(name, "system.posix_acl_default") == 0);
}

/* ---- SENDER: capture ---- */

FileXattrList* xattr_capture_path(const char* path, bool preserve_acls) {
  if (!path)
    return NULL;
  ssize_t list_size = listxattr(path, NULL, 0);
  if (list_size <= 0)
    return NULL; /* no xattrs, ENOTSUP, or error: nothing appliable */
  char* names = malloc((size_t)list_size);
  if (!names)
    return NULL;
  ssize_t got = listxattr(path, names, (size_t)list_size);
  if (got < 0) {
    free(names);
    return NULL;
  }
  FileXattrList* list = xattr_list_new();
  if (!list) {
    free(names);
    return NULL;
  }
  size_t budget = 0;
  ssize_t offset = 0;
  while (offset < got) {
    const char* name = names + offset;
    size_t name_len = strlen(name);
    if (name_len == 0)
      break; /* trailing double NUL not expected; stop */
    offset += (ssize_t)name_len + 1;
    /* Capture is sender-side: the scanner has already gated on -X/-A, so the
       per-name whitelist here allows the ACL names only when --acls was
       negotiated.  Without it a plain -X capture never carries an ACL. */
    if (!xattr_name_appliable(name, preserve_acls))
      continue;
    ssize_t value_size = getxattr(path, name, NULL, 0);
    if (value_size < 0)
      continue;
    if (value_size > XATTR_VALUE_MAX)
      continue; /* oversize value is refused up front (bounded capture) */
    if (name_len + (size_t)value_size > XATTR_TOTAL_MAX - budget)
      continue; /* would exceed the per-file budget: skip, keep the rest */
    unsigned char* buffer = malloc(value_size > 0 ? (size_t)value_size : 1);
    if (!buffer) {
      xattr_list_free(list);
      free(names);
      return NULL;
    }
    ssize_t read_len = getxattr(path, name, buffer, (size_t)value_size);
    if (read_len < 0 || read_len != value_size) {
      free(buffer);
      continue;
    }
    if (!xattr_list_append(list, name, buffer, (size_t)value_size)) {
      free(buffer);
      xattr_list_free(list);
      free(names);
      return NULL;
    }
    free(buffer);
    budget += name_len + (size_t)value_size;
  }
  free(names);
  if (list->count == 0) {
    xattr_list_free(list);
    return NULL;
  }
  return list;
}

/* ---- WIRE ---- */

bool xattr_send(int fd, const FileXattrList* list) {
  int count = list ? list->count : 0;
  if (!send_int(fd, count))
    return false;
  for (int i = 0; i < count; i++) {
    const FileXattr* xa = &list->items[i];
    size_t name_len = strlen(xa->name);
    if (name_len > INT32_MAX)
      return false;
    int32_t name_len32 = (int32_t)name_len;
    if (xa->value_len > INT32_MAX)
      return false;
    int32_t value_len32 = (int32_t)xa->value_len;
    if (!send_n_data(fd, &name_len32, sizeof(name_len32)) || !send_n_data(fd, xa->name, name_len) ||
        !send_n_data(fd, &value_len32, sizeof(value_len32)) ||
        (value_len32 > 0 && !send_n_data(fd, xa->value, (size_t)value_len32)))
      return false;
  }
  return true;
}

FileXattrList* xattr_receive(int fd, int* ok, bool preserve_acls) {
  if (ok)
    *ok = 0;
  int count;
  if (!receive_int(fd, &count))
    return NULL;
  if (count < 0 || count > XATTR_MAX_COUNT) {
    log_message(LOG_LEVEL_ERROR, "rejected xattr block: invalid attribute count %d", count);
    return NULL;
  }
  FileXattrList* list = xattr_list_new();
  if (!list)
    return NULL;
  size_t budget = 0;
  for (int i = 0; i < count; i++) {
    int32_t name_len32;
    if (!receive_n_data(fd, &name_len32, sizeof(name_len32))) {
      xattr_list_free(list);
      return NULL;
    }
    if (name_len32 <= 0 || name_len32 > XATTR_NAME_MAX) {
      log_message(LOG_LEVEL_ERROR, "rejected xattr block: invalid name length %d", name_len32);
      xattr_list_free(list);
      return NULL;
    }
    char* name = protocol_alloc((size_t)name_len32 + 1);
    if (!name) {
      xattr_list_free(list);
      return NULL;
    }
    if (!receive_n_data(fd, name, (size_t)name_len32)) {
      free(name);
      xattr_list_free(list);
      return NULL;
    }
    name[name_len32] = '\0';
    if (memchr(name, '\0', (size_t)name_len32) != NULL) {
      /* embedded NUL in the name: malformed, reject */
      free(name);
      xattr_list_free(list);
      return NULL;
    }
    bool skip = false;
    if (!xattr_name_appliable(name, preserve_acls)) {
      if (!preserve_acls && xattr_name_is_posix_acl(name)) {
        /* -X without -A: the sender may still carry ACLs, but the receiver must
           never apply an ACL it was not asked to preserve.  Consume and drop the
           entry (keeping -X compatibility) rather than failing the transfer. */
        skip = true;
      } else {
        log_message(LOG_LEVEL_ERROR, "rejected xattr block: disallowed namespace for '%s'", name);
        free(name);
        xattr_list_free(list);
        return NULL;
      }
    }
    int32_t value_len32;
    if (!receive_n_data(fd, &value_len32, sizeof(value_len32))) {
      free(name);
      xattr_list_free(list);
      return NULL;
    }
    if (value_len32 < 0 || value_len32 > XATTR_VALUE_MAX) {
      log_message(LOG_LEVEL_ERROR, "rejected xattr block: invalid value length %d for '%s'",
                  value_len32, name);
      free(name);
      xattr_list_free(list);
      return NULL;
    }
    if ((size_t)name_len32 + (size_t)value_len32 > XATTR_TOTAL_MAX - budget) {
      log_message(LOG_LEVEL_ERROR, "rejected xattr block: total size budget exceeded for '%s'",
                  name);
      free(name);
      xattr_list_free(list);
      return NULL;
    }
    unsigned char* value = NULL;
    if (value_len32 > 0) {
      value = protocol_alloc((size_t)value_len32);
      if (!value) {
        free(name);
        xattr_list_free(list);
        return NULL;
      }
      if (!receive_n_data(fd, value, (size_t)value_len32)) {
        free(value);
        free(name);
        xattr_list_free(list);
        return NULL;
      }
    }
    if (skip) {
      free(value);
      free(name);
      budget += (size_t)name_len32 + (size_t)value_len32;
      continue;
    }
    if (!xattr_list_append(list, name, value, (size_t)value_len32)) {
      free(value);
      free(name);
      xattr_list_free(list);
      return NULL;
    }
    free(value);
    free(name);
    budget += (size_t)name_len32 + (size_t)value_len32;
  }
  if (ok)
    *ok = 1;
  return list;
}

/* ---- RECEIVER: apply (fd-relative, best-effort) ---- */

bool xattr_apply_fd(int fd, const FileXattrList* list) {
  if (fd < 0 || !list)
    return false;
  bool warned = false;
  int first_errno = 0;
  for (int i = 0; i < list->count; i++) {
    const FileXattr* xa = &list->items[i];
    /* Defense in depth: even a hand-crafted list can never apply the reserved
       --fake-super key (only fake_super_store_fd may write it). */
    if (strcmp(xa->name, FAKESUPER_XATTR) == 0)
      continue;
    if (fsetxattr(fd, xa->name, xa->value, xa->value_len, 0) != 0) {
      if (!warned) {
        warned = true;
        first_errno = errno;
      }
    }
  }
  /* Collapse potentially many per-attribute failures into one per-file warning
     so a run with many unsettable attributes does not spam the log. */
  if (warned)
    log_message(LOG_LEVEL_WARNING, "could not set one or more xattrs on the destination file: %s",
                strerror(first_errno));
  return true;
}

/* ---- --fake-super: park ownership/mode/rdev in a reserved xattr ---- */

void fake_super_store_fd(int fd, uint32_t uid, uint32_t gid, uint32_t mode, uint32_t rdev_major,
                         uint32_t rdev_minor) {
  if (fd < 0)
    return;
  /* rsync 3.4.1's exact grammar: "<octal full st_mode> <rdev_major>,<rdev_minor>
   * <uid>:<gid>".  The octal mode carries the S_IFMT bits (e.g. 0104711 for a
   * setuid regular file, 020644 for a char device); the rdev pair is 0,0 for a
   * non-device.  No mtime field: rsync leaves the file's own timestamp in
   * charge of mtime.  This value is what rsync reads back to restore a
   * fake-super tree, so the field order and separators must not change. */
  char record[96];
  int len = snprintf(record, sizeof(record), "%o %u,%u %u:%u", (unsigned)mode, (unsigned)rdev_major,
                     (unsigned)rdev_minor, (unsigned)uid, (unsigned)gid);
  if (len <= 0 || (size_t)len >= sizeof(record))
    return;
  if (fsetxattr(fd, FAKESUPER_XATTR, record, (size_t)len, 0) != 0) {
    log_message(LOG_LEVEL_WARNING, "--fake-super: could not store %s on destination file: %s",
                FAKESUPER_XATTR, strerror(errno));
  }
}

/* --fake-super replay: read the freshly-stored record and re-apply its
 * permission bits fd-relative.  The recorded uid/gid are retained for a later
 * privileged restore but are NEVER chowned here: --fake-super only RECORDS
 * ownership, it must not real-chown the recorded (resolved) owner.  The
 * recorded rdev is likewise parsed for grammar compatibility but is not acted
 * on (device recreation is a separate, privilege-gated path).  mtime is not in
 * the record: the normal metadata path applies it (policy.times), exactly as
 * rsync relies on the file's own timestamp. */
bool fake_super_restore_fd(int fd, FileAttrPolicy policy) {
  if (fd < 0)
    return false;
  char record[128];
  ssize_t len = fgetxattr(fd, FAKESUPER_XATTR, record, sizeof(record) - 1);
  if (len < 0)
    return false; /* absent or filesystem without xattrs: silent no-op */
  record[len] = '\0';
  unsigned ul_mode, rdev_major, rdev_minor, ul_uid, ul_gid;
  if (sscanf(record, "%o %u,%u %u:%u", &ul_mode, &rdev_major, &rdev_minor, &ul_uid, &ul_gid) != 5)
    return false; /* malformed record: skip, never fatal */

  /* --fake-super NEVER performs a real chown: that would defeat the whole point
     of the flag (record privileged ownership on an unprivileged receiver for a
     later privileged restore).  The uid/gid parsed above are retained in the
     record for that later restore, but no ownership change happens here.  The
     rdev is retained for the same reason. */
  (void)rdev_major;
  (void)rdev_minor;
  (void)ul_uid;
  (void)ul_gid;
  /* Mode is applied only when the per-attribute policy asks for it, through the
     SAME shared helper the normal metadata path uses (metadata_mode_for_policy).
     The recorded special bits are stripped first: rsync's fake-super receiver
     stores the full mode in the xattr but never installs setuid/setgid/sticky on
     the real file, so only the 0777 permission bits may be replayed.  The -E
     rule then derives exec bits from the destination's read bits exactly like
     file_restore_metadata_fd. */
  if (policy.perms || policy.executability) {
    struct stat cur;
    mode_t want = 0;
    if (fstat(fd, &cur) != 0) {
      log_message(LOG_LEVEL_WARNING, "--fake-super: could not read destination mode: %s",
                  strerror(errno));
    } else if (metadata_mode_for_policy((mode_t)(ul_mode & 0777U), cur.st_mode, policy, &want)) {
      if (fchmod(fd, want) != 0)
        log_message(LOG_LEVEL_WARNING,
                    "--fake-super: could not restore mode on destination file: %s",
                    strerror(errno));
    }
  }
  return true;
}
