#define _GNU_SOURCE
#include "xattr.h"
#include "identity.h"
#include "log.h"
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
 * the unprivileged "user.*" namespace and the two POSIX ACL xattrs carried in
 * the "system." namespace.  Everything else -- especially "security.*" (ACLs,
 * capabilities, SELinux labels) and "trusted.*" -- is refused so a client can
 * never compel the receiver to apply a privileged attribute it would not
 * otherwise be able to set (and which would be a local privilege escalation if
 * it could). */
bool xattr_name_appliable(const char* name) {
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
    return true;
  if (strcmp(name, "system.posix_acl_default") == 0)
    return true;
  return false;
}

/* ---- SENDER: capture ---- */

FileXattrList* xattr_capture_path(const char* path) {
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
    if (!xattr_name_appliable(name))
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

FileXattrList* xattr_receive(int fd, int* ok) {
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
    if (!xattr_name_appliable(name)) {
      log_message(LOG_LEVEL_ERROR, "rejected xattr block: disallowed namespace for '%s'", name);
      free(name);
      xattr_list_free(list);
      return NULL;
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

/* ---- --fake-super: park ownership/mode/mtime in a reserved xattr ---- */

void fake_super_store_fd(int fd, uint32_t uid, uint32_t gid, uint32_t mode, int64_t mtime_sec,
                         int64_t mtime_nsec) {
  if (fd < 0)
    return;
  char record[128];
  int len =
      snprintf(record, sizeof(record), "%lu:%lu:%03o:%lld:%ld", (unsigned long)uid,
               (unsigned long)gid, (unsigned)mode & 0777U, (long long)mtime_sec, (long)mtime_nsec);
  if (len <= 0 || (size_t)len >= sizeof(record))
    return;
  if (fsetxattr(fd, FAKESUPER_XATTR, record, (size_t)len, 0) != 0) {
    log_message(LOG_LEVEL_WARNING, "--fake-super: could not store %s on destination file: %s",
                FAKESUPER_XATTR, strerror(errno));
  }
}

/* --fake-super replay: read the freshly-stored record and re-apply the source
 * stat fd-relative.  A privileged (root) run can actually change the owner;
 * a non-root run silently skips the fchown on EPERM/EACCES (never fatal,
 * mirroring the normal metadata identity path; other errors are logged) and
 * still applies mode/mtime where permitted.
 *
 * The OWNER leg additionally honors three policies:
 *   - an explicit ownership identity policy must be active (numeric-ids /
 *     chown / usermap / groupmap / copy-as).  --fake-super on its own only
 *     RECORDS the source owner; replaying that owner as a live chown without an
 *     explicit ownership opt-in would be an un-gated client-chosen-ownership
 *     primitive.
 *   - --no-super (privilege_super_permitted() false) suppresses it even for a
 *     root receiver, exactly like the normal metadata identity path.
 *   - an active --copy-as is AUTHORITATIVE: the identity path already forced the
 *     target owner, so replaying the recorded source owner here would silently
 *     override it.  The xattr record is still stored/replayed for a later
 *     privileged restore; only the live chown is skipped.  Mode/mtime remain
 *     applied either way so unprivileged --fake-super still works. */
bool fake_super_restore_fd(int fd) {
  if (fd < 0)
    return false;
  char record[128];
  ssize_t len = fgetxattr(fd, FAKESUPER_XATTR, record, sizeof(record) - 1);
  if (len < 0)
    return false; /* absent or filesystem without xattrs: silent no-op */
  record[len] = '\0';
  unsigned long ul_uid, ul_gid, ul_mode;
  long long mtime_sec;
  long mtime_nsec;
  if (sscanf(record, "%lu:%lu:%lo:%lld:%ld", &ul_uid, &ul_gid, &ul_mode, &mtime_sec, &mtime_nsec) !=
      5)
    return false; /* malformed record: skip, never fatal */

  /* Owner is applied best-effort only: a non-root process cannot chown and
     must not abort the transfer for that reason (FastSync identity philosophy).
     EPERM/EACCES (expected for a non-root receiver) are skipped silently; a
     genuine EINVAL (an impossible stored id) is logged so the corruption is
     not hidden.  --no-super suppresses the owner leg even for root, and an
     active --copy-as is authoritative so its forced owner must not be
     overwritten by the recorded source owner. */
  if (identity_active_enabled() && privilege_super_permitted() && !identity_copy_as_active() &&
      fchown(fd, (uid_t)ul_uid, (gid_t)ul_gid) != 0 && errno != EPERM && errno != EACCES)
    log_message(LOG_LEVEL_WARNING, "--fake-super: could not restore owner on destination file: %s",
                strerror(errno));
  /* Mode is applied through the same sanitization the normal metadata path
     uses (metadata_mode): group/other write bits are never granted, so a
     recorded source mode of 0666 restores as 0644 — identical to a non-fake-
     super --preserve run, never a privilege-granting regression. */
  if (fchmod(fd, (mode_t)(ul_mode & 0777U & ~(S_IWGRP | S_IWOTH))) != 0)
    log_message(LOG_LEVEL_WARNING, "--fake-super: could not restore mode on destination file: %s",
                strerror(errno));
  struct timespec times[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT},
                              {.tv_sec = (time_t)mtime_sec, .tv_nsec = mtime_nsec}};
  if (futimens(fd, times) != 0)
    log_message(LOG_LEVEL_WARNING, "--fake-super: could not restore mtime on destination file: %s",
                strerror(errno));
  return true;
}