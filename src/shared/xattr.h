#ifndef XATTR_H
#define XATTR_H

#include "file_attr.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Portable extended-attribute (xattr) and POSIX-ACL preservation (Phase 4,
 * protocol 2.13.0).  --xattrs/-X and --acls/-A are implemented on top of the
 * xattr machinery: the SENDER captures a bounded, namespace-whitelisted set of
 * `name = value` pairs per file, transmits them in a per-file wire block, and
 * the RECEIVER re-applies them fd-relative on the just-written file.  Linux
 * xattr syscalls are used; libacl is NOT required (ACLs travel as the
 * system.posix_acl_access / system.posix_acl_default xattrs).
 *
 * Security model:
 *   * A client can never force a `security.*` / privileged xattr onto the
 *     destination: both capture (sender) and apply (receiver) are restricted to
 *     the unprivileged `user.*` namespace and the two POSIX ACL xattrs.  The
 *     receiver independently re-validates every incoming name against this
 *     whitelist, so a malicious sender's `security.capability` payload is
 *     rejected, not applied.
 *   * Payloads are bounded (per-name length, per-value length, per-file count
 *     and total bytes) on BOTH ends to prevent OOM/memory abuse; an oversized
 *     or malformed frame is a clean protocol rejection, never an allocation
 *     blowup.
 *   * Application is confined to the exact destination file descriptor
 *     (fsetxattr on the just-written fd), never a caller-controlled path.
 */

/* Reserved key used by --fake-super to park the source's privileged ownership
 * / mode / mtime on the destination file as an unprivileged user.* xattr, so a
 * later privileged restore could re-apply them.  Exact documented format:
 *   uid:gid:mode:mtime_sec:mtime_nsec           (decimal, decimal, octal, dec, dec)
 * e.g. "1000:1000:644:1765238400:0". */
#define FAKESUPER_XATTR "user.fastsync.stat"

/* --- bounds --- */
#define XATTR_NAME_MAX 255                /* xattr names are limited to 255 bytes */
#define XATTR_VALUE_MAX (1024 * 1024)     /* per-value cap (1 MiB) */
#define XATTR_TOTAL_MAX (4 * 1024 * 1024) /* per-file total name+value bytes */
#define XATTR_MAX_COUNT 256

typedef struct {
  char* name;           /* owned, NUL-terminated */
  unsigned char* value; /* owned, may hold embedded NULs */
  size_t value_len;
} FileXattr;

typedef struct {
  FileXattr* items;
  int count;
} FileXattrList;

FileXattrList* xattr_list_new(void);
void xattr_list_free(FileXattrList* list);
/* Deep-copy `list` (NULL in, NULL out).  Returns NULL on allocation failure. */
FileXattrList* xattr_list_clone(const FileXattrList* list);
/* Append one entry (deep copy).  Returns false on allocation failure. */
bool xattr_list_append(FileXattrList* list, const char* name, const void* value, size_t value_len);

/* True when `name` is a well-formed xattr name AND belongs to a namespace this
 * build is authorized to apply.  `user.*` is always accepted for -X; the two
 * POSIX ACL xattrs are accepted only when `preserve_acls` (--acls/-A) is set, so
 * a plain -X run can never carry or apply an ACL the receiver did not ask for.
 * Used for both capture and receiver-side validation. */
bool xattr_name_appliable(const char* name, bool preserve_acls);

/* Sender: read the whitelisted xattrs of `path` into a new list.  The POSIX ACL
 * names are captured only when `preserve_acls` (--acls/-A) is set, so a plain
 * -X run never carries an ACL it was not asked to preserve; `user.*` is
 * unaffected.  Returns NULL when the path has no appliable xattrs (or the
 * filesystem has no xattr support); an empty-but-valid list is never returned
 * distinct from NULL. */
FileXattrList* xattr_capture_path(const char* path, bool preserve_acls);

/* Wire: bounded serialization.  xattr_send returns false on write failure; an
 * empty/NULL list transmits a zero-count block.  xattr_receive returns NULL and
 * sets *ok = 0 on any malformed / oversized / non-whitelisted entry.  When
 * `preserve_acls` is false, any POSIX ACL entries are consumed and DROPPED (so
 * a -X transfer still succeeds and never applies an ACL it did not negotiate);
 * a genuinely disallowed namespace is still rejected. */
bool xattr_send(int fd, const FileXattrList* list);
FileXattrList* xattr_receive(int fd, int* ok, bool preserve_acls);

/* Receiver: apply every entry fd-relative (fsetxattr) to the just-written file
 * descriptor.  A per-attribute failure (e.g. ACL set refused for non-root on a
 * file the process does not own) is logged and skipped, never fatal.  Returns
 * true when apply was attempted (allowing callers to treat it as best-effort). */
bool xattr_apply_fd(int fd, const FileXattrList* list);

/* --fake-super: write the source uid/gid/mode/mtime record into the reserved
 * FAKESUPER_XATTR on `fd`.  Best-effort (logged, never fatal).  Only meaningful
 * when metadata was transmitted so the values exist. */
void fake_super_store_fd(int fd, uint32_t uid, uint32_t gid, uint32_t mode, int64_t mtime_sec,
                         int64_t mtime_nsec);

/* --fake-super replay: parse the FAKESUPER_XATTR record previously written on
 * `fd` by fake_super_store_fd and re-apply mode/mtime fd-relative.  The
 * recorded uid/gid are deliberately NOT chowned for real: --fake-super only
 * RECORDS ownership (the caller stores the resolved mapping via
 * identity_resolve_storage_ids), it never performs a real chown.  Best-effort:
 * absence of the xattr or a malformed record is a silent no-op that never fails
 * the transfer.  The MODE leg is applied only when policy.perms||policy.
 * executability and the MTIME leg only when policy.times, so the fake-super
 * replay cannot bypass the per-attribute split; the mode is sanitized exactly
 * like the normal metadata path (group/other write bits never granted).
 * Returns true when the xattr was present and parsed. */
bool fake_super_restore_fd(int fd, FileAttrPolicy policy);

#endif