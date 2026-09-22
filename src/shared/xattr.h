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
 *   * Application is confined to the exact destination entry: fsetxattr on the
 *     just-written fd for regular files/directories, and for a symlink an
 *     lsetxattr on "/proc/self/fd/<parent_fd>/<leaf>" reached through the
 *     already-opened, confinement-checked parent directory -- never a
 *     caller-controlled path, and never following the link.
 */

/* Reserved key used by --fake-super to park the source's privileged ownership
 * / mode / rdev on the destination file as an unprivileged user.* xattr, so the
 * tree is interoperable with rsync 3.4.1 and a later privileged restore can
 * re-apply them.  This is rsync's own key and value grammar exactly:
 *   <octal st_mode with S_IFMT> <rdev_major>,<rdev_minor> <uid>:<gid>
 * e.g. "104711 0,0 1234:5678" for a setuid regular file owned by 1234:5678,
 * or "20644 1,3 111:222" for a char device.  mtime is deliberately NOT part of
 * the record: exactly like rsync, the file's own timestamp carries it. */
#define FAKESUPER_XATTR "user.rsync.%stat"

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

/* Sender: like xattr_capture_path() but reads the xattrs of `path` ITSELF,
 * never following a final symlink (llistxattr/lgetxattr).  A symlink entry must
 * use this so the scanner never captures the REFERENT's attributes onto the
 * link (the path-following variant would).  On Linux the VFS refuses to
 * associate xattrs with symlinks at all, so this normally returns NULL; it is
 * still correct and portable for a filesystem/platform that supports them.
 * The same whitelist/bounds as xattr_capture_path() apply.  Returns NULL when
 * the link has no appliable xattrs (or the filesystem does not support them);
 * an empty-but-valid list is never returned distinct from NULL. */
FileXattrList* xattr_capture_path_nofollow(const char* path, bool preserve_acls);

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

/* Receiver: apply every entry to the symlink named by (parent_fd, leaf) WITHOUT
 * following it, via lsetxattr() on the confined path
 * "/proc/self/fd/<parent_fd>/<leaf>".  A symlink cannot be targeted by the
 * fd-relative fsetxattr() path: there is no *at() xattr syscall and the kernel
 * rejects xattr syscalls on an O_PATH descriptor, so the already-opened,
 * confinement-checked parent directory is the anchor and only the final
 * component is the (no-follow) link.  `leaf` must be a single path component.
 * Best-effort exactly like xattr_apply_fd(): a per-attribute failure (on Linux
 * every set on a symlink fails with EPERM) is logged once and skipped, never
 * fatal.  Returns false only for an invalid anchor/list; true when an apply was
 * attempted.  The reserved --fake-super key is never applied. */
bool xattr_apply_path_nofollow(int parent_fd, const char* leaf, const FileXattrList* list);

/* --fake-super: write the source uid/gid/mode/rdev record into the reserved
 * FAKESUPER_XATTR on `fd`, using rsync 3.4.1's exact grammar (see the key
 * comment above).  `mode` is the full st_mode including its S_IFMT bits.
 * Best-effort (logged, never fatal).  Only meaningful when metadata was
 * transmitted so the values exist. */
void fake_super_store_fd(int fd, uint32_t uid, uint32_t gid, uint32_t mode, uint32_t rdev_major,
                         uint32_t rdev_minor);

/* --fake-super replay: parse the FAKESUPER_XATTR record previously written on
 * `fd` by fake_super_store_fd and re-apply the recorded permission bits
 * fd-relative.  The recorded uid/gid are deliberately NOT chowned for real:
 * --fake-super only RECORDS ownership (the caller stores the resolved mapping
 * via identity_resolve_storage_ids), it never performs a real chown.  The
 * recorded rdev is retained for a later privileged restore but is not acted on
 * here.  Best-effort: absence of the xattr or a malformed record is a silent
 * no-op that never fails the transfer.  The MODE leg is applied only when
 * policy.perms||policy.executability, and the recorded special bits
 * (setuid/setgid/sticky) are NOT applied to the real file -- exactly like
 * rsync's fake-super receiver, which stores the full mode in the xattr but
 * strips the special bits on disk.  mtime is not part of the record; the normal
 * metadata path carries it (policy.times) exactly as rsync sets the file's own
 * timestamp.  Returns true when the xattr was present and parsed. */
bool fake_super_restore_fd(int fd, FileAttrPolicy policy);

#endif