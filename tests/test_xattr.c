#include "test_xattr.h"
#include "xattr.h"
#include "config.h"
#include "file.h"
#include "identity.h"
#include "protocol.h"
#include "test_utils.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static void run_recv_helper(int fd) {
  int ok = 0;
  FileXattrList* list = xattr_receive(fd, &ok, false);
  if (!ok)
    _exit(1);
  if (!list) {
    /* NULL list only on error, already handled above. */
    _exit(1);
  }
  if (list->count != 2)
    _exit(1);
  if (strcmp(list->items[0].name, "user.foo") != 0 || list->items[0].value_len != 3 ||
      memcmp(list->items[0].value, "bar", 3) != 0)
    _exit(1);
  if (strcmp(list->items[1].name, "user.empty") != 0 || list->items[1].value_len != 0)
    _exit(1);
  xattr_list_free(list);
  _exit(0);
}

static void test_xattr_wire_roundtrip() {
  /* Round-trip a user.* list incl. an empty value. */
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    run_recv_helper(p[0]);
  }
  close(p[0]);
  io_set_fds(p[1], p[1]);
  FileXattrList* list = xattr_list_new();
  EXPECT_NOT_NULL(list);
  EXPECT_TRUE(xattr_list_append(list, "user.foo", "bar", 3));
  EXPECT_TRUE(xattr_list_append(list, "user.empty", NULL, 0));
  EXPECT_TRUE(xattr_send(p[1], list));
  xattr_list_free(list);
  int status;
  waitpid(pid, &status, 0);
  close(p[1]);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void run_recv_must_fail(int fd) {
  int ok = 0;
  FileXattrList* list = xattr_receive(fd, &ok, false);
  /* A NULL list with ok==0 is the expected rejection. */
  if (ok == 0 && list == NULL)
    _exit(0);
  xattr_list_free(list);
  _exit(1);
}

/* A receiver must reject a security.* (privileged-namespace) attribute, never
 * apply it: the send side can be malicious, so only the receiver whitelist
 * matters. */
static void test_xattr_reject_privileged_namespace() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    run_recv_must_fail(p[0]);
  }
  close(p[0]);
  io_set_fds(p[1], p[1]);
  FileXattrList* list = xattr_list_new();
  EXPECT_NOT_NULL(list);
  /* security.capability must be rejected by the receiver. */
  EXPECT_TRUE(xattr_list_append(list, "security.capability", "\x01\x00", 2));
  xattr_send(p[1], list); /* receiver rejects at the name check and exits */
  xattr_list_free(list);
  int status;
  waitpid(pid, &status, 0);
  close(p[1]);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* An oversized value (beyond XATTR_VALUE_MAX) must be rejected on receive. */
static void test_xattr_reject_oversized_value() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    run_recv_must_fail(p[0]);
  }
  close(p[0]);
  io_set_fds(p[1], p[1]);
  FileXattrList* list = xattr_list_new();
  EXPECT_NOT_NULL(list);
  size_t huge = (size_t)XATTR_VALUE_MAX + 1;
  unsigned char* blob = calloc(1, huge);
  EXPECT_NOT_NULL(blob);
  EXPECT_TRUE(xattr_list_append(list, "user.huge", blob, huge));
  xattr_send(p[1], list); /* send is best-effort; the receiver rejects and exits */
  free(blob);
  xattr_list_free(list);
  int status;
  waitpid(pid, &status, 0);
  close(p[1]);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* The list append enforces the count bound (defense in depth). */
static void test_xattr_count_bound() {
  FileXattrList* list = xattr_list_new();
  EXPECT_NOT_NULL(list);
  bool all_ok = true;
  for (int i = 0; i < XATTR_MAX_COUNT + 1; i++) {
    char name[32];
    snprintf(name, sizeof(name), "user.k%d", i);
    if (!xattr_list_append(list, name, "v", 1))
      all_ok = false;
  }
  EXPECT_FALSE(all_ok);
  EXPECT_EQ_INT(list->count, XATTR_MAX_COUNT);
  xattr_list_free(list);
}

/* The captured list on a plain file reflects only whitelisted namespaces
 * (Linux only; skipped when the filesystem has no xattr support). */
static void test_xattr_capture_and_appliable() {
  EXPECT_FALSE(xattr_name_appliable(NULL, false));
  EXPECT_FALSE(xattr_name_appliable("", false));
  EXPECT_FALSE(xattr_name_appliable("security.selinux", false));
  EXPECT_FALSE(xattr_name_appliable("trusted.blob", false));
  EXPECT_TRUE(xattr_name_appliable("user.foo", false));
  EXPECT_TRUE(xattr_name_appliable("user.foo", true));
  /* The reserved fake-super key is receiver-only and never forwarded/applied. */
  EXPECT_FALSE(xattr_name_appliable("user.fastsync.stat", false));
  EXPECT_FALSE(xattr_name_appliable("user.fastsync.stat", true));
  /* B4: the ACL names require --acls; -X alone must not authorize them. */
  EXPECT_FALSE(xattr_name_appliable("system.posix_acl_access", false));
  EXPECT_FALSE(xattr_name_appliable("system.posix_acl_default", false));
  EXPECT_TRUE(xattr_name_appliable("system.posix_acl_access", true));
  EXPECT_TRUE(xattr_name_appliable("system.posix_acl_default", true));
}

/* B4: a `-X`-only receiver (preserve_acls false) must NOT apply an incoming
 * ACL xattr, while a user.* attribute in the same block still survives.  The
 * ACL entry is dropped, not applied (and the -X transfer is not failed). */
static void run_recv_drops_acl_keeps_user(int fd) {
  int ok = 0;
  FileXattrList* list = xattr_receive(fd, &ok, false);
  if (!ok || list == NULL)
    _exit(1);
  bool saw_user = false;
  for (int i = 0; i < list->count; i++) {
    if (strcmp(list->items[i].name, "system.posix_acl_access") == 0)
      _exit(1); /* ACL must have been dropped */
    if (strcmp(list->items[i].name, "user.keep") == 0)
      saw_user = true;
  }
  xattr_list_free(list);
  _exit(saw_user ? 0 : 1);
}

static void test_xattr_receive_drops_acl_without_preserve_acls() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    run_recv_drops_acl_keeps_user(p[0]);
  }
  close(p[0]);
  io_set_fds(p[1], p[1]);
  FileXattrList* list = xattr_list_new();
  EXPECT_NOT_NULL(list);
  EXPECT_TRUE(xattr_list_append(list, "system.posix_acl_access", "\x02\x00\x00\x00", 4));
  EXPECT_TRUE(xattr_list_append(list, "user.keep", "yes", 3));
  xattr_send(p[1], list);
  xattr_list_free(list);
  int status;
  waitpid(pid, &status, 0);
  close(p[1]);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* MINOR-2: a --link-dest / -H copy fallback (linkat refused) must still apply
 * the per-file xattrs and --fake-super stat.  A DIRECTORY basis forces linkat
 * to fail with EPERM, exercising the byte-copy fallback deterministically.
 * Guarded on filesystem xattr support. */
static void test_link_copy_fallback_preserves_xattrs() {
  const char* dest = "test_link_xattr_dest.txt";
  const char* basis_dir = "test_link_xattr_basis_dir";
  unlink(dest);
  rmdir(basis_dir);
  EXPECT_EQ_INT(mkdir(basis_dir, 0700), 0);

  /* Probe xattr support on the cwd filesystem using the destination file. */
  int probe = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  bool has_xattr = probe >= 0 && setxattr(dest, "user.fastsync.xprobe", "p", 1, 0) == 0;
  if (probe >= 0)
    close(probe);
  if (!has_xattr) {
    removexattr(dest, "user.fastsync.xprobe");
    unlink(dest);
    rmdir(basis_dir);
    return; /* skip silently when the filesystem has no xattr support */
  }
  removexattr(dest, "user.fastsync.xprobe");

  FileXattrList* xattrs = xattr_list_new();
  EXPECT_NOT_NULL(xattrs);
  EXPECT_TRUE(xattr_list_append(xattrs, "user.fallback", "kept", 4));

  FileMetadata m;
  memset(&m, 0, sizeof(m));
  m.mode = 0640;
  m.uid = 1001;
  m.gid = 1002;
  m.mtime_sec = 1234567890;
  m.mtime_nsec = 0;
  m.atime_valid = false;
  m.crtime_valid = false;

  bool ok = file_to_disk_secure_link_attrs(dest, basis_dir, "payload", 7, false, &m, false, false,
                                           xattrs, true, NULL);
  xattr_list_free(xattrs);
  EXPECT_TRUE(ok);

  /* Content landed (the copy fallback wrote the caller's bytes). */
  int fd = open(dest, O_RDONLY);
  EXPECT_TRUE(fd >= 0);
  char buf[16];
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  EXPECT_EQ_INT((int)strlen("payload"), (int)n);
  if (n == 7)
    EXPECT_TRUE(memcmp(buf, "payload", 7) == 0);
  /* Per-file xattr applied on the copy. */
  char vbuf[16];
  ssize_t vlen = getxattr(dest, "user.fallback", vbuf, sizeof(vbuf));
  EXPECT_EQ_INT(4, (int)vlen);
  if (vlen == 4)
    EXPECT_TRUE(memcmp(vbuf, "kept", 4) == 0);
  /* fake-super stat parked by the receiver. */
  EXPECT_TRUE((int)getxattr(dest, FAKESUPER_XATTR, NULL, 0) > 0);

  unlink(dest);
  rmdir(basis_dir);
}

/* Capture must honor --acls: xattr_capture_path(path, false) (plain -X) must
 * never return the POSIX ACL names, while xattr_capture_path(path, true) (-A)
 * does; user.* is captured either way.  This is the capture-side counterpart of
 * the receiver's --acls gate and must not depend on the caller having checked
 * the flag.  Guarded on filesystem/ACL support. */
static void test_xattr_capture_filters_acls() {
  const char* path = "test_xattr_capture_acls.txt";
  unlink(path);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return;
  bool has_xattr = setxattr(path, "user.fastsync.xprobe", "p", 1, 0) == 0;
  if (has_xattr)
    removexattr(path, "user.fastsync.xprobe");
  if (!has_xattr) {
    close(fd);
    unlink(path);
    return; /* filesystem without xattr support */
  }
  if (setxattr(path, "user.keep", "yes", 3, 0) != 0) {
    close(fd);
    unlink(path);
    return;
  }

  /* Synthesize a valid non-trivial POSIX access ACL blob (little-endian):
     version 2 followed by USER_OBJ/USER/GROUP_OBJ/MASK/OTHER entries. */
  uint32_t acl_uid = geteuid() == 0 ? 65534u : (uint32_t)geteuid();
  unsigned char blob[4 + 5 * 8];
  uint32_t version = 2;
  memcpy(blob, &version, 4);
  const uint16_t tags[5] = {0x01, 0x02, 0x04, 0x10, 0x20}; /* OBJ/USER/GROUP/MASK/OTHER */
  const uint16_t perms[5] = {0x04, 0x04, 0x04, 0x04, 0x00};
  const uint32_t ids[5] = {0xFFFFFFFFu, acl_uid, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};
  size_t off = 4;
  for (int i = 0; i < 5; i++) {
    memcpy(blob + off, &tags[i], sizeof(tags[i]));
    off += sizeof(tags[i]);
    memcpy(blob + off, &perms[i], sizeof(perms[i]));
    off += sizeof(perms[i]);
    memcpy(blob + off, &ids[i], sizeof(ids[i]));
    off += sizeof(ids[i]);
  }
  if (setxattr(path, "system.posix_acl_access", blob, off, 0) != 0) {
    close(fd);
    unlink(path);
    return; /* no unprivileged ACL support: skip silently */
  }
  close(fd);

  FileXattrList* plain = xattr_capture_path(path, false);
  FileXattrList* with_acls = xattr_capture_path(path, true);
  bool plain_user = false, plain_acl = false, acl_user = false, acl_acl = false;
  for (int i = 0; plain && i < plain->count; i++) {
    if (strcmp(plain->items[i].name, "user.keep") == 0)
      plain_user = true;
    if (strcmp(plain->items[i].name, "system.posix_acl_access") == 0)
      plain_acl = true;
  }
  for (int i = 0; with_acls && i < with_acls->count; i++) {
    if (strcmp(with_acls->items[i].name, "user.keep") == 0)
      acl_user = true;
    if (strcmp(with_acls->items[i].name, "system.posix_acl_access") == 0)
      acl_acl = true;
  }
  EXPECT_TRUE(plain_user);
  EXPECT_FALSE(plain_acl);
  EXPECT_TRUE(acl_user);
  EXPECT_TRUE(acl_acl);
  xattr_list_free(plain);
  xattr_list_free(with_acls);
  unlink(path);
}

/* --fake-super replay: fake_super_store_fd records the source stat into the
 * reserved xattr, and fake_super_restore_fd re-applies mode/mtime (and owner,
 * when the process may) fd-relative.  Restore must also be a safe no-op with no
 * xattr present.  Guarded on filesystem xattr support. */
static void test_fake_super_restore() {
  const char* path = "test_fake_super_restore.txt";
  unlink(path);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return;
  bool has_xattr = setxattr(path, "user.fastsync.xprobe", "p", 1, 0) == 0;
  if (has_xattr)
    removexattr(path, "user.fastsync.xprobe");
  if (!has_xattr) {
    close(fd);
    unlink(path);
    return; /* skip silently when the filesystem has no xattr support */
  }

  /* No xattr present yet: restore is a silent no-op (returns false, no crash). */
  EXPECT_FALSE(fake_super_restore_fd(fd));

  fake_super_store_fd(fd, 1001, 1002, 0751, 1700000000, 123456789);
  EXPECT_TRUE(fake_super_restore_fd(fd));
  struct stat st;
  EXPECT_EQ_INT(fstat(fd, &st), 0);
  EXPECT_EQ_INT((int)(st.st_mode & 07777), 0751);

  /* Mode sanitization: the normal metadata path never grants group/other write
     bits, and fake-super replay must not re-add them (a recorded 0666 restores
     as 0644, never as world-writable). */
  fake_super_store_fd(fd, 1001, 1002, 0666, 1700000000, 0);
  EXPECT_TRUE(fake_super_restore_fd(fd));
  EXPECT_EQ_INT(fstat(fd, &st), 0);
  EXPECT_EQ_INT((int)(st.st_mode & 0777), 0644);

  /* Restore with a malformed record must skip without failing. */
  time_t before = st.st_mtime;
  int wfd = open(path, O_RDONLY);
  if (wfd >= 0) {
    EXPECT_EQ_INT((int)fsetxattr(wfd, FAKESUPER_XATTR, "not-a-valid-record", 19, 0), 0);
    close(wfd);
  }
  EXPECT_FALSE(fake_super_restore_fd(fd));
  fstat(fd, &st);
  EXPECT_EQ_INT((int)st.st_mtime, (int)before);

  close(fd);
  unlink(path);
}

/* --fake-super owner replay must honor the super gate and copy-as authority:
   --no-super suppresses the recorded-source-owner chown even for root, and an
   active --copy-as keeps its forced owner (the recorded source owner must never
   override it).  Root-gated: only root can observe a chown actually landing. */
static void test_fake_super_owner_gate() {
  if (geteuid() != 0)
    return; /* non-root cannot observe ownership changes; skip silently */
  const char* path = "test_fake_super_owner_gate.txt";
  unlink(path);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return;
  bool has_xattr = setxattr(path, "user.fastsync.xprobe", "p", 1, 0) == 0;
  if (has_xattr)
    removexattr(path, "user.fastsync.xprobe");
  if (!has_xattr) {
    close(fd);
    unlink(path);
    return; /* filesystem without xattr support */
  }
  if (fchown(fd, 0, 0) != 0) {
    close(fd);
    unlink(path);
    return;
  }
  fake_super_store_fd(fd, 12345, 12346, 0755, 1700000000, 0);

  Config* c = config_create();
  EXPECT_NOT_NULL(c);

  /* An explicit ownership policy is required before fake-super replay may
     chown; --fake-super alone only records the source owner (A2). */
  c->numeric_ids = true;

  /* --no-super: the owner leg is skipped even as root. */
  c->super_mode = SUPER_MODE_OFF;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_TRUE(fake_super_restore_fd(fd));
  struct stat st;
  EXPECT_EQ_INT(fstat(fd, &st), 0);
  EXPECT_EQ_INT((int)st.st_uid, 0);
  EXPECT_EQ_INT((int)st.st_gid, 0);

  /* AUTO with an identity policy: the recorded source owner is applied. */
  c->super_mode = SUPER_MODE_AUTO;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_TRUE(fake_super_restore_fd(fd));
  EXPECT_EQ_INT(fstat(fd, &st), 0);
  EXPECT_EQ_INT((int)st.st_uid, 12345);
  EXPECT_EQ_INT((int)st.st_gid, 12346);

  /* --super / --fake-super with NO explicit identity flag must NOT apply a
     client-chosen owner: super_mode alone never enables ownership. */
  EXPECT_EQ_INT(fchown(fd, 0, 0), 0);
  c->numeric_ids = false;
  c->super_mode = SUPER_MODE_ON;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_TRUE(fake_super_restore_fd(fd));
  EXPECT_EQ_INT(fstat(fd, &st), 0);
  EXPECT_EQ_INT((int)st.st_uid, 0);
  EXPECT_EQ_INT((int)st.st_gid, 0);

  /* Active --copy-as is authoritative: the recorded source owner must not
     override it, even with AUTO/ON. */
  c->copy_as_set = true;
  c->copy_as_uid = 777;
  c->copy_as_gid = 778;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_TRUE(fake_super_restore_fd(fd));
  EXPECT_EQ_INT(fstat(fd, &st), 0);
  EXPECT_EQ_INT((int)st.st_uid, 0);
  EXPECT_EQ_INT((int)st.st_gid, 0);

  identity_clear_active();
  config_delete(c);
  close(fd);
  unlink(path);
}

void test_xattr() {
  test_xattr_wire_roundtrip();
  test_xattr_reject_privileged_namespace();
  test_xattr_reject_oversized_value();
  test_xattr_count_bound();
  test_xattr_capture_and_appliable();
  test_xattr_capture_filters_acls();
  test_xattr_receive_drops_acl_without_preserve_acls();
  test_link_copy_fallback_preserves_xattrs();
  test_fake_super_restore();
  test_fake_super_owner_gate();
}