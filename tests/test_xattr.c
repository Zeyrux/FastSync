#include "test_xattr.h"
#include "xattr.h"
#include "file.h"
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
  FileXattrList* list = xattr_receive(fd, &ok);
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
  FileXattrList* list = xattr_receive(fd, &ok);
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
  EXPECT_FALSE(xattr_name_appliable(NULL));
  EXPECT_FALSE(xattr_name_appliable(""));
  EXPECT_FALSE(xattr_name_appliable("security.selinux"));
  EXPECT_FALSE(xattr_name_appliable("trusted.blob"));
  EXPECT_TRUE(xattr_name_appliable("user.foo"));
  /* The reserved fake-super key is receiver-only and never forwarded/applied. */
  EXPECT_FALSE(xattr_name_appliable("user.fastsync.stat"));
  EXPECT_TRUE(xattr_name_appliable("system.posix_acl_access"));
  EXPECT_TRUE(xattr_name_appliable("system.posix_acl_default"));
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

void test_xattr() {
  test_xattr_wire_roundtrip();
  test_xattr_reject_privileged_namespace();
  test_xattr_reject_oversized_value();
  test_xattr_count_bound();
  test_xattr_capture_and_appliable();
  test_link_copy_fallback_preserves_xattrs();
  test_fake_super_restore();
}