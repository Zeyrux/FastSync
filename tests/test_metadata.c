#include "test_metadata.h"
#include "chmod.h"
#include "metadata.h"
#include "protocol.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_metadata_to_from_buf_roundtrip() {
  FileMetadata original;
  original.mode = 0755;
  original.uid = 1000;
  original.gid = 1000;
  original.mtime_sec = 1234567890;
  original.mtime_nsec = 500000000;
  original.atime_valid = true;
  original.atime_sec = 1234567000;
  original.atime_nsec = 250000000;
  original.crtime_valid = true;
  original.crtime_sec = 1200000000;
  original.crtime_nsec = 750000000;

  char* buf = malloc(FILE_METADATA_WIRE_SIZE + sizeof(int));
  EXPECT_NOT_NULL(buf);
  char* write_ptr = buf;
  metadata_to_buf(&write_ptr, &original);

  char* read_ptr = buf;
  FileMetadata* result = metadata_from_buf(&read_ptr);

  EXPECT_NOT_NULL(result);
  EXPECT_EQ_INT(result->mode, 0755);
  EXPECT_EQ_INT(result->uid, 1000);
  EXPECT_EQ_INT(result->gid, 1000);
  EXPECT_EQ_INT(result->mtime_sec, 1234567890);
  EXPECT_EQ_INT(result->mtime_nsec, 500000000);
  EXPECT_TRUE(result->atime_valid);
  EXPECT_EQ_INT(result->atime_sec, 1234567000);
  EXPECT_EQ_INT(result->atime_nsec, 250000000);
  EXPECT_TRUE(result->crtime_valid);
  EXPECT_EQ_INT(result->crtime_sec, 1200000000);
  EXPECT_EQ_INT(result->crtime_nsec, 750000000);

  EXPECT_EQ_INT((int)(read_ptr - buf), (int)FILE_METADATA_WIRE_SIZE + (int)sizeof(int));

  free(result);
  free(buf);
}

static void test_metadata_to_buf_null() {
  char* buf = malloc(FILE_METADATA_WIRE_SIZE + sizeof(int));
  EXPECT_NOT_NULL(buf);
  char* write_ptr = buf;
  metadata_to_buf(&write_ptr, NULL);

  char* read_ptr = buf;
  int present;
  memcpy(&present, read_ptr, sizeof(int));
  EXPECT_EQ_INT(present, 0);

  free(buf);
}

static void test_metadata_from_buf_null() {
  char* buf = malloc(FILE_METADATA_WIRE_SIZE + sizeof(int));
  EXPECT_NOT_NULL(buf);
  int present = 0;
  memcpy(buf, &present, sizeof(int));

  char* read_ptr = buf;
  const FileMetadata* result = metadata_from_buf(&read_ptr);

  EXPECT_NULL(result);

  free(buf);
}

static void test_metadata_send_receive_roundtrip() {
  io_set_bwlimit(0);
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);

  FileMetadata original;
  original.mode = 0755;
  original.uid = 1000;
  original.gid = 1000;
  original.mtime_sec = 1234567890;
  original.mtime_nsec = 500000000;
  original.atime_valid = false;
  original.atime_sec = 0;
  original.atime_nsec = 0;
  original.crtime_valid = true;
  original.crtime_sec = 1200000000;
  original.crtime_nsec = 750000000;

  EXPECT_TRUE(metadata_send(p[1], &original));

  int ok = 0;
  FileMetadata* received = metadata_receive(p[0], &ok);
  EXPECT_NOT_NULL(received);
  EXPECT_EQ_INT(ok, 1);
  EXPECT_EQ_INT(received->mode, 0755);
  EXPECT_EQ_INT(received->uid, 1000);
  EXPECT_EQ_INT(received->gid, 1000);
  EXPECT_EQ_INT(received->mtime_sec, 1234567890);
  EXPECT_EQ_INT(received->mtime_nsec, 500000000);
  EXPECT_FALSE(received->atime_valid);
  EXPECT_TRUE(received->crtime_valid);
  EXPECT_EQ_INT(received->crtime_sec, 1200000000);
  EXPECT_EQ_INT(received->crtime_nsec, 750000000);

  free(received);
  close(p[0]);
  close(p[1]);
}

static void test_metadata_send_null() {
  io_set_bwlimit(0);
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);

  EXPECT_TRUE(metadata_send(p[1], NULL));

  int ok = 0;
  const FileMetadata* received = metadata_receive(p[0], &ok);
  EXPECT_NULL(received);
  EXPECT_EQ_INT(ok, 1);

  close(p[0]);
  close(p[1]);
}

/* protocol 2.20.0: metadata is one packed frame.  With metadata present the
 * wire record is exactly sizeof(int32_t) + FILE_METADATA_WIRE_SIZE bytes (the
 * present flag followed by the fixed field record); absent metadata is a lone
 * int32 zero. */
static void test_metadata_wire_is_one_packed_frame() {
  io_set_bwlimit(0);
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);

  FileMetadata original = {.mode = 0640,
                           .uid = 42,
                           .gid = 43,
                           .mtime_sec = 111,
                           .mtime_nsec = 222,
                           .atime_valid = true,
                           .atime_sec = 333,
                           .atime_nsec = 444,
                           .crtime_valid = false,
                           .crtime_sec = 0,
                           .crtime_nsec = 0};
  EXPECT_TRUE(metadata_send(p[1], &original));

  unsigned char wire[sizeof(int32_t) + FILE_METADATA_WIRE_SIZE];
  EXPECT_EQ_INT((int)read(p[0], wire, sizeof(wire)), (int)sizeof(wire));
  int32_t flag;
  memcpy(&flag, wire, sizeof(flag));
  EXPECT_EQ_INT(flag, 1);
  int avail = -1;
  EXPECT_EQ_INT(ioctl(p[0], FIONREAD, &avail), 0);
  EXPECT_EQ_INT(avail, 0);

  /* The present frame decodes in one shot with the shared codec. */
  char* cursor = (char*)wire;
  FileMetadata* decoded = metadata_from_buf(&cursor);
  EXPECT_NOT_NULL(decoded);
  EXPECT_EQ_INT((int)(cursor - (char*)wire), (int)sizeof(wire));
  EXPECT_EQ_INT(decoded->mode, 0640);
  EXPECT_EQ_INT(decoded->uid, 42);
  EXPECT_EQ_INT(decoded->gid, 43);
  EXPECT_EQ_INT(decoded->mtime_sec, 111);
  EXPECT_EQ_INT(decoded->mtime_nsec, 222);
  EXPECT_TRUE(decoded->atime_valid);
  EXPECT_EQ_INT(decoded->atime_sec, 333);
  EXPECT_EQ_INT(decoded->atime_nsec, 444);
  EXPECT_FALSE(decoded->crtime_valid);
  free(decoded);

  /* Absent metadata is a lone int32 zero (4 bytes). */
  EXPECT_TRUE(metadata_send(p[1], NULL));
  EXPECT_EQ_INT((int)read(p[0], wire, sizeof(int32_t)), (int)sizeof(int32_t));
  memcpy(&flag, wire, sizeof(flag));
  EXPECT_EQ_INT(flag, 0);
  avail = -1;
  EXPECT_EQ_INT(ioctl(p[0], FIONREAD, &avail), 0);
  EXPECT_EQ_INT(avail, 0);

  close(p[0]);
  close(p[1]);
}

/* Round-trip over a socketpair (not just a pipe): present metadata compares
 * equal field-by-field and absent metadata yields NULL with ok == 1. */
static void test_metadata_send_receive_socketpair() {
  io_set_bwlimit(0);
  int sv[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  io_set_fds(sv[0], sv[1]);

  FileMetadata original = {.mode = 0600,
                           .uid = 7,
                           .gid = 8,
                           .mtime_sec = 1000,
                           .mtime_nsec = 1,
                           .atime_valid = true,
                           .atime_sec = 2000,
                           .atime_nsec = 2,
                           .crtime_valid = true,
                           .crtime_sec = 3000,
                           .crtime_nsec = 3};
  EXPECT_TRUE(metadata_send(sv[1], &original));

  int ok = 0;
  FileMetadata* received = metadata_receive(sv[0], &ok);
  EXPECT_NOT_NULL(received);
  EXPECT_EQ_INT(ok, 1);
  EXPECT_EQ_INT(received->mode, 0600);
  EXPECT_EQ_INT(received->uid, 7);
  EXPECT_EQ_INT(received->gid, 8);
  EXPECT_EQ_INT(received->mtime_sec, 1000);
  EXPECT_EQ_INT(received->mtime_nsec, 1);
  EXPECT_TRUE(received->atime_valid);
  EXPECT_EQ_INT(received->atime_sec, 2000);
  EXPECT_EQ_INT(received->atime_nsec, 2);
  EXPECT_TRUE(received->crtime_valid);
  EXPECT_EQ_INT(received->crtime_sec, 3000);
  EXPECT_EQ_INT(received->crtime_nsec, 3);
  free(received);

  EXPECT_TRUE(metadata_send(sv[1], NULL));
  ok = 0;
  received = metadata_receive(sv[0], &ok);
  EXPECT_NULL(received);
  EXPECT_EQ_INT(ok, 1);

  close(sv[0]);
  close(sv[1]);
}

static void test_metadata_rejects_invalid_values() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  int32_t present = 2;
  EXPECT_TRUE(send_n_data(p[1], &present, sizeof(present)));
  int ok = 1;
  EXPECT_NULL(metadata_receive(p[0], &ok));
  EXPECT_EQ_INT(ok, 0);
  close(p[0]);
  close(p[1]);
}

/* metadata_receive must reject an out-of-range atime/crtime nsec even when the
 * flag would otherwise be valid (defense-in-depth on the -U/-N wire fields).
 * The packed record is built by the shared codec so the out-of-range value
 * actually reaches the wire. */
static void test_metadata_receive_rejects_bad_optional_times() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);

  FileMetadata bad = {.mode = 0644,
                      .uid = 1000,
                      .gid = 1000,
                      .mtime_sec = 1,
                      .mtime_nsec = 0,
                      .atime_valid = true,
                      .atime_sec = 1,
                      .atime_nsec = 2000000000, /* invalid: >= 1e9 */
                      .crtime_valid = false,
                      .crtime_sec = 0,
                      .crtime_nsec = 0};
  char packed[sizeof(int32_t) + FILE_METADATA_WIRE_SIZE];
  char* write_ptr = packed;
  metadata_to_buf(&write_ptr, &bad);
  EXPECT_TRUE(send_n_data(p[1], packed, sizeof(packed)));

  int ok = 1;
  EXPECT_NULL(metadata_receive(p[0], &ok));
  EXPECT_EQ_INT(ok, 0);
  close(p[0]);
  close(p[1]);
}

/* file_restore_metadata applies the source atime alongside mtime when -U
 * captured it (atime_valid set). */
static void test_file_restore_metadata_applies_atime() {
  const char* path = "temp_meta_atime_test.txt";
  EXPECT_TRUE(file_write_to_disk(path, "atime", 5, false, false));

  FileMetadata m;
  m.mode = 0644;
  m.uid = getuid();
  m.gid = getgid();
  m.mtime_sec = 1234567890;
  m.mtime_nsec = 0;
  m.atime_valid = true;
  m.atime_sec = 999999999;
  m.atime_nsec = 123456789;
  m.crtime_valid = false;
  m.crtime_sec = 0;
  m.crtime_nsec = 0;

  file_restore_metadata(path, &m, false);

  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT((int)st.st_mtime, 1234567890);
#ifdef __linux__
  EXPECT_EQ_INT((int)st.st_atime, 999999999);
#else
  EXPECT_EQ_INT((int)st.st_atime, 999999999);
#endif

  unlink(path);
}

static void test_metadata_mtime_window() {
  EXPECT_TRUE(metadata_mtime_matches(100, 100000000, 101, 600000000, 2));
  EXPECT_FALSE(metadata_mtime_matches(100, 100000000, 102, 600000000, 2));
  EXPECT_TRUE(metadata_mtime_matches(100, 100000000, 102, 100000000, 2));
  EXPECT_TRUE(metadata_mtime_matches(100, 900000000, 102, 100000000, 2));
  EXPECT_FALSE(metadata_mtime_matches(100, 100000000, 102, 900000000, 2));
  EXPECT_TRUE(metadata_mtime_matches(100, 900000000, 102, 900000000, 2));
  EXPECT_FALSE(metadata_mtime_matches(100, 900000000, 101, 100000001, 0));
  EXPECT_TRUE(metadata_mtime_matches(100, 100000000, 100, 100000001, 0));
  EXPECT_TRUE(metadata_mtime_matches(100, 100000000, 100, 100000000, 0));
}

static void test_file_restore_metadata() {
  const char* path = "temp_meta_restore_test.txt";
  const char* content = "test content";
  EXPECT_TRUE(file_write_to_disk(path, content, strlen(content), false, false));

  FileMetadata m = {.mode = 0644,
                    .uid = getuid(),
                    .gid = getgid(),
                    .mtime_sec = 1234567890,
                    .mtime_nsec = 0,
                    .atime_valid = false,
                    .crtime_valid = false};

  file_restore_metadata(path, &m, false);

  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT(st.st_mode & 07777, 0644);
  EXPECT_EQ_INT((int)st.st_mtime, 1234567890);

  unlink(path);
}

static void test_file_restore_executability_only() {
  const char* path = "temp_exec_restore_test.txt";
  EXPECT_TRUE(file_write_to_disk(path, "x", 1, false, false));
  EXPECT_EQ_INT(chmod(path, 0644), 0);

  FileMetadata m = {
      .mode = 0751, .uid = getuid(), .gid = getgid(), .mtime_sec = 0, .mtime_nsec = 0};
  file_restore_metadata(path, &m, true);

  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT(st.st_mode & 0777, 0755);
  unlink(path);
}

static void test_directory_restore_executability_only() {
  const char* path = "temp_exec_restore_test_dir";
  EXPECT_EQ_INT(mkdir(path, 0700), 0);

  FileMetadata m = {
      .mode = 0755, .uid = getuid(), .gid = getgid(), .mtime_sec = 0, .mtime_nsec = 0};
  file_restore_metadata(path, &m, true);

  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT(st.st_mode & 0777, 0711);
  rmdir(path);
}

static void test_chmod_changes() {
  mode_t result;
  EXPECT_TRUE(chmod_apply(0777, "u=rw,go=r", &result));
  EXPECT_EQ_INT(result, 0644);
  EXPECT_TRUE(chmod_apply(0644, "a+x", &result));
  EXPECT_EQ_INT(result, 0755);
  result = 0777;
  EXPECT_TRUE(chmod_apply(0777, "0000", &result));
  EXPECT_EQ_INT(result, 0000);
  result = 0777;
  EXPECT_TRUE(chmod_apply(0777, "7777", &result));
  EXPECT_EQ_INT(result, 07777);
  result = 0777;
  EXPECT_TRUE(chmod_apply(0777, "755", &result));
  EXPECT_EQ_INT(result, 0755);
  EXPECT_FALSE(chmod_apply(0777, "888", &result));
  EXPECT_FALSE(chmod_apply(0777, "10000", &result));
  EXPECT_FALSE(chmod_apply(0777, "a+X", &result));
  EXPECT_FALSE(chmod_apply(0777, "a+r,", &result));
}

/* P7 Wave D: symlink metadata is applied with no-follow primitives, and -J
 * (omit_link_times) suppresses the timestamp.  The positive apply path is
 * asserted when the filesystem actually stores symlink timestamps; a filesystem
 * that silently ignores them (or a platform where utimensat AT_SYMLINK_NOFOLLOW
 * is unsupported) is tolerated, in which case only the omit-path invariant is
 * checked. */
static void test_file_restore_symlink_metadata() {
  const char* dir = "temp_symlink_md_test";
  const char* target = "temp_symlink_md_test/target";
  const char* link = "temp_symlink_md_test/link";
  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  FILE* f = fopen(target, "w");
  EXPECT_NOT_NULL(f);
  fputs("t", f);
  fclose(f);
  EXPECT_EQ_INT(symlink("target", link), 0);

  /* Positive path: a non-omitted apply stamps the link's own mtime. */
  FileMetadata applied = {.mtime_sec = 1000000000, .mtime_nsec = 0};
  file_restore_symlink_metadata(link, &applied, false);
  struct stat st;
  EXPECT_EQ_INT(lstat(link, &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));
  bool symlink_times_supported = ((int)st.st_mtime == 1000000000);
  time_t t1 = st.st_mtime;

  /* -J: a different time must be left untouched. */
  FileMetadata newer = {.mtime_sec = 1234567890, .mtime_nsec = 0};
  file_restore_symlink_metadata(link, &newer, true);
  EXPECT_EQ_INT(lstat(link, &st), 0);
  EXPECT_EQ_INT((int)st.st_mtime, (int)t1);
  if (symlink_times_supported)
    EXPECT_EQ_INT((int)st.st_mtime, 1000000000);

  unlink(link);
  unlink(target);
  rmdir(dir);
}

void test_metadata() {
  test_metadata_to_from_buf_roundtrip();
  test_metadata_to_buf_null();
  test_metadata_from_buf_null();
  test_metadata_send_receive_roundtrip();
  test_metadata_send_null();
  test_metadata_wire_is_one_packed_frame();
  test_metadata_send_receive_socketpair();
  test_metadata_rejects_invalid_values();
  test_metadata_receive_rejects_bad_optional_times();
  test_metadata_mtime_window();
  test_file_restore_metadata();
  test_file_restore_metadata_applies_atime();
  test_file_restore_executability_only();
  test_directory_restore_executability_only();
  test_file_restore_symlink_metadata();
  test_chmod_changes();
}
