#include "test_metadata.h"
#include "chmod.h"
#include "identity.h"
#include "metadata.h"
#include "protocol.h"
#include "test_utils.h"
#include <fcntl.h>
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

  FileMetadata* result =
      metadata_from_buf((const uint8_t*)buf, FILE_METADATA_WIRE_SIZE + sizeof(int));

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

  const FileMetadata* result =
      metadata_from_buf((const uint8_t*)buf, FILE_METADATA_WIRE_SIZE + sizeof(int));

  EXPECT_NULL(result);

  free(buf);
}

/* The decoder must reject (never over-read) a present record that is even one
 * byte shorter than the full int32 flag + FILE_METADATA_WIRE_SIZE body, and
 * must reject a buffer too short to even hold the present flag. */
static void test_metadata_from_buf_bounds() {
  char* buf = malloc(FILE_METADATA_WIRE_SIZE + sizeof(int));
  EXPECT_NOT_NULL(buf);
  FileMetadata original = {.mode = 0644,
                           .uid = 1,
                           .gid = 2,
                           .mtime_sec = 3,
                           .mtime_nsec = 4,
                           .atime_valid = true,
                           .atime_sec = 5,
                           .atime_nsec = 6,
                           .crtime_valid = false};
  char* write_ptr = buf;
  metadata_to_buf(&write_ptr, &original);

  EXPECT_NULL(metadata_from_buf((const uint8_t*)buf, 0));
  EXPECT_NULL(metadata_from_buf((const uint8_t*)buf, sizeof(int)));
  EXPECT_NULL(metadata_from_buf((const uint8_t*)buf, FILE_METADATA_WIRE_SIZE + sizeof(int) - 1));
  /* A buffer larger than the record decodes using only the record prefix. */
  FileMetadata* decoded =
      metadata_from_buf((const uint8_t*)buf, FILE_METADATA_WIRE_SIZE + sizeof(int) + 16);
  EXPECT_NOT_NULL(decoded);
  EXPECT_EQ_INT(decoded->mode, 0644);
  free(decoded);
  EXPECT_NULL(metadata_from_buf(NULL, FILE_METADATA_WIRE_SIZE + sizeof(int)));

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
  FileMetadata* decoded = metadata_from_buf((const uint8_t*)wire, sizeof(wire));
  EXPECT_NOT_NULL(decoded);
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

  file_restore_metadata(path, &m, (FileAttrPolicy){true, true, true, false});

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

  file_restore_metadata(path, &m, (FileAttrPolicy){true, true, false, false});

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
  file_restore_metadata(path, &m, (FileAttrPolicy){false, false, false, true});

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
  file_restore_metadata(path, &m, (FileAttrPolicy){false, false, false, true});

  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  /* rsync -E: an executable source derives exec from the DESTINATION's read
   * bits.  A 0700 directory has read only for the owner, so only the owner
   * gains exec -- the result stays 0700 (not 0711, the old per-class copy). */
  EXPECT_EQ_INT(st.st_mode & 0777, 0700);
  rmdir(path);
}

/* rsync 3.4 -E truth table (preserve_perms off), verified against rsync 3.4.1:
 * (src,dest) -> result.  A non-executable source clears every execute bit; an
 * executable source sets a class's execute bit iff that class can read. */
static void test_file_restore_executability_rsync_rule() {
  static const struct {
    mode_t src;
    mode_t dest;
    mode_t want;
  } cases[] = {
      {0755, 0644, 0755}, {0755, 0600, 0700}, {0755, 0640, 0750}, {0755, 0666, 0777},
      {0700, 0640, 0750}, {0111, 0644, 0755}, {0644, 0755, 0644}, {0644, 0600, 0600},
  };
  const char* path = "temp_exec_rsync_rule.txt";
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    EXPECT_TRUE(file_write_to_disk(path, "x", 1, false, false));
    EXPECT_EQ_INT(chmod(path, cases[i].dest), 0);
    FileMetadata m = {.mode = cases[i].src, .uid = getuid(), .gid = getgid()};
    file_restore_metadata(path, &m, (FileAttrPolicy){false, false, false, true});
    struct stat st;
    EXPECT_EQ_INT(stat(path, &st), 0);
    EXPECT_EQ_INT(st.st_mode & 0777, cases[i].want);
    unlink(path);
  }
}

/* The shared metadata_mode_for_policy() helper is the single source of truth
 * used by both the normal metadata path and the --fake-super replay.  It must
 * reproduce the per-attribute split: no mode change when neither -p nor -E is
 * set; -p applies the source mode exactly (including group/other write and the
 * setuid/setgid/sticky bits) regardless of the destination; -E derives exec
 * bits from the destination and --perms wins when both are set. */
static void test_metadata_mode_for_policy() {
  mode_t out = 0xdead;
  EXPECT_FALSE(
      metadata_mode_for_policy(0777, 0644, (FileAttrPolicy){false, false, false, false}, &out));
  EXPECT_EQ_INT((int)out, 0xdead); /* untouched when no change is requested */

  EXPECT_TRUE(
      metadata_mode_for_policy(0777, 0644, (FileAttrPolicy){true, false, false, false}, &out));
  EXPECT_EQ_INT((int)(out & 0777), 0777); /* group/other write is preserved */

  mode_t specials = (mode_t)(S_ISUID | S_ISGID | S_ISVTX | 0672);
  EXPECT_TRUE(
      metadata_mode_for_policy(specials, 0644, (FileAttrPolicy){true, false, false, false}, &out));
  EXPECT_EQ_INT((int)(out & (S_ISUID | S_ISGID | S_ISVTX | 0777)),
                (int)(S_ISUID | S_ISGID | S_ISVTX | 0672));

  /* -E: exec bits derive from the DESTINATION's read bits. */
  EXPECT_TRUE(
      metadata_mode_for_policy(0755, 0644, (FileAttrPolicy){false, false, false, true}, &out));
  EXPECT_EQ_INT((int)(out & 0777), 0755);
  EXPECT_TRUE(
      metadata_mode_for_policy(0644, 0755, (FileAttrPolicy){false, false, false, true}, &out));
  EXPECT_EQ_INT((int)(out & 0777), 0644);
  EXPECT_TRUE(
      metadata_mode_for_policy(0755, 0600, (FileAttrPolicy){false, false, false, true}, &out));
  EXPECT_EQ_INT((int)(out & 0777), 0700);

  /* --perms wins over -E when both are set. */
  EXPECT_TRUE(
      metadata_mode_for_policy(0700, 0644, (FileAttrPolicy){true, false, false, true}, &out));
  EXPECT_EQ_INT((int)(out & 0777), 0700);
}

/* A brand-new file with -p off is created like rsync: source_mode & 0777 &
 * ~umask (when metadata is available).  The -E rule is then layered on top. */
static void test_new_file_mode_from_source_and_umask() {
  const char* path = "temp_new_file_base.txt";
  unlink(path);
  FileMetadata m = {.mode = 0751, .uid = getuid(), .gid = getgid()};
  mode_t want = (mode_t)(0751 & 0777 & ~(mode_t)file_process_umask());

  bool ok = file_to_disk_secure_attrs(path, "x", 1, false, false, false, &m,
                                      (FileAttrPolicy){false, false, false, false}, false, false,
                                      false, NULL, false, false, NULL);
  EXPECT_TRUE(ok);
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT(st.st_mode & 0777, want);
  unlink(path);

  /* -E on top of the source&~umask base (src 0751, umask 022 -> 0751). */
  ok = file_to_disk_secure_attrs(path, "x", 1, false, false, false, &m,
                                 (FileAttrPolicy){false, false, false, true}, false, false, false,
                                 NULL, false, false, NULL);
  EXPECT_TRUE(ok);
  EXPECT_EQ_INT(stat(path, &st), 0);
  mode_t want_e =
      (want & 0444) ? (mode_t)(want | ((want & 0444) >> 2)) : (mode_t)(want & ~(mode_t)0111);
  EXPECT_EQ_INT(st.st_mode & 0777, want_e);
  unlink(path);
}

/* The per-attribute split: -t/-U apply times without touching the mode; an
 * all-off policy applies neither mode nor times. */
static void test_file_restore_attribute_split() {
  const char* path = "temp_meta_split_test.txt";
  EXPECT_TRUE(file_write_to_disk(path, "x", 1, false, false));
  EXPECT_EQ_INT(chmod(path, 0640), 0);

  FileMetadata m = {.mode = 0755,
                    .uid = getuid(),
                    .gid = getgid(),
                    .mtime_sec = 1234567890,
                    .mtime_nsec = 0,
                    .atime_valid = false,
                    .crtime_valid = false};

  /* times only: mtime changes, mode stays 0640. */
  file_restore_metadata(path, &m, (FileAttrPolicy){false, true, false, false});
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT(st.st_mode & 0777, 0640);
  EXPECT_EQ_INT((int)st.st_mtime, 1234567890);

  /* no attributes: neither mode nor mtime changes. */
  EXPECT_EQ_INT(chmod(path, 0640), 0);
  struct timespec ts[2] = {{.tv_sec = 1000000000, .tv_nsec = 0},
                           {.tv_sec = 1000000000, .tv_nsec = 0}};
  EXPECT_EQ_INT(utimensat(AT_FDCWD, path, ts, 0), 0);
  FileMetadata m2 = m;
  m2.mode = 0700;
  m2.mtime_sec = 1600000000;
  file_restore_metadata(path, &m2, (FileAttrPolicy){false, false, false, false});
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT(st.st_mode & 0777, 0640);
  EXPECT_EQ_INT((int)st.st_mtime, 1000000000);

  unlink(path);
}

static void test_file_attr_policy_from_config() {
  FileAttrPolicy none = file_attr_policy_from_config(NULL);
  EXPECT_FALSE(none.perms);
  EXPECT_FALSE(none.times);
  EXPECT_FALSE(none.atimes);
  EXPECT_FALSE(none.executability);

  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->preserve_perms = true;
  c->preserve_times = true;
  c->preserve_atimes = true;
  c->use_executability = true;
  FileAttrPolicy p = file_attr_policy_from_config(c);
  EXPECT_TRUE(p.perms);
  EXPECT_TRUE(p.times);
  EXPECT_TRUE(p.atimes);
  EXPECT_TRUE(p.executability);
  config_delete(c);
}

/* Strict rsync parity: -p copies the source's setuid/setgid/sticky bits (they
 * are attempted, not masked away).  On Linux these are settable on a file the
 * receiving user owns; a mount that denies them would log a chmod failure. */
static void test_perms_preserves_special_bits() {
  const char* path = "temp_special_bits.txt";
  unlink(path);
  FileMetadata m = {
      .mode = (mode_t)(S_ISUID | S_ISGID | S_ISVTX | 0755), .uid = getuid(), .gid = getgid()};

  bool ok = file_to_disk_secure_attrs(path, "x", 1, false, false, false, &m,
                                      (FileAttrPolicy){true, false, false, false}, false, false,
                                      false, NULL, false, false, NULL);
  EXPECT_TRUE(ok);
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT((int)(st.st_mode & 0777), 0755);
  EXPECT_EQ_INT((int)(st.st_mode & (S_ISUID | S_ISGID | S_ISVTX)),
                (int)(S_ISUID | S_ISGID | S_ISVTX));
  unlink(path);
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
  EXPECT_FALSE(chmod_apply(0777, "a+r,", &result));

  /* go+w is honored (rsync gives 0666 from a 0644 file). */
  EXPECT_TRUE(chmod_apply(0644, "go+w", &result));
  EXPECT_EQ_INT(result, 0666);

  /* X only sets execute on directories or already-executable files. */
  EXPECT_TRUE(chmod_apply(0644, "a+X", &result));
  EXPECT_EQ_INT(result, 0644);
  EXPECT_TRUE(chmod_apply(0755, "a+X", &result));
  EXPECT_EQ_INT(result, 0755);
  EXPECT_TRUE(chmod_apply((mode_t)(S_IFDIR | 0644), "a+X", &result));
  EXPECT_EQ_INT((int)(result & 0777), 0755);
  EXPECT_TRUE(S_ISDIR(result));

  /* D/F selectors restrict a clause to directories/files. */
  EXPECT_TRUE(chmod_apply((mode_t)(S_IFDIR | 0700), "Dg+s", &result));
  EXPECT_EQ_INT((int)(result & 07777), 02700);
  EXPECT_TRUE(chmod_apply((mode_t)(S_IFREG | 0644), "Dg+s", &result));
  EXPECT_EQ_INT((int)(result & 07777), 0644);
  EXPECT_TRUE(chmod_apply((mode_t)(S_IFREG | 0644), "Fo-w", &result));
  EXPECT_EQ_INT((int)(result & 07777), 0644);
  EXPECT_TRUE(chmod_apply((mode_t)(S_IFREG | 0666), "Fo-w", &result));
  EXPECT_EQ_INT((int)(result & 07777), 0664);
  EXPECT_TRUE(chmod_apply((mode_t)(S_IFDIR | 0666), "Fo-w", &result));
  EXPECT_EQ_INT((int)(result & 07777), 0666);
  EXPECT_FALSE(chmod_apply(0644, "DFu+w", &result));

  /* Special bits: s/t map to setuid/setgid/sticky like rsync. */
  EXPECT_TRUE(chmod_apply(0755, "u+s", &result));
  EXPECT_EQ_INT((int)(result & 07777), 04755);
  EXPECT_TRUE(chmod_apply(0755, "g+s", &result));
  EXPECT_EQ_INT((int)(result & 07777), 02755);
  EXPECT_TRUE(chmod_apply(0755, "a+t", &result));
  EXPECT_EQ_INT((int)(result & 07777), 01755);

  /* Comma-separated clauses accumulate (the CLI joins repeated options). */
  EXPECT_TRUE(chmod_apply(0644, "g+w,u+x", &result));
  EXPECT_EQ_INT((int)(result & 07777), 0764);
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
  file_restore_symlink_metadata(link, &applied, (FileAttrPolicy){false, true, false, false}, false);
  struct stat st;
  EXPECT_EQ_INT(lstat(link, &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));
  bool symlink_times_supported = ((int)st.st_mtime == 1000000000);
  time_t t1 = st.st_mtime;

  /* -J: a different time must be left untouched. */
  FileMetadata newer = {.mtime_sec = 1234567890, .mtime_nsec = 0};
  file_restore_symlink_metadata(link, &newer, (FileAttrPolicy){false, true, false, false}, true);
  EXPECT_EQ_INT(lstat(link, &st), 0);
  EXPECT_EQ_INT((int)st.st_mtime, (int)t1);
  if (symlink_times_supported)
    EXPECT_EQ_INT((int)st.st_mtime, 1000000000);

  unlink(link);
  unlink(target);
  rmdir(dir);
}

/* Per-attribute gating of the descriptor restore path: -p alone applies the
 * mode, -t alone the mtime, -U alone the atime, and an all-off policy leaves
 * the destination's mode and times exactly as they are.  This pins the fd API
 * the receiver actually uses (the path-based file_restore_metadata has its own
 * split test). */
static void test_file_restore_metadata_fd_attribute_split() {
  identity_clear_active(); /* no ownership policy leaking from a previous test */
  const char* path = "temp_meta_fd_split_test.txt";
  EXPECT_TRUE(file_write_to_disk(path, "x", 1, false, false));
  EXPECT_EQ_INT(chmod(path, 0640), 0);
  int fd = open(path, O_RDWR);
  EXPECT_TRUE(fd >= 0);
  /* cppcheck-suppress knownConditionTrueFalse -- EXPECT_TRUE above asserts,
     but cppcheck cannot see through the macro; the guard is defensive. */
  if (fd < 0) {
    unlink(path);
    return;
  }

  FileMetadata m = {.mode = 0755,
                    .uid = getuid(),
                    .gid = getgid(),
                    .mtime_sec = 1234567890,
                    .mtime_nsec = 0,
                    .atime_valid = true,
                    .atime_sec = 999999999,
                    .atime_nsec = 0,
                    .crtime_valid = false};
  struct stat st;
  struct stat before;

  /* perms-only: mode applied, mtime untouched. */
  EXPECT_EQ_INT(fstat(fd, &before), 0);
  EXPECT_TRUE(file_restore_metadata_fd(fd, &m, (FileAttrPolicy){true, false, false, false}));
  EXPECT_EQ_INT(fstat(fd, &st), 0);
  EXPECT_EQ_INT(st.st_mode & 0777, 0755);
  EXPECT_EQ_INT((int)st.st_mtime, (int)before.st_mtime);

  /* times-only: mtime applied, mode untouched. */
  EXPECT_EQ_INT(chmod(path, 0600), 0);
  EXPECT_TRUE(file_restore_metadata_fd(fd, &m, (FileAttrPolicy){false, true, false, false}));
  EXPECT_EQ_INT(fstat(fd, &st), 0);
  EXPECT_EQ_INT(st.st_mode & 0777, 0600);
  EXPECT_EQ_INT((int)st.st_mtime, 1234567890);

  /* atime-only: atime applied, mtime and mode untouched. */
  struct timespec reset[2] = {{.tv_sec = 1000000000, .tv_nsec = 0},
                              {.tv_sec = 1000000000, .tv_nsec = 0}};
  EXPECT_EQ_INT(futimens(fd, reset), 0);
  EXPECT_EQ_INT(fstat(fd, &before), 0);
  EXPECT_TRUE(file_restore_metadata_fd(fd, &m, (FileAttrPolicy){false, false, true, false}));
  EXPECT_EQ_INT(fstat(fd, &st), 0);
  EXPECT_EQ_INT((int)st.st_atime, 999999999);
  EXPECT_EQ_INT((int)st.st_mtime, (int)before.st_mtime);
  EXPECT_EQ_INT(st.st_mode & 0777, 0600);

  /* all-off: neither mode nor either time is touched. */
  EXPECT_EQ_INT(chmod(path, 0640), 0);
  EXPECT_EQ_INT(futimens(fd, reset), 0);
  FileMetadata m2 = m;
  m2.mode = 0700;
  m2.mtime_sec = 1600000000;
  m2.atime_sec = 1700000000;
  EXPECT_TRUE(file_restore_metadata_fd(fd, &m2, (FileAttrPolicy){false, false, false, false}));
  EXPECT_EQ_INT(fstat(fd, &st), 0);
  EXPECT_EQ_INT(st.st_mode & 0777, 0640);
  EXPECT_EQ_INT((int)st.st_mtime, 1000000000);
  EXPECT_EQ_INT((int)st.st_atime, 1000000000);

  close(fd);
  unlink(path);
}

void test_metadata() {
  test_metadata_to_from_buf_roundtrip();
  test_metadata_to_buf_null();
  test_metadata_from_buf_null();
  test_metadata_from_buf_bounds();
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
  test_file_restore_executability_rsync_rule();
  test_metadata_mode_for_policy();
  test_new_file_mode_from_source_and_umask();
  test_file_restore_attribute_split();
  test_file_restore_metadata_fd_attribute_split();
  test_file_attr_policy_from_config();
  test_file_restore_symlink_metadata();
  test_perms_preserves_special_bits();
  test_chmod_changes();
}
