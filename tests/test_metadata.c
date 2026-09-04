#include "test_metadata.h"
#include "metadata.h"
#include "protocol.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_metadata_to_from_buf_roundtrip() {
  FileMetadata original;
  original.mode = 0755;
  original.uid = 1000;
  original.gid = 1000;
  original.mtime_sec = 1234567890;
  original.mtime_nsec = 500000000;

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

static void test_metadata_mtime_window() {
  EXPECT_TRUE(metadata_mtime_matches(100, 100000000, 101, 600000000, 2));
  EXPECT_FALSE(metadata_mtime_matches(100, 100000000, 102, 600000000, 2));
  EXPECT_TRUE(metadata_mtime_matches(100, 100000000, 102, 100000000, 2));
  EXPECT_TRUE(metadata_mtime_matches(100, 900000000, 102, 100000000, 2));
  EXPECT_FALSE(metadata_mtime_matches(100, 100000000, 102, 900000000, 2));
  EXPECT_TRUE(metadata_mtime_matches(100, 900000000, 102, 900000000, 2));
  EXPECT_FALSE(metadata_mtime_matches(100, 900000000, 101, 100000001, 0));
  EXPECT_FALSE(metadata_mtime_matches(100, 100000000, 100, 100000001, 0));
  EXPECT_TRUE(metadata_mtime_matches(100, 100000000, 100, 100000000, 0));
}

static void test_file_restore_metadata() {
  const char* path = "temp_meta_restore_test.txt";
  const char* content = "test content";
  EXPECT_TRUE(file_write_to_disk(path, content, strlen(content), false, false));

  FileMetadata m;
  m.mode = 0644;
  m.uid = getuid();
  m.gid = getgid();
  m.mtime_sec = 1234567890;
  m.mtime_nsec = 0;

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

void test_metadata() {
  test_metadata_to_from_buf_roundtrip();
  test_metadata_to_buf_null();
  test_metadata_from_buf_null();
  test_metadata_send_receive_roundtrip();
  test_metadata_send_null();
  test_metadata_rejects_invalid_values();
  test_metadata_mtime_window();
  test_file_restore_metadata();
  test_file_restore_executability_only();
  test_directory_restore_executability_only();
}
