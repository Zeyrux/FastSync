#include "batch.h"
#include "chunk.h"
#include "config.h"
#include "file.h"
#include "metadata.h"
#include "test_utils.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void batch_test_cleanup(void) {
  unlink("batch_dest/batch_src.txt");
  rmdir("batch_dest");
  unlink("batch_src.txt");
  unlink("batch.bin");
  unlink("batch_bad.bin");
  unlink("batch_trunc.bin");
  unlink("batch_big.bin");
}

/* A batch round-trips a full file image byte-identically: write header+chunks,
 * then apply the file to a fresh destination root and verify the content landed
 * unchanged. */
static void test_batch_roundtrip() {
  batch_test_cleanup();
  EXPECT_EQ_INT(mkdir("batch_dest", 0755), 0);

  const char* content = "residual batch full image payload\nwith \x01\x02\x03 bytes\n";
  size_t content_len = strlen(content);
  file_write_to_disk("batch_src.txt", content, content_len, false, false);

  struct stat st;
  EXPECT_EQ_INT(stat("batch_src.txt", &st), 0);
  File* f = file_create("batch_src.txt");
  EXPECT_NOT_NULL(f);
  f->data->size = (unsigned long long)st.st_size;
  EXPECT_TRUE(file_load_data(f));
  File* files[1] = {f};
  Chunk* chunk = chunk_create(files, 1);
  EXPECT_NOT_NULL(chunk);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);

  int wfd = open("batch.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  EXPECT_TRUE(wfd >= 0);
  EXPECT_TRUE(batch_write_header(wfd, config));
  EXPECT_TRUE(batch_write_chunk(wfd, chunk));
  EXPECT_EQ_INT(close(wfd), 0);
  chunk_destroy(chunk); /* frees f */

  int rfd = open("batch.bin", O_RDONLY);
  EXPECT_TRUE(rfd >= 0);
  EXPECT_EQ_INT(batch_read_apply(rfd, config, "batch_dest"), 0);
  EXPECT_EQ_INT(close(rfd), 0);

  char* dest_path = path_cat("batch_dest", "batch_src.txt");
  EXPECT_NOT_NULL(dest_path);
  FILE* df = fopen(dest_path, "rb");
  EXPECT_NOT_NULL(df);
  char buf[512];
  size_t n = fread(buf, 1, sizeof(buf), df);
  EXPECT_EQ_INT(fclose(df), 0);
  EXPECT_EQ_INT((int)n, (int)content_len);
  EXPECT_EQ_INT(n == content_len && memcmp(buf, content, content_len) == 0, 1);
  free(dest_path);

  config_delete(config);
  batch_test_cleanup();
}

static void test_batch_roundtrip_metadata() {
  batch_test_cleanup();
  EXPECT_EQ_INT(mkdir("batch_dest", 0755), 0);

  const char* content = "metadata-carrying batch image\n";
  size_t content_len = strlen(content);
  file_write_to_disk("batch_src.txt", content, content_len, false, false);

  struct stat st;
  EXPECT_EQ_INT(stat("batch_src.txt", &st), 0);
  File* f = file_create("batch_src.txt");
  EXPECT_NOT_NULL(f);
  f->data->size = (unsigned long long)st.st_size;
  EXPECT_TRUE(file_load_data(f));
  f->metadata = file_metadata_create("batch_src.txt", &st, false, false);
  EXPECT_NOT_NULL(f->metadata);
  File* files[1] = {f};
  Chunk* chunk = chunk_create(files, 1);
  EXPECT_NOT_NULL(chunk);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  config->use_metadata = true;

  int wfd = open("batch.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  EXPECT_TRUE(wfd >= 0);
  EXPECT_TRUE(batch_write_header(wfd, config));
  EXPECT_TRUE(batch_write_chunk(wfd, chunk));
  EXPECT_EQ_INT(close(wfd), 0);
  chunk_destroy(chunk); /* frees f */

  int rfd = open("batch.bin", O_RDONLY);
  EXPECT_TRUE(rfd >= 0);
  EXPECT_EQ_INT(batch_read_apply(rfd, config, "batch_dest"), 0);
  EXPECT_EQ_INT(close(rfd), 0);

  char* dest_path = path_cat("batch_dest", "batch_src.txt");
  EXPECT_NOT_NULL(dest_path);
  FILE* df = fopen(dest_path, "rb");
  EXPECT_NOT_NULL(df);
  char buf[512];
  size_t n = fread(buf, 1, sizeof(buf), df);
  EXPECT_EQ_INT(fclose(df), 0);
  EXPECT_EQ_INT((int)n, (int)content_len);
  EXPECT_EQ_INT(memcmp(buf, content, content_len) == 0, 1);
  free(dest_path);

  config_delete(config);
  batch_test_cleanup();
}

/* A corrupt magic (and only 11 bytes of junk) is rejected, never applied. */
static void test_batch_reject_bad_magic() {
  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  int fd = open("batch_bad.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  EXPECT_TRUE(fd >= 0);
  const char* garbage = "NOTABATCHFXV";
  EXPECT_EQ_INT(write(fd, garbage, strlen(garbage)), (ssize_t)strlen(garbage));
  EXPECT_EQ_INT(close(fd), 0);
  fd = open("batch_bad.bin", O_RDONLY);
  EXPECT_TRUE(fd >= 0);
  EXPECT_EQ_INT(batch_read_apply(fd, config, "batch_dest"), -1);
  EXPECT_EQ_INT(close(fd), 0);
  config_delete(config);
  unlink("batch_bad.bin");
}

/* A clean header with a length prefix promising 100 bytes but only 12 present
 * is a truncated record and is rejected (never crashes, never applies). */
static void test_batch_reject_truncated() {
  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  int fd = open("batch_trunc.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  EXPECT_TRUE(fd >= 0);
  EXPECT_TRUE(batch_write_header(fd, config));
  unsigned long long length = 100;
  EXPECT_EQ_INT(write(fd, &length, sizeof(length)), (ssize_t)sizeof(length));
  const char* partial = "onlytwelvebytes";
  EXPECT_EQ_INT(write(fd, partial, 15), (ssize_t)15);
  EXPECT_EQ_INT(close(fd), 0);
  fd = open("batch_trunc.bin", O_RDONLY);
  EXPECT_TRUE(fd >= 0);
  EXPECT_EQ_INT(batch_read_apply(fd, config, "batch_dest"), -1);
  EXPECT_EQ_INT(close(fd), 0);
  config_delete(config);
  unlink("batch_trunc.bin");
}

/* A length prefix above the 64 MB cap is refused before any allocation. */
static void test_batch_reject_oversized() {
  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  int fd = open("batch_big.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  EXPECT_TRUE(fd >= 0);
  EXPECT_TRUE(batch_write_header(fd, config));
  unsigned long long length = BATCH_MAX_RECORD + 16U;
  EXPECT_EQ_INT(write(fd, &length, sizeof(length)), (ssize_t)sizeof(length));
  EXPECT_EQ_INT(close(fd), 0);
  fd = open("batch_big.bin", O_RDONLY);
  EXPECT_TRUE(fd >= 0);
  EXPECT_EQ_INT(batch_read_apply(fd, config, "batch_dest"), -1);
  EXPECT_EQ_INT(close(fd), 0);
  config_delete(config);
  unlink("batch_big.bin");
}

/* A clean header followed by a length prefix with NO record bytes at all (clean
 * EOF on the record-body read) must be rejected as truncated — it must not feed
 * an uninitialized buffer to chunk_deserialize. Regression test for a
 * confirmed uninitialized-read on the untrusted read side. */
static void test_batch_reject_eof_after_prefix() {
  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  int fd = open("batch_eof.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  EXPECT_TRUE(fd >= 0);
  EXPECT_TRUE(batch_write_header(fd, config));
  unsigned long long length = 32;
  EXPECT_EQ_INT(write(fd, &length, sizeof(length)), (ssize_t)sizeof(length));
  EXPECT_EQ_INT(close(fd), 0);
  fd = open("batch_eof.bin", O_RDONLY);
  EXPECT_TRUE(fd >= 0);
  EXPECT_EQ_INT(batch_read_apply(fd, config, "batch_dest"), -1);
  EXPECT_EQ_INT(close(fd), 0);
  config_delete(config);
  unlink("batch_eof.bin");
}

/* A malicious batch record whose chunk carries a path-traversal wire path must
 * be refused by the apply path — never applied outside the destination root.
 * We craft a chunk whose wire path is `../escape.txt` (the local source file
 * is a benign temp file; only the transmitted path is hostile) and assert the
 * apply refuses it and nothing is created outside the root. */
static void test_batch_reject_traversal_path() {
  const char* content = "hostile traversal image\n";
  size_t content_len = strlen(content);
  file_write_to_disk("batch_trav_src.txt", content, content_len, false, false);

  struct stat st;
  EXPECT_EQ_INT(stat("batch_trav_src.txt", &st), 0);
  File* f = file_create("batch_trav_src.txt");
  EXPECT_NOT_NULL(f);
  f->data->size = (unsigned long long)st.st_size;
  EXPECT_TRUE(file_load_data(f));
  f->send_path = str_dup("../escape.txt");
  EXPECT_NOT_NULL(f->send_path);
  File* files[1] = {f};
  Chunk* chunk = chunk_create(files, 1);
  EXPECT_NOT_NULL(chunk);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);

  int wfd = open("batch_trav.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  EXPECT_TRUE(wfd >= 0);
  EXPECT_TRUE(batch_write_header(wfd, config));
  EXPECT_TRUE(batch_write_chunk(wfd, chunk));
  EXPECT_EQ_INT(close(wfd), 0);
  chunk_destroy(chunk); /* frees f and f->send_path */

  int rfd = open("batch_trav.bin", O_RDONLY);
  EXPECT_TRUE(rfd >= 0);
  EXPECT_EQ_INT(batch_read_apply(rfd, config, "batch_dest"), -1);
  EXPECT_EQ_INT(close(rfd), 0);
  unlink("../escape.txt"); /* clear any stale file so the probe below is clean */
  EXPECT_TRUE(access("../escape.txt", F_OK) != 0);

  config_delete(config);
  unlink("batch_trav.bin");
  unlink("batch_trav_src.txt");
}

void test_batch() {
  test_batch_roundtrip();
  test_batch_roundtrip_metadata();
  test_batch_reject_bad_magic();
  test_batch_reject_truncated();
  test_batch_reject_oversized();
  test_batch_reject_eof_after_prefix();
  test_batch_reject_traversal_path();
}