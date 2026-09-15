#include "test_fuzz_smoke.h"
#include "chunk.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delta.h"
#include "metadata.h"
#include "protocol.h"
#include "test_utils.h"
#include "utils.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* P8 config-frame tail: super_mode (4) + copy-as presence (4) + uid (4) + gid (4). */
#define P8_TAIL_BYTES 16
/* Protocol 2.23.0 appends one trailing bool (report_dest_info) AFTER the P8
 * tail, so the P8 fields sit this many bytes before the end of the frame. */
#define OUTPUT_TAIL_BYTES 4

/* Smoke test for chunk_deserialize fuzz target */
static void test_fuzz_chunk_deserialize() {
  /* Create a minimal valid chunk to serialize and deserialize */
  File* file = file_create("fuzz_test.txt");
  EXPECT_NOT_NULL(file);
  const char* content = "fuzz data";
  file->data->data = malloc(strlen(content));
  EXPECT_NOT_NULL(file->data->data);
  memcpy(file->data->data, content, strlen(content));
  file->data->size = strlen(content);

  File* chunk_files[] = {file};
  Chunk* chunk = chunk_create(chunk_files, 1);
  EXPECT_NOT_NULL(chunk);

  Data* serialized = chunk_serialize(chunk, true);
  EXPECT_NOT_NULL(serialized);

  /* Now deserialize (this is what the fuzzer does) */
  Chunk* deserialized = chunk_deserialize(serialized, true);
  EXPECT_NOT_NULL(deserialized);
  EXPECT_EQ_INT(deserialized->element_count, 1);

  chunk_destroy(deserialized);
  data_destroy(serialized);
  /* chunk_destroy will also destroy the file added to chunk */
  chunk_destroy(chunk);
}

/* Smoke test for compress/decompress fuzz target */
static void test_fuzz_compress_decompress() {
  const char* test_data_str = "Hello, this is some test data for compression fuzzing!";
  size_t len = strlen(test_data_str);
  void* test_data = malloc(len);
  EXPECT_NOT_NULL(test_data);
  memcpy(test_data, test_data_str, len);

  Data* original = data_create(test_data, len);
  EXPECT_NOT_NULL(original);

  /* Compress at level 3 */
  Data* compressed = data_compress(original, 3);
  EXPECT_NOT_NULL(compressed);

  /* Decompress */
  Data* decompressed = data_decompress(compressed);
  EXPECT_NOT_NULL(decompressed);
  EXPECT_EQ_INT((int)decompressed->size, (int)len);
  EXPECT_EQ_INT(memcmp(decompressed->data, test_data, len), 0);

  data_destroy(decompressed);
  data_destroy(compressed);
  data_destroy(original);
}

/* Smoke test for delta_deserialize fuzz target */
static void test_fuzz_delta_deserialize() {
  /* Create two buffers of data */
  const char* old_data_str = "Hello, World!";
  const char* new_data_str = "Hello, Delta!";
  size_t old_len = strlen(old_data_str);
  size_t new_len = strlen(new_data_str);

  /* Create delta signature from old data */
  DeltaSignature* sig = delta_signature_create((void*)old_data_str, old_len, 64);
  EXPECT_NOT_NULL(sig);

  /* Create delta from signature and new data */
  Delta* delta = delta_compute((void*)new_data_str, new_len, sig, 64);
  EXPECT_NOT_NULL(delta);
  EXPECT_EQ_INT((int)delta->new_file_size, (int)new_len);

  /* Serialize the delta */
  Data* serialized = delta_serialize(delta);
  EXPECT_NOT_NULL(serialized);

  /* Deserialize (this is what the fuzzer does) */
  Delta* deserialized = delta_deserialize(serialized);
  EXPECT_NOT_NULL(deserialized);
  EXPECT_EQ_INT((int)deserialized->new_file_size, (int)new_len);

  delta_destroy(deserialized);
  data_destroy(serialized);
  delta_destroy(delta);
  delta_signature_destroy(sig);
}

/* Smoke test for metadata_from_buf fuzz target */
static void test_fuzz_metadata_from_buf() {
  /* Create a real file to get metadata from */
  EXPECT_TRUE(file_write_to_disk("fuzz_meta_test.txt", "metadata test", 13, false, false));

  struct stat st;
  EXPECT_EQ_INT(stat("fuzz_meta_test.txt", &st), 0);

  FileMetadata* meta = file_metadata_create("fuzz_meta_test.txt", &st, false, false);
  EXPECT_NOT_NULL(meta);
  EXPECT_EQ_INT((int)meta->mode, (int)st.st_mode);
  EXPECT_EQ_INT((int)meta->mtime_sec, (int)st.st_mtime);

  /* Serialize metadata to buffer using the same approach as chunk.c */
  size_t meta_buf_size = sizeof(int32_t) + FILE_METADATA_WIRE_SIZE;
  char* meta_buf = malloc(meta_buf_size);
  EXPECT_NOT_NULL(meta_buf);
  char* meta_ptr = meta_buf;
  metadata_to_buf(&meta_ptr, meta);
  EXPECT_EQ_INT((int)(meta_ptr - meta_buf), (int)meta_buf_size);

  /* Deserialize from buffer (simulates fuzz_metadata_from_buf) */
  FileMetadata* deserialized = metadata_from_buf((const uint8_t*)meta_buf, (size_t)meta_buf_size);
  EXPECT_NOT_NULL(deserialized);
  EXPECT_EQ_INT((int)deserialized->mode, (int)meta->mode);
  EXPECT_EQ_INT((int)deserialized->mtime_sec, (int)meta->mtime_sec);

  file_metadata_destroy(deserialized);
  free(meta_buf);
  file_metadata_destroy(meta);
  unlink("fuzz_meta_test.txt");
}

/* Smoke test for delta_signature_deserialize fuzz target */
static void test_fuzz_delta_signature_deserialize() {
  const char* data_str = "Test data for signature";
  size_t len = strlen(data_str);

  DeltaSignature* sig = delta_signature_create((void*)data_str, len, 64);
  EXPECT_NOT_NULL(sig);

  /* Serialize */
  Data* serialized = delta_signature_serialize(sig);
  EXPECT_NOT_NULL(serialized);

  /* Deserialize (simulates what the fuzzer tests) */
  DeltaSignature* deserialized = delta_signature_deserialize(serialized);
  EXPECT_NOT_NULL(deserialized);
  EXPECT_EQ_INT((int)deserialized->block_size, 64);

  delta_signature_destroy(deserialized);
  data_destroy(serialized);
  delta_signature_destroy(sig);
}

/* Smoke test for glob_match fuzz target */
static void test_fuzz_glob_match() {
  /* Test various pattern matches */
  EXPECT_TRUE(glob_match("*.txt", "file.txt"));
  /* Glob is case-sensitive on this platform */
  EXPECT_TRUE(glob_match("*.txt", "file.txt"));
  EXPECT_FALSE(glob_match("*.txt", "file.TXT"));
  EXPECT_FALSE(glob_match("*.txt", "file.c"));
  EXPECT_TRUE(glob_match("data?", "data1"));
  EXPECT_TRUE(glob_match("data?", "dataX"));
  EXPECT_FALSE(glob_match("data?", "data12"));
  EXPECT_TRUE(glob_match("src/**/*.c", "src/main.c"));
  EXPECT_TRUE(glob_match("**/test*.py", "src/tests/test_foo.py"));
  EXPECT_FALSE(glob_match("*.md", "readme.txt"));
}

/* ---- Deterministic config-frame receive hardening (P8) ----
 *
 * The P8 tail (--super / --copy-as) and the identity-map count only parse after
 * the entire preceding frame validates, which random bytes almost never reach.
 * These tests capture one valid frame with the production sender and then
 * mutate/truncate the exact tail bytes. */

/* Serialize cfg with the production sender into a heap buffer.  The frame is
 * written into a pipe (64 KiB kernel buffer, far larger than one config frame)
 * whose read end is drained afterwards; the required STATUS_OK ack is
 * pre-loaded into a second pipe, so a single thread suffices. */
static bool capture_config_frame(const Config* cfg, unsigned char** out, size_t* out_len) {
  *out = NULL;
  *out_len = 0;

  int frame_pipe[2];
  int status_pipe[2];
  if (pipe(frame_pipe) != 0)
    return false;
  if (pipe(status_pipe) != 0) {
    close(frame_pipe[0]);
    close(frame_pipe[1]);
    return false;
  }

  int ack = STATUS_OK;
  bool ok = write(status_pipe[1], &ack, sizeof(ack)) == (ssize_t)sizeof(ack);
  if (ok) {
    io_set_fds(status_pipe[0], frame_pipe[1]);
    io_set_bwlimit(0);
    ok = config_send(frame_pipe[1], cfg);
  }
  close(frame_pipe[1]);
  close(status_pipe[0]);
  close(status_pipe[1]);

  unsigned char* buf = NULL;
  if (ok) {
    size_t cap = 4096;
    size_t len = 0;
    buf = malloc(cap);
    if (!buf) {
      ok = false;
    }
    while (ok) {
      if (len == cap) {
        size_t grown = cap * 2;
        unsigned char* bigger = realloc(buf, grown);
        if (!bigger) {
          ok = false;
          break;
        }
        buf = bigger;
        cap = grown;
      }
      ssize_t n = read(frame_pipe[0], buf + len, cap - len);
      if (n > 0) {
        len += (size_t)n;
        continue;
      }
      if (n < 0 && errno == EINTR)
        continue;
      break;
    }
    if (ok && len > 0) {
      *out = buf;
      *out_len = len;
      buf = NULL;
    }
  }
  close(frame_pipe[0]);
  free(buf);
  return *out != NULL;
}

/* Feed a raw config frame to config_receive over a socketpair.  The write half
 * is shut down (not closed) after the data so the receiver sees EOF but its
 * STATUS_ERROR replies do not hit a closed peer. */
static bool receive_config_frame(const unsigned char* buf, size_t len) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    return false;

  size_t off = 0;
  while (off < len) {
    ssize_t n = write(sv[0], buf + off, len - off);
    if (n > 0) {
      off += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR)
      continue;
    break;
  }
  shutdown(sv[0], SHUT_WR);
  io_set_fds(sv[1], sv[1]);
  io_set_bwlimit(0);
  Config* cfg = config_receive(sv[1]);
  bool accepted = cfg != NULL;
  config_delete(cfg);
  close(sv[0]);
  close(sv[1]);
  return accepted;
}

static void put_i32(unsigned char* buf, size_t off, int32_t value) {
  memcpy(buf + off, &value, sizeof(value));
}

static size_t find_bytes(const unsigned char* haystack, size_t haystack_len,
                         const unsigned char* needle, size_t needle_len) {
  if (needle_len == 0 || haystack_len < needle_len)
    return SIZE_MAX;
  for (size_t i = 0; i + needle_len <= haystack_len; i++) {
    if (memcmp(haystack + i, needle, needle_len) == 0)
      return i;
  }
  return SIZE_MAX;
}

static Config* make_copy_as_config(void) {
  Config* c = config_create();
  if (!c)
    return NULL;
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->copy_as_set = true;
  c->copy_as_uid = 0;
  c->copy_as_gid = 0;
  c->use_metadata = true; /* --copy-as requires the metadata path */
  return c;
}

/* The P8 tail must reject an out-of-range super_mode, a negative copy-as id and
 * any truncation inside the tail, while the untouched frame is accepted. */
static void test_fuzz_config_receive_p8_tail() {
  Config* c = make_copy_as_config();
  EXPECT_NOT_NULL(c);

  unsigned char* frame = NULL;
  size_t len = 0;
  bool captured = capture_config_frame(c, &frame, &len);
  config_delete(c);
  if (!captured || len <= P8_TAIL_BYTES) {
    free(frame);
    EXPECT_TRUE(false);
    return;
  }

  /* Baseline: the untouched frame is accepted. */
  EXPECT_TRUE(receive_config_frame(frame, len));

  unsigned char* mut = malloc(len);
  EXPECT_NOT_NULL(mut);

  /* super_mode outside the 0..2 tri-state is refused. */
  memcpy(mut, frame, len);
  put_i32(mut, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES, 99);
  EXPECT_FALSE(receive_config_frame(mut, len));
  put_i32(mut, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES, -1);
  EXPECT_FALSE(receive_config_frame(mut, len));

  /* A negative (sentinel) and an extreme copy-as uid/gid are refused. */
  memcpy(mut, frame, len);
  put_i32(mut, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES, SUPER_MODE_AUTO);
  put_i32(mut, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES + 4, 1);
  put_i32(mut, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES + 8, -1);
  put_i32(mut, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES + 12, 0);
  EXPECT_FALSE(receive_config_frame(mut, len));
  put_i32(mut, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES + 8, 0);
  put_i32(mut, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES + 12, INT32_MIN);
  EXPECT_FALSE(receive_config_frame(mut, len));

  /* A presence int that is not a wire bool is refused. */
  memcpy(mut, frame, len);
  put_i32(mut, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES, SUPER_MODE_AUTO);
  put_i32(mut, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES + 4, 2);
  EXPECT_FALSE(receive_config_frame(mut, len));

  /* Truncating anywhere inside the P8 tail is refused. */
  EXPECT_FALSE(receive_config_frame(frame, len - 2));
  EXPECT_FALSE(receive_config_frame(frame, len - OUTPUT_TAIL_BYTES - P8_TAIL_BYTES));

  free(mut);
  free(frame);
}

/* A huge or negative --usermap count must be refused up front, never driving a
 * giant allocation.  The count is located by searching for a sentinel entry. */
static void test_fuzz_config_receive_huge_map_count() {
  Config* c = make_copy_as_config();
  EXPECT_NOT_NULL(c);
  int32_t sentinel_from = 0x11223344;
  int32_t sentinel_to = 0x55667788;
  c->usermap = malloc(sizeof(IdentityMap));
  if (!c->usermap) {
    config_delete(c);
    EXPECT_TRUE(false);
    return;
  }
  c->usermap_count = 1;
  c->usermap[0].from = sentinel_from;
  c->usermap[0].from_hi = sentinel_from;
  c->usermap[0].to = sentinel_to;
  c->usermap[0].to_name = NULL;

  unsigned char* frame = NULL;
  size_t len = 0;
  bool captured = capture_config_frame(c, &frame, &len);
  config_delete(c);
  if (!captured) {
    EXPECT_TRUE(false);
    return;
  }

  /* One wire entry is [from][from_hi][to][to_name]; search the fixed-width
     prefix (the to_name length-prefixed string follows). */
  unsigned char pattern[12];
  memcpy(pattern, &sentinel_from, sizeof(sentinel_from));
  memcpy(pattern + sizeof(sentinel_from), &sentinel_from, sizeof(sentinel_from));
  memcpy(pattern + 2 * sizeof(sentinel_from), &sentinel_to, sizeof(sentinel_to));
  size_t entry_off = find_bytes(frame, len, pattern, sizeof(pattern));
  if (entry_off == SIZE_MAX || entry_off < sizeof(int32_t)) {
    free(frame);
    EXPECT_TRUE(false);
    return;
  }
  size_t count_off = entry_off - sizeof(int32_t);

  /* Baseline accepted. */
  EXPECT_TRUE(receive_config_frame(frame, len));

  unsigned char* mut = malloc(len);
  EXPECT_NOT_NULL(mut);
  memcpy(mut, frame, len);
  put_i32(mut, count_off, INT_MAX);
  EXPECT_FALSE(receive_config_frame(mut, len));
  put_i32(mut, count_off, -1);
  EXPECT_FALSE(receive_config_frame(mut, len));
  put_i32(mut, count_off, MAX_IDENTITY_MAP + 1);
  EXPECT_FALSE(receive_config_frame(mut, len));

  free(mut);
  free(frame);
}

/* A mismatched version and a matching version followed by a wrong-order field
 * (an int that is not a wire bool) are both refused at/just after the gate. */
static void test_fuzz_config_receive_version_gate() {
  unsigned char buf[64];

  size_t off = 0;
  const char* bad_version = "1.2.3";
  size_t bad_len = strlen(bad_version);
  memcpy(buf + off, &bad_len, sizeof(bad_len));
  off += sizeof(bad_len);
  memcpy(buf + off, bad_version, bad_len);
  off += bad_len;
  EXPECT_FALSE(receive_config_frame(buf, off));

  off = 0;
  size_t good_len = strlen(PROTOCOL_VERSION);
  memcpy(buf + off, &good_len, sizeof(good_len));
  off += sizeof(good_len);
  memcpy(buf + off, PROTOCOL_VERSION, good_len);
  off += good_len;
  put_i32(buf, off, -1);
  off += sizeof(int32_t);
  EXPECT_FALSE(receive_config_frame(buf, off));
}

void test_fuzz_smoke() {
  test_fuzz_chunk_deserialize();
  test_fuzz_compress_decompress();
  test_fuzz_delta_deserialize();
  test_fuzz_metadata_from_buf();
  test_fuzz_delta_signature_deserialize();
  test_fuzz_glob_match();
  test_fuzz_config_receive_p8_tail();
  test_fuzz_config_receive_huge_map_count();
  test_fuzz_config_receive_version_gate();
}
