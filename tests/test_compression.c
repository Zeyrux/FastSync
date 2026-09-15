#include "test_utils.h"
#include "chunk.h"
#include "compression.h"
#include "data.h"
#include "file.h"
#include "utils.h"
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <threads.h>
#include <unistd.h>
#include <zstd.h>

static void test_data_compress_decompress_roundtrip() {
  const char original[] = "Hello, World! This is test data for compression round-trip!";
  size_t len = strlen(original);

  char* buf = malloc(len);
  if (!buf)
    return;
  memcpy(buf, original, len);
  Data* original_data = data_create(buf, len);
  EXPECT_NOT_NULL(original_data);

  Data* compressed = data_compress(original_data, 3);
  EXPECT_NOT_NULL(compressed);

  Data* decompressed = data_decompress(compressed);
  EXPECT_NOT_NULL(decompressed);
  EXPECT_EQ_INT((int)decompressed->size, (int)len);
  EXPECT_EQ_INT(memcmp(decompressed->data, original, len), 0);

  data_destroy(original_data);
  data_destroy(compressed);
  data_destroy(decompressed);
}

static void test_data_compress_decompress_large() {
  size_t size = 1024 * 10;
  char* original = malloc(size);
  EXPECT_NOT_NULL(original);
  for (size_t i = 0; i < size; i++)
    original[i] = (char)(i % 256);

  Data* original_data = data_create(original, size);
  EXPECT_NOT_NULL(original_data);

  Data* compressed = data_compress(original_data, 1);
  EXPECT_NOT_NULL(compressed);

  Data* decompressed = data_decompress(compressed);
  EXPECT_NOT_NULL(decompressed);
  EXPECT_EQ_INT((int)decompressed->size, (int)size);
  EXPECT_EQ_INT(memcmp(decompressed->data, original, size), 0);

  data_destroy(original_data);
  data_destroy(compressed);
  data_destroy(decompressed);
}

static void test_skip_compress_suffix_matching() {
  char* suffixes[] = {".ZIP", ".GZ"};
  EXPECT_TRUE(compression_should_skip_with_suffixes("archive.zip", suffixes, 2));
  EXPECT_TRUE(compression_should_skip_with_suffixes("backup.TAR.GZ", suffixes, 2));
  EXPECT_FALSE(compression_should_skip_with_suffixes("notes.txt", suffixes, 2));
  EXPECT_FALSE(compression_should_skip_with_suffixes("archive.zip", suffixes, 0));

  /* A user suffix may omit the leading dot (rsync's spelling). */
  char* bare[] = {"zip", "gz"};
  EXPECT_TRUE(compression_should_skip_with_suffixes("archive.zip", bare, 2));
  EXPECT_TRUE(compression_should_skip_with_suffixes("x.GZ", bare, 2));

  /* No user list (count < 0) selects rsync 3.4.1's built-in default list. */
  EXPECT_TRUE(compression_should_skip_with_suffixes("movie.mp4", NULL, -1));
  EXPECT_TRUE(compression_should_skip_with_suffixes("archive.TAR.GZ", NULL, -1));
  EXPECT_TRUE(compression_should_skip_with_suffixes("photo.jpeg", NULL, -1));
  EXPECT_TRUE(compression_should_skip_with_suffixes("disk.squashfs", NULL, -1));
  EXPECT_TRUE(compression_should_skip_with_suffixes("data.7z", NULL, -1));
  EXPECT_FALSE(compression_should_skip_with_suffixes("notes.txt", NULL, -1));
  EXPECT_FALSE(compression_should_skip_with_suffixes("program", NULL, -1));
  EXPECT_FALSE(compression_should_skip_with_suffixes("trailing.", NULL, -1));
}

static void test_data_compress_with_threads_roundtrip() {
  const size_t size = 8 * 1024 * 1024;
  Data* input = data_create_empty(size);
  EXPECT_NOT_NULL(input);
  for (size_t i = 0; i < size; i++)
    ((char*)input->data)[i] = (char)((i / 4096) % 7);
  Data* compressed = data_compress_with_threads(input, 3, 2);
  EXPECT_NOT_NULL(compressed);
  Data* decompressed = data_decompress(compressed);
  EXPECT_NOT_NULL(decompressed);
  EXPECT_EQ_INT((int)decompressed->size, (int)size);
  EXPECT_EQ_INT(memcmp(decompressed->data, input->data, size), 0);
  data_destroy(input);
  data_destroy(compressed);
  data_destroy(decompressed);
}

static void test_chunk_compress_decompress_roundtrip() {
  char* path1 = "temp_comp_test_1.txt";
  char* content1 = "chunk compression test file 1";
  unsigned long long len1 = strlen(content1);

  char* path2 = "temp_comp_test_2.txt";
  char* content2 = "chunk compression test file 2 with more data";
  unsigned long long len2 = strlen(content2);

  file_write_to_disk(path1, content1, len1, false, false);
  file_write_to_disk(path2, content2, len2, false, false);

  struct stat st1, st2;
  EXPECT_EQ_INT(stat(path1, &st1), 0);
  EXPECT_EQ_INT(stat(path2, &st2), 0);

  File* f1 = file_create(path1);
  f1->data->size = st1.st_size;
  File* f2 = file_create(path2);
  f2->data->size = st2.st_size;
  EXPECT_NOT_NULL(f1);
  EXPECT_NOT_NULL(f2);

  file_load_data(f1);
  file_load_data(f2);

  File* files[2] = {f1, f2};
  Chunk* chunk = chunk_create(files, 2);
  EXPECT_NOT_NULL(chunk);

  Data* compressed = chunk_compress(chunk, 3, false);
  EXPECT_NOT_NULL(compressed);

  Data* decompressed_data = data_decompress(compressed);
  EXPECT_NOT_NULL(decompressed_data);

  Chunk* decompressed_chunk = chunk_deserialize(decompressed_data, false);
  EXPECT_NOT_NULL(decompressed_chunk);
  EXPECT_EQ_INT(decompressed_chunk->element_count, 2);

  EXPECT_EQ_STR(decompressed_chunk->items[0]->path, path1);
  EXPECT_EQ_INT((int)decompressed_chunk->items[0]->data->size, (int)len1);
  EXPECT_EQ_INT(memcmp(decompressed_chunk->items[0]->data->data, content1, len1), 0);

  EXPECT_EQ_STR(decompressed_chunk->items[1]->path, path2);
  EXPECT_EQ_INT((int)decompressed_chunk->items[1]->data->size, (int)len2);
  EXPECT_EQ_INT(memcmp(decompressed_chunk->items[1]->data->data, content2, len2), 0);

  chunk_destroy(chunk);
  data_destroy(compressed);
  data_destroy(decompressed_data);
  chunk_destroy(decompressed_chunk);

  unlink(path1);
  unlink(path2);
}

/* Build a zstd frame whose header omits the content size (the content size
 * flag is cleared), which ZSTD_getFrameContentSize reports as
 * ZSTD_CONTENTSIZE_UNKNOWN. */
static Data* make_unknown_size_frame(const void* src, size_t len) {
  ZSTD_CCtx* cctx = ZSTD_createCCtx();
  if (!cctx)
    return NULL;
  ZSTD_CCtx_setParameter(cctx, ZSTD_c_contentSizeFlag, 0);
  size_t cap = ZSTD_compressBound(len);
  Data* out = data_create_empty(cap);
  if (!out) {
    ZSTD_freeCCtx(cctx);
    return NULL;
  }
  ZSTD_inBuffer in = {src, len, 0};
  ZSTD_outBuffer ob = {out->data, cap, 0};
  size_t ret;
  do {
    ret = ZSTD_compressStream2(cctx, &ob, &in, ZSTD_e_end);
    if (ZSTD_isError(ret)) {
      data_destroy(out);
      ZSTD_freeCCtx(cctx);
      return NULL;
    }
  } while (ret > 0);
  out->size = ob.pos;
  ZSTD_freeCCtx(cctx);
  return out;
}

/* ZSTD_CONTENTSIZE_UNKNOWN is flagged by ZSTD_isError(), so a naive
 * ZSTD_isError() check rejects every unknown-size frame.  Such a frame must
 * instead reach the 3x estimate fallback and decompress correctly. */
static void test_data_decompress_unknown_size_frame() {
  const char original[] = "unknown-content-size frame: the decompressor must use the 3x estimate, "
                          "not reject the frame as an error.";
  size_t len = strlen(original);
  char* buf = malloc(len);
  EXPECT_NOT_NULL(buf);
  memcpy(buf, original, len);

  Data* frame = make_unknown_size_frame(buf, len);
  free(buf);
  EXPECT_NOT_NULL(frame);
  /* Guard the premise of the test: the frame really has no stored size. */
  EXPECT_EQ_INT((int)ZSTD_getFrameContentSize(frame->data, frame->size),
                (int)ZSTD_CONTENTSIZE_UNKNOWN);

  Data* decompressed = data_decompress(frame);
  EXPECT_NOT_NULL(decompressed);
  EXPECT_EQ_INT((int)decompressed->size, (int)len);
  EXPECT_EQ_INT(memcmp(decompressed->data, original, len), 0);

  data_destroy(decompressed);
  data_destroy(frame);
}

typedef struct {
  int id;
  int iterations;
  bool ok;
} CompressionThreadArg;

/* Each worker exercises the per-thread cached zstd contexts: several
 * compress/decompress round-trips with varying payload sizes, levels and
 * worker counts so the context is reused (and its parameters re-applied)
 * across calls, concurrently with other workers. */
static int compression_reuse_worker(void* arg) {
  CompressionThreadArg* a = (CompressionThreadArg*)arg;
  a->ok = true;
  for (int it = 0; it < a->iterations; it++) {
    size_t size = 512 + (size_t)((a->id * 7919 + it * 104729) % (48 * 1024));
    char* original = malloc(size);
    if (!original) {
      a->ok = false;
      break;
    }
    for (size_t i = 0; i < size; i++)
      original[i] = (char)((i * 31 + (size_t)a->id + (size_t)it * 7) % 251);
    Data* input = data_create(original, size);
    if (!input) { /* data_create takes ownership of original, even on failure */
      a->ok = false;
      break;
    }
    int level = 1 + ((it / 2) % 5);
    int threads = ((it / 2) % 2 == 0) ? 2 : 0;
    Data* compressed = data_compress_with_threads(input, level, threads);
    if (!compressed) {
      data_destroy(input);
      a->ok = false;
      break;
    }
    Data* decompressed = data_decompress(compressed);
    bool roundtrip_ok = decompressed != NULL && decompressed->size == size &&
                        memcmp(decompressed->data, original, size) == 0;
    data_destroy(decompressed);
    data_destroy(compressed);
    data_destroy(input);
    if (!roundtrip_ok) {
      a->ok = false;
      break;
    }
  }
  /* Deliberately do NOT free the thread context here: the C11 tss destructor
   * must release it when this thread exits (validated by LeakSanitizer). */
  return thrd_success;
}

static void test_data_compress_reused_contexts_multithreaded() {
  enum { NTHREADS = 8, ITERATIONS = 6 };
  thrd_t threads[NTHREADS];
  CompressionThreadArg args[NTHREADS];
  bool all_created = true;
  for (int i = 0; i < NTHREADS; i++) {
    args[i].id = i;
    args[i].iterations = ITERATIONS;
    args[i].ok = false;
    if (thrd_create(&threads[i], compression_reuse_worker, &args[i]) != thrd_success) {
      all_created = false;
      break;
    }
  }
  EXPECT_TRUE(all_created);
  for (int i = 0; i < NTHREADS; i++)
    EXPECT_EQ_INT(thrd_join(threads[i], NULL), thrd_success);
  for (int i = 0; i < NTHREADS; i++)
    EXPECT_TRUE(args[i].ok);
  compression_free_thread_contexts();
}

/* A truncated zstd frame used to make the decompressor spin forever: the
 * stream call keeps returning a positive hint with all input consumed.  Run the
 * decompression in a child with an alarm so a regression (infinite loop) is
 * caught as a timeout failure instead of hanging the whole unit suite. */
static void test_data_decompress_truncated_frame_fails() {
  const char* original =
      "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
  size_t len = strlen(original);
  char* buf = malloc(len);
  EXPECT_NOT_NULL(buf);
  memcpy(buf, original, len);
  Data* input = data_create(buf, len);
  EXPECT_NOT_NULL(input);

  pid_t pid = fork();
  EXPECT_TRUE(pid >= 0);
  if (pid == 0) {
    alarm(10); /* kills the child if the decompressor hangs */
    Data* compressed = data_compress(input, 3);
    if (compressed && compressed->size > 1) {
      compressed->size -= 1; /* drop the final byte: frame is now incomplete */
      Data* out = data_decompress(compressed);
      bool failed_cleanly = (out == NULL);
      data_destroy(out);
      data_destroy(compressed);
      /* The child inherited `input` across fork(); free it before _exit so the
       * valgrind CI job (which instruments forked children too) sees no leak. */
      data_destroy(input);
      _exit(failed_cleanly ? 0 : 1);
    }
    data_destroy(compressed);
    data_destroy(input);
    _exit(2);
  }
  int status;
  waitpid(pid, &status, 0);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  data_destroy(input);
}

void test_compression() {
  test_data_compress_decompress_roundtrip();
  test_data_compress_decompress_large();
  test_data_decompress_unknown_size_frame();
  test_data_decompress_truncated_frame_fails();
  test_skip_compress_suffix_matching();
  test_data_compress_with_threads_roundtrip();
  test_data_compress_reused_contexts_multithreaded();
  test_chunk_compress_decompress_roundtrip();
}
