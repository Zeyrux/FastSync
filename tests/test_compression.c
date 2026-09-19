#include "test_utils.h"
#include "chunk.h"
#include "compression.h"
#include "data.h"
#include "file.h"
#include "utils.h"
#include <stdlib.h>
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
 * ZSTD_CONTENTSIZE_UNKNOWN.  The frame carries the codec-id prefix the
 * decompressor dispatches on. */
static Data* make_unknown_size_frame(const void* src, size_t len) {
  ZSTD_CCtx* cctx = ZSTD_createCCtx();
  if (!cctx)
    return NULL;
  ZSTD_CCtx_setParameter(cctx, ZSTD_c_contentSizeFlag, 0);
  size_t cap = ZSTD_compressBound(len);
  Data* out = data_create_empty(cap + 1);
  if (!out) {
    ZSTD_freeCCtx(cctx);
    return NULL;
  }
  ((uint8_t*)out->data)[0] = (uint8_t)COMPRESSION_ALGO_ZSTD;
  ZSTD_inBuffer in = {src, len, 0};
  ZSTD_outBuffer ob = {(uint8_t*)out->data + 1, cap, 0};
  size_t ret;
  do {
    ret = ZSTD_compressStream2(cctx, &ob, &in, ZSTD_e_end);
    if (ZSTD_isError(ret)) {
      data_destroy(out);
      ZSTD_freeCCtx(cctx);
      return NULL;
    }
  } while (ret > 0);
  out->size = ob.pos + 1;
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
  /* Guard the premise of the test: the frame (after the codec byte) really has
   * no stored size. */
  EXPECT_EQ_INT((int)ZSTD_getFrameContentSize((uint8_t*)frame->data + 1, frame->size - 1),
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

/* Every codec must round-trip byte-exactly through the self-describing frame,
 * including the empty and a highly compressible large payload. */
static void codec_roundtrip(CompressionAlgo algo) {
  const char* samples[] = {
      "",
      "Hello, World! This is test data for compression round-trip!",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  };
  for (size_t s = 0; s < sizeof(samples) / sizeof(samples[0]); s++) {
    size_t len = strlen(samples[s]);
    Data* original = data_create_empty(len);
    EXPECT_NOT_NULL(original);
    if (len > 0)
      memcpy(original->data, samples[s], len);
    original->size = len;

    Data* compressed = data_compress_codec(original, algo, 3, 0);
    EXPECT_NOT_NULL(compressed);
    EXPECT_EQ_INT((int)((uint8_t*)compressed->data)[0], (int)algo);
    Data* decompressed = data_decompress(compressed);
    EXPECT_NOT_NULL(decompressed);
    EXPECT_EQ_INT((int)decompressed->size, (int)len);
    EXPECT_EQ_INT(memcmp(decompressed->data, original->data, len), 0);
    data_destroy(decompressed);
    data_destroy(compressed);
    data_destroy(original);
  }
}

static void test_codec_roundtrips() {
  codec_roundtrip(COMPRESSION_ALGO_NONE);
  codec_roundtrip(COMPRESSION_ALGO_ZSTD);
  codec_roundtrip(COMPRESSION_ALGO_LZ4);
  codec_roundtrip(COMPRESSION_ALGO_ZLIB);
  codec_roundtrip(COMPRESSION_ALGO_ZLIBX);
}

static void test_codec_name_mapping() {
  EXPECT_EQ_INT(compression_algo_from_name("zstd"), (int)COMPRESSION_ALGO_ZSTD);
  EXPECT_EQ_INT(compression_algo_from_name("ZSTD"), (int)COMPRESSION_ALGO_ZSTD);
  EXPECT_EQ_INT(compression_algo_from_name("lz4"), (int)COMPRESSION_ALGO_LZ4);
  EXPECT_EQ_INT(compression_algo_from_name("zlib"), (int)COMPRESSION_ALGO_ZLIB);
  EXPECT_EQ_INT(compression_algo_from_name("zlibx"), (int)COMPRESSION_ALGO_ZLIBX);
  EXPECT_EQ_INT(compression_algo_from_name("none"), (int)COMPRESSION_ALGO_NONE);
  EXPECT_TRUE(compression_algo_from_name("bogus") < 0);
  EXPECT_TRUE(compression_algo_from_name(NULL) < 0);
  EXPECT_TRUE(compression_algo_valid((int)COMPRESSION_ALGO_LZ4));
  EXPECT_TRUE(compression_algo_valid((int)COMPRESSION_ALGO_ZLIB));
  EXPECT_TRUE(compression_algo_valid((int)COMPRESSION_ALGO_ZLIBX));
  EXPECT_FALSE(compression_algo_valid(99));
  EXPECT_EQ_STR(compression_algo_name(COMPRESSION_ALGO_ZSTD), "zstd");
  EXPECT_EQ_STR(compression_algo_name(COMPRESSION_ALGO_LZ4), "lz4");
  EXPECT_EQ_STR(compression_algo_name(COMPRESSION_ALGO_ZLIB), "zlib");
  EXPECT_EQ_STR(compression_algo_name(COMPRESSION_ALGO_ZLIBX), "zlibx");
  EXPECT_EQ_STR(compression_algo_name(COMPRESSION_ALGO_NONE), "none");
  /* rsync 3.4.1 auto-negotiates zstd first. */
  EXPECT_EQ_INT((int)compression_negotiate_default(), (int)COMPRESSION_ALGO_ZSTD);
  EXPECT_FALSE(compression_algo_enabled(COMPRESSION_ALGO_NONE));
  EXPECT_TRUE(compression_algo_enabled(COMPRESSION_ALGO_ZSTD));
}

/* rsync 3.4.1's per-codec default levels and its clamping ranges. */
static void test_codec_level_defaults_and_clamp() {
  EXPECT_EQ_INT(compression_default_level(COMPRESSION_ALGO_ZSTD), ZSTD_CLEVEL_DEFAULT);
  EXPECT_EQ_INT(compression_default_level(COMPRESSION_ALGO_ZSTD), 3);
  EXPECT_EQ_INT(compression_default_level(COMPRESSION_ALGO_ZLIB), 6);
  EXPECT_EQ_INT(compression_default_level(COMPRESSION_ALGO_ZLIBX), 6);
  /* lz4 has no tunable level; a positive placeholder keeps the codec engaged. */
  EXPECT_TRUE(compression_default_level(COMPRESSION_ALGO_LZ4) > 0);
  EXPECT_EQ_INT(compression_default_level(COMPRESSION_ALGO_NONE), 0);

  EXPECT_EQ_INT(compression_clamp_level(COMPRESSION_ALGO_ZSTD, 1), 1);
  EXPECT_EQ_INT(compression_clamp_level(COMPRESSION_ALGO_ZSTD, 22), 22);
  EXPECT_EQ_INT(compression_clamp_level(COMPRESSION_ALGO_ZSTD, 23), 22);
  EXPECT_EQ_INT(compression_clamp_level(COMPRESSION_ALGO_ZSTD, 0), 1);
  EXPECT_EQ_INT(compression_clamp_level(COMPRESSION_ALGO_ZLIB, 15), 9);
  EXPECT_EQ_INT(compression_clamp_level(COMPRESSION_ALGO_ZLIBX, 15), 9);
  EXPECT_EQ_INT(compression_clamp_level(COMPRESSION_ALGO_ZLIB, 1), 1);
  EXPECT_TRUE(compression_clamp_level(COMPRESSION_ALGO_LZ4, 20) > 0);
  EXPECT_EQ_INT(compression_clamp_level(COMPRESSION_ALGO_NONE, 20), 0);
}

/* RSYNC_COMPRESS_LIST precedence, syntax and fallback. */
static void test_codec_choice_env_list() {
  unsetenv("RSYNC_COMPRESS_LIST");
  EXPECT_EQ_INT(compression_choice_resolve(), (int)COMPRESSION_ALGO_ZSTD);
  EXPECT_EQ_INT((int)compression_negotiate_default(), (int)COMPRESSION_ALGO_ZSTD);

  /* Unknown entries are skipped; the first supported wins. */
  setenv("RSYNC_COMPRESS_LIST", "bogus zlib lz4", 1);
  EXPECT_EQ_INT(compression_choice_resolve(), (int)COMPRESSION_ALGO_ZLIB);

  /* Case-insensitive. */
  setenv("RSYNC_COMPRESS_LIST", "ZSTD", 1);
  EXPECT_EQ_INT(compression_choice_resolve(), (int)COMPRESSION_ALGO_ZSTD);

  /* Whitespace-separated; the client half ends at '&'. */
  setenv("RSYNC_COMPRESS_LIST", "lz4  zlib & zstd", 1);
  EXPECT_EQ_INT(compression_choice_resolve(), (int)COMPRESSION_ALGO_LZ4);

  /* Blank falls back to the compiled-in order. */
  setenv("RSYNC_COMPRESS_LIST", "   ", 1);
  EXPECT_EQ_INT(compression_choice_resolve(), (int)COMPRESSION_ALGO_ZSTD);

  /* rsync's syntax has no comma/colon separator: this is one unknown name. */
  setenv("RSYNC_COMPRESS_LIST", "bogus,lz4", 1);
  EXPECT_EQ_INT(compression_choice_resolve(), -1);

  unsetenv("RSYNC_COMPRESS_LIST");
}

/* The process-global codec selects what the legacy wrappers produce. */
static void test_codec_global_selection() {
  Data* original = data_create_empty(64);
  EXPECT_NOT_NULL(original);
  memset(original->data, 'q', 64);
  original->size = 64;

  compression_set_algo(COMPRESSION_ALGO_LZ4);
  Data* compressed = data_compress(original, 3);
  EXPECT_NOT_NULL(compressed);
  EXPECT_EQ_INT((int)((uint8_t*)compressed->data)[0], (int)COMPRESSION_ALGO_LZ4);
  Data* decompressed = data_decompress(compressed);
  EXPECT_NOT_NULL(decompressed);
  EXPECT_TRUE(memcmp(decompressed->data, original->data, 64) == 0);
  data_destroy(decompressed);
  data_destroy(compressed);

  /* Restore the default so later tests are unaffected. */
  compression_set_algo(COMPRESSION_ALGO_ZSTD);
  data_destroy(original);
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
  test_codec_roundtrips();
  test_codec_name_mapping();
  test_codec_level_defaults_and_clamp();
  test_codec_choice_env_list();
  test_codec_global_selection();
}
