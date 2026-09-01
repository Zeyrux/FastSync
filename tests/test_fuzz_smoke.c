#include "test_fuzz_smoke.h"
#include "chunk.h"
#include "compression.h"
#include "data.h"
#include "delta.h"
#include "metadata.h"
#include "test_utils.h"
#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

  FileMetadata* meta = file_metadata_create(&st);
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
  char* buf_copy = meta_buf;
  FileMetadata* deserialized = metadata_from_buf(&buf_copy);
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

void test_fuzz_smoke() {
  test_fuzz_chunk_deserialize();
  test_fuzz_compress_decompress();
  test_fuzz_delta_deserialize();
  test_fuzz_metadata_from_buf();
  test_fuzz_delta_signature_deserialize();
  test_fuzz_glob_match();
}
