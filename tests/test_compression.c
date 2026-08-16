#include "test_utils.h"
#include "chunk.h"
#include "compression.h"
#include "data.h"
#include "file.h"
#include "utils.h"
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

static void test_chunk_compress_decompress_roundtrip() {
  char* path1 = "temp_comp_test_1.txt";
  char* content1 = "chunk compression test file 1";
  unsigned long long len1 = strlen(content1);

  char* path2 = "temp_comp_test_2.txt";
  char* content2 = "chunk compression test file 2 with more data";
  unsigned long long len2 = strlen(content2);

  to_disk(path1, content1, len1, false, false);
  to_disk(path2, content2, len2, false, false);

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

void test_compression() {
  test_data_compress_decompress_roundtrip();
  test_data_compress_decompress_large();
  test_chunk_compress_decompress_roundtrip();
}
