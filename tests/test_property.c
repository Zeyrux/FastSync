#include "test_property.h"
#include "test_utils.h"
#include "chunk.h"
#include "delta.h"
#include "data.h"
#include "compression.h"
#include "file.h"
#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static Data* random_data(int min_size, int max_size) {
  int size = min_size + rand() % (max_size - min_size + 1);
  char* buf = malloc(size);
  for (int i = 0; i < size; i++)
    buf[i] = (char)(rand() % 256);
  return data_create(buf, size);
}

static void test_property_compress_roundtrip() {
  srand(42);
  for (int iter = 0; iter < 10; iter++) {
    Data* original = random_data(1, 10000);
    EXPECT_NOT_NULL(original);

    size_t orig_size = original->size;
    void* orig_copy = malloc(orig_size);
    EXPECT_NOT_NULL(orig_copy);
    memcpy(orig_copy, original->data, orig_size);

    Data* compressed = data_compress(original, 3);
    EXPECT_NOT_NULL(compressed);

    Data* decompressed = data_decompress(compressed);
    EXPECT_NOT_NULL(decompressed);
    EXPECT_EQ_INT((int)decompressed->size, (int)orig_size);
    EXPECT_EQ_INT(memcmp(decompressed->data, orig_copy, orig_size), 0);

    free(orig_copy);
    data_destroy(original);
    data_destroy(compressed);
    data_destroy(decompressed);
  }
}

static void test_property_delta_roundtrip() {
  for (int iter = 0; iter < 5; iter++) {
    char old_data[4096], new_data[4096];
    for (int i = 0; i < 4096; i++) {
      old_data[i] = (char)(rand() % 256);
      new_data[i] = old_data[i];
    }

    int num_changes = 1 + rand() % 10;
    for (int c = 0; c < num_changes; c++) {
      int offset = rand() % 4096;
      new_data[offset] = (char)(rand() % 256);
    }

    DeltaSignature* sig = delta_signature_create(old_data, 4096, 1024);
    EXPECT_NOT_NULL(sig);

    Delta* delta = delta_compute(new_data, 4096, sig, 1024);
    EXPECT_NOT_NULL(delta);

    void* result = delta_apply(old_data, 4096, delta, 1024);
    EXPECT_NOT_NULL(result);
    EXPECT_EQ_INT(memcmp(result, new_data, 4096), 0);

    free(result);
    delta_signature_destroy(sig);
    delta_destroy(delta);
  }
}

static void test_property_chunk_roundtrip() {
  for (int iter = 0; iter < 5; iter++) {
    char path[64];
    snprintf(path, sizeof(path), "test_prop_chunk_%d.txt", iter);

    int content_len = 1 + rand() % 4096;
    char* content = malloc(content_len);
    for (int i = 0; i < content_len; i++)
      content[i] = (char)(rand() % 256);

    to_disk(path, content, content_len);

    struct stat st;
    stat(path, &st);

    File* f = file_create(path);
    f->data->size = st.st_size;
    file_load_data(f);

    File* files[1] = {f};
    Chunk* chunk = chunk_create(files, 1);
    Data* serialized = chunk_serialize(chunk, false);
    EXPECT_NOT_NULL(serialized);

    Chunk* deserialized = chunk_deserialize(serialized, false);
    EXPECT_NOT_NULL(deserialized);
    EXPECT_EQ_INT(deserialized->element_count, 1);
    EXPECT_EQ_INT((int)deserialized->items[0]->data->size, content_len);
    EXPECT_EQ_INT(memcmp(deserialized->items[0]->data->data, content, content_len), 0);

    free(content);
    data_destroy(serialized);
    chunk_destroy(deserialized);
    chunk_destroy(chunk);
    unlink(path);
  }
}

void test_property() {
  test_property_compress_roundtrip();
  test_property_delta_roundtrip();
  test_property_chunk_roundtrip();
}
