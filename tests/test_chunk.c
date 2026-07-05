
#include "chunk.h"
#include "test_utils.h"
#include "utils.h"
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_file_operations() {
  char *test_path = "temp_file_test.txt";
  char *test_content = "Hello, Chunk System!";
  unsigned long long test_len = strlen(test_content);

  to_disk(test_path, test_content, test_len);

  File *f = file_create(test_path);
  EXPECT_NOT_NULL(f);
  EXPECT_EQ_STR(f->path, test_path);
  EXPECT_NOT_NULL(f->data);
  EXPECT_NULL(f->data->data);
  EXPECT_EQ_INT((int)f->data->size, 0);

  struct stat st;
  stat(test_path, &st);
  f->data->size = st.st_size;

  file_load_data(f);
  EXPECT_NOT_NULL(f->data);
  EXPECT_NOT_NULL(f->data->data);
  EXPECT_EQ_INT((int)f->data->size, (int)test_len);
  EXPECT_EQ_INT(memcmp(f->data->data, test_content, test_len), 0);

  file_destroy(f);
  unlink(test_path);
}

static void test_chunk_operations() {
  char *path1 = "temp_chunk_1.txt";
  char *content1 = "chunk item 1";
  unsigned long long len1 = strlen(content1);

  char *path2 = "temp_chunk_2.txt";
  char *content2 = "chunk item number 2";
  unsigned long long len2 = strlen(content2);

  to_disk(path1, content1, len1);
  to_disk(path2, content2, len2);

  struct stat st1, st2;
  stat(path1, &st1);
  stat(path2, &st2);

  File *f1 = file_create(path1);
  f1->data->size = st1.st_size;
  File *f2 = file_create(path2);
  f2->data->size = st2.st_size;

  File *files[2] = {f1, f2};
  Chunk *chunk = chunk_create(files, 2);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 2);
  EXPECT_NOT_NULL(chunk->items[0]);
  EXPECT_NOT_NULL(chunk->items[1]);

  // load data before serializing
  file_load_data(f1);
  file_load_data(f2);

  // Test chunk_serialize / chunk_deserialize round-trip
  Data *serialized = chunk_serialize(chunk);
  EXPECT_NOT_NULL(serialized);

  Chunk *deserialized = chunk_deserialize(serialized);
  EXPECT_NOT_NULL(deserialized);
  EXPECT_EQ_INT(deserialized->element_count, 2);
  EXPECT_EQ_STR(deserialized->items[0]->path, path1);
  EXPECT_EQ_STR(deserialized->items[1]->path, path2);
  EXPECT_EQ_INT((int)deserialized->items[0]->data->size, (int)len1);
  EXPECT_EQ_INT((int)deserialized->items[1]->data->size, (int)len2);
  EXPECT_EQ_INT(memcmp(deserialized->items[0]->data->data, content1, len1), 0);
  EXPECT_EQ_INT(memcmp(deserialized->items[1]->data->data, content2, len2), 0);

  chunk_data_delete(serialized);
  chunk_destroy(deserialized);

  // Test chunk_format layout (old format)
  Data *formatted = chunk_format(chunk);
  EXPECT_NOT_NULL(formatted);

  unsigned long long expected_size =
      (sizeof(int) + strlen(path1) + sizeof(int) + sizeof(unsigned long long) + len1) +
      (sizeof(int) + strlen(path2) + sizeof(int) + sizeof(unsigned long long) + len2);
  EXPECT_EQ_INT((int)formatted->size, (int)expected_size);

  char *ptr = (char *)formatted->data;

  // File 1
  int p_len1;
  memcpy(&p_len1, ptr, sizeof(int));
  ptr += sizeof(int);
  EXPECT_EQ_INT(p_len1, (int)strlen(path1));

  char read_path1[256];
  memcpy(read_path1, ptr, p_len1);
  read_path1[p_len1] = '\0';
  ptr += p_len1;
  EXPECT_EQ_STR(read_path1, path1);

  int meta_present1;
  memcpy(&meta_present1, ptr, sizeof(int));
  ptr += sizeof(int);
  EXPECT_EQ_INT(meta_present1, 0);

  unsigned long long d_len1;
  memcpy(&d_len1, ptr, sizeof(unsigned long long));
  ptr += sizeof(unsigned long long);
  EXPECT_EQ_INT((int)d_len1, (int)len1);

  char read_content1[256];
  memcpy(read_content1, ptr, d_len1);
  read_content1[d_len1] = '\0';
  ptr += d_len1;
  EXPECT_EQ_STR(read_content1, content1);

  // File 2
  int p_len2;
  memcpy(&p_len2, ptr, sizeof(int));
  ptr += sizeof(int);
  EXPECT_EQ_INT(p_len2, (int)strlen(path2));

  char read_path2[256];
  memcpy(read_path2, ptr, p_len2);
  read_path2[p_len2] = '\0';
  ptr += p_len2;
  EXPECT_EQ_STR(read_path2, path2);

  int meta_present2;
  memcpy(&meta_present2, ptr, sizeof(int));
  ptr += sizeof(int);
  EXPECT_EQ_INT(meta_present2, 0);

  unsigned long long d_len2;
  memcpy(&d_len2, ptr, sizeof(unsigned long long));
  ptr += sizeof(unsigned long long);
  EXPECT_EQ_INT((int)d_len2, (int)len2);

  char read_content2[256];
  memcpy(read_content2, ptr, d_len2);
  read_content2[d_len2] = '\0';
  ptr += d_len2;
  EXPECT_EQ_STR(read_content2, content2);

  chunk_data_delete(formatted);
  chunk_destroy(chunk);

  unlink(path1);
  unlink(path2);
}

void test_chunk() {
  test_file_operations();
  test_chunk_operations();
}
