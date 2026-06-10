#include "test_chunk.h"
#include "chunk.h"
#include "utils.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_file_operations() {
  char *test_path = "temp_file_test.txt";
  char *test_content = "Hello, Chunk System!";
  unsigned long long test_len = strlen(test_content);

  to_disk(test_path, test_content, test_len);

  struct stat st;
  int stat_res = stat(test_path, &st);
  EXPECT_EQ_INT(stat_res, 0);
  EXPECT_EQ_INT((int)st.st_size, (int)test_len);

  File *f = file_create(test_path, &st);
  EXPECT_NOT_NULL(f);
  EXPECT_EQ_STR(f->path, test_path);
  EXPECT_NULL(f->data);

  file_load_data(f);
  EXPECT_NOT_NULL(f->data);
  EXPECT_EQ_INT(memcmp(f->data, test_content, test_len), 0);

  file_destroy(f);
  unlink(test_path);
}

static void test_file_receive_operations() {
  char *path = str_dup("temp_receive.txt");
  char *data = str_dup("receive data content");
  unsigned long long size = strlen(data);

  DataFragment *df = data_fragment_create(data, size);
  EXPECT_NOT_NULL(df);
  EXPECT_EQ_INT((int)df->size, (int)size);
  EXPECT_EQ_STR(df->data, "receive data content");

  FileReceive *fr = file_receive_create(path, df);
  EXPECT_NOT_NULL(fr);
  EXPECT_EQ_STR(fr->path, "temp_receive.txt");
  EXPECT_NOT_NULL(fr->data_fragment);
  EXPECT_EQ_STR(fr->data_fragment->data, "receive data content");

  file_receive_destroy(fr);
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

  File *f1 = file_create(path1, &st1);
  File *f2 = file_create(path2, &st2);

  File *files[2] = {f1, f2};
  Chunk *chunk = chunk_create(files, 2);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 2);
  EXPECT_NOT_NULL(chunk->items[0]);
  EXPECT_NOT_NULL(chunk->items[1]);

  Data *formatted = chunk_format(chunk);
  EXPECT_NOT_NULL(formatted);

  unsigned long long expected_size = 
    (sizeof(int) + strlen(path1) + sizeof(unsigned long long) + len1) +
    (sizeof(int) + strlen(path2) + sizeof(unsigned long long) + len2);
  EXPECT_EQ_INT((int)formatted->data_size, (int)expected_size);

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
  test_file_receive_operations();
  test_chunk_operations();
}
