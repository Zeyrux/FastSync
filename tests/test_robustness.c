#include "test_robustness.h"
#include "test_utils.h"
#include "chunk.h"
#include "delta.h"
#include "data.h"
#include "file.h"
#include "protocol.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_chunk_deserialize_truncated() {
  char* path = "test_rob_trunc.txt";
  char* content = "hello";
  to_disk(path, content, strlen(content));

  struct stat st;
  stat(path, &st);

  File* f = file_create(path);
  f->data->size = st.st_size;
  file_load_data(f);

  File* files[1] = {f};
  Chunk* chunk = chunk_create(files, 1);
  Data* serialized = chunk_serialize(chunk, false);
  EXPECT_NOT_NULL(serialized);

  size_t orig_size = serialized->size;
  serialized->size = orig_size / 2;

  const Chunk* result = chunk_deserialize(serialized, false);
  EXPECT_NULL(result);

  serialized->size = orig_size;
  data_destroy(serialized);
  chunk_destroy(chunk);
  unlink(path);
}

static void test_chunk_deserialize_empty() {
  unsigned char garbage[] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB};
  Data* d = data_create(malloc(sizeof(garbage)), sizeof(garbage));
  EXPECT_NOT_NULL(d);
  memcpy(d->data, garbage, sizeof(garbage));

  const Chunk* result = chunk_deserialize(d, false);
  EXPECT_NULL(result);

  data_destroy(d);
}

static void test_chunk_deserialize_garbage() {
  unsigned char garbage[] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA};
  Data* d = data_create(malloc(sizeof(garbage)), sizeof(garbage));
  EXPECT_NOT_NULL(d);
  memcpy(d->data, garbage, sizeof(garbage));

  const Chunk* result = chunk_deserialize(d, false);
  EXPECT_NULL(result);

  data_destroy(d);
}

static void test_delta_deserialize_truncated() {
  char old_data[4096], new_data[4096];
  for (int i = 0; i < 4096; i++) {
    old_data[i] = (char)(i % 256);
    new_data[i] = old_data[i];
  }
  new_data[100] = 'X';

  DeltaSignature* sig = delta_signature_create(old_data, 4096, 1024);
  Delta* delta = delta_compute(new_data, 4096, sig, 1024);
  Data* serialized = delta_serialize(delta);
  EXPECT_NOT_NULL(serialized);

  serialized->size = 4;
  const Delta* result = delta_deserialize(serialized);
  EXPECT_NULL(result);

  data_destroy(serialized);
  delta_destroy(delta);
  delta_signature_destroy(sig);
}

static void test_delta_deserialize_empty() {
  char garbage[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  Data* d = data_create(malloc(sizeof(garbage)), sizeof(garbage));
  EXPECT_NOT_NULL(d);
  memcpy(d->data, garbage, sizeof(garbage));

  const Delta* result = delta_deserialize(d);
  EXPECT_NULL(result);

  data_destroy(d);
}

static void test_delta_deserialize_garbage() {
  unsigned char garbage[] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA};
  Data* d = data_create(malloc(sizeof(garbage)), sizeof(garbage));
  EXPECT_NOT_NULL(d);
  memcpy(d->data, garbage, sizeof(garbage));

  const Delta* result = delta_deserialize(d);
  EXPECT_NULL(result);

  data_destroy(d);
}

static void test_delta_signature_deserialize_truncated() {
  char old_data[4096];
  for (int i = 0; i < 4096; i++)
    old_data[i] = (char)(i % 256);

  DeltaSignature* sig = delta_signature_create(old_data, 4096, 1024);
  Data* serialized = delta_signature_serialize(sig);
  EXPECT_NOT_NULL(serialized);

  serialized->size = 4;
  const DeltaSignature* result = delta_signature_deserialize(serialized);
  EXPECT_NULL(result);

  data_destroy(serialized);
  delta_signature_destroy(sig);
}

static void test_delta_apply_null() {
  const void* result = delta_apply(NULL, 0, NULL, 0);
  EXPECT_NULL(result);
}

static void test_protocol_receive_n_data_closed_pipe() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  close(p[1]);

  char buf[32];
  EXPECT_FALSE(receive_n_data(0, buf, 32));

  close(p[0]);
}

static void test_receive_data_closed_pipe() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  close(p[1]);

  const Data* result = receive_data(0);
  EXPECT_NULL(result);

  close(p[0]);
}

static void test_receive_str_closed_pipe() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  close(p[1]);

  const char* result = receive_str(0);
  EXPECT_NULL(result);

  close(p[0]);
}

void test_robustness() {
  test_chunk_deserialize_truncated();
  test_chunk_deserialize_empty();
  test_chunk_deserialize_garbage();
  test_delta_deserialize_truncated();
  test_delta_deserialize_empty();
  test_delta_deserialize_garbage();
  test_delta_signature_deserialize_truncated();
  test_delta_apply_null();
  test_protocol_receive_n_data_closed_pipe();
  test_receive_data_closed_pipe();
  test_receive_str_closed_pipe();
}
