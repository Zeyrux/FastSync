#include "test_utils.h"
#include "delta.h"
#include <string.h>
#include <stdlib.h>

static void test_adler32_basic() {
  const char *data = "Hello";
  uint32_t h = delta_adler32(data, 5);
  EXPECT_TRUE(h != 0);
  uint32_t h2 = delta_adler32(data, 5);
  EXPECT_EQ_INT((int)h, (int)h2);
}

static void test_adler32_different_data() {
  const char *a = "AAAA";
  const char *b = "BBBB";
  uint32_t ha = delta_adler32(a, 4);
  uint32_t hb = delta_adler32(b, 4);
  EXPECT_TRUE(ha != hb);
}

static void test_xxhash32_basic() {
  const char *data = "Hello";
  uint32_t h = delta_xxhash32(data, 5);
  EXPECT_TRUE(h != 0);
  uint32_t h2 = delta_xxhash32(data, 5);
  EXPECT_EQ_INT((int)h, (int)h2);
}

static void test_xxhash32_different_data() {
  const char *a = "AAAA";
  const char *b = "BBBB";
  uint32_t ha = delta_xxhash32(a, 4);
  uint32_t hb = delta_xxhash32(b, 4);
  EXPECT_TRUE(ha != hb);
}

static void test_signature_roundtrip() {
  char old_data[4096];
  for (int i = 0; i < 4096; i++) old_data[i] = (char)(i % 256);

  DeltaSignature *sig = delta_signature_create(old_data, 4096, 1024);
  EXPECT_NOT_NULL(sig);
  EXPECT_EQ_INT((int)sig->block_count, 4);
  EXPECT_EQ_INT((int)sig->block_size, 1024);

  Data *serialized = delta_signature_serialize(sig);
  EXPECT_NOT_NULL(serialized);

  DeltaSignature *deserialized = delta_signature_deserialize(serialized);
  EXPECT_NOT_NULL(deserialized);
  EXPECT_EQ_INT((int)deserialized->block_count, (int)sig->block_count);
  EXPECT_EQ_INT((int)deserialized->block_size, (int)sig->block_size);

  for (uint32_t i = 0; i < sig->block_count; i++) {
    EXPECT_EQ_INT((int)deserialized->blocks[i].adler32, (int)sig->blocks[i].adler32);
    EXPECT_EQ_INT((int)deserialized->blocks[i].xxhash, (int)sig->blocks[i].xxhash);
  }

  delta_signature_destroy(sig);
  data_destroy(serialized);
  delta_signature_destroy(deserialized);
}

static void test_delta_identical_files() {
  char data[2048];
  for (int i = 0; i < 2048; i++) data[i] = (char)(i % 128);

  DeltaSignature *sig = delta_signature_create(data, 2048, 512);
  EXPECT_NOT_NULL(sig);

  Delta *delta = delta_compute(data, 2048, sig, 512);
  EXPECT_NOT_NULL(delta);

  bool has_match = false;
  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (delta->instructions[i].type == DELTA_INSTR_BLOCK_MATCH) {
      has_match = true;
      break;
    }
  }
  EXPECT_TRUE(has_match);

  bool all_match = true;
  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (delta->instructions[i].type != DELTA_INSTR_BLOCK_MATCH) {
      all_match = false;
      break;
    }
  }
  EXPECT_TRUE(all_match);

  delta_signature_destroy(sig);
  delta_destroy(delta);
}

static void test_delta_small_edit() {
  char old_data[4096];
  char new_data[4096];
  for (int i = 0; i < 4096; i++) {
    old_data[i] = (char)(i % 256);
    new_data[i] = old_data[i];
  }
  new_data[100] = 'X';
  new_data[101] = 'Y';
  new_data[102] = 'Z';

  DeltaSignature *sig = delta_signature_create(old_data, 4096, 1024);
  EXPECT_NOT_NULL(sig);

  Delta *delta = delta_compute(new_data, 4096, sig, 1024);
  EXPECT_NOT_NULL(delta);

  uint64_t total_literal = 0;
  uint32_t match_count = 0;
  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (delta->instructions[i].type == DELTA_INSTR_LITERAL)
      total_literal += delta->instructions[i].literal.length;
    else
      match_count++;
  }
  EXPECT_TRUE(match_count > 0);
  EXPECT_TRUE(total_literal < 4096);

  void *reconstructed = delta_apply(old_data, 4096, delta, 1024);
  EXPECT_NOT_NULL(reconstructed);
  EXPECT_EQ_INT(memcmp(reconstructed, new_data, 4096), 0);

  free(reconstructed);
  delta_signature_destroy(sig);
  delta_destroy(delta);
}

static void test_delta_completely_different() {
  char old_data[4096];
  char new_data[4096];
  for (int i = 0; i < 4096; i++) {
    old_data[i] = (char)(i * 7 + 3);
    new_data[i] = (char)(i * 13 + 97);
  }

  DeltaSignature *sig = delta_signature_create(old_data, 4096, 1024);
  EXPECT_NOT_NULL(sig);

  Delta *delta = delta_compute(new_data, 4096, sig, 1024);
  EXPECT_NOT_NULL(delta);

  bool has_match = false;
  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (delta->instructions[i].type == DELTA_INSTR_BLOCK_MATCH) {
      has_match = true;
      break;
    }
  }
  EXPECT_TRUE(!has_match);
  EXPECT_TRUE(!delta_is_worthwhile(delta, 4096));

  delta_signature_destroy(sig);
  delta_destroy(delta);
}

static void test_delta_serialize_roundtrip() {
  char old_data[4096];
  char new_data[4096];
  for (int i = 0; i < 4096; i++) {
    old_data[i] = (char)(i % 256);
    new_data[i] = old_data[i];
  }
  new_data[500] = 'A';
  new_data[501] = 'B';

  DeltaSignature *sig = delta_signature_create(old_data, 4096, 1024);
  Delta *delta = delta_compute(new_data, 4096, sig, 1024);
  EXPECT_NOT_NULL(delta);

  Data *serialized = delta_serialize(delta);
  EXPECT_NOT_NULL(serialized);

  Delta *deserialized = delta_deserialize(serialized);
  EXPECT_NOT_NULL(deserialized);
  EXPECT_EQ_INT((int)deserialized->new_file_size, (int)delta->new_file_size);
  EXPECT_EQ_INT((int)deserialized->instruction_count, (int)delta->instruction_count);

  void *reconstructed = delta_apply(old_data, 4096, deserialized, 1024);
  EXPECT_NOT_NULL(reconstructed);
  EXPECT_EQ_INT(memcmp(reconstructed, new_data, 4096), 0);

  free(reconstructed);
  data_destroy(serialized);
  delta_destroy(deserialized);
  delta_signature_destroy(sig);
  delta_destroy(delta);
}

static void test_delta_file_growth() {
  char old_data[2048];
  char new_data[3072];
  for (int i = 0; i < 2048; i++) old_data[i] = (char)(i % 256);
  memcpy(new_data, old_data, 2048);
  for (int i = 2048; i < 3072; i++) new_data[i] = (char)(i % 256);

  DeltaSignature *sig = delta_signature_create(old_data, 2048, 512);
  EXPECT_NOT_NULL(sig);

  Delta *delta = delta_compute(new_data, 3072, sig, 512);
  EXPECT_NOT_NULL(delta);

  void *reconstructed = delta_apply(old_data, 2048, delta, 512);
  EXPECT_NOT_NULL(reconstructed);
  EXPECT_EQ_INT(delta->new_file_size, 3072);
  EXPECT_EQ_INT(memcmp(reconstructed, new_data, 3072), 0);

  free(reconstructed);
  delta_signature_destroy(sig);
  delta_destroy(delta);
}

static void test_delta_file_shrink() {
  char old_data[3072];
  char new_data[2048];
  for (int i = 0; i < 3072; i++) old_data[i] = (char)(i % 256);
  for (int i = 0; i < 2048; i++) new_data[i] = old_data[i];

  DeltaSignature *sig = delta_signature_create(old_data, 3072, 512);
  EXPECT_NOT_NULL(sig);

  Delta *delta = delta_compute(new_data, 2048, sig, 512);
  EXPECT_NOT_NULL(delta);

  void *reconstructed = delta_apply(old_data, 3072, delta, 512);
  EXPECT_NOT_NULL(reconstructed);
  EXPECT_EQ_INT(delta->new_file_size, 2048);
  EXPECT_EQ_INT(memcmp(reconstructed, new_data, 2048), 0);

  free(reconstructed);
  delta_signature_destroy(sig);
  delta_destroy(delta);
}

static void test_should_attempt() {
  EXPECT_TRUE(delta_should_attempt(100000, 100000));
  EXPECT_TRUE(!delta_should_attempt(100, 100));
  EXPECT_TRUE(!delta_should_attempt(100000, 10));
  EXPECT_TRUE(!delta_should_attempt(300000000, 300000000));
  EXPECT_TRUE(delta_should_attempt(50000, 60000));
  EXPECT_TRUE(!delta_should_attempt(50000, 600000));
}

static void test_is_worthwhile() {
  Delta d;
  d.instruction_count = 1;
  DeltaInstruction instr;
  instr.type = DELTA_INSTR_BLOCK_MATCH;
  d.instructions = &instr;

  d.delta_size = 100;
  EXPECT_TRUE(delta_is_worthwhile(&d, 1000));

  d.delta_size = 800;
  EXPECT_TRUE(!delta_is_worthwhile(&d, 1000));

  d.instruction_count = 1;
  instr.type = DELTA_INSTR_LITERAL;
  EXPECT_TRUE(!delta_is_worthwhile(&d, 1000));

  EXPECT_TRUE(!delta_is_worthwhile(NULL, 1000));
}

void test_delta() {
  test_adler32_basic();
  test_adler32_different_data();
  test_xxhash32_basic();
  test_xxhash32_different_data();
  test_signature_roundtrip();
  test_delta_identical_files();
  test_delta_small_edit();
  test_delta_completely_different();
  test_delta_serialize_roundtrip();
  test_delta_file_growth();
  test_delta_file_shrink();
  test_should_attempt();
  test_is_worthwhile();
}
