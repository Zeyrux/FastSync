#include "test_utils.h"
#include "delta.h"
#include <string.h>
#include <stdlib.h>

static void test_adler32_basic() {
  const char* data = "Hello";
  uint32_t h = delta_adler32(data, 5);
  EXPECT_TRUE(h != 0);
  uint32_t h2 = delta_adler32(data, 5);
  EXPECT_EQ_INT((int)h, (int)h2);
}

static void test_adler32_different_data() {
  const char* a = "AAAA";
  const char* b = "BBBB";
  uint32_t ha = delta_adler32(a, 4);
  uint32_t hb = delta_adler32(b, 4);
  EXPECT_TRUE(ha != hb);
}

static void test_xxhash32_basic() {
  const char* data = "Hello";
  uint32_t h = delta_xxhash32(data, 5);
  EXPECT_TRUE(h != 0);
  uint32_t h2 = delta_xxhash32(data, 5);
  EXPECT_EQ_INT((int)h, (int)h2);
}

static void test_xxhash32_different_data() {
  const char* a = "AAAA";
  const char* b = "BBBB";
  uint32_t ha = delta_xxhash32(a, 4);
  uint32_t hb = delta_xxhash32(b, 4);
  EXPECT_TRUE(ha != hb);
}

static void test_xxhash64_different_data() {
  EXPECT_TRUE(delta_xxhash64("AAAA", 4) != delta_xxhash64("BBBB", 4));
}

static void test_signature_roundtrip() {
  char old_data[4096];
  for (int i = 0; i < 4096; i++)
    old_data[i] = (char)(i % 256);

  DeltaSignature* sig = delta_signature_create(old_data, 4096, 1024);
  EXPECT_NOT_NULL(sig);
  EXPECT_EQ_INT((int)sig->block_count, 4);
  EXPECT_EQ_INT((int)sig->block_size, 1024);

  Data* serialized = delta_signature_serialize(sig);
  EXPECT_NOT_NULL(serialized);

  DeltaSignature* deserialized = delta_signature_deserialize(serialized);
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
  for (int i = 0; i < 2048; i++)
    data[i] = (char)(i % 128);

  DeltaSignature* sig = delta_signature_create(data, 2048, 512);
  EXPECT_NOT_NULL(sig);

  Delta* delta = delta_compute(data, 2048, sig, 512);
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

  DeltaSignature* sig = delta_signature_create(old_data, 4096, 1024);
  EXPECT_NOT_NULL(sig);

  Delta* delta = delta_compute(new_data, 4096, sig, 1024);
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

  void* reconstructed = delta_apply(old_data, 4096, delta, 1024);
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

  DeltaSignature* sig = delta_signature_create(old_data, 4096, 1024);
  EXPECT_NOT_NULL(sig);

  Delta* delta = delta_compute(new_data, 4096, sig, 1024);
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

  DeltaSignature* sig = delta_signature_create(old_data, 4096, 1024);
  Delta* delta = delta_compute(new_data, 4096, sig, 1024);
  EXPECT_NOT_NULL(delta);

  Data* serialized = delta_serialize(delta);
  EXPECT_NOT_NULL(serialized);

  Delta* deserialized = delta_deserialize(serialized);
  EXPECT_NOT_NULL(deserialized);
  EXPECT_EQ_INT((int)deserialized->new_file_size, (int)delta->new_file_size);
  EXPECT_EQ_INT((int)deserialized->instruction_count, (int)delta->instruction_count);

  void* reconstructed = delta_apply(old_data, 4096, deserialized, 1024);
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
  for (int i = 0; i < 2048; i++)
    old_data[i] = (char)(i % 256);
  memcpy(new_data, old_data, 2048);
  for (int i = 2048; i < 3072; i++)
    new_data[i] = (char)(i % 256);

  DeltaSignature* sig = delta_signature_create(old_data, 2048, 512);
  EXPECT_NOT_NULL(sig);

  Delta* delta = delta_compute(new_data, 3072, sig, 512);
  EXPECT_NOT_NULL(delta);

  void* reconstructed = delta_apply(old_data, 2048, delta, 512);
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
  for (int i = 0; i < 3072; i++)
    old_data[i] = (char)(i % 256);
  for (int i = 0; i < 2048; i++)
    new_data[i] = old_data[i];

  DeltaSignature* sig = delta_signature_create(old_data, 3072, 512);
  EXPECT_NOT_NULL(sig);

  Delta* delta = delta_compute(new_data, 2048, sig, 512);
  EXPECT_NOT_NULL(delta);

  void* reconstructed = delta_apply(old_data, 3072, delta, 512);
  EXPECT_NOT_NULL(reconstructed);
  EXPECT_EQ_INT(delta->new_file_size, 2048);
  EXPECT_EQ_INT(memcmp(reconstructed, new_data, 2048), 0);

  free(reconstructed);
  delta_signature_destroy(sig);
  delta_destroy(delta);
}

static void test_should_attempt() {
  EXPECT_TRUE(delta_should_attempt(100000, 100000, DELTA_MAX_FILE_SIZE));
  EXPECT_TRUE(!delta_should_attempt(100, 100, DELTA_MAX_FILE_SIZE));
  EXPECT_TRUE(!delta_should_attempt(100000, 10, DELTA_MAX_FILE_SIZE));
  EXPECT_TRUE(!delta_should_attempt(300000000, 300000000, DELTA_MAX_FILE_SIZE));
  EXPECT_TRUE(delta_should_attempt(50000, 60000, DELTA_MAX_FILE_SIZE));
  EXPECT_TRUE(!delta_should_attempt(50000, 600000, DELTA_MAX_FILE_SIZE));
  EXPECT_TRUE(delta_should_attempt(50000, 60000, 500000));
  EXPECT_TRUE(!delta_should_attempt(100000, 100000, 50000));
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

static void test_large_file_delta() {
  uint32_t block_size = 8192;
  uint64_t old_size = 200000;
  uint64_t new_size = 200000;

  void* old_data = malloc((size_t)old_size);
  void* new_data = malloc((size_t)new_size);
  EXPECT_TRUE(old_data != NULL && new_data != NULL);

  for (uint64_t i = 0; i < old_size; i++)
    ((uint8_t*)old_data)[i] = (uint8_t)(i % 251);
  memcpy(new_data, old_data, (size_t)old_size);

  uint64_t offset = 100000;
  uint32_t change_len = 4096;
  for (uint32_t i = 0; i < change_len; i++)
    ((uint8_t*)new_data)[offset + i] = (uint8_t)((i * 7 + 13) % 256);

  DeltaSignature* sig = delta_signature_create(old_data, old_size, block_size);
  EXPECT_TRUE(sig != NULL);
  EXPECT_TRUE(sig->block_count == (uint32_t)((old_size + block_size - 1) / block_size));

  Delta* delta = delta_compute(new_data, new_size, sig, block_size);
  EXPECT_TRUE(delta != NULL);

  uint64_t total_literal = 0;
  uint32_t match_count = 0;
  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (delta->instructions[i].type == DELTA_INSTR_LITERAL)
      total_literal += delta->instructions[i].literal.length;
    else
      match_count++;
  }
  EXPECT_TRUE(total_literal > 0);
  EXPECT_TRUE(match_count > 0);
  EXPECT_TRUE(delta->delta_size < new_size / 2);

  void* result = delta_apply(old_data, old_size, delta, block_size);
  EXPECT_TRUE(result != NULL);
  EXPECT_TRUE(delta->new_file_size == new_size);
  EXPECT_TRUE(memcmp(result, new_data, (size_t)new_size) == 0);

  free(result);
  delta_destroy(delta);
  delta_signature_destroy(sig);
  free(old_data);
  free(new_data);
}

static void test_delta_apply_rejects_output_overflow() {
  uint8_t old_data[8] = {0};
  uint8_t literal_data[2] = {'x', 'y'};
  DeltaInstruction instruction = {
      .type = DELTA_INSTR_LITERAL,
      .literal = {.data = literal_data, .length = sizeof(literal_data)},
  };
  Delta delta = {
      .new_file_size = 1,
      .instruction_count = 1,
      .instructions = &instruction,
  };

  EXPECT_TRUE(delta_apply(old_data, sizeof(old_data), &delta, 1) == NULL);
}

/* ---------------------------------------------------------------------------
 * Hash-index lookup differential tests.
 *
 * delta_compute buckets signature blocks by their weak checksum.  These tests
 * prove the bucket-indexed candidate lookup is behaviour-identical to the
 * original per-window linear scan: the emitted instruction stream (types,
 * lengths, literal bytes and chosen block indices) must match a naive linear
 * reference exactly, and the delta must reconstruct the new buffer.
 * ------------------------------------------------------------------------- */

#define REF_NO_MATCH UINT32_MAX

typedef struct {
  DeltaInstruction* items;
  uint32_t count;
  uint32_t cap;
} RefDelta;

static void ref_delta_free(RefDelta* ref) {
  if (!ref->items)
    return;
  for (uint32_t i = 0; i < ref->count; i++)
    if (ref->items[i].type == DELTA_INSTR_LITERAL)
      free(ref->items[i].literal.data);
  free(ref->items);
  ref->items = NULL;
  ref->count = 0;
  ref->cap = 0;
}

static bool ref_delta_push(RefDelta* ref, DeltaInstruction instr) {
  if (ref->count == ref->cap) {
    uint32_t new_cap = ref->cap ? ref->cap * 2 : 16;
    DeltaInstruction* tmp = realloc(ref->items, (size_t)new_cap * sizeof(DeltaInstruction));
    if (!tmp)
      return false;
    ref->items = tmp;
    ref->cap = new_cap;
  }
  ref->items[ref->count++] = instr;
  return true;
}

static bool ref_delta_flush_literal(RefDelta* ref, const uint8_t* data, uint64_t start,
                                    uint64_t end) {
  if (start >= end)
    return true;
  uint8_t* lit = malloc((size_t)(end - start));
  if (!lit)
    return false;
  memcpy(lit, data + start, (size_t)(end - start));
  DeltaInstruction instr = {
      .type = DELTA_INSTR_LITERAL,
      .literal = {.data = lit, .length = (uint32_t)(end - start)},
  };
  return ref_delta_push(ref, instr);
}

/* Naive O(windows x blocks) re-implementation of the historical delta_compute
 * candidate scan: only full windows may match, a candidate needs both the weak
 * (Adler-32) and strong (xxHash32) checksums to agree, and the lowest matching
 * block index is selected. */
static bool ref_delta_build(RefDelta* ref, const uint8_t* new_data, uint64_t new_size,
                            const DeltaSignature* sig) {
  uint32_t block_size = sig->block_size;
  uint64_t i = 0;
  uint64_t literal_start = 0;
  bool has_literal = false;

  while (i < new_size) {
    uint32_t window_len = (uint32_t)((new_size - i < block_size) ? (new_size - i) : block_size);
    bool full_window = (window_len == block_size);

    uint32_t matched = REF_NO_MATCH;
    if (full_window) {
      uint32_t adler = delta_adler32(new_data + i, window_len);
      for (uint32_t j = 0; j < sig->block_count; j++) {
        if (sig->blocks[j].adler32 == adler &&
            delta_xxhash32(new_data + i, window_len) == sig->blocks[j].xxhash) {
          matched = j;
          break;
        }
      }
    }

    if (matched != REF_NO_MATCH) {
      if (has_literal) {
        if (!ref_delta_flush_literal(ref, new_data, literal_start, i))
          return false;
        has_literal = false;
      }
      DeltaInstruction instr = {
          .type = DELTA_INSTR_BLOCK_MATCH,
          .match = {.block_index = matched, .block_offset = 0, .length = window_len},
      };
      if (!ref_delta_push(ref, instr))
        return false;
      i += window_len;
    } else {
      if (!has_literal) {
        literal_start = i;
        has_literal = true;
      }
      i++;
    }
  }

  if (has_literal && !ref_delta_flush_literal(ref, new_data, literal_start, new_size))
    return false;
  return true;
}

static bool ref_delta_matches(const RefDelta* ref, const Delta* delta) {
  if (ref->count != delta->instruction_count)
    return false;
  for (uint32_t i = 0; i < ref->count; i++) {
    const DeltaInstruction* a = &ref->items[i];
    const DeltaInstruction* b = &delta->instructions[i];
    if (a->type != b->type)
      return false;
    if (a->type == DELTA_INSTR_BLOCK_MATCH) {
      if (a->match.block_index != b->match.block_index ||
          a->match.block_offset != b->match.block_offset || a->match.length != b->match.length)
        return false;
    } else {
      if (a->literal.length != b->literal.length ||
          memcmp(a->literal.data, b->literal.data, a->literal.length) != 0)
        return false;
    }
  }
  return true;
}

static void expect_linear_reference_match(const uint8_t* old_data, uint64_t old_size,
                                          const uint8_t* new_data, uint64_t new_size,
                                          uint32_t block_size, const char* label) {
  DeltaSignature* sig = delta_signature_create(old_data, old_size, block_size);
  if (!sig) {
    printf("      [FAIL] %s: signature creation failed\n", label);
    EXPECT_NOT_NULL(sig);
    return;
  }
  Delta* delta = delta_compute(new_data, new_size, sig, block_size);
  if (!delta) {
    printf("      [FAIL] %s: delta_compute returned NULL\n", label);
    delta_signature_destroy(sig);
    EXPECT_NOT_NULL(delta);
    return;
  }
  RefDelta ref = {0};
  bool ok = ref_delta_build(&ref, new_data, new_size, sig);
  if (ok)
    ok = ref_delta_matches(&ref, delta);
  if (!ok) {
    printf("      [FAIL] %s: instruction stream differs from linear reference "
           "(linear=%u indexed=%u)\n",
           label, ref.count, delta->instruction_count);
  }
  ref_delta_free(&ref);
  delta_destroy(delta);
  delta_signature_destroy(sig);
  EXPECT_TRUE(ok);
}

static void fill_delta_pattern(uint8_t* buf, uint64_t size, uint32_t seed) {
  uint32_t x = seed ? seed : 1;
  for (uint64_t i = 0; i < size; i++) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    buf[i] = (uint8_t)(x >> 24);
  }
}

static void test_delta_hash_index_matches_linear_reference() {
  /* Identical file (full block alignment). */
  uint8_t old_a[32768];
  uint8_t new_a[32768];
  fill_delta_pattern(old_a, sizeof(old_a), 42);
  memcpy(new_a, old_a, sizeof(old_a));
  expect_linear_reference_match(old_a, sizeof(old_a), new_a, sizeof(new_a), 2048,
                                "identical 32KiB @ 2KiB");

  /* Scattered single-byte edits in the middle of each block. */
  uint8_t new_b[32768];
  memcpy(new_b, old_a, sizeof(old_a));
  for (size_t p = 100; p < sizeof(new_b); p += 4096)
    new_b[p] ^= 0x5A;
  expect_linear_reference_match(old_a, sizeof(old_a), new_b, sizeof(new_b), 2048,
                                "32KiB scattered single-byte edits @ 2KiB");

  /* Non-aligned old file (partial final block) with a single edit. */
  uint8_t old_c[30000];
  uint8_t new_c[30000];
  fill_delta_pattern(old_c, sizeof(old_c), 7);
  memcpy(new_c, old_c, sizeof(old_c));
  new_c[15000] ^= 0x3C;
  expect_linear_reference_match(old_c, sizeof(old_c), new_c, sizeof(new_c), 2048,
                                "30KiB partial-tail single edit @ 2KiB");

  /* Growth: appended data after an identical prefix. */
  uint8_t old_d[24576];
  uint8_t new_d[34576];
  fill_delta_pattern(old_d, sizeof(old_d), 11);
  memcpy(new_d, old_d, sizeof(old_d));
  fill_delta_pattern(new_d + sizeof(old_d), sizeof(new_d) - sizeof(old_d), 23);
  expect_linear_reference_match(old_d, sizeof(old_d), new_d, sizeof(new_d), 2048,
                                "24KiB -> 34KiB appended @ 2KiB");

  /* Insertion shifting everything after the edit point (rsync re-sync). */
  uint8_t old_e[65536];
  uint8_t new_e[65536 + 3000];
  fill_delta_pattern(old_e, sizeof(old_e), 99);
  memcpy(new_e, old_e, 20000);
  fill_delta_pattern(new_e + 20000, 3000, 101);
  memcpy(new_e + 23000, old_e + 20000, sizeof(old_e) - 20000);
  expect_linear_reference_match(old_e, sizeof(old_e), new_e, sizeof(new_e), 2048,
                                "64KiB + 3KiB insertion @ 2KiB");

  /* Deletion shrinking the file. */
  uint8_t new_f[sizeof(old_e) - 5000];
  memcpy(new_f, old_e, 30000);
  memcpy(new_f + 30000, old_e + 35000, sizeof(old_e) - 35000);
  expect_linear_reference_match(old_e, sizeof(old_e), new_f, sizeof(new_f), 2048,
                                "64KiB - 5KiB deletion @ 2KiB");

  /* Repeated identical blocks must resolve to the lowest block index. */
  uint8_t old_g[4 * 4096];
  uint8_t new_g[4 * 4096];
  for (uint32_t b = 0; b < 4; b++)
    fill_delta_pattern(old_g + b * 4096, 4096, b % 2 == 0 ? 500 : 501); /* block0==block2 */
  memcpy(new_g, old_g, sizeof(old_g));
  new_g[4096 + 5] ^= 0x11; /* edit inside the second (duplicated) chunk */
  expect_linear_reference_match(old_g, sizeof(old_g), new_g, sizeof(new_g), 4096,
                                "duplicated chunks @ 4KiB");

  /* Block larger than the file: nothing can match, all literal. */
  uint8_t old_h[1000];
  uint8_t new_h[1000];
  fill_delta_pattern(old_h, sizeof(old_h), 3);
  memcpy(new_h, old_h, sizeof(old_h));
  expect_linear_reference_match(old_h, sizeof(old_h), new_h, sizeof(new_h), 4096,
                                "1KiB file @ 4KiB block");
}

static void test_delta_hash_index_large_mostly_matching() {
  const uint64_t size = 4ULL * 1024 * 1024;
  const uint32_t block_size = 8192;

  uint8_t* old_data = malloc((size_t)size);
  uint8_t* new_data = malloc((size_t)size);
  EXPECT_TRUE(old_data != NULL && new_data != NULL);

  fill_delta_pattern(old_data, size, 1234);
  memcpy(new_data, old_data, (size_t)size);

  /* Scattered single-byte changes across the whole buffer.  Each change forces
   * the diff to re-synchronise by walking one byte at a time through the
   * affected block, which is exactly the case that used to cost O(bytes x
   * blocks) with the linear scan. */
  const uint64_t nchanges = 64;
  for (uint64_t c = 0; c < nchanges; c++) {
    uint64_t pos = (c * (size / nchanges)) + (c % 17);
    new_data[pos] ^= (uint8_t)(0xA0 + (c % 16));
  }

  DeltaSignature* sig = delta_signature_create(old_data, size, block_size);
  EXPECT_NOT_NULL(sig);
  EXPECT_EQ_INT((int)sig->block_count, (int)(size / block_size));

  Delta* delta = delta_compute(new_data, size, sig, block_size);
  EXPECT_NOT_NULL(delta);
  EXPECT_EQ_INT((int)delta->new_file_size, (int)size);

  uint32_t match_count = 0;
  for (uint32_t i = 0; i < delta->instruction_count; i++)
    if (delta->instructions[i].type == DELTA_INSTR_BLOCK_MATCH)
      match_count++;
  EXPECT_TRUE(match_count > 0);

  void* result = delta_apply(old_data, size, delta, block_size);
  EXPECT_NOT_NULL(result);
  EXPECT_EQ_INT(memcmp(result, new_data, (size_t)size), 0);

  free(result);
  delta_destroy(delta);
  delta_signature_destroy(sig);
  free(old_data);
  free(new_data);
}

/* --checksum-seed: the delta strong (block) hash is genuinely seed-aware.  A
 * nonzero seed changes the per-block xxHash32, and a signature + delta computed
 * with the same seed still reconstruct the file exactly (symmetric), while a
 * mismatched seed produces a delta that does not match the signature blocks. */
static void test_delta_xxhash32_seeded() {
  const char* data = "seedme";
  uint32_t a = delta_xxhash32(data, 6);
  uint32_t b = delta_xxhash32_seeded(data, 6, 42);
  uint32_t c = delta_xxhash32_seeded(data, 6, 42);
  EXPECT_TRUE(a != b);
  EXPECT_EQ_INT((int)b, (int)c);
  /* Unseeded == seeded with 0 (default reproduces today's behavior). */
  EXPECT_EQ_INT((int)delta_xxhash32(data, 6), (int)delta_xxhash32_seeded(data, 6, 0));
}

static void test_delta_seeded_signature_compute_matches() {
  uint32_t block_size = 1024;
  /* Identical old/new data with a non-zero seed: the receiver builds a seeded
     signature and the sender computes a seeded delta over the same bytes, so
     every block matches and applying the delta rebuilds the file exactly. */
  char data[4096];
  for (int i = 0; i < 4096; i++)
    data[i] = (char)(i % 256);

  DeltaSignature* sig = delta_signature_create_seeded(data, 4096, block_size, 99);
  EXPECT_NOT_NULL(sig);
  Delta* delta = delta_compute_seeded(data, 4096, sig, block_size, 99);
  EXPECT_NOT_NULL(delta);
  void* rebuilt = delta_apply(data, 4096, delta, block_size);
  EXPECT_NOT_NULL(rebuilt);
  EXPECT_TRUE(memcmp(rebuilt, data, 4096) == 0);
  free(rebuilt);
  delta_destroy(delta);
  delta_signature_destroy(sig);

  /* A MISMATCHED seed means the sender's window xxHash32 never equals the
     receiver's signature-block xxHash32: no block can match, so the delta is
     not worthwhile / has no block matches.  This proves the seed really gates
     the block comparison rather than being an inert parameter. */
  sig = delta_signature_create_seeded(data, 4096, block_size, 99);
  EXPECT_NOT_NULL(sig);
  delta = delta_compute_seeded(data, 4096, sig, block_size, 7);
  EXPECT_NOT_NULL(delta);
  bool any_match = false;
  for (uint32_t i = 0; i < delta->instruction_count; i++)
    if (delta->instructions[i].type == DELTA_INSTR_BLOCK_MATCH)
      any_match = true;
  EXPECT_FALSE(any_match);
  delta_destroy(delta);
  delta_signature_destroy(sig);
}

void test_delta() {
  test_adler32_basic();
  test_adler32_different_data();
  test_xxhash32_basic();
  test_xxhash32_different_data();
  test_xxhash64_different_data();
  test_delta_xxhash32_seeded();
  test_signature_roundtrip();
  test_delta_identical_files();
  test_delta_small_edit();
  test_delta_completely_different();
  test_delta_serialize_roundtrip();
  test_delta_file_growth();
  test_delta_file_shrink();
  test_should_attempt();
  test_is_worthwhile();
  test_large_file_delta();
  test_delta_apply_rejects_output_overflow();
  test_delta_hash_index_matches_linear_reference();
  test_delta_hash_index_large_mostly_matching();
  test_delta_seeded_signature_compute_matches();
}
