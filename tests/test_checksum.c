#include "test_checksum.h"
#include "checksum.h"
#include "test_utils.h"
#include <string.h>

/* Known xxHash64 vector (seed 0) for the empty string and a literal.
 * The md5 vectors are the standard NIST/RFC1321 test strings.  These pin the
 * digest selection to genuinely distinct algorithm outputs so a --checksum-
 * choice change is observable, not a silent no-op. */

static void test_checksum_xxh64_seed0() {
  uint8_t out[CHECKSUM_MAX_DIGEST_LEN];
  size_t len = 0;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH64, 0, "hello", 5, out, sizeof(out), &len));
  EXPECT_TRUE(len == (size_t)8);
  /* Hard-coded: XXH64("hello", 5, 0). */
  const uint8_t expect[8] = {0xa3, 0x6d, 0x9f, 0x88, 0x7d, 0x82, 0xc7, 0x26};
  for (int i = 0; i < 8; i++)
    EXPECT_EQ_INT(out[i], expect[i]);
}

static void test_checksum_xxh64_empty() {
  uint8_t out[CHECKSUM_MAX_DIGEST_LEN];
  size_t len = 0;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH64, 0, "", 0, out, sizeof(out), &len));
  EXPECT_TRUE(len == (size_t)8);
  /* XXH64("", 0, 0). */
  const uint8_t expect[8] = {0x99, 0xe9, 0xd8, 0x51, 0x37, 0xdb, 0x46, 0xef};
  for (int i = 0; i < 8; i++)
    EXPECT_EQ_INT(out[i], expect[i]);
}

/* A nonzero seed must change the xxh64 digest: the algorithm is genuinely
 * seed-aware, deterministic, and distinct from seed 0. */
static void test_checksum_xxh64_seed_changes_digest() {
  uint8_t a[CHECKSUM_MAX_DIGEST_LEN], b[CHECKSUM_MAX_DIGEST_LEN];
  size_t alen = 0, blen = 0;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH64, 7, "payload", 7, a, sizeof(a), &alen));
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH64, 0, "payload", 7, b, sizeof(b), &blen));
  EXPECT_TRUE(alen == blen);
  EXPECT_TRUE(memcmp(a, b, alen) != 0);
}

static void test_checksum_xxh64_seed_deterministic() {
  uint8_t a[CHECKSUM_MAX_DIGEST_LEN], b[CHECKSUM_MAX_DIGEST_LEN];
  size_t alen = 0, blen = 0;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH64, 12345, "same", 4, a, sizeof(a), &alen));
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH64, 12345, "same", 4, b, sizeof(b), &blen));
  EXPECT_TRUE(alen == blen);
  EXPECT_TRUE(memcmp(a, b, alen) == 0);
}

static void test_checksum_md5_vectors() {
  uint8_t out[CHECKSUM_MAX_DIGEST_LEN];
  size_t len = 0;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_MD5, 0, "", 0, out, sizeof(out), &len));
  EXPECT_TRUE(len == (size_t)16);
  const uint8_t expect_empty[16] = {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                                    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e};
  EXPECT_TRUE(memcmp(out, expect_empty, 16) == 0);

  /* MD5("abc") */
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_MD5, 0, "abc", 3, out, sizeof(out), &len));
  const uint8_t expect_abc[16] = {0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
                                  0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72};
  EXPECT_TRUE(memcmp(out, expect_abc, 16) == 0);
}

/* md5 is 16 bytes and differs from the 8-byte xxh64 for the same input, so the
 * choice is observably different both in length and in content. */
static void test_checksum_algo_lengths_distinct() {
  EXPECT_EQ_INT((int)checksum_digest_len(CHECKSUM_ALGO_XXH64), 8);
  EXPECT_EQ_INT((int)checksum_digest_len(CHECKSUM_ALGO_MD5), 16);

  uint8_t x[CHECKSUM_MAX_DIGEST_LEN], m[CHECKSUM_MAX_DIGEST_LEN];
  size_t xl = 0, ml = 0;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH64, 0, "same content", 12, x, sizeof(x), &xl));
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_MD5, 0, "same content", 12, m, sizeof(m), &ml));
  EXPECT_TRUE(xl == (size_t)8);
  EXPECT_TRUE(ml == (size_t)16);
  EXPECT_TRUE(memcmp(x, m, 8) != 0);
}

/* md5 has no seed: two distinct seeds give the same md5 digest (documented);
 * the seed is only honored by xxh64 and the delta block hash (low 32 bits). */
static void test_checksum_md5_seed_ignored() {
  uint8_t a[CHECKSUM_MAX_DIGEST_LEN], b[CHECKSUM_MAX_DIGEST_LEN];
  size_t alen = 0, blen = 0;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_MD5, 0, "data", 4, a, sizeof(a), &alen));
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_MD5, 99, "data", 4, b, sizeof(b), &blen));
  EXPECT_TRUE(memcmp(a, b, alen) == 0);
}

static void test_checksum_algo_name_mapping() {
  EXPECT_EQ_INT(checksum_algo_from_name("xxh64"), (int)CHECKSUM_ALGO_XXH64);
  EXPECT_EQ_INT(checksum_algo_from_name("XXH64"), (int)CHECKSUM_ALGO_XXH64);
  EXPECT_EQ_INT(checksum_algo_from_name("xxhash"), (int)CHECKSUM_ALGO_XXH64);
  EXPECT_EQ_INT(checksum_algo_from_name("XXHASH"), (int)CHECKSUM_ALGO_XXH64);
  EXPECT_EQ_INT(checksum_algo_from_name("md5"), (int)CHECKSUM_ALGO_MD5);
  EXPECT_EQ_INT(checksum_algo_from_name("MD5"), (int)CHECKSUM_ALGO_MD5);
  EXPECT_TRUE(checksum_algo_from_name("sha256") < 0);
  EXPECT_TRUE(checksum_algo_from_name("crc32") < 0);
  EXPECT_TRUE(checksum_algo_from_name("none") < 0);
  EXPECT_TRUE(checksum_algo_from_name("") < 0);
  EXPECT_TRUE(checksum_algo_from_name(NULL) < 0);

  EXPECT_TRUE(checksum_algo_valid((int)CHECKSUM_ALGO_XXH64));
  EXPECT_TRUE(checksum_algo_valid((int)CHECKSUM_ALGO_MD5));
  EXPECT_FALSE(checksum_algo_valid(99));
  EXPECT_EQ_STR(checksum_algo_name(CHECKSUM_ALGO_XXH64), "xxh64");
  EXPECT_EQ_STR(checksum_algo_name(CHECKSUM_ALGO_MD5), "md5");
}

static void test_checksum_truncated_buffer_rejected() {
  uint8_t small[4];
  size_t len = 0;
  /* The digest cannot fit in a 4-byte buffer. */
  EXPECT_FALSE(checksum_digest(CHECKSUM_ALGO_XXH64, 0, "x", 1, small, sizeof(small), &len));
  EXPECT_FALSE(checksum_digest(CHECKSUM_ALGO_MD5, 0, "x", 1, small, sizeof(small), &len));
  EXPECT_FALSE(checksum_digest(CHECKSUM_ALGO_XXH64, 0, NULL, 5, small, sizeof(small), &len));
  EXPECT_FALSE(checksum_digest(CHECKSUM_ALGO_XXH64, 0, "x", 1, NULL, 0, &len));
  EXPECT_FALSE(checksum_digest(CHECKSUM_ALGO_XXH64, 0, "x", 1, small, sizeof(small), NULL));
}

/* A NULL data pointer with size 0 is the empty input, not an error. */
static void test_checksum_null_empty_digest() {
  uint8_t a[CHECKSUM_MAX_DIGEST_LEN], b[CHECKSUM_MAX_DIGEST_LEN];
  size_t alen = 0, blen = 0;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH64, 0, NULL, 0, a, sizeof(a), &alen));
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH64, 0, "", 0, b, sizeof(b), &blen));
  EXPECT_TRUE(alen == blen);
  EXPECT_TRUE(memcmp(a, b, alen) == 0);
}

void test_checksum(void) {
  test_checksum_xxh64_seed0();
  test_checksum_xxh64_empty();
  test_checksum_xxh64_seed_changes_digest();
  test_checksum_xxh64_seed_deterministic();
  test_checksum_md5_vectors();
  test_checksum_algo_lengths_distinct();
  test_checksum_md5_seed_ignored();
  test_checksum_algo_name_mapping();
  test_checksum_truncated_buffer_rejected();
  test_checksum_null_empty_digest();
}