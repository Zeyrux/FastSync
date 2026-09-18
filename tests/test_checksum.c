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

static void test_checksum_md4_vectors() {
  uint8_t out[CHECKSUM_MAX_DIGEST_LEN];
  size_t len = 0;
  /* RFC 1320 / RFC 1321 test vectors. */
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_MD4, 0, "", 0, out, sizeof(out), &len));
  EXPECT_TRUE(len == (size_t)16);
  const uint8_t expect_empty[16] = {0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
                                    0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0};
  EXPECT_TRUE(memcmp(out, expect_empty, 16) == 0);

  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_MD4, 0, "abc", 3, out, sizeof(out), &len));
  const uint8_t expect_abc[16] = {0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52,
                                  0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d};
  EXPECT_TRUE(memcmp(out, expect_abc, 16) == 0);

  /* A longer input exercises the block loop and the padding boundary. */
  const char* msg =
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_MD4, 0, msg, strlen(msg), out, sizeof(out), &len));
  const uint8_t expect_long[16] = {0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38, 0xf2, 0x19,
                                   0x9c, 0x3e, 0x7b, 0x16, 0x4f, 0xcc, 0x05, 0x36};
  EXPECT_TRUE(memcmp(out, expect_long, 16) == 0);
}

static void test_checksum_sha1_vectors() {
  uint8_t out[CHECKSUM_MAX_DIGEST_LEN];
  size_t len = 0;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_SHA1, 0, "abc", 3, out, sizeof(out), &len));
  EXPECT_TRUE(len == (size_t)20);
  const uint8_t expect_abc[20] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                                  0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
  EXPECT_TRUE(memcmp(out, expect_abc, 20) == 0);

  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_SHA1, 0, "", 0, out, sizeof(out), &len));
  EXPECT_TRUE(len == (size_t)20);
  const uint8_t expect_empty[20] = {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
                                    0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09};
  EXPECT_TRUE(memcmp(out, expect_empty, 20) == 0);

  /* sha1 has no seed: the digest is seed-independent (documented). */
  uint8_t seeded[CHECKSUM_MAX_DIGEST_LEN];
  size_t seeded_len = 0;
  EXPECT_TRUE(
      checksum_digest(CHECKSUM_ALGO_SHA1, 12345, "abc", 3, seeded, sizeof(seeded), &seeded_len));
  EXPECT_TRUE(seeded_len == (size_t)20);
  EXPECT_TRUE(memcmp(expect_abc, seeded, 20) == 0);
}

/* "none" is a successful no-digest: length 0, nothing written. */
static void test_checksum_none_digest() {
  uint8_t out[CHECKSUM_MAX_DIGEST_LEN];
  size_t len = 99;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_NONE, 0, "data", 4, out, sizeof(out), &len));
  EXPECT_EQ_INT((int)len, 0);
  EXPECT_EQ_INT((int)checksum_digest_len(CHECKSUM_ALGO_NONE), 0);
}

static void test_checksum_algo_name_mapping() {
  EXPECT_EQ_INT(checksum_algo_from_name("xxh64"), (int)CHECKSUM_ALGO_XXH64);
  EXPECT_EQ_INT(checksum_algo_from_name("XXH64"), (int)CHECKSUM_ALGO_XXH64);
  EXPECT_EQ_INT(checksum_algo_from_name("xxhash"), (int)CHECKSUM_ALGO_XXH64);
  EXPECT_EQ_INT(checksum_algo_from_name("XXHASH"), (int)CHECKSUM_ALGO_XXH64);
  EXPECT_EQ_INT(checksum_algo_from_name("md5"), (int)CHECKSUM_ALGO_MD5);
  EXPECT_EQ_INT(checksum_algo_from_name("MD5"), (int)CHECKSUM_ALGO_MD5);
  EXPECT_EQ_INT(checksum_algo_from_name("xxh3"), (int)CHECKSUM_ALGO_XXH3);
  EXPECT_EQ_INT(checksum_algo_from_name("XXH3"), (int)CHECKSUM_ALGO_XXH3);
  EXPECT_EQ_INT(checksum_algo_from_name("xxh128"), (int)CHECKSUM_ALGO_XXH128);
  EXPECT_EQ_INT(checksum_algo_from_name("XXH128"), (int)CHECKSUM_ALGO_XXH128);
  EXPECT_EQ_INT(checksum_algo_from_name("md4"), (int)CHECKSUM_ALGO_MD4);
  EXPECT_EQ_INT(checksum_algo_from_name("MD4"), (int)CHECKSUM_ALGO_MD4);
  EXPECT_EQ_INT(checksum_algo_from_name("sha1"), (int)CHECKSUM_ALGO_SHA1);
  EXPECT_EQ_INT(checksum_algo_from_name("SHA1"), (int)CHECKSUM_ALGO_SHA1);
  EXPECT_EQ_INT(checksum_algo_from_name("none"), (int)CHECKSUM_ALGO_NONE);
  /* Names rsync does not offer (or FastSync cannot compute) are rejected. */
  EXPECT_TRUE(checksum_algo_from_name("sha256") < 0);
  EXPECT_TRUE(checksum_algo_from_name("crc32") < 0);
  EXPECT_TRUE(checksum_algo_from_name("") < 0);
  EXPECT_TRUE(checksum_algo_from_name(NULL) < 0);

  EXPECT_TRUE(checksum_algo_valid((int)CHECKSUM_ALGO_XXH64));
  EXPECT_TRUE(checksum_algo_valid((int)CHECKSUM_ALGO_MD5));
  EXPECT_TRUE(checksum_algo_valid((int)CHECKSUM_ALGO_XXH3));
  EXPECT_TRUE(checksum_algo_valid((int)CHECKSUM_ALGO_XXH128));
  EXPECT_TRUE(checksum_algo_valid((int)CHECKSUM_ALGO_MD4));
  EXPECT_TRUE(checksum_algo_valid((int)CHECKSUM_ALGO_SHA1));
  EXPECT_TRUE(checksum_algo_valid((int)CHECKSUM_ALGO_NONE));
  EXPECT_FALSE(checksum_algo_valid(99));
  EXPECT_EQ_STR(checksum_algo_name(CHECKSUM_ALGO_XXH64), "xxh64");
  EXPECT_EQ_STR(checksum_algo_name(CHECKSUM_ALGO_MD5), "md5");
  EXPECT_EQ_STR(checksum_algo_name(CHECKSUM_ALGO_XXH3), "xxh3");
  EXPECT_EQ_STR(checksum_algo_name(CHECKSUM_ALGO_XXH128), "xxh128");
  EXPECT_EQ_STR(checksum_algo_name(CHECKSUM_ALGO_MD4), "md4");
  EXPECT_EQ_STR(checksum_algo_name(CHECKSUM_ALGO_SHA1), "sha1");
  EXPECT_EQ_STR(checksum_algo_name(CHECKSUM_ALGO_NONE), "none");

  /* rsync 3.4.1 auto-negotiates xxh128 first. */
  EXPECT_EQ_INT((int)checksum_negotiate_default(), (int)CHECKSUM_ALGO_XXH128);
}

/* xxh3 is 8 bytes and seed-aware; xxh128 is 16 bytes and differs from both
 * xxh64 and md5 for the same input. */
static void test_checksum_xxh3_xxh128() {
  EXPECT_EQ_INT((int)checksum_digest_len(CHECKSUM_ALGO_XXH3), 8);
  EXPECT_EQ_INT((int)checksum_digest_len(CHECKSUM_ALGO_XXH128), 16);

  uint8_t a[CHECKSUM_MAX_DIGEST_LEN], b[CHECKSUM_MAX_DIGEST_LEN];
  size_t alen = 0, blen = 0;
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH3, 0, "payload", 7, a, sizeof(a), &alen));
  EXPECT_TRUE(alen == (size_t)8);
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH3, 5, "payload", 7, b, sizeof(b), &blen));
  EXPECT_TRUE(memcmp(a, b, alen) != 0);

  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH128, 0, "payload", 7, a, sizeof(a), &alen));
  EXPECT_TRUE(alen == (size_t)16);
  EXPECT_TRUE(checksum_digest(CHECKSUM_ALGO_XXH128, 0, "payload", 7, b, sizeof(b), &blen));
  EXPECT_TRUE(memcmp(a, b, blen) == 0);
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
  test_checksum_md4_vectors();
  test_checksum_sha1_vectors();
  test_checksum_none_digest();
  test_checksum_algo_lengths_distinct();
  test_checksum_md5_seed_ignored();
  test_checksum_algo_name_mapping();
  test_checksum_xxh3_xxh128();
  test_checksum_truncated_buffer_rejected();
  test_checksum_null_empty_digest();
}