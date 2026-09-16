#include "checksum.h"
#include <openssl/evp.h>
#include <string.h>
#include <strings.h>

/* delta.c owns the single XXH_IMPLEMENTATION that provides the xxHash symbols
 * for the whole binary; this TU only needs the declarations. */
#include <xxhash.h>

/* ---------------------------------------------------------------------------
 * Self-contained MD4 (RFC 1320).  OpenSSL's MD4 lives in the legacy provider
 * and is not guaranteed present, so FastSync carries its own implementation to
 * keep --checksum-choice=md4 working on every build.
 * ------------------------------------------------------------------------- */

typedef struct {
  uint32_t state[4];
  uint64_t bit_count;
  uint8_t buffer[64];
  size_t buffer_len;
} Md4Ctx;

static uint32_t md4_rotl(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

static void md4_transform(uint32_t state[4], const uint8_t block[64]) {
  uint32_t x[16];
  for (int i = 0; i < 16; i++)
    x[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) |
           ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);

  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define ROUND1(a, b, c, d, k, s) a = md4_rotl(a + F(b, c, d) + x[k], s)
#define ROUND2(a, b, c, d, k, s) a = md4_rotl(a + G(b, c, d) + x[k] + 0x5a827999u, s)
#define ROUND3(a, b, c, d, k, s) a = md4_rotl(a + H(b, c, d) + x[k] + 0x6ed9eba1u, s)

  ROUND1(a, b, c, d, 0, 3);
  ROUND1(d, a, b, c, 1, 7);
  ROUND1(c, d, a, b, 2, 11);
  ROUND1(b, c, d, a, 3, 19);
  ROUND1(a, b, c, d, 4, 3);
  ROUND1(d, a, b, c, 5, 7);
  ROUND1(c, d, a, b, 6, 11);
  ROUND1(b, c, d, a, 7, 19);
  ROUND1(a, b, c, d, 8, 3);
  ROUND1(d, a, b, c, 9, 7);
  ROUND1(c, d, a, b, 10, 11);
  ROUND1(b, c, d, a, 11, 19);
  ROUND1(a, b, c, d, 12, 3);
  ROUND1(d, a, b, c, 13, 7);
  ROUND1(c, d, a, b, 14, 11);
  ROUND1(b, c, d, a, 15, 19);

  ROUND2(a, b, c, d, 0, 3);
  ROUND2(d, a, b, c, 4, 5);
  ROUND2(c, d, a, b, 8, 9);
  ROUND2(b, c, d, a, 12, 13);
  ROUND2(a, b, c, d, 1, 3);
  ROUND2(d, a, b, c, 5, 5);
  ROUND2(c, d, a, b, 9, 9);
  ROUND2(b, c, d, a, 13, 13);
  ROUND2(a, b, c, d, 2, 3);
  ROUND2(d, a, b, c, 6, 5);
  ROUND2(c, d, a, b, 10, 9);
  ROUND2(b, c, d, a, 14, 13);
  ROUND2(a, b, c, d, 3, 3);
  ROUND2(d, a, b, c, 7, 5);
  ROUND2(c, d, a, b, 11, 9);
  ROUND2(b, c, d, a, 15, 13);

  ROUND3(a, b, c, d, 0, 3);
  ROUND3(d, a, b, c, 8, 9);
  ROUND3(c, d, a, b, 4, 11);
  ROUND3(b, c, d, a, 12, 15);
  ROUND3(a, b, c, d, 2, 3);
  ROUND3(d, a, b, c, 10, 9);
  ROUND3(c, d, a, b, 6, 11);
  ROUND3(b, c, d, a, 14, 15);
  ROUND3(a, b, c, d, 1, 3);
  ROUND3(d, a, b, c, 9, 9);
  ROUND3(c, d, a, b, 5, 11);
  ROUND3(b, c, d, a, 13, 15);
  ROUND3(a, b, c, d, 3, 3);
  ROUND3(d, a, b, c, 11, 9);
  ROUND3(c, d, a, b, 7, 11);
  ROUND3(b, c, d, a, 15, 15);

#undef F
#undef G
#undef H
#undef ROUND1
#undef ROUND2
#undef ROUND3

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

static void md4_init(Md4Ctx* ctx) {
  ctx->state[0] = 0x67452301u;
  ctx->state[1] = 0xefcdab89u;
  ctx->state[2] = 0x98badcfeu;
  ctx->state[3] = 0x10325476u;
  ctx->bit_count = 0;
  ctx->buffer_len = 0;
}

static void md4_update(Md4Ctx* ctx, const uint8_t* data, size_t len) {
  ctx->bit_count += (uint64_t)len * 8;
  while (len > 0) {
    size_t space = sizeof(ctx->buffer) - ctx->buffer_len;
    size_t take = len < space ? len : space;
    memcpy(ctx->buffer + ctx->buffer_len, data, take);
    ctx->buffer_len += take;
    data += take;
    len -= take;
    if (ctx->buffer_len == sizeof(ctx->buffer)) {
      md4_transform(ctx->state, ctx->buffer);
      ctx->buffer_len = 0;
    }
  }
}

static void md4_final(Md4Ctx* ctx, uint8_t out[16]) {
  uint64_t bit_count = ctx->bit_count;
  uint8_t pad = 0x80;
  md4_update(ctx, &pad, 1);
  uint8_t zero = 0;
  while (ctx->buffer_len != 56)
    md4_update(ctx, &zero, 1);
  uint8_t length_le[8];
  for (int i = 0; i < 8; i++)
    length_le[i] = (uint8_t)((bit_count >> (8 * i)) & 0xff);
  md4_update(ctx, length_le, sizeof(length_le));
  for (int i = 0; i < 4; i++) {
    out[i * 4] = (uint8_t)(ctx->state[i] & 0xff);
    out[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
    out[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
    out[i * 4 + 3] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
  }
}

/* One-shot EVP digest (md5/sha1).  Returns false when OpenSSL refuses. */
static bool evp_digest(const EVP_MD* md, const void* data, size_t size, uint8_t* out,
                       size_t out_capacity, size_t* out_len) {
  static const uint8_t empty = 0;
  const void* input = data ? data : &empty;
  unsigned int digest_len = 0;
  if (EVP_Digest(input, size, out, &digest_len, md, NULL) != 1)
    return false;
  if (digest_len > out_capacity)
    return false;
  *out_len = digest_len;
  return true;
}

bool checksum_digest(ChecksumAlgo algo, uint64_t seed, const void* data, size_t size, uint8_t* out,
                     size_t out_capacity, size_t* out_len) {
  if (!out || !out_len || out_capacity < CHECKSUM_MAX_DIGEST_LEN)
    return false;
  if (data == NULL && size != 0)
    return false;

  switch (algo) {
  case CHECKSUM_ALGO_XXH64: {
    uint64_t digest = XXH64(data, size, seed);
    memcpy(out, &digest, sizeof(digest));
    *out_len = sizeof(digest);
    return true;
  }
  case CHECKSUM_ALGO_XXH3: {
    uint64_t digest = XXH3_64bits_withSeed(data, size, seed);
    memcpy(out, &digest, sizeof(digest));
    *out_len = sizeof(digest);
    return true;
  }
  case CHECKSUM_ALGO_XXH128: {
    XXH128_hash_t digest = XXH3_128bits_withSeed(data, size, seed);
    memcpy(out, &digest, sizeof(digest));
    *out_len = sizeof(digest);
    return true;
  }
  case CHECKSUM_ALGO_MD5:
    /* md5 takes no seed; the caller's seed is deliberately ignored (documented
     * in RSYNC_COMPAT.md). */
    return evp_digest(EVP_md5(), data, size, out, out_capacity, out_len);
  case CHECKSUM_ALGO_MD4: {
    Md4Ctx ctx;
    md4_init(&ctx);
    md4_update(&ctx, (const uint8_t*)data, size);
    md4_final(&ctx, out);
    *out_len = 16;
    return true;
  }
  case CHECKSUM_ALGO_SHA1:
    /* sha1 takes no seed; the caller's seed is deliberately ignored. */
    return evp_digest(EVP_sha1(), data, size, out, out_capacity, out_len);
  case CHECKSUM_ALGO_NONE:
    /* No checksum requested: an empty digest is the successful result. */
    *out_len = 0;
    return true;
  }
  return false;
}

int checksum_algo_from_name(const char* name) {
  if (!name)
    return -1;
  if (strcasecmp(name, "xxh64") == 0 || strcasecmp(name, "xxhash") == 0)
    return (int)CHECKSUM_ALGO_XXH64;
  if (strcasecmp(name, "xxh3") == 0)
    return (int)CHECKSUM_ALGO_XXH3;
  if (strcasecmp(name, "xxh128") == 0)
    return (int)CHECKSUM_ALGO_XXH128;
  if (strcasecmp(name, "md5") == 0)
    return (int)CHECKSUM_ALGO_MD5;
  if (strcasecmp(name, "md4") == 0)
    return (int)CHECKSUM_ALGO_MD4;
  if (strcasecmp(name, "sha1") == 0)
    return (int)CHECKSUM_ALGO_SHA1;
  if (strcasecmp(name, "none") == 0)
    return (int)CHECKSUM_ALGO_NONE;
  return -1;
}

const char* checksum_algo_name(ChecksumAlgo algo) {
  switch (algo) {
  case CHECKSUM_ALGO_XXH64:
    return "xxh64";
  case CHECKSUM_ALGO_XXH3:
    return "xxh3";
  case CHECKSUM_ALGO_XXH128:
    return "xxh128";
  case CHECKSUM_ALGO_MD5:
    return "md5";
  case CHECKSUM_ALGO_MD4:
    return "md4";
  case CHECKSUM_ALGO_SHA1:
    return "sha1";
  case CHECKSUM_ALGO_NONE:
    return "none";
  }
  return "<unknown>";
}

bool checksum_algo_valid(int algo) {
  return algo == (int)CHECKSUM_ALGO_XXH64 || algo == (int)CHECKSUM_ALGO_MD5 ||
         algo == (int)CHECKSUM_ALGO_XXH3 || algo == (int)CHECKSUM_ALGO_XXH128 ||
         algo == (int)CHECKSUM_ALGO_MD4 || algo == (int)CHECKSUM_ALGO_SHA1 ||
         algo == (int)CHECKSUM_ALGO_NONE;
}

uint8_t checksum_digest_len(ChecksumAlgo algo) {
  switch (algo) {
  case CHECKSUM_ALGO_XXH64:
  case CHECKSUM_ALGO_XXH3:
    return 8;
  case CHECKSUM_ALGO_XXH128:
  case CHECKSUM_ALGO_MD5:
  case CHECKSUM_ALGO_MD4:
    return 16;
  case CHECKSUM_ALGO_SHA1:
    return 20;
  case CHECKSUM_ALGO_NONE:
    return 0;
  }
  return 0;
}

ChecksumAlgo checksum_negotiate_default(void) {
  /* rsync 3.4.1 default preference order; every entry is compiled in, so this
   * resolves to xxh128. */
  static const ChecksumAlgo preference[] = {
      CHECKSUM_ALGO_XXH128, CHECKSUM_ALGO_XXH3, CHECKSUM_ALGO_XXH64, CHECKSUM_ALGO_MD5,
      CHECKSUM_ALGO_MD4,    CHECKSUM_ALGO_SHA1, CHECKSUM_ALGO_NONE,
  };
  for (size_t i = 0; i < sizeof(preference) / sizeof(preference[0]); i++) {
    if (checksum_algo_valid((int)preference[i]))
      return preference[i];
  }
  return CHECKSUM_ALGO_XXH64;
}
