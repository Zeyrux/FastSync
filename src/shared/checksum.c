#include "checksum.h"
#include <openssl/evp.h>
#include <string.h>
#include <strings.h>

/* delta.c owns the single XXH_IMPLEMENTATION that provides the xxHash symbols
 * for the whole binary; this TU only needs the declarations. */
#include <xxhash.h>

bool checksum_digest(ChecksumAlgo algo, uint64_t seed, const void* data, size_t size, uint8_t* out,
                     size_t out_capacity, size_t* out_len) {
  if (!out || !out_len || out_capacity < CHECKSUM_MAX_DIGEST_LEN)
    return false;
  if (data == NULL && size != 0)
    return false;

  if (algo == CHECKSUM_ALGO_XXH64) {
    uint64_t digest = XXH64(data, size, seed);
    uint8_t buf[CHECKSUM_MAX_DIGEST_LEN];
    memcpy(buf, &digest, sizeof(digest));
    memcpy(out, buf, sizeof(digest));
    *out_len = sizeof(digest);
    return true;
  }

  if (algo == CHECKSUM_ALGO_MD5) {
    /* md5 takes no seed; the caller's seed is deliberately ignored (documented
     * in RSYNC_COMPAT.md).  OpenSSL's one-shot EVP_Digest needs a non-NULL
     * buffer even for an empty input, so map a NULL data + size==0 to an empty
     * buffer. */
    static const uint8_t empty = 0;
    const void* input = data ? data : &empty;
    unsigned int digest_len = 0;
    if (EVP_Digest(input, size, out, &digest_len, EVP_md5(), NULL) != 1)
      return false;
    if (digest_len > out_capacity)
      return false;
    *out_len = digest_len;
    return true;
  }

  return false;
}

int checksum_algo_from_name(const char* name) {
  if (!name)
    return -1;
  if (strcasecmp(name, "xxh64") == 0 || strcasecmp(name, "xxhash") == 0 ||
      strcasecmp(name, "xxh3") == 0)
    return (int)CHECKSUM_ALGO_XXH64;
  if (strcasecmp(name, "md5") == 0)
    return (int)CHECKSUM_ALGO_MD5;
  return -1;
}

const char* checksum_algo_name(ChecksumAlgo algo) {
  switch (algo) {
  case CHECKSUM_ALGO_XXH64:
    return "xxh64";
  case CHECKSUM_ALGO_MD5:
    return "md5";
  }
  return "<unknown>";
}

bool checksum_algo_valid(int algo) {
  return algo == (int)CHECKSUM_ALGO_XXH64 || algo == (int)CHECKSUM_ALGO_MD5;
}

uint8_t checksum_digest_len(ChecksumAlgo algo) {
  switch (algo) {
  case CHECKSUM_ALGO_XXH64:
    return 8;
  case CHECKSUM_ALGO_MD5:
    return 16;
  }
  return 0;
}