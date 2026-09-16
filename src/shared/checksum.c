#include "checksum.h"
#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/* delta.c owns the single XXH_IMPLEMENTATION that provides the xxHash symbols
 * for the whole binary; this TU only needs the declarations.  The streaming
 * state structs and XXH3_update are exposed only with XXH_STATIC_LINKING_ONLY. */
#define XXH_STATIC_LINKING_ONLY
#include <xxhash.h>

bool checksum_digest(ChecksumAlgo algo, uint64_t seed, const void* data, size_t size, uint8_t* out,
                     size_t out_capacity, size_t* out_len) {
  if (!out || !out_len || out_capacity < CHECKSUM_MAX_DIGEST_LEN)
    return false;
  if (data == NULL && size != 0)
    return false;

  if (algo == CHECKSUM_ALGO_XXH64) {
    uint64_t digest = XXH64(data, size, seed);
    memcpy(out, &digest, sizeof(digest));
    *out_len = sizeof(digest);
    return true;
  }

  if (algo == CHECKSUM_ALGO_XXH3) {
    uint64_t digest = XXH3_64bits_withSeed(data, size, seed);
    memcpy(out, &digest, sizeof(digest));
    *out_len = sizeof(digest);
    return true;
  }

  if (algo == CHECKSUM_ALGO_XXH128) {
    XXH128_hash_t digest = XXH3_128bits_withSeed(data, size, seed);
    memcpy(out, &digest, sizeof(digest));
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

bool checksum_digest_file(ChecksumAlgo algo, uint64_t seed, const char* path, uint8_t* out,
                          size_t out_capacity, size_t* out_len) {
  if (!path || !out || !out_len || out_capacity < CHECKSUM_MAX_DIGEST_LEN)
    return false;

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return false;

  uint8_t buffer[64 * 1024];
  bool ok = false;

  if (algo == CHECKSUM_ALGO_MD5) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
      close(fd);
      return false;
    }
    unsigned int digest_len = 0;
    if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) == 1) {
      ok = true;
      ssize_t got;
      while ((got = read(fd, buffer, sizeof(buffer))) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) {
          ok = false;
          break;
        }
      }
      if (got < 0)
        ok = false;
      if (ok && EVP_DigestFinal_ex(ctx, out, &digest_len) == 1 && digest_len <= out_capacity)
        *out_len = digest_len;
      else
        ok = false;
    }
    EVP_MD_CTX_free(ctx);
    close(fd);
    return ok;
  }

  XXH64_state_t xxh64;
  XXH3_state_t* xxh3 = NULL;
  if (algo == CHECKSUM_ALGO_XXH64) {
    XXH64_reset(&xxh64, seed);
  } else if (algo == CHECKSUM_ALGO_XXH3 || algo == CHECKSUM_ALGO_XXH128) {
    xxh3 = XXH3_createState();
    if (!xxh3) {
      close(fd);
      return false;
    }
    if (algo == CHECKSUM_ALGO_XXH3)
      XXH3_64bits_reset_withSeed(xxh3, seed);
    else
      XXH3_128bits_reset_withSeed(xxh3, seed);
  } else {
    close(fd);
    return false;
  }

  ok = true;
  ssize_t got;
  while ((got = read(fd, buffer, sizeof(buffer))) > 0) {
    if (algo == CHECKSUM_ALGO_XXH64)
      XXH64_update(&xxh64, buffer, (size_t)got);
    else if (XXH3_64bits_update(xxh3, buffer, (size_t)got) == XXH_ERROR) {
      ok = false;
      break;
    }
  }
  if (got < 0)
    ok = false;

  if (ok) {
    if (algo == CHECKSUM_ALGO_XXH64) {
      uint64_t digest = XXH64_digest(&xxh64);
      memcpy(out, &digest, sizeof(digest));
      *out_len = sizeof(digest);
    } else if (algo == CHECKSUM_ALGO_XXH3) {
      uint64_t digest = XXH3_64bits_digest(xxh3);
      memcpy(out, &digest, sizeof(digest));
      *out_len = sizeof(digest);
    } else {
      XXH128_hash_t digest = XXH3_128bits_digest(xxh3);
      memcpy(out, &digest, sizeof(digest));
      *out_len = sizeof(digest);
    }
  }
  if (xxh3)
    XXH3_freeState(xxh3);
  close(fd);
  return ok;
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
  }
  return "<unknown>";
}

bool checksum_algo_valid(int algo) {
  return algo == (int)CHECKSUM_ALGO_XXH64 || algo == (int)CHECKSUM_ALGO_MD5 ||
         algo == (int)CHECKSUM_ALGO_XXH3 || algo == (int)CHECKSUM_ALGO_XXH128;
}

uint8_t checksum_digest_len(ChecksumAlgo algo) {
  switch (algo) {
  case CHECKSUM_ALGO_XXH64:
  case CHECKSUM_ALGO_XXH3:
    return 8;
  case CHECKSUM_ALGO_XXH128:
  case CHECKSUM_ALGO_MD5:
    return 16;
  }
  return 0;
}