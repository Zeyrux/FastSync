#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Whole-file content-digest algorithms selectable with --checksum-choice and
 * seeded with --checksum-seed.  The ids are the values actually placed on the
 * wire (config frame), so they must be kept stable and validated on receive.
 * CHECKSUM_ALGO_XXH64 == 0 is the default and is byte-for-byte what FastSync
 * computed before these options existed (xxHash64 with seed 0).  The set mirrors
 * the algorithms rsync 3.4.1 can be built with; the ones FastSync does not
 * implement (md4, sha1, none) are rejected by name at parse time. */
typedef enum {
  CHECKSUM_ALGO_XXH64 = 0,
  CHECKSUM_ALGO_MD5 = 1,
  CHECKSUM_ALGO_XXH3 = 2,
  CHECKSUM_ALGO_XXH128 = 3
} ChecksumAlgo;

/* xxh128 digest is 16 bytes, the longest supported. */
#define CHECKSUM_MAX_DIGEST_LEN 16

/* Compute the whole-file digest of the first `size` bytes of `data`.
 *
 *  - CHECKSUM_ALGO_XXH64: xxHash64(data, size, seed) (full 64-bit seed).
 *  - CHECKSUM_ALGO_MD5:   md5(data, size) via OpenSSL EVP.
 *                          md5 has no seed, so `seed` is ignored (documented).
 *  - `size == 0` hashes the empty input (plus its seed), not a NULL input.
 *
 * Writes up to `out_capacity` bytes into `out`, storing the digest length in
 * *out_len.  Returns false on NULL out* or when the digest would not fit.
 * Never writes more than CHECKSUM_MAX_DIGEST_LEN bytes. */
bool checksum_digest(ChecksumAlgo algo, uint64_t seed, const void* data, size_t size, uint8_t* out,
                     size_t out_capacity, size_t* out_len);

/* Resolve a --checksum-choice string (case-insensitive) to an algorithm id.
 * Accepts "xxh64"/"xxhash", "xxh3", "xxh128" and "md5".  "auto", rsync's
 * default automatic choice, is resolved to the default by the caller (it is not
 * a distinct algorithm here).  Returns -1 for any name FastSync does not
 * implement (md4/sha1/none included). */
int checksum_algo_from_name(const char* name);

/* Canonical name of an algorithm (used in CLI error messages). */
const char* checksum_algo_name(ChecksumAlgo algo);

/* True when `algo` is a supported id (used by config receive validation). */
bool checksum_algo_valid(int algo);

/* Digest length in bytes for an algorithm (xxh64/xxh3 = 8, md5/xxh128 = 16). */
uint8_t checksum_digest_len(ChecksumAlgo algo);

#endif /* CHECKSUM_H */