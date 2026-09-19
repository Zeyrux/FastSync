#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Whole-file content-digest algorithms selectable with --checksum-choice and
 * seeded with --checksum-seed.  The ids are the values actually placed on the
 * wire (config frame), so they must be kept stable and validated on receive.
 * CHECKSUM_ALGO_XXH64 == 0 is the historical FastSync default and its numeric
 * value is preserved.  The full set mirrors the algorithms rsync 3.4.1 can be
 * built with; every one of them is implemented here. */
typedef enum {
  CHECKSUM_ALGO_XXH64 = 0,
  CHECKSUM_ALGO_MD5 = 1,
  CHECKSUM_ALGO_XXH3 = 2,
  CHECKSUM_ALGO_XXH128 = 3,
  CHECKSUM_ALGO_MD4 = 4,
  CHECKSUM_ALGO_SHA1 = 5,
  CHECKSUM_ALGO_NONE = 6
} ChecksumAlgo;

/* FastSync's negotiated default (rsync 3.4.1 auto-negotiates xxh128 first).
 * The wire default for Config->checksum_algo is this value. */
#define CHECKSUM_ALGO_DEFAULT CHECKSUM_ALGO_XXH128

/* sha1 digest is 20 bytes, the longest supported. */
#define CHECKSUM_MAX_DIGEST_LEN 20

/* Compute the whole-file digest of the first `size` bytes of `data`.
 *
 *  - CHECKSUM_ALGO_XXH64: xxHash64(data, size, seed) (full 64-bit seed).
 *  - CHECKSUM_ALGO_XXH3:  XXH3_64bits_withSeed(data, size, seed).
 *  - CHECKSUM_ALGO_XXH128: XXH3_128bits_withSeed(data, size, seed).
 *  - CHECKSUM_ALGO_MD5:   md5(data, size) via OpenSSL EVP (seed ignored).
 *  - CHECKSUM_ALGO_MD4:   md4(data, size), self-contained RFC 1320 (seed ignored).
 *  - CHECKSUM_ALGO_SHA1:  sha1(data, size) via OpenSSL EVP (seed ignored).
 *  - CHECKSUM_ALGO_NONE:  no digest; *out_len is 0 and nothing is written.
 *  - `size == 0` hashes the empty input (plus its seed), not a NULL input.
 *
 * Writes up to `out_capacity` bytes into `out`, storing the digest length in
 * *out_len.  Returns false on NULL out* or when the digest would not fit.
 * Never writes more than CHECKSUM_MAX_DIGEST_LEN bytes. */
bool checksum_digest(ChecksumAlgo algo, uint64_t seed, const void* data, size_t size, uint8_t* out,
                     size_t out_capacity, size_t* out_len);

/* Streaming whole-file digest: hash the contents of `path` without holding the
 * whole file in memory.  Same digest/capacity contract as checksum_digest.
 * Returns false on open/read failure or an undersized buffer. */
bool checksum_digest_file(ChecksumAlgo algo, uint64_t seed, const char* path, uint8_t* out,
                          size_t out_capacity, size_t* out_len);

/* Descriptor form of the streaming digest: rewinds `fd` to the start and hashes
 * to EOF without closing it.  Used by the --verify-basis path to hash an
 * already-open, root-confined basis descriptor.  Same contract as
 * checksum_digest_file. */
bool checksum_digest_fd(ChecksumAlgo algo, uint64_t seed, int fd, uint8_t* out, size_t out_capacity,
                        size_t* out_len);

/* Resolve a --checksum-choice string (case-insensitive) to an algorithm id.
 * Accepts "xxh64"/"xxhash", "xxh3", "xxh128", "md5", "md4", "sha1", "none".
 * "auto" is not an algorithm here; the caller resolves it to the negotiated
 * default.  Returns -1 for any unrecognized name. */
int checksum_algo_from_name(const char* name);

/* Canonical name of an algorithm (used in CLI error messages). */
const char* checksum_algo_name(ChecksumAlgo algo);

/* True when `algo` is a supported id (used by config receive validation). */
bool checksum_algo_valid(int algo);

/* Digest length in bytes for an algorithm (xxh64/xxh3 = 8,
 * md5/md4/xxh128 = 16, sha1 = 20, none = 0). */
uint8_t checksum_digest_len(ChecksumAlgo algo);

/* Pick the first algorithm from FastSync's compiled-in preference list that is
 * supported on this build (rsync 3.4.1's `--version` order:
 * xxh128 xxh3 xxh64 md5 md4 sha1 none).  Used to resolve "auto". */
ChecksumAlgo checksum_negotiate_default(void);

/* Resolve "auto" the way rsync does: the first supported name in
 * RSYNC_CHECKSUM_LIST (whitespace-separated, client half ends at '&'), then the
 * compiled-in preference order when the variable is unset/blank.  Returns -1
 * when the variable is set but names no supported checksum (rsync's failed
 * negotiation), otherwise a valid ChecksumAlgo id. */
int checksum_choice_resolve(void);

#endif /* CHECKSUM_H */
