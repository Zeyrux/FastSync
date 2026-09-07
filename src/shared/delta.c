#include "delta.h"
#include "log.h"
#include "protocol.h"
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
#include <xxhash.h>

/* Maximum number of blocks/instructions allowed from the wire to prevent OOM */
#define MAX_DELTA_BLOCKS (1024U * 1024U)       /* 1M signature blocks */
#define MAX_DELTA_INSTRUCTIONS (1024U * 1024U) /* 1M delta instructions */

uint32_t delta_adler32(const void* data, uint32_t len) {
  const uint8_t* p = (const uint8_t*)data;
  uint32_t s1 = 1;
  uint32_t s2 = 0;
  for (uint32_t i = 0; i < len; i++) {
    s1 = (s1 + p[i]) % DELTA_ADLER32_MODULUS;
    s2 = (s2 + s1) % DELTA_ADLER32_MODULUS;
  }
  return (s2 << 16) | s1;
}

uint32_t delta_xxhash32(const void* data, uint32_t len) {
  return XXH32(data, len, 0);
}

uint32_t delta_xxhash32_seeded(const void* data, uint32_t len, uint32_t seed) {
  return XXH32(data, len, seed);
}

uint64_t delta_xxhash64(const void* data, size_t len) {
  return XXH64(data, len, 0);
}

DeltaSignature* delta_signature_create(const void* old_file_data, uint64_t old_file_size,
                                       uint32_t block_size) {
  return delta_signature_create_seeded(old_file_data, old_file_size, block_size, 0);
}

DeltaSignature* delta_signature_create_seeded(const void* old_file_data, uint64_t old_file_size,
                                              uint32_t block_size, uint32_t seed) {
  if (old_file_data == NULL || old_file_size == 0 || block_size == 0)
    return NULL;

  if (old_file_size > DELTA_MAX_FILE_SIZE || block_size > DELTA_BLOCK_SIZE_MAX ||
      old_file_size > UINT32_MAX * (uint64_t)block_size)
    return NULL;

  uint32_t block_count = (uint32_t)((old_file_size + block_size - 1) / block_size);

  DeltaSignature* sig = protocol_alloc(sizeof(DeltaSignature));
  if (!sig)
    return NULL;

  sig->file_size = old_file_size;
  sig->block_size = block_size;
  sig->block_count = block_count;
  if (block_count == 0) {
    free(sig);
    return NULL;
  }
  sig->blocks = protocol_alloc((size_t)block_count * sizeof(DeltaBlockSig));
  if (!sig->blocks) {
    free(sig);
    return NULL;
  }

  const uint8_t* data = (const uint8_t*)old_file_data;
  for (uint32_t i = 0; i < block_count; i++) {
    uint64_t offset = (uint64_t)i * block_size;
    uint32_t len =
        (uint32_t)((old_file_size - offset < block_size) ? (old_file_size - offset) : block_size);
    sig->blocks[i].adler32 = delta_adler32(data + offset, len);
    sig->blocks[i].xxhash = delta_xxhash32_seeded(data + offset, len, seed);
  }

  return sig;
}

Data* delta_signature_serialize(const DeltaSignature* sig) {
  if (!sig)
    return NULL;

  uint64_t block_bytes = (uint64_t)sig->block_count * (sizeof(uint32_t) + sizeof(uint32_t));
  uint64_t total = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + block_bytes;
  if (block_bytes > UINT64_MAX - (sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t)) ||
      total > SIZE_MAX)
    return NULL;

  uint8_t* buf = protocol_alloc((size_t)total);
  if (!buf)
    return NULL;

  size_t pos = 0;
  memcpy(buf + pos, &sig->file_size, sizeof(uint64_t));
  pos += sizeof(uint64_t);
  memcpy(buf + pos, &sig->block_size, sizeof(uint32_t));
  pos += sizeof(uint32_t);
  memcpy(buf + pos, &sig->block_count, sizeof(uint32_t));
  pos += sizeof(uint32_t);

  for (uint32_t i = 0; i < sig->block_count; i++) {
    memcpy(buf + pos, &sig->blocks[i].adler32, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    memcpy(buf + pos, &sig->blocks[i].xxhash, sizeof(uint32_t));
    pos += sizeof(uint32_t);
  }

  return data_create(buf, (size_t)total);
}

DeltaSignature* delta_signature_deserialize(const Data* data) {
  if (!data || data->size < sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t))
    return NULL;

  const uint8_t* buf = (const uint8_t*)data->data;
  size_t pos = 0;

  DeltaSignature* sig = protocol_alloc(sizeof(DeltaSignature));
  if (!sig)
    return NULL;

  memcpy(&sig->file_size, buf + pos, sizeof(uint64_t));
  pos += sizeof(uint64_t);
  memcpy(&sig->block_size, buf + pos, sizeof(uint32_t));
  pos += sizeof(uint32_t);
  memcpy(&sig->block_count, buf + pos, sizeof(uint32_t));
  pos += sizeof(uint32_t);

  // Reject unreasonably large block counts to prevent OOM
  if (sig->block_count > MAX_DELTA_BLOCKS) {
    log_message(LOG_LEVEL_ERROR, "Delta signature block count %u exceeds maximum %u",
                sig->block_count, MAX_DELTA_BLOCKS);
    free(sig);
    return NULL;
  }

  if (sig->block_size == 0 || sig->block_size > DELTA_BLOCK_SIZE_MAX ||
      sig->file_size > DELTA_MAX_FILE_SIZE || sig->file_size == 0 ||
      (sig->file_size + sig->block_size - 1) / sig->block_size != sig->block_count) {
    free(sig);
    return NULL;
  }

  uint64_t expected = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) +
                      (uint64_t)sig->block_count * (sizeof(uint32_t) + sizeof(uint32_t));
  if (data->size < expected) {
    free(sig);
    return NULL;
  }

  uint64_t blocks_size = (uint64_t)sig->block_count * sizeof(DeltaBlockSig);
  if (blocks_size > SIZE_MAX) {
    free(sig);
    return NULL;
  }
  sig->blocks = protocol_alloc((size_t)blocks_size);
  if (!sig->blocks) {
    free(sig);
    return NULL;
  }

  for (uint32_t i = 0; i < sig->block_count; i++) {
    memcpy(&sig->blocks[i].adler32, buf + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    memcpy(&sig->blocks[i].xxhash, buf + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);
  }

  return sig;
}

void delta_signature_destroy(DeltaSignature* sig) {
  if (!sig)
    return;
  free(sig->blocks);
  free(sig);
}

static bool ensure_capacity(DeltaInstruction** instrs, uint32_t* capacity, uint32_t count) {
  if (count < *capacity)
    return true;
  if (*capacity > MAX_DELTA_INSTRUCTIONS / 2)
    return false;
  uint32_t new_cap = *capacity * 2;
  DeltaInstruction* tmp = protocol_realloc(*instrs, (size_t)new_cap * sizeof(DeltaInstruction));
  if (!tmp)
    return false;
  *instrs = tmp;
  *capacity = new_cap;
  return true;
}

static bool flush_literal(DeltaInstruction** instrs, uint32_t* capacity, uint32_t* count,
                          const uint8_t* data, uint64_t start, uint64_t end) {
  if (start >= end)
    return true;
  if (end - start > UINT32_MAX || *count >= MAX_DELTA_INSTRUCTIONS)
    return false;
  uint32_t lit_len = (uint32_t)(end - start);
  if (!ensure_capacity(instrs, capacity, *count))
    return false;
  uint8_t* lit_data = protocol_alloc(lit_len);
  if (!lit_data)
    return false;
  memcpy(lit_data, data + start, lit_len);
  (*instrs)[*count].type = DELTA_INSTR_LITERAL;
  (*instrs)[*count].literal.data = lit_data;
  (*instrs)[*count].literal.length = lit_len;
  (*count)++;
  return true;
}

static void free_instructions(DeltaInstruction* instrs, uint32_t count) {
  if (!instrs)
    return;
  for (uint32_t i = 0; i < count; i++)
    if (instrs[i].type == DELTA_INSTR_LITERAL)
      free(instrs[i].literal.data);
  free(instrs);
}

/* Sentinel meaning "no signature block" in the lookup index chains.  Block
 * counts are bounded well below UINT32_MAX, so it doubles as a null link. */
#define DELTA_NO_BLOCK UINT32_MAX

/* Avalanche mix for the rolling checksum so blocks do not cluster in the
 * bucket table when the weak checksum has little entropy (e.g. all-zero or
 * patterned files). */
static uint32_t delta_adler_mix(uint32_t h) {
  h ^= h >> 16;
  h *= 0x7feb352dU;
  h ^= h >> 15;
  h *= 0x846ca68bU;
  h ^= h >> 16;
  return h;
}

/* Smallest power of two >= v.  v must be non-zero. */
static uint32_t delta_next_pow2(uint32_t v) {
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  return v + 1;
}

/* Build a hash index over sig->blocks keyed by the (mixed) rolling checksum.
 * All blocks sharing an Adler-32 value land in the same bucket; collisions
 * are chained through a single contiguous allocation:
 *
 *   [0, bucket_count)                 heads (first block per bucket)
 *   [bucket_count, 2*bucket_count)    tails (last block per bucket)
 *   [2*bucket_count, ...)             per-block chain links
 *
 * Blocks are inserted in ascending index order so every bucket chain is
 * ordered exactly like the historical linear scan.  Returns the base pointer
 * (also the heads array) or NULL when no index could be allocated; callers
 * then fall back to the linear scan. */
static uint32_t* delta_build_index(const DeltaSignature* sig, uint32_t bucket_count) {
  if (sig->block_count == 0 || bucket_count == 0)
    return NULL;

  size_t entries = (size_t)2 * bucket_count + sig->block_count;
  if (entries > SIZE_MAX / sizeof(uint32_t))
    return NULL;

  uint32_t* index = protocol_alloc(entries * sizeof(uint32_t));
  if (!index)
    return NULL;

  uint32_t* heads = index;
  uint32_t* tails = index + bucket_count;
  uint32_t* next = index + 2 * bucket_count;
  uint32_t mask = bucket_count - 1;

  memset(heads, 0xFF, (size_t)bucket_count * sizeof(uint32_t));
  memset(tails, 0xFF, (size_t)bucket_count * sizeof(uint32_t));

  for (uint32_t j = 0; j < sig->block_count; j++) {
    uint32_t b = delta_adler_mix(sig->blocks[j].adler32) & mask;
    if (heads[b] == DELTA_NO_BLOCK)
      heads[b] = j;
    else
      next[tails[b]] = j;
    tails[b] = j;
    next[j] = DELTA_NO_BLOCK;
  }
  return index;
}

/* Locate the signature block matching the byte window at new_data[i].
 *
 * Mirrors the original per-window behaviour exactly: only a full block_size
 * window can match, candidates are accepted only when the weak (Adler-32) and
 * strong (xxHash32) checksums both agree, and the lowest block index wins so
 * the emitted op stream is byte-identical to the linear scan.  When heads is
 * non-NULL the candidate set is reached through the bucket index (expected
 * O(1) per window); otherwise an exact linear scan is used. */
static uint32_t delta_find_match(const uint8_t* window, uint32_t window_len, uint32_t adler,
                                 bool full_window, const DeltaSignature* sig, const uint32_t* heads,
                                 const uint32_t* next, uint32_t mask, uint32_t seed) {
  if (!full_window || sig->block_count == 0)
    return DELTA_NO_BLOCK;

  if (heads) {
    uint32_t b = delta_adler_mix(adler) & mask;
    uint32_t window_xxh = 0;
    bool have_xxh = false;
    for (uint32_t j = heads[b]; j != DELTA_NO_BLOCK; j = next[j]) {
      if (sig->blocks[j].adler32 != adler)
        continue;
      if (!have_xxh) {
        window_xxh = delta_xxhash32_seeded(window, window_len, seed);
        have_xxh = true;
      }
      if (window_xxh == sig->blocks[j].xxhash)
        return j;
    }
    return DELTA_NO_BLOCK;
  }

  /* Fallback used when the index could not be allocated. */
  for (uint32_t j = 0; j < sig->block_count; j++) {
    if (sig->blocks[j].adler32 == adler) {
      uint32_t window_xxh = delta_xxhash32_seeded(window, window_len, seed);
      if (window_xxh == sig->blocks[j].xxhash)
        return j;
    }
  }
  return DELTA_NO_BLOCK;
}

Delta* delta_compute(const void* new_file_data, uint64_t new_file_size, const DeltaSignature* sig,
                     uint32_t block_size) {
  return delta_compute_seeded(new_file_data, new_file_size, sig, block_size, 0);
}

Delta* delta_compute_seeded(const void* new_file_data, uint64_t new_file_size,
                            const DeltaSignature* sig, uint32_t block_size, uint32_t seed) {
  if (!new_file_data || !sig || !sig->blocks || new_file_size == 0 || block_size == 0 ||
      block_size > DELTA_BLOCK_SIZE_MAX || sig->block_size != block_size)
    return NULL;

  const uint8_t* new_data = (const uint8_t*)new_file_data;

  uint32_t capacity = 64;
  uint32_t count = 0;
  DeltaInstruction* instrs = protocol_alloc((size_t)capacity * sizeof(DeltaInstruction));
  if (!instrs)
    return NULL;

  /* Build a one-time bucket index over the signature blocks keyed by the weak
   * checksum.  This turns the per-byte-window candidate lookup from an
   * O(block_count) linear scan into an expected O(1) probe, which dominates
   * the cost for large mostly-matching files (the diff steps one byte at a
   * time through changed regions).  On allocation failure the probe falls back
   * to the original linear scan, so behaviour is unchanged under memory
   * pressure. */
  uint32_t* index = NULL;
  const uint32_t* chain_next = NULL;
  uint32_t mask = 0;
  if (sig->block_count > 0) {
    uint32_t bucket_count = delta_next_pow2(sig->block_count);
    index = delta_build_index(sig, bucket_count);
    if (index) {
      chain_next = index + 2 * bucket_count;
      mask = bucket_count - 1;
    }
  }

  uint64_t literal_start = 0;
  bool has_literal = false;

  uint64_t i = 0;

  uint32_t s1 = 1, s2 = 0;
  bool rolling_valid = false;

  while (i < new_file_size) {
    uint32_t window_len =
        (uint32_t)((new_file_size - i < block_size) ? (new_file_size - i) : block_size);
    bool full_window = (window_len == block_size);

    uint32_t adler;
    if (rolling_valid && full_window) {
      uint8_t old_byte = new_data[i - 1];
      uint8_t new_byte = new_data[i + block_size - 1];
      s1 = (s1 + DELTA_ADLER32_MODULUS - old_byte + new_byte) % DELTA_ADLER32_MODULUS;
      s2 = (s2 + DELTA_ADLER32_MODULUS -
            (uint32_t)((uint64_t)block_size * old_byte % DELTA_ADLER32_MODULUS) + s1 - 1) %
           DELTA_ADLER32_MODULUS;
      adler = (s2 << 16) | s1;
    } else {
      s1 = 1;
      s2 = 0;
      for (uint32_t k = 0; k < window_len; k++) {
        s1 = (s1 + new_data[i + k]) % DELTA_ADLER32_MODULUS;
        s2 = (s2 + s1) % DELTA_ADLER32_MODULUS;
      }
      adler = (s2 << 16) | s1;
      rolling_valid = full_window;
    }

    bool matched = false;
    uint32_t match_block = delta_find_match(new_data + i, window_len, adler, full_window, sig,
                                            index, chain_next, mask, seed);
    if (match_block != DELTA_NO_BLOCK) {
      if (has_literal) {
        if (!flush_literal(&instrs, &capacity, &count, new_data, literal_start, i)) {
          free_instructions(instrs, count);
          free(index);
          return NULL;
        }
        has_literal = false;
      }

      if (!ensure_capacity(&instrs, &capacity, count)) {
        free_instructions(instrs, count);
        free(index);
        return NULL;
      }
      instrs[count].type = DELTA_INSTR_BLOCK_MATCH;
      instrs[count].match.block_index = match_block;
      instrs[count].match.block_offset = 0;
      instrs[count].match.length = window_len;
      count++;

      i += window_len;
      rolling_valid = false;
      matched = true;
    }

    if (!matched) {
      if (!has_literal) {
        literal_start = i;
        has_literal = true;
      }
      i++;
    }
  }

  free(index);

  if (has_literal) {
    if (!flush_literal(&instrs, &capacity, &count, new_data, literal_start, new_file_size)) {
      free_instructions(instrs, count);
      return NULL;
    }
  }

  Delta* delta = protocol_alloc(sizeof(Delta));
  if (!delta) {
    free_instructions(instrs, count);
    return NULL;
  }

  delta->new_file_size = new_file_size;
  delta->instruction_count = count;
  delta->instructions = instrs;
  delta->delta_size = 0;

  for (uint32_t k = 0; k < count; k++) {
    if (delta->delta_size == UINT64_MAX) {
      delta_destroy(delta);
      return NULL;
    }
    delta->delta_size += 1;
    if (instrs[k].type == DELTA_INSTR_BLOCK_MATCH) {
      if (delta->delta_size > UINT64_MAX - sizeof(uint32_t) * 3) {
        delta_destroy(delta);
        return NULL;
      }
      delta->delta_size += sizeof(uint32_t) * 3;
    } else {
      uint64_t extra = sizeof(uint32_t) + instrs[k].literal.length;
      if (delta->delta_size > UINT64_MAX - extra) {
        delta_destroy(delta);
        return NULL;
      }
      delta->delta_size += extra;
    }
  }

  return delta;
}

Data* delta_serialize(const Delta* delta) {
  if (!delta)
    return NULL;

  if (delta->instruction_count > 0 && !delta->instructions)
    return NULL;
  uint64_t header_size = sizeof(uint64_t) + sizeof(uint32_t);
  if (delta->delta_size > UINT64_MAX - header_size || header_size + delta->delta_size > SIZE_MAX)
    return NULL;
  uint64_t total = header_size + delta->delta_size;
  uint8_t* buf = protocol_alloc((size_t)total);
  if (!buf)
    return NULL;

  size_t pos = 0;
  memcpy(buf + pos, &delta->new_file_size, sizeof(uint64_t));
  pos += sizeof(uint64_t);
  memcpy(buf + pos, &delta->instruction_count, sizeof(uint32_t));
  pos += sizeof(uint32_t);

  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    uint8_t type = (uint8_t)delta->instructions[i].type;
    memcpy(buf + pos, &type, sizeof(uint8_t));
    pos += sizeof(uint8_t);

    if (delta->instructions[i].type == DELTA_INSTR_BLOCK_MATCH) {
      memcpy(buf + pos, &delta->instructions[i].match.block_index, sizeof(uint32_t));
      pos += sizeof(uint32_t);
      memcpy(buf + pos, &delta->instructions[i].match.block_offset, sizeof(uint32_t));
      pos += sizeof(uint32_t);
      memcpy(buf + pos, &delta->instructions[i].match.length, sizeof(uint32_t));
      pos += sizeof(uint32_t);
    } else {
      memcpy(buf + pos, &delta->instructions[i].literal.length, sizeof(uint32_t));
      pos += sizeof(uint32_t);
      memcpy(buf + pos, delta->instructions[i].literal.data, delta->instructions[i].literal.length);
      pos += delta->instructions[i].literal.length;
    }
  }

  return data_create(buf, (size_t)total);
}

Delta* delta_deserialize(const Data* data) {
  if (!data || data->size < sizeof(uint64_t) + sizeof(uint32_t))
    return NULL;

  const uint8_t* buf = (const uint8_t*)data->data;
  size_t pos = 0;

  Delta* delta = protocol_alloc(sizeof(Delta));
  if (!delta)
    return NULL;

  memcpy(&delta->new_file_size, buf + pos, sizeof(uint64_t));
  pos += sizeof(uint64_t);
  memcpy(&delta->instruction_count, buf + pos, sizeof(uint32_t));
  pos += sizeof(uint32_t);

  // Reject unreasonably large instruction counts to prevent OOM
  if (delta->instruction_count > MAX_DELTA_INSTRUCTIONS) {
    log_message(LOG_LEVEL_ERROR, "Delta instruction count %u exceeds maximum %u",
                delta->instruction_count, MAX_DELTA_INSTRUCTIONS);
    free(delta);
    return NULL;
  }

  delta->instructions =
      delta->instruction_count == 0
          ? NULL
          : protocol_alloc((size_t)delta->instruction_count * sizeof(DeltaInstruction));
  if (delta->instruction_count > 0 && !delta->instructions) {
    free(delta);
    return NULL;
  }

  delta->delta_size = 0;

  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (pos >= data->size) {
      free_instructions(delta->instructions, i);
      free(delta);
      return NULL;
    }

    uint8_t type;
    memcpy(&type, buf + pos, sizeof(uint8_t));
    pos += sizeof(uint8_t);

    delta->delta_size += 1;

    if (type == DELTA_OP_BLOCK_MATCH) {
      if (data->size - pos < sizeof(uint32_t) * 3) {
        free_instructions(delta->instructions, i);
        free(delta);
        return NULL;
      }
      delta->instructions[i].type = DELTA_INSTR_BLOCK_MATCH;
      memcpy(&delta->instructions[i].match.block_index, buf + pos, sizeof(uint32_t));
      pos += sizeof(uint32_t);
      memcpy(&delta->instructions[i].match.block_offset, buf + pos, sizeof(uint32_t));
      pos += sizeof(uint32_t);
      memcpy(&delta->instructions[i].match.length, buf + pos, sizeof(uint32_t));
      pos += sizeof(uint32_t);
      delta->delta_size += sizeof(uint32_t) * 3;
    } else if (type == DELTA_OP_LITERAL) {
      if (data->size - pos < sizeof(uint32_t)) {
        free_instructions(delta->instructions, i);
        free(delta);
        return NULL;
      }
      delta->instructions[i].type = DELTA_INSTR_LITERAL;
      memcpy(&delta->instructions[i].literal.length, buf + pos, sizeof(uint32_t));
      pos += sizeof(uint32_t);

      uint32_t lit_len = delta->instructions[i].literal.length;
      if (lit_len > data->size - pos) {
        free_instructions(delta->instructions, i);
        free(delta);
        return NULL;
      }
      delta->instructions[i].literal.data = protocol_alloc(lit_len ? lit_len : 1);
      if (!delta->instructions[i].literal.data) {
        log_message(LOG_LEVEL_ERROR, "Failed to allocate %u bytes for literal data", lit_len);
        free_instructions(delta->instructions, i);
        free(delta);
        return NULL;
      }
      memcpy(delta->instructions[i].literal.data, buf + pos, lit_len);
      pos += lit_len;
      delta->delta_size += sizeof(uint32_t) + lit_len;
    } else {
      free_instructions(delta->instructions, i);
      free(delta);
      return NULL;
    }
  }

  return delta;
}

void* delta_apply(const void* old_data, uint64_t old_size, const Delta* delta,
                  uint32_t block_size) {
  if (!old_data || !delta || (delta->new_file_size > 0 && delta->instructions == NULL) ||
      (delta->instruction_count > 0 && block_size == 0) ||
      delta->new_file_size > DELTA_MAX_FILE_SIZE || delta->new_file_size > SIZE_MAX)
    return NULL;

  void* output = protocol_alloc(delta->new_file_size ? (size_t)delta->new_file_size : 1);
  if (!output)
    return NULL;

  uint8_t* out = (uint8_t*)output;
  const uint8_t* old = (const uint8_t*)old_data;
  uint64_t out_pos = 0;

  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (delta->instructions[i].type == DELTA_INSTR_BLOCK_MATCH) {
      uint64_t src_offset = (uint64_t)delta->instructions[i].match.block_index * block_size;
      if (src_offset > UINT64_MAX - delta->instructions[i].match.block_offset) {
        free(output);
        return NULL;
      }
      src_offset += delta->instructions[i].match.block_offset;
      uint32_t len = delta->instructions[i].match.length;

      if (src_offset > old_size || (uint64_t)len > old_size - src_offset ||
          out_pos > delta->new_file_size || (uint64_t)len > delta->new_file_size - out_pos) {
        free(output);
        return NULL;
      }
      memcpy(out + out_pos, old + src_offset, len);
      out_pos += len;
    } else if (delta->instructions[i].type == DELTA_INSTR_LITERAL) {
      uint32_t len = delta->instructions[i].literal.length;
      if (out_pos > delta->new_file_size || (uint64_t)len > delta->new_file_size - out_pos) {
        free(output);
        return NULL;
      }
      memcpy(out + out_pos, delta->instructions[i].literal.data, len);
      out_pos += len;
    } else {
      free(output);
      return NULL;
    }
  }

  if (out_pos != delta->new_file_size) {
    free(output);
    return NULL;
  }

  return output;
}

void delta_destroy(Delta* delta) {
  if (!delta)
    return;
  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (delta->instructions[i].type == DELTA_INSTR_LITERAL)
      free(delta->instructions[i].literal.data);
  }
  free(delta->instructions);
  free(delta);
}

bool delta_should_attempt(uint64_t old_size, uint64_t new_size, uint64_t max_file_size) {
  if (old_size < DELTA_MIN_FILE_SIZE || new_size < DELTA_MIN_FILE_SIZE)
    return false;
  if (old_size > max_file_size || new_size > max_file_size)
    return false;
  double large = (old_size > new_size) ? (double)old_size : (double)new_size;
  double small = (old_size > new_size) ? (double)new_size : (double)old_size;
  if (small == 0 || large / small > DELTA_MAX_SIZE_RATIO)
    return false;
  return true;
}

bool delta_is_worthwhile(const Delta* delta, uint64_t new_file_size) {
  if (!delta || delta->instruction_count == 0 || new_file_size == 0)
    return false;

  bool has_match = false;
  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (delta->instructions[i].type == DELTA_INSTR_BLOCK_MATCH) {
      has_match = true;
      break;
    }
  }
  if (!has_match)
    return false;

  double ratio = (double)delta->delta_size / (double)new_file_size;
  return ratio < DELTA_FALLBACK_RATIO;
}
