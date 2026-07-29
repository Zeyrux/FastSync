#include "delta.h"
#include "log.h"
#include <stdint.h>
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

DeltaSignature* delta_signature_create(const void* old_file_data, uint64_t old_file_size,
                                       uint32_t block_size) {
  if (old_file_data == NULL || old_file_size == 0 || block_size == 0)
    return NULL;

  uint32_t block_count = (uint32_t)((old_file_size + block_size - 1) / block_size);

  DeltaSignature* sig = malloc(sizeof(DeltaSignature));
  if (!sig)
    return NULL;

  sig->file_size = old_file_size;
  sig->block_size = block_size;
  sig->block_count = block_count;
  sig->blocks = malloc(block_count * sizeof(DeltaBlockSig));
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
    sig->blocks[i].xxhash = delta_xxhash32(data + offset, len);
  }

  return sig;
}

Data* delta_signature_serialize(const DeltaSignature* sig) {
  if (!sig)
    return NULL;

  uint64_t total = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) +
                   (uint64_t)sig->block_count * (sizeof(uint32_t) + sizeof(uint32_t));

  uint8_t* buf = malloc((size_t)total);
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

  DeltaSignature* sig = malloc(sizeof(DeltaSignature));
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
  sig->blocks = malloc((size_t)blocks_size);
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
  uint32_t new_cap = *capacity * 2;
  DeltaInstruction* tmp = realloc(*instrs, new_cap * sizeof(DeltaInstruction));
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
  uint32_t lit_len = (uint32_t)(end - start);
  if (!ensure_capacity(instrs, capacity, *count))
    return false;
  uint8_t* lit_data = malloc(lit_len);
  if (!lit_data)
    return false;
  memcpy(lit_data, data + start, lit_len);
  (*instrs)[*count].type = DELTA_INSTR_LITERAL;
  (*instrs)[*count].literal.data = lit_data;
  (*instrs)[*count].literal.length = lit_len;
  (*count)++;
  return true;
}

Delta* delta_compute(const void* new_file_data, uint64_t new_file_size, const DeltaSignature* sig,
                     uint32_t block_size) {
  if (!new_file_data || !sig || new_file_size == 0 || block_size == 0)
    return NULL;

  const uint8_t* new_data = (const uint8_t*)new_file_data;

  uint32_t capacity = 64;
  uint32_t count = 0;
  DeltaInstruction* instrs = malloc(capacity * sizeof(DeltaInstruction));
  if (!instrs)
    return NULL;

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
    for (uint32_t j = 0; j < sig->block_count; j++) {
      if (adler == sig->blocks[j].adler32 && full_window) {
        uint32_t xxh = delta_xxhash32(new_data + i, window_len);
        if (xxh == sig->blocks[j].xxhash) {
          if (has_literal) {
            if (!flush_literal(&instrs, &capacity, &count, new_data, literal_start, i)) {
              free(instrs);
              return NULL;
            }
            has_literal = false;
          }

          if (!ensure_capacity(&instrs, &capacity, count)) {
            free(instrs);
            return NULL;
          }
          instrs[count].type = DELTA_INSTR_BLOCK_MATCH;
          instrs[count].match.block_index = j;
          instrs[count].match.block_offset = 0;
          instrs[count].match.length = window_len;
          count++;

          i += window_len;
          rolling_valid = false;
          matched = true;
          break;
        }
      }
    }

    if (!matched) {
      if (!has_literal) {
        literal_start = i;
        has_literal = true;
      }
      i++;
    }
  }

  if (has_literal) {
    if (!flush_literal(&instrs, &capacity, &count, new_data, literal_start, new_file_size)) {
      free(instrs);
      return NULL;
    }
  }

  Delta* delta = malloc(sizeof(Delta));
  if (!delta) {
    for (uint32_t k = 0; k < count; k++) {
      if (instrs[k].type == DELTA_INSTR_LITERAL)
        free(instrs[k].literal.data);
    }
    free(instrs);
    return NULL;
  }

  delta->new_file_size = new_file_size;
  delta->instruction_count = count;
  delta->instructions = instrs;
  delta->delta_size = 0;

  for (uint32_t k = 0; k < count; k++) {
    delta->delta_size += 1;
    if (instrs[k].type == DELTA_INSTR_BLOCK_MATCH) {
      delta->delta_size += sizeof(uint32_t) * 3;
    } else {
      delta->delta_size += sizeof(uint32_t) + instrs[k].literal.length;
    }
  }

  return delta;
}

Data* delta_serialize(const Delta* delta) {
  if (!delta)
    return NULL;

  uint64_t total = sizeof(uint64_t) + sizeof(uint32_t) + delta->delta_size;
  uint8_t* buf = malloc((size_t)total);
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

  Delta* delta = malloc(sizeof(Delta));
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

  delta->instructions = malloc(delta->instruction_count * sizeof(DeltaInstruction));
  if (!delta->instructions) {
    free(delta);
    return NULL;
  }

  delta->delta_size = 0;

  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (pos >= data->size) {
      for (uint32_t k = 0; k < i; k++) {
        if (delta->instructions[k].type == DELTA_INSTR_LITERAL)
          free(delta->instructions[k].literal.data);
      }
      free(delta->instructions);
      free(delta);
      return NULL;
    }

    uint8_t type;
    memcpy(&type, buf + pos, sizeof(uint8_t));
    pos += sizeof(uint8_t);

    delta->delta_size += 1;

    if (type == DELTA_OP_BLOCK_MATCH) {
      if (pos + sizeof(uint32_t) * 3 > data->size) {
        free(delta->instructions);
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
      if (pos + sizeof(uint32_t) > data->size) {
        for (uint32_t k = 0; k < i; k++) {
          if (delta->instructions[k].type == DELTA_INSTR_LITERAL)
            free(delta->instructions[k].literal.data);
        }
        free(delta->instructions);
        free(delta);
        return NULL;
      }
      delta->instructions[i].type = DELTA_INSTR_LITERAL;
      memcpy(&delta->instructions[i].literal.length, buf + pos, sizeof(uint32_t));
      pos += sizeof(uint32_t);

      uint32_t lit_len = delta->instructions[i].literal.length;
      if (pos + lit_len > data->size) {
        for (uint32_t k = 0; k < i; k++) {
          if (delta->instructions[k].type == DELTA_INSTR_LITERAL)
            free(delta->instructions[k].literal.data);
        }
        free(delta->instructions);
        free(delta);
        return NULL;
      }
      delta->instructions[i].literal.data = malloc(lit_len);
      if (!delta->instructions[i].literal.data) {
        free(delta->instructions);
        free(delta);
        return NULL;
      }
      memcpy(delta->instructions[i].literal.data, buf + pos, lit_len);
      pos += lit_len;
      delta->delta_size += sizeof(uint32_t) + lit_len;
    } else {
      for (uint32_t k = 0; k < i; k++) {
        if (delta->instructions[k].type == DELTA_INSTR_LITERAL)
          free(delta->instructions[k].literal.data);
      }
      free(delta->instructions);
      free(delta);
      return NULL;
    }
  }

  return delta;
}

void* delta_apply(const void* old_data, uint64_t old_size, const Delta* delta,
                  uint32_t block_size) {
  if (!old_data || !delta)
    return NULL;

  void* output = malloc((size_t)delta->new_file_size);
  if (!output)
    return NULL;

  uint8_t* out = (uint8_t*)output;
  const uint8_t* old = (const uint8_t*)old_data;
  uint64_t out_pos = 0;

  for (uint32_t i = 0; i < delta->instruction_count; i++) {
    if (delta->instructions[i].type == DELTA_INSTR_BLOCK_MATCH) {
      uint64_t src_offset = (uint64_t)delta->instructions[i].match.block_index * block_size;
      src_offset += delta->instructions[i].match.block_offset;
      uint32_t len = delta->instructions[i].match.length;

      if (src_offset + len > old_size) {
        free(output);
        return NULL;
      }
      memcpy(out + out_pos, old + src_offset, len);
      out_pos += len;
    } else {
      uint32_t len = delta->instructions[i].literal.length;
      memcpy(out + out_pos, delta->instructions[i].literal.data, len);
      out_pos += len;
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
  if (!delta || delta->instruction_count == 0)
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
