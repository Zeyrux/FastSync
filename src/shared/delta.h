#ifndef DELTA_H
#define DELTA_H

#include "data.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define DELTA_BLOCK_SIZE_DEFAULT 8192U
#define DELTA_BLOCK_SIZE_MIN 1024U
#define DELTA_BLOCK_SIZE_MAX 65536U
#define DELTA_MIN_FILE_SIZE 16384ULL
#define DELTA_MAX_FILE_SIZE (256ULL * 1024 * 1024)
#define DELTA_MAX_SIZE_RATIO 10.0
#define DELTA_FALLBACK_RATIO 0.7
#define DELTA_ADLER32_MODULUS 65521U

#define DELTA_OP_BLOCK_MATCH 0x01
#define DELTA_OP_LITERAL 0x02

typedef struct {
  uint32_t adler32;
  uint32_t xxhash;
} DeltaBlockSig;

typedef struct {
  uint64_t file_size;
  uint32_t block_size;
  uint32_t block_count;
  DeltaBlockSig* blocks;
} DeltaSignature;

typedef enum { DELTA_INSTR_BLOCK_MATCH = 0x01, DELTA_INSTR_LITERAL = 0x02 } DeltaInstrType;

typedef struct {
  DeltaInstrType type;
  union {
    struct {
      uint32_t block_index;
      uint32_t block_offset;
      uint32_t length;
    } match;
    struct {
      uint8_t* data;
      uint32_t length;
    } literal;
  };
} DeltaInstruction;

typedef struct {
  uint64_t new_file_size;
  uint32_t instruction_count;
  DeltaInstruction* instructions;
  uint64_t delta_size;
} Delta;

DeltaSignature* delta_signature_create(const void* old_file_data, uint64_t old_file_size,
                                       uint32_t block_size);
Data* delta_signature_serialize(const DeltaSignature* sig);
DeltaSignature* delta_signature_deserialize(const Data* data);
void delta_signature_destroy(DeltaSignature* sig);

Delta* delta_compute(const void* new_file_data, uint64_t new_file_size, const DeltaSignature* sig,
                     uint32_t block_size);
Data* delta_serialize(const Delta* delta);
Delta* delta_deserialize(const Data* data);
void* delta_apply(const void* old_data, uint64_t old_size, const Delta* delta, uint32_t block_size);
void delta_destroy(Delta* delta);

bool delta_should_attempt(uint64_t old_size, uint64_t new_size, uint64_t max_file_size);
bool delta_is_worthwhile(const Delta* delta, uint64_t new_file_size);

uint32_t delta_adler32(const void* data, uint32_t len);
uint32_t delta_xxhash32(const void* data, uint32_t len);

#endif
