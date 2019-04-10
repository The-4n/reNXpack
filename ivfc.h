#ifndef RENXPACK_IVFC_H
#define RENXPACK_IVFC_H

#include "types.h"
#include "utils.h"
#include "settings.h"


#define IVFC_HEADER_SIZE 0xE0
#define IVFC_MAX_LEVEL 6
#define IVFC_MAX_BUFFERSIZE 0x4000

#define MAGIC_IVFC 0x43465649

#pragma pack(push, 1)
typedef struct {
    uint64_t logical_offset;
    uint64_t hash_data_size;
    uint32_t block_size;
    uint32_t reserved;
} ivfc_level_hdr_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint64_t data_offset;
    uint64_t data_size;
    uint64_t hash_offset;
    uint32_t hash_block_size;
    validity_t hash_validity;
} ivfc_level_ctx_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t id;
    uint32_t master_hash_size;
    uint32_t num_levels;
    ivfc_level_hdr_t level_headers[IVFC_MAX_LEVEL];
    uint8_t _0xA0[0x20];
    uint8_t master_hash[0x20];
} ivfc_hdr_t;
#pragma pack(pop)

#endif
