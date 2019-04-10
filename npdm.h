#ifndef RENXPACK_NPDM_H
#define RENXPACK_NPDM_H

#include "types.h"
#include "utils.h"
#include "settings.h"

#define MAGIC_META 0x4154454D
#define MAGIC_ACID 0x44494341

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t _0x4;
    uint32_t _0x8;
    uint8_t mmu_flags;
    uint8_t _0xD;
    uint8_t main_thread_prio;
    uint8_t default_cpuid;
    uint64_t _0x10;
    uint32_t process_category;
    uint32_t main_stack_size;
    char title_name[0x50];
    uint32_t aci0_offset;
    uint32_t aci0_size;
    uint32_t acid_offset;
    uint32_t acid_size;
} npdm_t;
#pragma pack(pop)

#endif
