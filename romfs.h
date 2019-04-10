#ifndef RENXPACK_ROMFS_H
#define RENXPACK_ROMFS_H
#include <stdint.h>
#include "ivfc.h"
#include "filepath.h"
#include "nsp.h"

/* RomFS structs. */
#define ROMFS_HEADER_SIZE 0x00000050
#define ROMFS_ENTRY_EMPTY 0xFFFFFFFF

#pragma pack(push, 1)
typedef struct {
    uint64_t header_size;
    uint64_t dir_hash_table_offset;
    uint64_t dir_hash_table_size;
    uint64_t dir_meta_table_offset;
    uint64_t dir_meta_table_size;
    uint64_t file_hash_table_offset;
    uint64_t file_hash_table_size;
    uint64_t file_meta_table_offset;
    uint64_t file_meta_table_size;
    uint64_t data_offset;
} romfs_hdr_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t parent;
    uint32_t sibling;
    uint32_t child;
    uint32_t file;
    uint32_t hash;
    uint32_t name_size;
    char name[];
} romfs_direntry_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t parent;
    uint32_t sibling;
    uint64_t offset;
    uint64_t size;
    uint32_t hash;
    uint32_t name_size;
    char name[];
} romfs_fentry_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    ivfc_hdr_t ivfc_header;
    uint8_t _0xE0[0x58];
} romfs_superblock_t;
#pragma pack(pop)

typedef struct {
    romfs_superblock_t *superblock;
    FILE *file;
    renxpack_ctx_t *tool_ctx;
    validity_t superblock_hash_validity;
    ivfc_level_ctx_t ivfc_levels[IVFC_MAX_LEVEL];
    uint64_t romfs_offset;
    romfs_hdr_t header;
    romfs_direntry_t *directories;
    romfs_fentry_t *files;
} romfs_ctx_t;

static inline romfs_direntry_t *romfs_get_direntry(romfs_direntry_t *directories, uint32_t offset) {
    return (romfs_direntry_t *)((char *)directories + offset);
}

static inline romfs_fentry_t *romfs_get_fentry(romfs_fentry_t *files, uint32_t offset) {
    return (romfs_fentry_t *)((char *)files + offset);
}

#endif