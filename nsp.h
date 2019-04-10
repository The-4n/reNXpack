#ifndef RENXPACK_NSP_H
#define RENXPACK_NSP_H

#include <inttypes.h>
#include "filepath.h"
#include "settings.h"

#pragma pack(push, 1)
typedef struct {
    filepath_t filepath;
    char *nsp_filename;
    uint64_t filesize;
} nsp_entry_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint64_t offset;
    uint64_t size;
    uint32_t filename_offset;
    uint32_t padding;
} nsp_file_entry_table_t;
#pragma pack(pop)

typedef struct {
    filepath_t filepath;
    char title_name[0x200];
    char title_display_version[0x10];
    uint8_t entry_count;
    nsp_entry_t *nsp_entry;
} nsp_ctx_t;

void nsp_create(nsp_ctx_t *nsp_ctx);

extern nsp_ctx_t *application_nsps;
extern nsp_ctx_t *patch_nsps;
extern nsp_ctx_t *addon_nsps;

#endif
