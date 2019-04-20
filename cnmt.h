#ifndef RENXPACK_CNMT_H
#define RENXPACK_CNMT_H

#include <stdint.h>
#include "nsp.h"
#include "settings.h"
#include "filepath.h"

typedef struct {
    char *type;
    char id[0x21];
    uint64_t size;
    char hash[0x41];		// SHA-256
    unsigned char keygeneration;
} cnmt_xml_content_t;

typedef struct {
    filepath_t filepath;
    char *title_id;
    char *patch_id;
    uint32_t title_version;
    char *type;
    char *digest;
    unsigned char keygen_min;
    uint32_t requiredsysversion;
    cnmt_xml_content_t *contents;
} cnmt_xml_ctx_t;

#pragma pack(push, 1)
typedef struct {
    uint64_t title_id;
    uint32_t title_version;
    uint8_t type;
    uint8_t _0xD;
    uint16_t extended_header_size;
    uint16_t content_entry_count;
    uint16_t meta_entry_count;
    uint8_t _0x14[0xC];
} cnmt_header_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    union 
    {
        uint64_t application_title_id;
        uint64_t patch_title_id;
    };
    union
    {
        uint32_t required_system_version;
        uint32_t required_application_version;
    };
    union
    {
        uint32_t extended_data_size;
        uint32_t padding;
    };
} cnmt_extended_header_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    unsigned char hash[0x20];
    uint8_t ncaid[0x10];
    uint8_t size[0x06];
    uint8_t type;
    uint8_t _0x37;
} cnmt_content_record_t;
#pragma pack(pop)

typedef struct {
    uint64_t title_id;
    uint64_t extended_header_patch_id;
    uint16_t extended_header_size;
    uint8_t type;
    uint8_t nca_count;
    uint32_t title_version;
    unsigned char digest[0x20];
    unsigned char keygen_min;
    uint32_t requiredsysversion;
    cnmt_content_record_t *cnmt_content_records;
    filepath_t meta_filepath;
} cnmt_ctx_t;

typedef struct {
    uint8_t count;
    cnmt_ctx_t *cnmt;
    cnmt_xml_ctx_t *cnmt_xml;
} cnmts_ctx_t;

void cnmt_create_xml(cnmt_xml_ctx_t *cnmt_xml_ctx, cnmt_ctx_t *cnmt_ctx, nsp_ctx_t *nsp_ctx);

void cnmt_process(renxpack_ctx_t *tool, cnmt_xml_ctx_t *cnmt_xml_ctx, cnmt_ctx_t *cnmt_ctx, nsp_ctx_t *nsp_ctx);

char *cnmt_get_content_type(uint8_t type);
char *cnmt_get_title_type(cnmt_ctx_t *cnmt_ctx);

extern cnmts_ctx_t applications_cnmt_ctx;
extern cnmts_ctx_t patches_cnmt_ctx;
extern cnmts_ctx_t addons_cnmt_ctx;

#endif
