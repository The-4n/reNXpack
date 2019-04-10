#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include <inttypes.h>
#include "nca.h"
#include "aes.h"
#include "pki.h"
#include "sha.h"
#include "rsa.h"
#include "romfs.h"
#include "utils.h"
#include "extkeys.h"
#include "filepath.h"
#include "ticket.h"

/* Initialize the context. */
void nca_init(nca_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void nca_free_section_contexts(nca_ctx_t *ctx)
{
    for (unsigned int i = 0; i < 4; i++)
    {
        if (ctx->section_contexts[i].is_present)
        {
            if (ctx->section_contexts[i].aes)
            {
                free_aes_ctx(ctx->section_contexts[i].aes);
            }
            if (ctx->section_contexts[i].type == PFS0 && ctx->section_contexts[i].pfs0_ctx.is_exefs)
            {
                free(ctx->section_contexts[i].pfs0_ctx.npdm);
            }
            else if (ctx->section_contexts[i].type == ROMFS)
            {
                if (ctx->section_contexts[i].romfs_ctx.directories)
                {
                    free(ctx->section_contexts[i].romfs_ctx.directories);
                }
                if (ctx->section_contexts[i].romfs_ctx.files)
                {
                    free(ctx->section_contexts[i].romfs_ctx.files);
                }
            }
            else if (ctx->section_contexts[i].type == BKTR)
            {
                if (ctx->section_contexts[i].bktr_ctx.subsection_block)
                {
                    free(ctx->section_contexts[i].bktr_ctx.subsection_block);
                }
                if (ctx->section_contexts[i].bktr_ctx.relocation_block)
                {
                    free(ctx->section_contexts[i].bktr_ctx.relocation_block);
                }
                if (ctx->section_contexts[i].bktr_ctx.directories)
                {
                    free(ctx->section_contexts[i].bktr_ctx.directories);
                }
                if (ctx->section_contexts[i].bktr_ctx.files)
                {
                    free(ctx->section_contexts[i].bktr_ctx.files);
                }
            }
        }
    }
}

/* Updates the CTR for an offset. */
void nca_update_ctr(unsigned char *ctr, uint64_t ofs)
{
    ofs >>= 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctr[0x10 - j - 1] = (unsigned char)(ofs & 0xFF);
        ofs >>= 8;
    }
}

/* Seek to an offset within a section. */
void nca_section_fseek(nca_section_ctx_t *ctx, uint64_t offset)
{
    fseeko64(ctx->file, (ctx->offset + offset) & ~0xF, SEEK_SET);
    ctx->cur_seek = (ctx->offset + offset) & ~0xF;
    nca_update_ctr(ctx->ctr, ctx->offset + offset);
    ctx->sector_ofs = offset & 0xF;
}

// Read and decrypt part of section into a buff
size_t nca_section_fread(nca_section_ctx_t *ctx, void *buffer, size_t count)
{
    size_t read = 0; /* XXX */
    char block_buf[0x10];
    if (ctx->sector_ofs)
    {
        if ((read = fread(block_buf, 1, 0x10, ctx->file)) != 0x10)
        {
            return 0;
        }
        aes_setiv(ctx->aes, ctx->ctr, 0x10);
        aes_decrypt(ctx->aes, block_buf, block_buf, 0x10);
        if (count + ctx->sector_ofs < 0x10)
        {
            memcpy(buffer, block_buf + ctx->sector_ofs, count);
            ctx->sector_ofs += count;
            nca_section_fseek(ctx, ctx->cur_seek - ctx->offset);
            return count;
        }
        memcpy(buffer, block_buf + ctx->sector_ofs, 0x10 - ctx->sector_ofs);
        uint32_t read_in_block = 0x10 - ctx->sector_ofs;
        nca_section_fseek(ctx, ctx->cur_seek - ctx->offset + 0x10);
        return read_in_block + nca_section_fread(ctx, (char *)buffer + read_in_block, count - read_in_block);
    }
    if ((read = fread(buffer, 1, count, ctx->file)) != count)
    {
        return 0;
    }
    aes_setiv(ctx->aes, ctx->ctr, 16);
    aes_decrypt(ctx->aes, buffer, buffer, count);
    nca_section_fseek(ctx, ctx->cur_seek - ctx->offset + count);
    return read;
}

// Get a buff, encrypt it and write it in section
size_t nca_section_fwrite(nca_section_ctx_t *ctx, void *buffer, size_t count, uint64_t offset)
{
    nca_section_fseek(ctx, offset);
    uint8_t sector_ofs = ctx->sector_ofs;
    uint64_t temp_buff_size = sector_ofs + count;
    unsigned char *temp_buff = (unsigned char *)malloc(temp_buff_size);
    nca_section_fseek(ctx, ctx->cur_seek - ctx->offset);
    nca_section_fread(ctx, temp_buff, sector_ofs);
    nca_section_fseek(ctx, ctx->cur_seek - ctx->offset);
    memcpy(temp_buff + sector_ofs, buffer, count);
    aes_setiv(ctx->aes, ctx->ctr, 16);
    aes_encrypt(ctx->aes, temp_buff, temp_buff, temp_buff_size);
    if (!fwrite(temp_buff, 1, temp_buff_size, ctx->file))
    {
        fprintf(stderr, "Unable to modify NCA");
        return 0;
    }
    nca_section_fseek(ctx, ctx->cur_seek - ctx->offset + count);
    return count;
}

// Rewrite modified header
static void nca_save(nca_ctx_t *ctx)
{
    fseeko64(ctx->file, 0, SEEK_SET);
    if (!fwrite(&ctx->header, 1, 0xC00, ctx->file))
    {
        fprintf(stderr, "Unable to patch NCA header");
        exit(EXIT_FAILURE);
    }
}

// Patch ACID public key and sign nca header with it (sig 2)
void nca_exefs_npdm_process(nca_ctx_t *ctx)
{
    pfs0_header_t pfs0_header;
    npdm_t npdm_header;
    uint64_t pfs0_start_offset = 0;
    uint64_t file_entry_table_offset = 0;
    uint64_t file_entry_table_size = 0;
    uint64_t meta_offset = 0;
    uint64_t acid_offset = 0;
    uint64_t acid_pubkey_offset = 0;
    uint64_t raw_data_offset = 0;
    uint64_t file_raw_data_offset = 0;
    uint64_t block_start_offset = 0;
    uint64_t block_hash_table_offset = 0;
    uint64_t block_hash_table_end_offset = 0;
    uint64_t block_size = 0;

    // Looking for main.npdm / META
    ctx->section_contexts[0].aes = new_aes_ctx(ctx->header.encrypted_keys[2], 16, AES_MODE_CTR);
    ctx->section_contexts[0].offset = media_to_real(ctx->header.section_entries[0].media_start_offset);
    ctx->section_contexts[0].sector_ofs = 0;
    ctx->section_contexts[0].file = ctx->file;
    ctx->section_contexts[0].crypt_type = CRYPT_CTR;
    ctx->section_contexts[0].header = &ctx->header.fs_headers[0];

    // Calculate counter for section decryption
    uint64_t ofs = ctx->section_contexts[0].offset >> 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctx->section_contexts[0].ctr[j] = ctx->section_contexts[0].header->section_ctr[0x8 - j - 1];
        ctx->section_contexts[0].ctr[0x10 - j - 1] = (unsigned char)(ofs & 0xFF);
        ofs >>= 8;
    }

    // Read and decrypt PFS0 header
    pfs0_start_offset = ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;
    nca_section_fseek(&ctx->section_contexts[0], pfs0_start_offset);
    nca_section_fread(&ctx->section_contexts[0], &pfs0_header, sizeof(pfs0_header_t));
    // Read and decrypt file entry table
    file_entry_table_offset = pfs0_start_offset + sizeof(pfs0_header_t);
    file_entry_table_size = sizeof(pfs0_file_entry_t) * pfs0_header.num_files;
    pfs0_file_entry_t *pfs0_file_entry_table = (pfs0_file_entry_t *)malloc(file_entry_table_size);
    nca_section_fseek(&ctx->section_contexts[0], file_entry_table_offset);
    nca_section_fread(&ctx->section_contexts[0], pfs0_file_entry_table, file_entry_table_size);

    // Looking for META magic
    uint32_t magic = 0;
    raw_data_offset = file_entry_table_offset + file_entry_table_size + pfs0_header.string_table_size;
    for (unsigned int i2 = 0; i2 < pfs0_header.num_files; i2++)
    {
        file_raw_data_offset = raw_data_offset + pfs0_file_entry_table[i2].offset;
        nca_section_fseek(&ctx->section_contexts[0], file_raw_data_offset);
        nca_section_fread(&ctx->section_contexts[0], &magic, sizeof(magic));
        if (magic == MAGIC_META)
        {
            // Read and decrypt npdm header
            meta_offset = file_raw_data_offset;
            nca_section_fseek(&ctx->section_contexts[0], meta_offset);
            nca_section_fread(&ctx->section_contexts[0], &npdm_header, sizeof(npdm_t));

            // Patch acid pubkey and change it to self-generated pubkey
            acid_offset = meta_offset + npdm_header.acid_offset;
            acid_pubkey_offset = acid_offset + 0x100;
            nca_section_fseek(&ctx->section_contexts[0], acid_pubkey_offset);
            nca_section_fwrite(&ctx->section_contexts[0], (unsigned char *)rsa_get_public_key(), 0x100, acid_pubkey_offset);

            // Calculate new block hash
            block_hash_table_offset = (0x20 * ((acid_pubkey_offset - ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset) / ctx->header.fs_headers[0].pfs0_superblock.block_size)) + ctx->header.fs_headers[0].pfs0_superblock.hash_table_offset;
            block_hash_table_end_offset = (0x20 * ((acid_pubkey_offset + 0x100 - ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset) / ctx->header.fs_headers[0].pfs0_superblock.block_size)) + ctx->header.fs_headers[0].pfs0_superblock.hash_table_offset;
            block_start_offset = (((acid_pubkey_offset - ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset) / ctx->header.fs_headers[0].pfs0_superblock.block_size) * ctx->header.fs_headers[0].pfs0_superblock.block_size) + ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;
            // Make sure block doesn't pass pfs0
            if (block_start_offset - ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset + ctx->header.fs_headers[0].pfs0_superblock.block_size > ctx->header.fs_headers[0].pfs0_superblock.pfs0_size)
                block_size = ctx->header.fs_headers[0].pfs0_superblock.pfs0_size - block_start_offset - ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;
            else
                block_size = ctx->header.fs_headers[0].pfs0_superblock.block_size;
            unsigned char *block_data = (unsigned char *)malloc(block_size);
            unsigned char *block_hash = (unsigned char *)malloc(0x20);
            nca_section_fseek(&ctx->section_contexts[0], block_start_offset);
            nca_section_fread(&ctx->section_contexts[0], block_data, block_size);
            sha_ctx_t *pfs0_sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
            sha_update(pfs0_sha_ctx, block_data, block_size);
            sha_get_hash(pfs0_sha_ctx, block_hash);
            nca_section_fwrite(&ctx->section_contexts[0], block_hash, 0x20, block_hash_table_offset);
            free(block_hash);
            free(block_data);
            free_sha_ctx(pfs0_sha_ctx);
            // Make sure that 1 block covers all patched bytes, othervise recalculate another hash block
            if (block_hash_table_offset != block_hash_table_end_offset)
            {
                block_start_offset = (((acid_pubkey_offset + 0x100 - ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset) / ctx->header.fs_headers[0].pfs0_superblock.block_size) * ctx->header.fs_headers[0].pfs0_superblock.block_size) + ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;
                if (block_start_offset - ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset + ctx->header.fs_headers[0].pfs0_superblock.block_size > ctx->header.fs_headers[0].pfs0_superblock.pfs0_size)
                    block_size = ctx->header.fs_headers[0].pfs0_superblock.pfs0_size - block_start_offset - ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;
                else
                    block_size = ctx->header.fs_headers[0].pfs0_superblock.block_size;

                block_data = (unsigned char *)malloc(block_size);
                block_hash = (unsigned char *)malloc(0x20);
                nca_section_fseek(&ctx->section_contexts[0], block_start_offset);
                nca_section_fread(&ctx->section_contexts[0], block_data, block_size);
                pfs0_sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
                sha_update(pfs0_sha_ctx, block_data, block_size);
                sha_get_hash(pfs0_sha_ctx, block_hash);
                nca_section_fwrite(&ctx->section_contexts[0], block_hash, 0x20, block_hash_table_end_offset);
                free(block_hash);
                free(block_data);
                free_sha_ctx(pfs0_sha_ctx);
            }

            // Calculate PFS0 sueperblock hash
            sha_ctx_t *hash_table_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
            unsigned char *hash_table = (unsigned char *)malloc(ctx->header.fs_headers[0].pfs0_superblock.hash_table_size);
            unsigned char *master_hash = (unsigned char *)malloc(0x20);
            nca_section_fseek(&ctx->section_contexts[0], ctx->header.fs_headers[0].pfs0_superblock.hash_table_offset);
            nca_section_fread(&ctx->section_contexts[0], hash_table, ctx->header.fs_headers[0].pfs0_superblock.hash_table_size);
            sha_update(hash_table_ctx, hash_table, ctx->header.fs_headers[0].pfs0_superblock.hash_table_size);
            sha_get_hash(hash_table_ctx, master_hash);
            memcpy(&ctx->header.fs_headers[0].pfs0_superblock.master_hash, master_hash, 0x20);
            free(master_hash);
            free(hash_table);
            free_sha_ctx(hash_table_ctx);

            // Calculate section hash
            unsigned char *section_hash = (unsigned char *)malloc(0x20);
            sha_ctx_t *section_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
            sha_update(section_ctx, &ctx->header.fs_headers[0], 0x200);
            sha_get_hash(section_ctx, section_hash);
            memcpy(&ctx->header.section_hashes[0], section_hash, 0x20);
            free(section_hash);
            free_sha_ctx(section_ctx);
        }
    }
    free(pfs0_file_entry_table);
}

// Modify cnmt
void nca_cnmt_process(nca_ctx_t *ctx, cnmt_ctx_t *cnmt_ctx)
{
    pfs0_header_t pfs0_header;
    uint64_t pfs0_start_offset = 0;
    uint64_t file_entry_table_offset = 0;
    uint64_t file_entry_table_size = 0;
    uint64_t raw_data_offset = 0;
    uint8_t meta_type = 0;
    uint64_t extended_header_min = 0;
    uint64_t content_records_offset = 0;

    ctx->section_contexts[0].aes = new_aes_ctx(ctx->header.encrypted_keys[2], 16, AES_MODE_CTR);
    ctx->section_contexts[0].offset = media_to_real(ctx->header.section_entries[0].media_start_offset);
    ctx->section_contexts[0].sector_ofs = 0;
    ctx->section_contexts[0].file = ctx->file;
    ctx->section_contexts[0].crypt_type = CRYPT_CTR;
    ctx->section_contexts[0].header = &ctx->header.fs_headers[0];

    // Calculate counter for section decryption
    uint64_t ofs = ctx->section_contexts[0].offset >> 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctx->section_contexts[0].ctr[j] = ctx->section_contexts[0].header->section_ctr[0x8 - j - 1];
        ctx->section_contexts[0].ctr[0x10 - j - 1] = (unsigned char)(ofs & 0xFF);
        ofs >>= 8;
    }

    // Read and decrypt PFS0 header
    pfs0_start_offset = ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;
    nca_section_fseek(&ctx->section_contexts[0], pfs0_start_offset);
    nca_section_fread(&ctx->section_contexts[0], &pfs0_header, sizeof(pfs0_header_t));

    file_entry_table_offset = pfs0_start_offset + sizeof(pfs0_header_t);
    file_entry_table_size = sizeof(pfs0_file_entry_t) * pfs0_header.num_files;
    raw_data_offset = file_entry_table_offset + file_entry_table_size + pfs0_header.string_table_size;
    // Find Meta type
    nca_section_fseek(&ctx->section_contexts[0], raw_data_offset + 0xC);
    nca_section_fread(&ctx->section_contexts[0], &meta_type, 0x1);
    // Set Extended header
    char temp_buff[0x4] = {0};
    extended_header_min = raw_data_offset + sizeof(cnmt_header_t) + 0x8;
    nca_section_fseek(&ctx->section_contexts[0], extended_header_min);
    nca_section_fwrite(&ctx->section_contexts[0], temp_buff, 0x4, extended_header_min);

    // Write meta content records
    content_records_offset = raw_data_offset + sizeof(cnmt_header_t) + cnmt_ctx->extended_header_size;
    for (int i = 0; i < cnmt_ctx->nca_count; i++)
    {
        nca_section_fwrite(&ctx->section_contexts[0], &cnmt_ctx->cnmt_content_records[i], sizeof(cnmt_content_record_t), content_records_offset + (i * sizeof(cnmt_content_record_t)));
    }

    // Calculate block hash
    unsigned char *block_data = (unsigned char *)malloc(ctx->header.fs_headers[0].pfs0_superblock.pfs0_size);
    unsigned char *block_hash = (unsigned char *)malloc(0x20);
    nca_section_fseek(&ctx->section_contexts[0], ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset);
    nca_section_fread(&ctx->section_contexts[0], block_data, ctx->header.fs_headers[0].pfs0_superblock.pfs0_size);
    sha_ctx_t *pfs0_sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    sha_update(pfs0_sha_ctx, block_data, ctx->header.fs_headers[0].pfs0_superblock.pfs0_size);
    sha_get_hash(pfs0_sha_ctx, block_hash);
    nca_section_fwrite(&ctx->section_contexts[0], block_hash, 0x20, ctx->header.fs_headers[0].pfs0_superblock.hash_table_offset);
    free(block_hash);
    free(block_data);
    free_sha_ctx(pfs0_sha_ctx);

    // Calculate PFS0 sueperblock hash
    sha_ctx_t *hash_table_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    unsigned char *hash_table = (unsigned char *)malloc(ctx->header.fs_headers[0].pfs0_superblock.hash_table_size);
    unsigned char *master_hash = (unsigned char *)malloc(0x20);
    nca_section_fseek(&ctx->section_contexts[0], ctx->header.fs_headers[0].pfs0_superblock.hash_table_offset);
    nca_section_fread(&ctx->section_contexts[0], hash_table, ctx->header.fs_headers[0].pfs0_superblock.hash_table_size);
    sha_update(hash_table_ctx, hash_table, ctx->header.fs_headers[0].pfs0_superblock.hash_table_size);
    sha_get_hash(hash_table_ctx, master_hash);
    memcpy(&ctx->header.fs_headers[0].pfs0_superblock.master_hash, master_hash, 0x20);
    free(master_hash);
    free(hash_table);
    free_sha_ctx(hash_table_ctx);

    // Calculate section hash
    unsigned char *section_hash = (unsigned char *)malloc(0x20);
    sha_ctx_t *section_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    sha_update(section_ctx, &ctx->header.fs_headers[0], 0x200);
    sha_get_hash(section_ctx, section_hash);
    memcpy(&ctx->header.section_hashes[0], section_hash, 0x20);
    free(section_hash);
    free_sha_ctx(section_ctx);
}

void nca_meta_context_process(cnmt_ctx_t *cnmt_ctx, nca_ctx_t *ctx, cnmt_header_t *cnmt_header, cnmt_extended_header_t *cnmt_extended_header, uint64_t digest_offset, uint64_t content_records_start_offset, filepath_t *filepath)
{
    cnmt_ctx->nca_count = 0;
    cnmt_ctx->type = cnmt_header->type;
    cnmt_ctx->title_id = cnmt_header->title_id;
    cnmt_ctx->extended_header_patch_id = cnmt_extended_header->patch_title_id;
    cnmt_ctx->title_version = cnmt_header->title_version;
    cnmt_ctx->requiredsysversion = cnmt_extended_header->required_system_version;
    cnmt_ctx->extended_header_size = cnmt_header->extended_header_size;
    if (ctx->header.crypto_type2 > ctx->header.crypto_type)
        cnmt_ctx->keygen_min = ctx->header.crypto_type2;
    else
        cnmt_ctx->keygen_min = ctx->header.crypto_type;

    // Read content and decrypt records
    cnmt_ctx->cnmt_content_records = (cnmt_content_record_t *)malloc(sizeof(cnmt_content_record_t));
    for (int i = 0; i < cnmt_header->content_entry_count; i++)
    {
        cnmt_content_record_t temp_content_record;
        nca_section_fseek(&ctx->section_contexts[0], content_records_start_offset + (i * sizeof(cnmt_content_record_t)));
        nca_section_fread(&ctx->section_contexts[0], &temp_content_record, sizeof(cnmt_content_record_t));
        if (temp_content_record.type != 0x6) // Skip DeltaFragment
        {
            memcpy(&cnmt_ctx->cnmt_content_records[cnmt_ctx->nca_count], &temp_content_record, sizeof(cnmt_content_record_t));
            cnmt_ctx->nca_count++;
            cnmt_ctx->cnmt_content_records = (cnmt_content_record_t *)realloc(cnmt_ctx->cnmt_content_records, (cnmt_ctx->nca_count + 1) * sizeof(cnmt_content_record_t));
        }
    }

    // Get Digest, last 32 bytes of PFS0
    nca_section_fseek(&ctx->section_contexts[0], digest_offset);
    nca_section_fread(&ctx->section_contexts[0], cnmt_ctx->digest, 0x20);

    // Set meta filepath
    filepath_init(&cnmt_ctx->meta_filepath);
    filepath_copy(&cnmt_ctx->meta_filepath, filepath);
}

void nca_saved_meta_process(nca_ctx_t *ctx, filepath_t *filepath)
{
    /* Decrypt header */
    if (!nca_decrypt_header(ctx))
    {
        fprintf(stderr, "Invalid NCA header! Are keys correct?\n");
        exit(EXIT_FAILURE);
    }

    /* Sort out crypto type. */
    ctx->crypto_type = ctx->header.crypto_type;
    if (ctx->header.crypto_type2 > ctx->header.crypto_type)
        ctx->crypto_type = ctx->header.crypto_type2;
    if (ctx->crypto_type)
        ctx->crypto_type--; /* 0, 1 are both master key 0. */

    nca_decrypt_header_key_area(ctx);
    ctx->section_contexts[0].aes = new_aes_ctx(ctx->header.encrypted_keys[2], 16, AES_MODE_CTR);
    ctx->section_contexts[0].offset = media_to_real(ctx->header.section_entries[0].media_start_offset);
    ctx->section_contexts[0].sector_ofs = 0;
    ctx->section_contexts[0].file = ctx->file;
    ctx->section_contexts[0].crypt_type = CRYPT_CTR;
    ctx->section_contexts[0].header = &ctx->header.fs_headers[0];
    uint64_t ofs = ctx->section_contexts[0].offset >> 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctx->section_contexts[0].ctr[j] = ctx->section_contexts[0].header->section_ctr[0x8 - j - 1];
        ctx->section_contexts[0].ctr[0x10 - j - 1] = (unsigned char)(ofs & 0xFF);
        ofs >>= 8;
    }

    // Read and decrypt PFS0 header
    uint64_t pfs0_offset = 0;
    uint64_t pfs0_string_table_offset = 0;
    uint64_t cnmt_start_offset = 0;
    uint64_t content_records_start_offset = 0;
    cnmt_header_t cnmt_header;
    pfs0_header_t pfs0_header;
    cnmt_extended_header_t cnmt_extended_header;
    pfs0_offset = ctx->header.fs_headers[0].pfs0_superblock.pfs0_offset;
    nca_section_fseek(&ctx->section_contexts[0], pfs0_offset);
    nca_section_fread(&ctx->section_contexts[0], &pfs0_header, sizeof(pfs0_header_t));

    // Read and decrypt cnmt header
    pfs0_string_table_offset = pfs0_offset + sizeof(pfs0_header_t) + (pfs0_header.num_files * sizeof(pfs0_file_entry_t));
    cnmt_start_offset = pfs0_string_table_offset + pfs0_header.string_table_size;
    nca_section_fseek(&ctx->section_contexts[0], cnmt_start_offset);
    nca_section_fread(&ctx->section_contexts[0], &cnmt_header, sizeof(cnmt_header_t));
    nca_section_fread(&ctx->section_contexts[0], &cnmt_extended_header, sizeof(cnmt_extended_header_t));

    // Read and decrypt content records
    uint64_t digest_offset = 0;
    digest_offset = pfs0_offset + ctx->header.fs_headers[0].pfs0_superblock.pfs0_size - 0x20;
    content_records_start_offset = cnmt_start_offset + sizeof(cnmt_header_t) + cnmt_header.extended_header_size;

    switch (cnmt_header.type)
    {
    case 0x80: // Application
        // Gamecard may contain more than one Application Meta
        if (applications_cnmt_ctx.count == 0)
        {
            applications_cnmt_ctx.cnmt = (cnmt_ctx_t *)calloc(1, sizeof(cnmt_ctx_t));
            applications_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)calloc(1, sizeof(cnmt_xml_ctx_t));
        }
        else
        {
            applications_cnmt_ctx.cnmt = (cnmt_ctx_t *)realloc(applications_cnmt_ctx.cnmt, (applications_cnmt_ctx.count + 1) * sizeof(cnmt_ctx_t));
            applications_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)realloc(applications_cnmt_ctx.cnmt_xml, (applications_cnmt_ctx.count + 1) * sizeof(cnmt_xml_ctx_t));
            memset(&applications_cnmt_ctx.cnmt[applications_cnmt_ctx.count], 0, sizeof(cnmt_ctx_t));
            memset(&applications_cnmt_ctx.cnmt_xml[applications_cnmt_ctx.count], 0, sizeof(cnmt_xml_ctx_t));
        }
        nca_meta_context_process(&applications_cnmt_ctx.cnmt[applications_cnmt_ctx.count], ctx, &cnmt_header, &cnmt_extended_header, digest_offset, content_records_start_offset, filepath);
        applications_cnmt_ctx.count++;
        break;
    case 0x81: // Patch
        // Gamecard may contain more than one Patch Meta
        if (patches_cnmt_ctx.count == 0)
        {
            patches_cnmt_ctx.cnmt = (cnmt_ctx_t *)calloc(1, sizeof(cnmt_ctx_t));
            patches_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)calloc(1, sizeof(cnmt_xml_ctx_t));
        }
        else
        {
            patches_cnmt_ctx.cnmt = (cnmt_ctx_t *)realloc(patches_cnmt_ctx.cnmt, (patches_cnmt_ctx.count + 1) * sizeof(cnmt_ctx_t));
            patches_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)realloc(patches_cnmt_ctx.cnmt_xml, (patches_cnmt_ctx.count + 1) * sizeof(cnmt_xml_ctx_t));
            memset(&patches_cnmt_ctx.cnmt[patches_cnmt_ctx.count], 0, sizeof(cnmt_ctx_t));
            memset(&patches_cnmt_ctx.cnmt_xml[patches_cnmt_ctx.count], 0, sizeof(cnmt_xml_ctx_t));
        }
        nca_meta_context_process(&patches_cnmt_ctx.cnmt[patches_cnmt_ctx.count], ctx, &cnmt_header, &cnmt_extended_header, digest_offset, content_records_start_offset, filepath);
        patches_cnmt_ctx.count++;
        break;
    case 0x82: // AddOn
        // Gamecard may contain more than one Addon Meta
        if (addons_cnmt_ctx.count == 0)
        {
            addons_cnmt_ctx.cnmt = (cnmt_ctx_t *)calloc(1, sizeof(cnmt_ctx_t));
            addons_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)calloc(1, sizeof(cnmt_xml_ctx_t));
        }
        else
        {
            addons_cnmt_ctx.cnmt = (cnmt_ctx_t *)realloc(addons_cnmt_ctx.cnmt, (addons_cnmt_ctx.count + 1) * sizeof(cnmt_ctx_t));
            addons_cnmt_ctx.cnmt_xml = (cnmt_xml_ctx_t *)realloc(addons_cnmt_ctx.cnmt_xml, (addons_cnmt_ctx.count + 1) * sizeof(cnmt_xml_ctx_t));
            memset(&addons_cnmt_ctx.cnmt[addons_cnmt_ctx.count], 0, sizeof(cnmt_ctx_t));
            memset(&addons_cnmt_ctx.cnmt_xml[addons_cnmt_ctx.count], 0, sizeof(cnmt_xml_ctx_t));
        }
        nca_meta_context_process(&addons_cnmt_ctx.cnmt[addons_cnmt_ctx.count], ctx, &cnmt_header, &cnmt_extended_header, digest_offset, content_records_start_offset, filepath);
        addons_cnmt_ctx.count++;
        break;
    default:
        fprintf(stderr, "Unknown meta type! Are keys correct?\n");
        exit(EXIT_FAILURE);
    }
}

void nca_process(nca_ctx_t *ctx, filepath_t *filepath, int index, cnmt_xml_ctx_t *cnmt_xml_ctx, cnmt_ctx_t *cnmt_ctx, nsp_ctx_t *nsp_ctx)
{
    /* Decrypt header */
    if (!nca_decrypt_header(ctx))
    {
        fprintf(stderr, "Invalid NCA header! Are keys correct?\n");
        exit(EXIT_FAILURE);
    }

    uint8_t content_type = ctx->header.content_type;
    uint64_t nca_size = ctx->header.nca_size;

    /* Sort out crypto type. */
    ctx->crypto_type = ctx->header.crypto_type;
    if (ctx->header.crypto_type2 > ctx->header.crypto_type)
        ctx->crypto_type = ctx->header.crypto_type2;
    if (ctx->crypto_type)
        ctx->crypto_type--; /* 0, 1 are both master key 0. */

    /* Rights ID. */
    for (unsigned int i = 0; i < 0x10; i++)
    {
        if (ctx->header.rights_id[i] != 0)
        {
            ctx->has_rights_id = 1;
            break;
        }
    }

    if (ctx->has_rights_id)
        memcpy(ctx->header.encrypted_keys[2], ticket_get_titlekey(ctx), 16);
    else
    {
        // Decrypt kaek
        nca_decrypt_header_key_area(ctx);
    }

    // Set required values for creating .cnmt.xml
    cnmt_xml_ctx->contents[index].size = ctx->header.nca_size;
    if (ctx->header.crypto_type2 > ctx->header.crypto_type)
        cnmt_xml_ctx->contents[index].keygeneration = ctx->header.crypto_type2;
    else
        cnmt_xml_ctx->contents[index].keygeneration = ctx->header.crypto_type;
    if (content_type != 1) // Meta nca lacks of content records
        cnmt_xml_ctx->contents[index].type = cnmt_get_content_type(cnmt_ctx->cnmt_content_records[index].type);
    else
        cnmt_xml_ctx->contents[index].type = cnmt_get_content_type(0x00);

    // Patch ACID pubkey if nca type = program and sign nca sig 2
    if (content_type == 0) // Program nca
    {
        nca_exefs_npdm_process(ctx);
    }
    else if (content_type == 1) // Meta nca
        nca_cnmt_process(ctx, cnmt_ctx);

    // Set keygen to 0
    ctx->header.crypto_type = 0;
    ctx->header.crypto_type2 = 0;

    // Remove rights id
    memset(ctx->header.rights_id, 0, 0x10);

    // Re-encrypt header
    nca_encrypt_header_key_area(ctx);
    if (content_type == 0) // Sign NCA sig 2 with self-generated ACID pubkey
        rsa_sign(&ctx->header.magic, 0x200, (unsigned char *)ctx->header.npdm_key_sig, 0x100);
    nca_encrypt_header(ctx);
    printf("Patching %s\n", filepath->char_path);
    nca_save(ctx);

    // Calculate SHA-256 hash
    sha_ctx_t *sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    uint64_t read_size = 0x61A8000; // 100 MB buffer.
    unsigned char *buf = malloc(read_size);
    if (buf == NULL)
    {
        fprintf(stderr, "Failed to allocate file-read buffer!\n");
        exit(EXIT_FAILURE);
    }
    fseeko64(ctx->file, 0, SEEK_SET);
    uint64_t ofs = 0;
    uint64_t filesize = nca_size;
    while (ofs < filesize)
    {
        if (ofs + read_size >= filesize)
            read_size = filesize - ofs;
        if (fread(buf, 1, read_size, ctx->file) != read_size)
        {
            fprintf(stderr, "Failed to read file!\n");
            exit(EXIT_FAILURE);
        }
        sha_update(sha_ctx, buf, read_size);
        ofs += read_size;
    }
    fclose(ctx->file);
    free(buf);
    unsigned char *hash_result = (unsigned char *)calloc(1, 32);
    sha_get_hash(sha_ctx, hash_result);

    // Update nca hash and ncaid
    if (content_type != 1)
        memcpy(cnmt_ctx->cnmt_content_records[index].hash, hash_result, 32);
    free_sha_ctx(sha_ctx);

    // Convert hash to hex string
    char *hash_hex = (char *)calloc(1, 65);
    hexBinaryString(hash_result, 32, hash_hex, 65);

    // Set hash and id for xml meta, id = first 16 bytes of hash if keepncaid != 1
    strncpy(cnmt_xml_ctx->contents[index].hash, hash_hex, 64);
    cnmt_xml_ctx->contents[index].hash[64] = '\0';
    if (content_type == 1)
        strncpy(cnmt_xml_ctx->contents[index].id, basename(cnmt_ctx->meta_filepath.char_path), 32);
    else
    {
        char *ncaid = (char *)calloc(1, 33);
        hexBinaryString(cnmt_ctx->cnmt_content_records[index].ncaid, 16, ncaid, 33);
        strncpy(cnmt_xml_ctx->contents[index].id, ncaid, 32);
        free(ncaid);
    }
    cnmt_xml_ctx->contents[index].id[32] = '\0';
    free(hash_hex);
    free(hash_result);

    // + cnmt.xml
    index += 1;

    // Set filesize for creating nsp
    nsp_ctx->nsp_entry[index].filesize = cnmt_xml_ctx->contents[index - 1].size;

    // Set filepath for creating nsp
    filepath_init(&nsp_ctx->nsp_entry[index].filepath);
    filepath_copy(&nsp_ctx->nsp_entry[index].filepath, filepath);

    // Set new filename for creating nsp
    if (content_type != 1)
    {
        nsp_ctx->nsp_entry[index].nsp_filename = (char *)calloc(1, 37);
        memcpy(nsp_ctx->nsp_entry[index].nsp_filename, cnmt_xml_ctx->contents[index - 1].id, 0x20);
        strcat(nsp_ctx->nsp_entry[index].nsp_filename, ".nca");
    }
    else // Meta nca
    {
        nsp_ctx->nsp_entry[index].nsp_filename = (char *)calloc(1, 42);
        memcpy(nsp_ctx->nsp_entry[index].nsp_filename, cnmt_xml_ctx->contents[index - 1].id, 0x20);
        strcat(nsp_ctx->nsp_entry[index].nsp_filename, ".cnmt.nca");
    }
}

void nca_decrypt_header_key_area(nca_ctx_t *ctx)
{
    aes_ctx_t *aes_ctx = new_aes_ctx(ctx->tool_ctx->settings.keyset.key_area_keys[ctx->crypto_type][ctx->header.kaek_ind], 16, AES_MODE_ECB);
    aes_decrypt(aes_ctx, ctx->header.encrypted_keys, ctx->header.encrypted_keys, 0x40);
    free_aes_ctx(aes_ctx);
}

void nca_encrypt_header_key_area(nca_ctx_t *ctx)
{
    aes_ctx_t *aes_ctx = new_aes_ctx(ctx->tool_ctx->settings.keyset.key_area_keys[0][ctx->header.kaek_ind], 16, AES_MODE_ECB);
    aes_encrypt(aes_ctx, ctx->header.encrypted_keys, ctx->header.encrypted_keys, 0x40);
    free_aes_ctx(aes_ctx);
}

/* Decrypt NCA header. */
int nca_decrypt_header(nca_ctx_t *ctx)
{
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&ctx->header, 1, 0xC00, ctx->file) != 0xC00)
    {
        fprintf(stderr, "Failed to read NCA header!\n");
        return 0;
    }
    ctx->is_decrypted = 0;

    nca_header_t dec_header;

    aes_ctx_t *hdr_aes_ctx = new_aes_ctx(ctx->tool_ctx->settings.keyset.header_key, 32, AES_MODE_XTS);
    aes_xts_decrypt(hdr_aes_ctx, &dec_header, &ctx->header, 0x400, 0, 0x200);

    if (dec_header.magic == MAGIC_NCA3)
    {
        ctx->format_version = NCAVERSION_NCA3;
        aes_xts_decrypt(hdr_aes_ctx, &dec_header, &ctx->header, 0xC00, 0, 0x200);
        ctx->header = dec_header;
    }
    else
    {
        fprintf(stderr, "Invalid NCA magic!\n");
        exit(EXIT_FAILURE);
    }
    free_aes_ctx(hdr_aes_ctx);
    return ctx->format_version != NCAVERSION_UNKNOWN;
}

// Encrypt NCA header
void nca_encrypt_header(nca_ctx_t *ctx)
{
    nca_header_t enc_header;
    aes_ctx_t *hdr_aes_ctx = new_aes_ctx(ctx->tool_ctx->settings.keyset.header_key, 32, AES_MODE_XTS);
    aes_xts_encrypt(hdr_aes_ctx, &enc_header, &ctx->header, 0xC00, 0, 0x200);
    ctx->header = enc_header;
    free_aes_ctx(hdr_aes_ctx);
}
