#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include "nsp.h"
#include "pfs0.h"
#include "utils.h"

void nsp_create(nsp_ctx_t *nsp_ctx)
{
    // nsp file name is tid.nsp
    printf("Creating nsp %s\n", nsp_ctx->filepath.char_path);

    uint32_t string_table_size = 42 * nsp_ctx->entry_count;
    pfs0_header_t nsp_header = {
        .magic = MAGIC_PFS0,
        .num_files = nsp_ctx->entry_count,
        .string_table_size = string_table_size,
        .reserved = 0};

    uint64_t offset = 0;
    uint32_t filename_offset = 0;
    char *string_table = (char *)calloc(1, string_table_size);
    nsp_file_entry_table_t *file_entry_table = (nsp_file_entry_table_t *)calloc(1, nsp_ctx->entry_count * sizeof(nsp_file_entry_table_t));

    // Fill file entry table
    for (int i = 0; i < nsp_ctx->entry_count; i++)
    {
        file_entry_table[i].offset = offset;
        file_entry_table[i].filename_offset = filename_offset;
        file_entry_table[i].padding = 0;
        file_entry_table[i].size = nsp_ctx->nsp_entry[i].filesize;
        offset += nsp_ctx->nsp_entry[i].filesize;
        strcpy(string_table + filename_offset, nsp_ctx->nsp_entry[i].nsp_filename);
        filename_offset += strlen(nsp_ctx->nsp_entry[i].nsp_filename) + 1;
    }

    FILE *nsp_file;
    if ((nsp_file = os_fopen(nsp_ctx->filepath.os_path, OS_MODE_WRITE)) == NULL)
    {
        fprintf(stderr, "unable to create nsp\n");
        exit(EXIT_FAILURE);
    }

    // Write header
    if (!fwrite(&nsp_header, sizeof(pfs0_header_t), 1, nsp_file))
    {
        fprintf(stderr, "Unable to write nsp header");
        exit(EXIT_FAILURE);
    }

    // Write file entry table
    if (!fwrite(file_entry_table, sizeof(nsp_file_entry_table_t), nsp_ctx->entry_count, nsp_file))
    {
        fprintf(stderr, "Unable to write nsp file entry table");
        exit(EXIT_FAILURE);
    }

    // Write string table
    if (!fwrite(string_table, 1, string_table_size, nsp_file))
    {
        fprintf(stderr, "Unable to write nsp string table");
        exit(EXIT_FAILURE);
    }

    for (int i2 = 0; i2 < nsp_ctx->entry_count; i2++)
    {
        FILE *nsp_data_file;
        printf("Packing %s into %s\n", nsp_ctx->nsp_entry[i2].filepath.char_path, nsp_ctx->filepath.char_path);
        if (!(nsp_data_file = os_fopen(nsp_ctx->nsp_entry[i2].filepath.os_path, OS_MODE_READ)))
        {
            fprintf(stderr, "unable to open %s: %s\n", nsp_ctx->nsp_entry[i2].filepath.char_path, strerror(errno));
            exit(EXIT_FAILURE);
        }
        uint64_t read_size = 0x61A8000; // 100 MB buffer.
        unsigned char *buf = malloc(read_size);
        if (buf == NULL)
        {
            fprintf(stderr, "Failed to allocate file-read buffer!\n");
            exit(EXIT_FAILURE);
        }

        uint64_t ofs = 0;
        while (ofs < nsp_ctx->nsp_entry[i2].filesize)
        {
            if (ofs + read_size >= nsp_ctx->nsp_entry[i2].filesize)
                read_size = nsp_ctx->nsp_entry[i2].filesize - ofs;
            if (fread(buf, 1, read_size, nsp_data_file) != read_size)
            {
                fprintf(stderr, "Failed to read file %s\n", nsp_ctx->nsp_entry[i2].filepath.char_path);
                exit(EXIT_FAILURE);
            }
            fwrite(buf, read_size, 1, nsp_file);
            ofs += read_size;
        }
        fclose(nsp_data_file);
        free(buf);
    }

    fclose(nsp_file);
    printf("\n");
}
