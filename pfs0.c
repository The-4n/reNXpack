#include <string.h>
#include "pfs0.h"
#include "nca.h"

void pfs0_process(pfs0_ctx_t *ctx)
{
    /* Read *just* safe amount. */
    pfs0_header_t raw_header;
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&raw_header, 1, sizeof(raw_header), ctx->file) != sizeof(raw_header))
    {
        fprintf(stderr, "Failed to read PFS0 header!\n");
        exit(EXIT_FAILURE);
    }

    if (raw_header.magic != MAGIC_PFS0)
    {
        printf("Error: PFS0 is corrupt!\n");
        exit(EXIT_FAILURE);
    }

    uint64_t header_size = pfs0_get_header_size(&raw_header);
    ctx->header = malloc(header_size);
    if (ctx->header == NULL)
    {
        fprintf(stderr, "Failed to allocate PFS0 header!\n");
        exit(EXIT_FAILURE);
    }

    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(ctx->header, 1, header_size, ctx->file) != header_size)
    {
        fprintf(stderr, "Failed to read PFS0 header!\n");
        exit(EXIT_FAILURE);
    }

    /* Weak file validation. */
    uint64_t max_size = 0x1ULL;
    max_size <<= 48; /* Switch file sizes are capped at 48 bits. */
    uint64_t cur_ofs = 0;
    for (unsigned int i = 0; i < ctx->header->num_files; i++)
    {
        pfs0_file_entry_t *cur_file = pfs0_get_file_entry(ctx->header, i);
        if (cur_file->offset != cur_ofs)
        {
            printf("Error: PFS0 is corrupt!\n");
            exit(EXIT_FAILURE);
        }
        cur_ofs += cur_file->size;
    }

    pfs0_save(ctx);
}

static void pfs0_save_file(pfs0_ctx_t *ctx, uint32_t i, filepath_t *dirpath)
{
    if (i >= ctx->header->num_files)
    {
        fprintf(stderr, "Could not save file %" PRId32 "!\n", i);
        exit(EXIT_FAILURE);
    }
    pfs0_file_entry_t *cur_file = pfs0_get_file_entry(ctx->header, i);

    if (strlen(pfs0_get_file_name(ctx->header, i)) >= MAX_PATH - strlen(dirpath->char_path) - 1)
    {
        fprintf(stderr, "Filename too long in PFS0!\n");
        exit(EXIT_FAILURE);
    }

    filepath_t filepath;
    filepath_copy(&filepath, dirpath);
    filepath_append(&filepath, "%s", pfs0_get_file_name(ctx->header, i));

    printf("Saving %s to %s...\n", pfs0_get_file_name(ctx->header, i), filepath.char_path);
    uint64_t ofs = pfs0_get_header_size(ctx->header) + cur_file->offset;
    save_file_section(ctx->file, ofs, cur_file->size, &filepath);
    if (!pfs0_saved_nca_process(&filepath, ctx->tool_ctx))
    {
        exit(EXIT_FAILURE);
    }
}

void pfs0_save(pfs0_ctx_t *ctx)
{
    /* Extract to directory. */
    for (uint32_t i = 0; i < ctx->header->num_files; i++)
        pfs0_save_file(ctx, i, &ctx->tool_ctx->settings.temp_dir_path);
}

int pfs0_saved_nca_process(filepath_t *filepath, renxpack_ctx_t *tool)
{
    char *ext = filepath->char_path + (strlen(filepath->char_path) - 9);
    if (!(strncmp(ext, ".cnmt.nca", 9)))
    {
        nca_ctx_t nca_ctx;
        nca_init(&nca_ctx);
        nca_ctx.tool_ctx = tool;
        if (!(nca_ctx.file = os_fopen(filepath->os_path, OS_MODE_READ)))
        {
            fprintf(stderr, "unable to open %s: %s\n", filepath->char_path, strerror(errno));
            return 0;
        }
        nca_saved_meta_process(&nca_ctx, filepath);
        fclose(nca_ctx.file);
        nca_free_section_contexts(&nca_ctx);
    }
    return 1;
}