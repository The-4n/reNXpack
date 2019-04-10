#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <libgen.h>
#include "ticket.h"
#include "aes.h"
#include "filepath.h"

unsigned char *ticket_get_titlekey(nca_ctx_t *ctx)
{
    // Find ticket filepath
    char *rights_id = (char *)calloc(1, 33);
    hexBinaryString((unsigned char *)ctx->header.rights_id, 16, rights_id, 33);
    filepath_t ticket_filepath;
    filepath_init(&ticket_filepath);
    filepath_copy(&ticket_filepath, &ctx->tool_ctx->settings.temp_dir_path);
    filepath_append(&ticket_filepath, "%s.tik", rights_id); // tik filename is: rightsid + .tik
    free(rights_id);

    // Read titlekey
    unsigned char* title_key = (unsigned char*)calloc(1, 0x10);
    FILE *file;
    if (!(file = os_fopen(ticket_filepath.os_path, OS_MODE_READ)))
    {
        fprintf(stderr, "Error: unable to open ticket file: %s\n", ticket_filepath.char_path);
        exit(EXIT_FAILURE);
    }

    fseeko64(file, 0x180, SEEK_SET);
    if (fread(title_key, 1, 0x10, file) != 0x10)
    {
        fprintf(stderr, "Error: Failed to read title key from ticket file!\n");
        exit(EXIT_FAILURE);
    }

    // Decrypt titlekey
    aes_ctx_t *aes_tkey_ctx = new_aes_ctx(ctx->tool_ctx->settings.keyset.titlekeks[ctx->crypto_type], 16, AES_MODE_ECB);
    aes_decrypt(aes_tkey_ctx, title_key, title_key, 0x10);
    free_aes_ctx(aes_tkey_ctx);

    return title_key;
}