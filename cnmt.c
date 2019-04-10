#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <libgen.h>
#include "nca.h"
#include "cnmt.h"

/* Create .cnmt.xml
 The process is done without xml libs cause i don't want to add more dependency for now
  */
void cnmt_create_xml(cnmt_xml_ctx_t *cnmt_xml_ctx, cnmt_ctx_t *cnmt_ctx, nsp_ctx_t *nsp_ctx)
{
    unsigned int xml_records_count = cnmt_ctx->nca_count + 1;
    FILE *file;
    printf("Creating xml metadata %s\n", cnmt_xml_ctx->filepath.char_path);
    if (!(file = os_fopen(cnmt_xml_ctx->filepath.os_path, OS_MODE_WRITE)))
    {
        fprintf(stderr, "unable to create xml metadata\n");
        exit(EXIT_FAILURE);
    }
    fprintf(file, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\x0D\x0A");
    fprintf(file, "<ContentMeta>\x0D\x0A");
    fprintf(file, "  <Type>%s</Type>\x0D\x0A", cnmt_xml_ctx->type);
    fprintf(file, "  <Id>0x%s</Id>\x0D\x0A", cnmt_xml_ctx->title_id);
    fprintf(file, "  <Version>%" PRIu32 "</Version>\x0D\x0A", cnmt_xml_ctx->title_version);
    fprintf(file, "  <RequiredDownloadSystemVersion>0</RequiredDownloadSystemVersion>\x0D\x0A");
    for (unsigned int index = 0; index < xml_records_count; index++)
    {
        fprintf(file, "  <Content>\x0D\x0A");
        fprintf(file, "    <Type>%s</Type>\x0D\x0A", cnmt_xml_ctx->contents[index].type);
        fprintf(file, "    <Id>%s</Id>\x0D\x0A", cnmt_xml_ctx->contents[index].id);
        fprintf(file, "    <Size>%" PRIu64 "</Size>\x0D\x0A", cnmt_xml_ctx->contents[index].size);
        fprintf(file, "    <Hash>%s</Hash>\x0D\x0A", cnmt_xml_ctx->contents[index].hash);
        fprintf(file, "    <KeyGeneration>%u</KeyGeneration>\x0D\x0A", cnmt_xml_ctx->contents[index].keygeneration);
        fprintf(file, "  </Content>\x0D\x0A");
    }
    fprintf(file, "  <Digest>%s</Digest>\x0D\x0A", cnmt_xml_ctx->digest);
    fprintf(file, "  <KeyGenerationMin>%u</KeyGenerationMin>\x0D\x0A", cnmt_xml_ctx->keygen_min);
    fprintf(file, "  <RequiredSystemVersion>%" PRIu64 "</RequiredSystemVersion>\x0D\x0A", cnmt_xml_ctx->requiredsysversion);
    fprintf(file, "  <PatchId>0x%s</PatchId>\x0D\x0A", cnmt_xml_ctx->patch_id);
    fprintf(file, "</ContentMeta>");

    // Set file size for creating nsp
    nsp_ctx->nsp_entry[0].filesize = (uint64_t)ftello64(file);

    // Set file path for creating nsp
    filepath_init(&nsp_ctx->nsp_entry[0].filepath);
    nsp_ctx->nsp_entry[0].filepath = cnmt_xml_ctx->filepath;

    // Set nsp filename
    nsp_ctx->nsp_entry[0].nsp_filename = (char *)calloc(1, 42);
    strcpy(nsp_ctx->nsp_entry[0].nsp_filename, cnmt_xml_ctx->contents[cnmt_ctx->nca_count].id);
    strcat(nsp_ctx->nsp_entry[0].nsp_filename, ".cnmt.xml");

    fclose(file);
}

void cnmt_process(renxpack_ctx_t *tool, cnmt_xml_ctx_t *cnmt_xml_ctx, cnmt_ctx_t *cnmt_ctx, nsp_ctx_t *nsp_ctx)
{
    // Set xml meta values
    cnmt_xml_ctx->contents = (cnmt_xml_content_t *)malloc((cnmt_ctx->nca_count + 1) * sizeof(cnmt_xml_content_t)); // ncas + meta nca
    cnmt_xml_ctx->title_id = (char *)calloc(1, 17);
    sprintf(cnmt_xml_ctx->title_id, "%016" PRIx64, cnmt_ctx->title_id);
    cnmt_xml_ctx->patch_id = (char *)calloc(1, 17);
    sprintf(cnmt_xml_ctx->patch_id, "%016" PRIx64, cnmt_ctx->extended_header_patch_id);
    cnmt_xml_ctx->digest = (char *)calloc(1, 65);
    hexBinaryString(cnmt_ctx->digest, 32, cnmt_xml_ctx->digest, 65);
    cnmt_xml_ctx->requiredsysversion = cnmt_ctx->requiredsysversion;
    cnmt_xml_ctx->title_version = cnmt_ctx->title_version;
    cnmt_xml_ctx->keygen_min = cnmt_ctx->keygen_min;
    cnmt_xml_ctx->type = cnmt_get_title_type(cnmt_ctx);
    char *cnmt_xml_filepath = (char *)calloc(1, strlen(cnmt_ctx->meta_filepath.char_path) + 1);
    memcpy(cnmt_xml_filepath, cnmt_ctx->meta_filepath.char_path, strlen(cnmt_ctx->meta_filepath.char_path) - 4);
    strcat(cnmt_xml_filepath, ".xml");
    filepath_init(&cnmt_xml_ctx->filepath);
    filepath_set(&cnmt_xml_ctx->filepath, cnmt_xml_filepath);

    // nsp entries count = nca counts + .cnmmt.xml + .cnmt.nca
    nsp_ctx->entry_count = cnmt_ctx->nca_count + 2;
    nsp_ctx->nsp_entry = (nsp_entry_t *)calloc(1, sizeof(nsp_entry_t) * (cnmt_ctx->nca_count + 2));

    // Process NCA files
    nca_ctx_t nca_ctx;
    filepath_t filepath;
    char *filename;
    for (int index = 0; index < cnmt_ctx->nca_count; index++)
    {
        nca_init(&nca_ctx);
        nca_ctx.tool_ctx = tool;
        filepath_init(&filepath);
        filename = (char *)calloc(1, 37);
        hexBinaryString(cnmt_ctx->cnmt_content_records[index].ncaid, 16, filename, 33);
        strcat(filename, ".nca");
        filepath_copy(&filepath, &nca_ctx.tool_ctx->settings.temp_dir_path);
        filepath_append(&filepath, "%s", filename);
        free(filename);
        if (!(nca_ctx.file = os_fopen(filepath.os_path, OS_MODE_EDIT)))
        {
            fprintf(stderr, "unable to open %s: %s\n", filepath.char_path, strerror(errno));
            exit(EXIT_FAILURE);
        }
        nca_process(&nca_ctx, &filepath, index, cnmt_xml_ctx, cnmt_ctx, nsp_ctx);
        nca_free_section_contexts(&nca_ctx);
    }

    // Process meta nca
    nca_init(&nca_ctx);
    nca_ctx.tool_ctx = tool;
    if (!(nca_ctx.file = os_fopen(cnmt_ctx->meta_filepath.os_path, OS_MODE_EDIT)))
    {
        fprintf(stderr, "unable to open %s: %s\n", cnmt_ctx->meta_filepath.char_path, strerror(errno));
        exit(EXIT_FAILURE);
    }
    nca_process(&nca_ctx, &cnmt_ctx->meta_filepath, cnmt_ctx->nca_count, cnmt_xml_ctx, cnmt_ctx, nsp_ctx);
    nca_free_section_contexts(&nca_ctx);

    // Create .cnmt.xml
    printf("\n");
    cnmt_create_xml(cnmt_xml_ctx, cnmt_ctx, nsp_ctx);

    // Set NSP filename
    char *nsp_filename;
    // nsp filename = tid + .nsp
    nsp_filename = (char *)calloc(1, 30);
    strncpy(nsp_filename, cnmt_xml_ctx->title_id, 16);
    strcat(nsp_filename, "_reNXpack");
    strcat(nsp_filename, ".nsp");
    filepath_init(&nsp_ctx->filepath);
    if (tool->settings.out_dir_path.valid == VALIDITY_VALID)
    {
        filepath_copy(&nsp_ctx->filepath, &tool->settings.out_dir_path);
        filepath_append(&nsp_ctx->filepath, "%s", nsp_filename);
    }
    else
        filepath_set(&nsp_ctx->filepath, nsp_filename);
    free(nsp_filename);

    printf("\n");
    nsp_create(nsp_ctx);
}

char *cnmt_get_title_type(cnmt_ctx_t *cnmt_ctx)
{
    switch (cnmt_ctx->type)
    {
    case 0x80: // Application
        return "Application";
        break;
    case 0x81: // Patch
        return "Patch";
        break;
    case 0x82: // AddOn
        return "AddOnContent";
        break;
    default:
        fprintf(stderr, "Unknown meta type\n");
        exit(EXIT_FAILURE);
    }
}

char *cnmt_get_content_type(uint8_t type)
{
    switch (type)
    {
    case 0x00:
        return "Meta";
        break;
    case 0x01:
        return "Program";
        break;
    case 0x02:
        return "Data";
        break;
    case 0x03:
        return "Control";
        break;
    case 0x04:
        return "HtmlDocument";
        break;
    case 0x05:
        return "LegalInformation";
        break;
    default:
        fprintf(stderr, "Unknown meta content type\n");
        exit(EXIT_FAILURE);
    }
}
