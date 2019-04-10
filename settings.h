#ifndef RENXPACK_SETTINGS_H
#define RENXPACK_SETTINGS_H
#include <stdio.h>
#include "types.h"
#include "filepath.h"

typedef struct
{
    unsigned char secure_boot_key[0x10];                 /* Secure boot key for use in key derivation. NOTE: CONSOLE UNIQUE. */
    unsigned char tsec_key[0x10];                        /* TSEC key for use in key derivation. NOTE: CONSOLE UNIQUE. */
    unsigned char keyblob_keys[0x20][0x10];              /* Actual keys used to decrypt keyblobs. NOTE: CONSOLE UNIQUE.*/
    unsigned char keyblob_mac_keys[0x20][0x10];          /* Keys used to validate keyblobs. NOTE: CONSOLE UNIQUE. */
    unsigned char encrypted_keyblobs[0x20][0xB0];        /* Actual encrypted keyblobs (EKS). NOTE: CONSOLE UNIQUE. */
    unsigned char keyblobs[0x20][0x90];                  /* Actual decrypted keyblobs (EKS). */
    unsigned char keyblob_key_sources[0x20][0x10];       /* Seeds for keyblob keys. */
    unsigned char keyblob_mac_key_source[0x10];          /* Seed for keyblob MAC key derivation. */
    unsigned char tsec_root_kek[0x10];                   /* Used to generate TSEC root keys. */
    unsigned char package1_mac_kek[0x10];                /* Used to generate Package1 MAC keys. */
    unsigned char package1_kek[0x10];                    /* Used to generate Package1 keys. */
    unsigned char tsec_auth_signatures[0x20][0x10];      /* Auth signatures, seeds for tsec root key/package1 mac kek/package1 key on 6.2.0+. */
    unsigned char tsec_root_keys[0x20][0x10];            /* Key for master kek decryption, from TSEC firmware on 6.2.0+. */
    unsigned char tsec_root_key[0x10];                   /* Seed for master kek decryption, from TSEC firmware on 6.2.0+. */
    unsigned char master_kek_sources[0x20][0x10];        /* Seeds for firmware master keks. */
    unsigned char master_keks[0x20][0x10];               /* Firmware master keks, stored in keyblob prior to 6.2.0. */
    unsigned char master_key_source[0x10];               /* Seed for master key derivation. */
    unsigned char master_keys[0x20][0x10];               /* Firmware master keys. */
    unsigned char package1_mac_keys[0x20][0x10];         /* Package1 MAC keys. */
    unsigned char package1_keys[0x20][0x10];             /* Package1 keys. */
    unsigned char package2_keys[0x20][0x10];             /* Package2 keys. */
    unsigned char package2_key_source[0x10];             /* Seed for Package2 key. */
    unsigned char aes_kek_generation_source[0x10];       /* Seed for GenerateAesKek, usecase + generation 0. */
    unsigned char aes_key_generation_source[0x10];       /* Seed for GenerateAesKey. */
    unsigned char key_area_key_application_source[0x10]; /* Seed for kaek 0. */
    unsigned char key_area_key_ocean_source[0x10];       /* Seed for kaek 1. */
    unsigned char key_area_key_system_source[0x10];      /* Seed for kaek 2. */
    unsigned char titlekek_source[0x10];                 /* Seed for titlekeks. */
    unsigned char header_kek_source[0x10];               /* Seed for header kek. */
    unsigned char sd_card_kek_source[0x10];              /* Seed for SD card kek. */
    unsigned char sd_card_key_sources[2][0x20];          /* Seed for SD card encryption keys. */
    unsigned char save_mac_kek_source[0x10];             /* Seed for save kek. */
    unsigned char save_mac_key_source[0x10];             /* Seed for save key. */
    unsigned char header_key_source[0x20];               /* Seed for NCA header key. */
    unsigned char header_key[0x20];                      /* NCA header key. */
    unsigned char titlekeks[0x20][0x10];                 /* Title key encryption keys. */
    unsigned char key_area_keys[0x20][3][0x10];          /* Key area encryption keys. */
    unsigned char sd_card_keys[2][0x20];
    unsigned char nca_hdr_fixed_key_modulus[0x100];  /* NCA header fixed key RSA pubk. */
    unsigned char acid_fixed_key_modulus[0x100];     /* ACID fixed key RSA pubk. */
    unsigned char package2_fixed_key_modulus[0x100]; /* Package2 Header RSA pubk. */
} nca_keyset_t;

typedef struct
{
    int enabled;
    filepath_t path;
} override_filepath_t;

typedef struct
{
    nca_keyset_t keyset;
    filepath_t temp_dir_path;
    filepath_t out_dir_path;
} renxpack_settings_t;

struct nca_ctx; /* This will get re-defined by nca.h. */

typedef struct
{
    FILE *file;
    struct nca_ctx *base_nca_ctx;
    renxpack_settings_t settings;
} renxpack_ctx_t;

#endif
