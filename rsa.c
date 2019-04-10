#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "rsa_keys.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"

void rsa_sign(void* input, size_t input_size, unsigned char* output, size_t output_size)
{
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "rsa_sign_pss";
    size_t olen = 0;

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_pk_init(&pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Parse private key and sign input
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    mbedtls_pk_parse_key(&pk, (unsigned char*)rsa_private_key, strlen(rsa_private_key) + 1, NULL, 0);
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (unsigned char*)input, input_size, hash);
    mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, buf, &olen, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Copy signature to output
    memcpy(output, buf, output_size);

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

const unsigned char *rsa_get_public_key()
{
    return rsa_public_key;
}