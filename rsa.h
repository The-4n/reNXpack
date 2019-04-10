#ifndef RENXPACK_RSA_H
#define RENXPACK_RSA_H

#include <inttypes.h>

void rsa_sign(void* input, size_t input_size, unsigned char* output, size_t output_size);
const unsigned char *rsa_get_public_key();

#endif