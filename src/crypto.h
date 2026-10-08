#ifndef VAULT_CRYPTO_H
#define VAULT_CRYPTO_H
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#define VAULT_HEADER_SIZE 56
#define VAULT_TAG_SIZE 16
#define VAULT_ITERATIONS 600000U
#define VAULT_MAX_BYTES ((uint64_t)4 * 1024 * 1024 * 1024)
typedef struct {
    const unsigned char *bytes;
    size_t length;
    int key_file;
} vault_secret;
int random_bytes(unsigned char *output, size_t count);
int crypto_encrypt(FILE *input, FILE *output, const vault_secret *secret, int folder);
int crypto_decrypt(FILE *input, FILE *output, const vault_secret *secret, int folder);
#endif