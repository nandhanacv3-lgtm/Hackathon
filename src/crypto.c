#include "crypto.h"
#include "platform.h"
#include <string.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>

static const unsigned char magic[8] = {'L','V','A','U','L','T','\r','\n'};
static void put32(unsigned char *target, uint32_t value) {
    for (unsigned int index = 0; index < 4; ++index) target[index] = (unsigned char)(value >> (24 - index * 8));
}
static uint32_t get32(const unsigned char *source) {
    uint32_t value = 0;
    for (unsigned int index = 0; index < 4; ++index) value = (value << 8) | source[index];
    return value;
}
int random_bytes(unsigned char *output, size_t count) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context generator;
    const unsigned char personalization[] = "localvault-v1";
    mbedtls_entropy_init(&entropy); mbedtls_ctr_drbg_init(&generator);
    int result = mbedtls_ctr_drbg_seed(&generator, mbedtls_entropy_func, &entropy,
                                      personalization, sizeof(personalization) - 1);
    if (!result) result = mbedtls_ctr_drbg_random(&generator, output, count);
    mbedtls_ctr_drbg_free(&generator); mbedtls_entropy_free(&entropy);
    return result;
}
static int derive_key(const vault_secret *secret, const unsigned char *header, unsigned char *key) {
    if (secret->key_file) {
        if (secret->length != 32) return -1;
        memcpy(key, secret->bytes, 32); return 0;
    }
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, secret->bytes, secret->length,
                                        header + 16, 16, get32(header + 12), 32, key);
}
static int stream_transform(FILE *input, FILE *output, mbedtls_gcm_context *context, uint64_t length) {
    unsigned char source[65536], destination[65552];
    int result = 0;
    while (length && !vault_interrupted) {
        size_t count = length > sizeof(source) ? sizeof(source) : (size_t)length;
        size_t written = 0;
        if (fread(source, 1, count, input) != count ||
            mbedtls_gcm_update(context, source, count, destination, sizeof(destination), &written) != 0 ||
            fwrite(destination, 1, written, output) != written) { result = -1; break; }
        length -= count;
    }
    mbedtls_platform_zeroize(source, sizeof(source));
    mbedtls_platform_zeroize(destination, sizeof(destination));
    return vault_interrupted ? -1 : result;
}
static int file_size(FILE *input, uint64_t *size) {
#ifdef _WIN32
    if (_fseeki64(input, 0, SEEK_END) != 0) return -1;
    __int64 position = _ftelli64(input);
    if (position < 0 || _fseeki64(input, 0, SEEK_SET) != 0) return -1;
#else
    if (fseeko(input, 0, SEEK_END) != 0) return -1;
    off_t position = ftello(input);
    if (position < 0 || fseeko(input, 0, SEEK_SET) != 0) return -1;
#endif
    *size = (uint64_t)position; return 0;
}
int crypto_encrypt(FILE *input, FILE *output, const vault_secret *secret, int folder) {
    uint64_t size;
    if (file_size(input, &size) != 0 || size > VAULT_MAX_BYTES) return -1;
    unsigned char header[VAULT_HEADER_SIZE] = {0}, key[32] = {0}, tag[16], tail[16];
    memcpy(header, magic, sizeof(magic));
    header[8] = 1; header[9] = 1; header[10] = secret->key_file ? 2 : 1; header[11] = (unsigned char)folder;
    put32(header + 12, secret->key_file ? 0 : VAULT_ITERATIONS);
    for (unsigned int index = 0; index < 8; ++index) header[44 + index] = (unsigned char)(size >> (56 - index * 8));
    mbedtls_gcm_context context; mbedtls_gcm_init(&context);
    int result = -1; size_t tail_length = 0;
    if (random_bytes(header + 16, 28) || derive_key(secret, header, key) ||
        mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, 256) ||
        mbedtls_gcm_starts(&context, MBEDTLS_GCM_ENCRYPT, header + 32, 12) ||
        mbedtls_gcm_update_ad(&context, header, sizeof(header)) ||
        fwrite(header, 1, sizeof(header), output) != sizeof(header) ||
        stream_transform(input, output, &context, size) ||
        fgetc(input) != EOF || ferror(input) ||
        mbedtls_gcm_finish(&context, tail, sizeof(tail), &tail_length, tag, sizeof(tag)) ||
        fwrite(tail, 1, tail_length, output) != tail_length ||
        fwrite(tag, 1, sizeof(tag), output) != sizeof(tag)) goto cleanup;
    result = 0;
cleanup:
    mbedtls_gcm_free(&context); mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(tail, sizeof(tail)); return result;
}
int crypto_decrypt(FILE *input, FILE *output, const vault_secret *secret, int folder) {
    uint64_t total, size = 0;
    unsigned char header[VAULT_HEADER_SIZE], key[32] = {0}, tag[16], expected[16], tail[16];
    mbedtls_gcm_context context; mbedtls_gcm_init(&context);
    int result = -1; size_t tail_length = 0;
    if (file_size(input, &total) || total < VAULT_HEADER_SIZE + VAULT_TAG_SIZE ||
        fread(header, 1, sizeof(header), input) != sizeof(header)) goto cleanup;
    if (memcmp(header, magic, sizeof(magic)) || header[8] != 1 || header[9] != 1 ||
        header[10] != (secret->key_file ? 2 : 1) || header[11] != folder ||
        header[52] || header[53] || header[54] || header[55]) goto cleanup;
    uint32_t iterations = get32(header + 12);
    if ((secret->key_file && iterations != 0) ||
        (!secret->key_file && (iterations < VAULT_ITERATIONS || iterations > 2000000U))) goto cleanup;
    for (unsigned int index = 0; index < 8; ++index) size = (size << 8) | header[44 + index];
    if (size > VAULT_MAX_BYTES || total != VAULT_HEADER_SIZE + size + VAULT_TAG_SIZE) goto cleanup;
    if (derive_key(secret, header, key) ||
        mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, 256) ||
        mbedtls_gcm_starts(&context, MBEDTLS_GCM_DECRYPT, header + 32, 12) ||
        mbedtls_gcm_update_ad(&context, header, sizeof(header)) ||
        stream_transform(input, output, &context, size) ||
        fread(expected, 1, sizeof(expected), input) != sizeof(expected) ||
        mbedtls_gcm_finish(&context, tail, sizeof(tail), &tail_length, tag, sizeof(tag))) goto cleanup;
    unsigned int difference = 0;
    for (unsigned int index = 0; index < sizeof(tag); ++index) difference |= tag[index] ^ expected[index];
    if (difference || vault_interrupted || fwrite(tail, 1, tail_length, output) != tail_length) goto cleanup;
    result = 0;
cleanup:
    mbedtls_gcm_free(&context); mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(tail, sizeof(tail)); return result;
}