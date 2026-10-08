#include "platform.h"
#include "crypto.h"
#include "archive.h"
#include "cli.h"
#include <mbedtls/platform_util.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif

static void usage(void) {
    puts("LocalVault: offline authenticated file encryption\n"
         "  vault encrypt INPUT --output OUTPUT [--key-file KEY] [--force]\n"
         "  vault decrypt INPUT --output OUTPUT [--key-file KEY] [--force]\n"
         "  vault encrypt-folder INPUT --output OUTPUT [--key-file KEY] [--force]\n"
         "  vault decrypt-folder INPUT --output NEW_DIRECTORY [--key-file KEY]\n"
         "  vault keygen --output KEY\n"
         "Without --key-file, passwords are requested privately in the terminal.");
}
int vault_run(int argc, char **argv) {
    platform_init();
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "help"))) { usage(); return 0; }
    if (argc < 2) { usage(); return 2; }
    int generate = !strcmp(argv[1], "keygen");
    int folder = !strcmp(argv[1], "encrypt-folder") || !strcmp(argv[1], "decrypt-folder");
    int encrypt = !strcmp(argv[1], "encrypt") || !strcmp(argv[1], "encrypt-folder");
    if (!generate && !encrypt && strcmp(argv[1], "decrypt") && strcmp(argv[1], "decrypt-folder")) { usage(); return 2; }
    const char *input = NULL, *output = NULL, *key_path = NULL;
    int force = 0;
    for (int index = 2; index < argc; ++index) {
        if (!strcmp(argv[index], "--output") && index + 1 < argc && !output) output = argv[++index];
        else if (!strcmp(argv[index], "--key-file") && index + 1 < argc && !key_path) key_path = argv[++index];
        else if (!strcmp(argv[index], "--force") && !force) force = 1;
        else if (argv[index][0] != '-' && !input && !generate) input = argv[index];
        else { fprintf(stderr, "Invalid or repeated argument.\n"); return 2; }
    }
    if (!output || !*output || (!generate && (!input ||
        (folder && encrypt ? !path_is_directory(input) : !path_is_regular(input)))) ||
        (generate && (force || key_path)) || (folder && !encrypt && force) ||
        (input && (!strcmp(input, output) || path_same(input, output))) ||
        (key_path && (!strcmp(key_path, output) || path_same(key_path, output)))) {
        fprintf(stderr, "Invalid paths/options, input type, or output aliases input/key.\n"); return 2;
    }
    if (folder && encrypt && path_contains(input, output) != 0) {
        fprintf(stderr, "Folder output must be outside the source tree, with an existing parent.\n"); return 2;
    }
    if (path_exists(output) && (!force || !path_is_regular(output))) {
        fprintf(stderr, "Output exists; use --force to replace a regular file.\n"); return 2;
    }
    unsigned char secret_bytes[1024] = {0};
    char confirmation[1024] = {0};
    vault_secret secret = {secret_bytes, 0, key_path != NULL};
    FILE *source = NULL, *destination = NULL, *archive_file = NULL;
    char *temporary = NULL, *archive_name = NULL, *staging = NULL;
    int result = 1;
    if (generate) {
        if (random_bytes(secret_bytes, 32)) goto cleanup;
    } else if (key_path) {
        if (!path_is_regular(key_path)) { fprintf(stderr, "Key must be a regular file.\n"); goto cleanup; }
        FILE *key = path_open(key_path, "rb");
        if (!key) goto cleanup;
        secret.length = fread(secret_bytes, 1, 32, key);
        int valid = secret.length == 32 && fgetc(key) == EOF && !ferror(key);
        fclose(key);
        if (!valid) { fprintf(stderr, "Key file must contain exactly 32 bytes.\n"); goto cleanup; }
    } else {
        if (password_read((char *)secret_bytes, sizeof(secret_bytes), "Password: ")) goto cleanup;
        secret.length = strlen((char *)secret_bytes);
        if (!secret.length || (encrypt && secret.length < 12)) {
            fprintf(stderr, "New passwords must be at least 12 UTF-8 bytes; empty passwords are rejected.\n"); goto cleanup;
        }
        if (encrypt && (password_read(confirmation, sizeof(confirmation), "Confirm password: ") ||
                        strcmp((char *)secret_bytes, confirmation))) {
            fprintf(stderr, "Passwords do not match.\n"); goto cleanup;
        }
    }
    if (folder) {
        archive_file = private_temp(output, &archive_name);
        if (!archive_file) goto cleanup;
    }
    if (folder && encrypt) {
        if (archive_pack(input, archive_file)) { fprintf(stderr, "Cannot archive folder: unsafe name/link, limit, or I/O failure.\n"); goto cleanup; }
        source = archive_file;
    } else if (!generate && !(source = path_open(input, "rb"))) goto cleanup;
    destination = private_temp(output, &temporary);
    if (!destination) { fprintf(stderr, "Cannot create private temporary output; check the parent directory.\n"); goto cleanup; }
    if (generate) {
        if (fwrite(secret_bytes, 1, 32, destination) != 32) goto cleanup;
    } else if ((encrypt ? crypto_encrypt(source, destination, &secret, folder) :
                         crypto_decrypt(source, destination, &secret, folder)) != 0) {
        fprintf(stderr, "Operation failed: wrong secret, damaged/unsupported input, size limit, or I/O error.\n"); goto cleanup;
    }
    if (vault_interrupted || flush_file(destination)) goto cleanup;
    if (folder && !encrypt) {
        staging = private_temp_directory(output);
        if (!staging || archive_unpack(destination, staging) || vault_interrupted || publish_directory(staging, output)) {
            fprintf(stderr, "Folder extraction failed; destination must be new and archive paths safe.\n"); goto cleanup;
        }
        free(staging); staging = NULL;
        result = 0; puts("Done. Folder restored; original input preserved."); goto cleanup;
    }
    if (source && source != archive_file) { fclose(source); source = NULL; }
    int close_result = fclose(destination); destination = NULL;
    if (close_result || vault_interrupted || publish_file(temporary, output, force)) {
        fprintf(stderr, "Could not publish output; no existing output was intentionally removed.\n"); goto cleanup;
    }
    result = 0; puts(generate ? "Key created. Keep a protected backup." : "Done. Original input preserved.");
cleanup:
    if (source && source != archive_file) fclose(source);
    if (archive_file) fclose(archive_file);
    if (destination) fclose(destination);
    if (temporary) { path_remove(temporary); free(temporary); }
    if (archive_name) { path_remove(archive_name); free(archive_name); }
    if (staging) {
        if (remove_tree(staging)) fprintf(stderr, "Warning: could not remove private staging folder: %s\n", staging);
        free(staging);
    }
    mbedtls_platform_zeroize(secret_bytes, sizeof(secret_bytes));
    mbedtls_platform_zeroize(confirmation, sizeof(confirmation));
    if (vault_interrupted) fprintf(stderr, "Interrupted; unpublished temporary output removed.\n");
    else if (result) fprintf(stderr, "No output published.\n");
    return vault_interrupted ? 130 : result;
}
#ifndef VAULT_NO_MAIN
#ifdef _WIN32
int wmain(int argc, wchar_t **arguments) {
    char **utf8 = calloc((size_t)argc + 1, sizeof(char *));
    if (!utf8) return 1;
    int valid = 1;
    for (int index = 0; index < argc; ++index) {
        int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, arguments[index], -1, NULL, 0, NULL, NULL);
        utf8[index] = size ? malloc((size_t)size) : NULL;
        if (!utf8[index] || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, arguments[index], -1,
                                               utf8[index], size, NULL, NULL)) { valid = 0; break; }
    }
    int result = valid ? vault_run(argc, utf8) : 1;
    for (int index = 0; index < argc; ++index) free(utf8[index]);
    free(utf8); return result;
}
#else
int main(int argc, char **argv) { return vault_run(argc, argv); }
#endif
#endif