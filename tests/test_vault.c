#include "cli.h"
#include "crypto.h"
#include "platform.h"
#include "archive.h"
#include <miniz.h>
#include <stdlib.h>
#include <string.h>

static int checks = 0;
static char *work = NULL;
static unsigned char good_bytes[32], wrong_bytes[32];
static vault_secret good = {good_bytes, 32, 1};
static void require(int condition, const char *label) {
    ++checks;
    if (!condition) { fprintf(stderr, "FAIL: %s\n", label); exit(1); }
    printf("PASS: %s\n", label);
}
static char *location(const char *name) {
    char *path = path_join(work, name);
    if (!path) exit(1);
    return path;
}
static int equal_files(FILE *first, FILE *second) {
    rewind(first); rewind(second);
    int left, right;
    do { left = fgetc(first); right = fgetc(second); if (left != right) return 0; } while (left != EOF);
    return !ferror(first) && !ferror(second);
}
static int files_match(const char *first, const char *second) {
    FILE *left = path_open(first, "rb"), *right = path_open(second, "rb");
    int result = left && right && equal_files(left, right);
    if (left) fclose(left);
    if (right) fclose(right);
    return result;
}
static void write_fixture(const char *path, size_t count) {
    FILE *file = private_create(path);
    if (!file) exit(1);
    for (size_t index = 0; index < count; ++index) if (fputc((int)((index * 37) & 255), file) == EOF) exit(1);
    if (fclose(file)) exit(1);
}
static int command(const char *verb, const char *input, const char *output, const char *key, int force) {
    char *arguments[10]; int count = 0;
    arguments[count++] = "vault"; arguments[count++] = (char *)verb;
    if (input) arguments[count++] = (char *)input;
    arguments[count++] = "--output"; arguments[count++] = (char *)output;
    if (key) { arguments[count++] = "--key-file"; arguments[count++] = (char *)key; }
    if (force) arguments[count++] = "--force";
    arguments[count] = NULL;
    return vault_run(count, arguments);
}
static void roundtrip(size_t count, const vault_secret *secret, const char *label) {
    FILE *input = tmpfile(), *encrypted = tmpfile(), *restored = tmpfile();
    if (!input || !encrypted || !restored) exit(1);
    for (size_t index = 0; index < count; ++index) fputc((int)((index * 37) & 255), input);
    require(!crypto_encrypt(input, encrypted, secret, 0), "encrypt fixture");
    rewind(encrypted);
    require(!crypto_decrypt(encrypted, restored, secret, 0) && equal_files(input, restored), label);
    fclose(input); fclose(encrypted); fclose(restored);
}
static void test_password(void) {
    const unsigned char password[] = "demo-only-password-123";
    const unsigned char bad_password[] = "not-the-demo-password";
    vault_secret password_secret = {password, sizeof(password) - 1, 0};
    vault_secret bad_secret = {bad_password, sizeof(bad_password) - 1, 0};
    roundtrip(65537, &password_secret, "password-derived key round-trip");
    FILE *input = tmpfile(), *cipher = tmpfile(), *plain = tmpfile();
    if (!input || !cipher || !plain) exit(1);
    fputs("private", input);
    require(!crypto_encrypt(input, cipher, &password_secret, 0), "password encryption");
    require(crypto_decrypt(cipher, plain, &bad_secret, 0) != 0, "wrong password rejected");
    fclose(input); fclose(cipher); fclose(plain);
}
static void copy_modified(const char *source, const char *output, int offset, size_t truncate) {
    FILE *input = path_open(source, "rb"), *destination = private_create(output);
    if (!input || !destination) exit(1);
    size_t position = 0; int value;
    while ((value = fgetc(input)) != EOF && (!truncate || position < truncate)) {
        if ((int)position == offset) value ^= 1;
        fputc(value, destination); ++position;
    }
    fclose(input); fclose(destination);
}
static int count_temporary(const char *full, const char *relative, int directory, void *opaque) {
    (void)full; (void)directory;
    if (strstr(relative, ".vault-tmp-")) ++*(int *)opaque;
    return 0;
}
static void assert_clean(void) {
    int count = 0;
    require(!walk_tree(work, count_temporary, &count) && count == 0, "no unpublished temporary files/folders remain");
}
static void encrypted_zip(const char *output, const char *entry, unsigned int attributes) {
    mz_zip_archive zip; memset(&zip, 0, sizeof(zip));
    char writer_name[512]; snprintf(writer_name, sizeof(writer_name), "%s", entry);
    if (writer_name[0] == '/') writer_name[0] = 'x';
    if (!mz_zip_writer_init_heap(&zip, 0, 0) || !mz_zip_writer_add_mem(&zip, writer_name, "unsafe", 6, 0)) exit(1);
    void *bytes = NULL; size_t count = 0;
    if (!mz_zip_writer_finalize_heap_archive(&zip, &bytes, &count)) exit(1);
    mz_zip_writer_end(&zip);
    if (entry[0] == '/') {
        unsigned char *raw = bytes;
        for (size_t index = 0; index + 46 + strlen(entry) <= count; ++index) {
            if (!memcmp(raw + index, "PK\3\4", 4)) memcpy(raw + index + 30, entry, strlen(entry));
            if (!memcmp(raw + index, "PK\1\2", 4)) memcpy(raw + index + 46, entry, strlen(entry));
        }
    }
    if (attributes) {
        unsigned char *raw = bytes;
        for (size_t index = 0; index + 46 < count; ++index) {
            if (!memcmp(raw + index, "PK\1\2", 4)) {
                for (unsigned int part = 0; part < 4; ++part) raw[index + 38 + part] = (unsigned char)(attributes >> (part * 8));
                break;
            }
        }
    }
    FILE *archive = tmpfile(), *encrypted = private_create(output);
    if (!archive || !encrypted || fwrite(bytes, 1, count, archive) != count) exit(1);
    if (crypto_encrypt(archive, encrypted, &good, 1)) exit(1);
    fclose(archive); fclose(encrypted); mz_free(bytes);
}
int main(void) {
    platform_init();
    work = private_temp_directory("vault-test");
    if (!work || random_bytes(good_bytes, 32) || random_bytes(wrong_bytes, 32)) return 1;
    char *key = location("key"), *bad_key = location("wrong-key");
    FILE *file = private_create(key);
    if (!file || fwrite(good_bytes, 1, 32, file) != 32) return 1;
    fclose(file); file = private_create(bad_key);
    if (!file || fwrite(wrong_bytes, 1, 32, file) != 32) return 1;
    fclose(file);
    roundtrip(0, &good, "empty file round-trip");
    roundtrip(1, &good, "one-byte file round-trip");
    roundtrip(15, &good, "partial AES block round-trip");
    roundtrip(16, &good, "exact AES block round-trip");
    roundtrip(17, &good, "AES block boundary round-trip");
    roundtrip(200003, &good, "binary multi-buffer round-trip");
    test_password();
    char *input = location("input.bin"), *cipher = location("cipher.enc"), *output = location("restored.bin");
    write_fixture(input, 200003);
    require(!command("encrypt", input, cipher, key, 0), "CLI encrypt");
    require(!command("decrypt", cipher, output, key, 0) && files_match(input, output), "CLI decrypt exact bytes");
    require(command("encrypt", input, cipher, key, 0) != 0, "existing output protected");
    require(!command("encrypt", input, cipher, key, 1), "explicit file overwrite succeeds");
    require(command("encrypt", input, input, key, 1) != 0, "same input/output rejected");
    require(command("encrypt", input, key, key, 1) != 0, "key-file overwrite rejected");
    require(command("decrypt", cipher, output, bad_key, 1) != 0 && files_match(input, output), "wrong key preserves existing output even with --force");
    char *absent = location("absent.bin");
    require(command("decrypt", cipher, absent, bad_key, 0) != 0 && !path_exists(absent), "wrong key publishes no new output");
    const int changes[] = {8, 16, 56, 200073};
    const char *labels[] = {"unsupported version rejected", "salt/header tampering rejected", "ciphertext tampering rejected", "tag tampering rejected"};
    for (unsigned int index = 0; index < 4; ++index) {
        char name[32]; snprintf(name, sizeof(name), "corrupt-%u", index);
        char *damaged = location(name); copy_modified(cipher, damaged, changes[index], 0);
        require(command("decrypt", damaged, absent, key, 0) != 0 && !path_exists(absent), labels[index]); free(damaged);
    }
    const size_t truncations[] = {1, 55, 71, 100, 200074};
    for (unsigned int index = 0; index < 5; ++index) {
        char name[32]; snprintf(name, sizeof(name), "truncated-%u", index);
        char *damaged = location(name); copy_modified(cipher, damaged, -1, truncations[index]);
        require(command("decrypt", damaged, absent, key, 0) != 0 && !path_exists(absent), "truncated input rejected"); free(damaged);
    }
    char *short_key = location("short-key"); write_fixture(short_key, 31);
    require(command("encrypt", input, absent, short_key, 0) != 0 && !path_exists(absent), "invalid key length rejected");
    vault_interrupted = 1;
    require(command("decrypt", cipher, output, key, 1) == 130 && files_match(input, output), "graceful interruption preserves old output");
    vault_interrupted = 0; assert_clean();
    char *unicode = location("caf\xc3\xa9-\xe6\x96\x87\xe4\xbb\xb6.bin"); write_fixture(unicode, 511);
    char *unicode_cipher = location("\xe5\x8a\xa0\xe5\xaf\x86.enc"), *unicode_output = location("r\xc3\xa9tabli.bin");
    require(!command("encrypt", unicode, unicode_cipher, key, 0) &&
            !command("decrypt", unicode_cipher, unicode_output, key, 0) && files_match(unicode, unicode_output), "Unicode paths round-trip");
    char *folder = location("documents"), *empty_dir = path_join(folder, "empty"), *nested = path_join(folder, "nested");
    require(!private_mkdir(folder) && !private_mkdir(empty_dir) && !private_mkdir(nested), "folder fixtures created");
    char *child = path_join(nested, "caf\xc3\xa9.bin"); write_fixture(child, 100003);
    char *folder_cipher = location("documents.enc"), *restored = location("documents-restored");
    require(!command("encrypt-folder", folder, folder_cipher, key, 0), "folder encryption");
    require(!command("decrypt-folder", folder_cipher, restored, key, 0), "folder decryption");
    char *restored_child = path_join(restored, "nested/caf\xc3\xa9.bin"), *restored_empty = path_join(restored, "empty");
    require(files_match(child, restored_child) && path_is_directory(restored_empty), "folder content, Unicode name, and empty directory preserved");
    require(command("decrypt-folder", folder_cipher, restored, key, 0) != 0, "existing destination folder protected");
    require(command("decrypt-folder", folder_cipher, restored, key, 1) != 0, "folder --force refused");
    char *inside = path_join(folder, "must-not-exist.enc");
    require(command("encrypt-folder", folder, inside, key, 0) != 0 && !path_exists(inside), "output inside source tree rejected");
    require(command("decrypt", folder_cipher, absent, key, 0) != 0, "folder/file type confusion rejected");
    const char *unsafe[] = {"../escape", "/absolute", "C:/drive", "safe/../../escape", "link", "CON.txt"};
    for (unsigned int index = 0; index < 6; ++index) {
        char name[32]; snprintf(name, sizeof(name), "hostile-%u.enc", index);
        char *hostile = location(name), *target = location("hostile-output");
        encrypted_zip(hostile, unsafe[index], index == 4 ? (0120777U << 16) : 0);
        require(command("decrypt-folder", hostile, target, key, 0) != 0 && !path_exists(target), "authenticated unsafe archive rejected without publishing folder");
        free(hostile); free(target);
    }
    char *empty_folder = location("empty-source"), *empty_cipher = location("empty-folder.enc"), *empty_restored = location("empty-restored");
    require(!private_mkdir(empty_folder) && !command("encrypt-folder", empty_folder, empty_cipher, key, 0) &&
            !command("decrypt-folder", empty_cipher, empty_restored, key, 0) && path_is_directory(empty_restored), "empty folder round-trip");
    assert_clean();
    char *generated = location("generated.key");
    require(!command("keygen", NULL, generated, NULL, 0) && path_is_regular(generated), "CLI key generation");
    require(command("keygen", NULL, generated, NULL, 0) != 0, "key overwrite protected");
    free(key); free(bad_key); free(input); free(cipher); free(output); free(absent); free(short_key);
    free(unicode); free(unicode_cipher); free(unicode_output); free(folder); free(empty_dir); free(nested);
    free(child); free(folder_cipher); free(restored); free(restored_child); free(restored_empty); free(inside);
    free(empty_folder); free(empty_cipher); free(empty_restored); free(generated);
    require(!remove_tree(work), "test fixtures cleaned"); free(work);
    printf("All %d checks passed.\n", checks); return 0;
}