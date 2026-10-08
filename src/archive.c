#include "archive.h"
#include "platform.h"
#include "crypto.h"
#include <miniz.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int seek_file(FILE *file, uint64_t offset) {
    if (offset > VAULT_MAX_BYTES) return -1;
#ifdef _WIN32
    return _fseeki64(file, (__int64)offset, SEEK_SET);
#else
    return fseeko(file, (off_t)offset, SEEK_SET);
#endif
}
static int measure_file(FILE *file, uint64_t *size) {
#ifdef _WIN32
    if (_fseeki64(file, 0, SEEK_END)) return -1;
    __int64 position = _ftelli64(file);
#else
    if (fseeko(file, 0, SEEK_END)) return -1;
    off_t position = ftello(file);
#endif
    if (position < 0 || (uint64_t)position > VAULT_MAX_BYTES) return -1;
    *size = (uint64_t)position; return seek_file(file, 0);
}
static size_t read_data(void *opaque, mz_uint64 offset, void *buffer, size_t length) {
    FILE *file = opaque;
    if (vault_interrupted || seek_file(file, offset)) return 0;
    return fread(buffer, 1, length, file);
}
static size_t write_data(void *opaque, mz_uint64 offset, const void *buffer, size_t length) {
    FILE *file = opaque;
    if (vault_interrupted || offset > VAULT_MAX_BYTES || length > VAULT_MAX_BYTES - offset || seek_file(file, offset)) return 0;
    return fwrite(buffer, 1, length, file);
}
int archive_safe_name(const char *name, int directory) {
    size_t length = strlen(name);
    if (!length || length > 500 || name[0] == '/' || name[0] == '\\') return 0;
    if (directory) {
        if (name[length - 1] != '/') return 0;
        --length;
    } else if (name[length - 1] == '/') return 0;
    size_t start = 0; unsigned int depth = 0;
    for (size_t index = 0; index <= length; ++index) {
        unsigned char character = (unsigned char)name[index];
        if (index != length && (character < 32 || character == 127 || strchr("\\:*?\"<>|", character))) return 0;
        if (index == length || character == '/') {
            size_t count = index - start;
            if (!count || count > 240 || ++depth > 32 || name[index - 1] == '.' || name[index - 1] == ' ') return 0;
            char base[8] = {0}; size_t base_count = 0;
            while (base_count < count && base_count < 7 && name[start + base_count] != '.') {
                base[base_count] = (char)toupper((unsigned char)name[start + base_count]); ++base_count;
            }
            if (!strcmp(base, "CON") || !strcmp(base, "PRN") || !strcmp(base, "AUX") || !strcmp(base, "NUL") ||
                (base_count == 4 && (!memcmp(base, "COM", 3) || !memcmp(base, "LPT", 3)) && base[3] >= '1' && base[3] <= '9')) return 0;
            start = index + 1;
        }
    }
    return 1;
}
typedef struct { mz_zip_archive zip; uint64_t bytes; unsigned int entries; } pack_context;
static int pack_entry(const char *full, const char *relative, int directory, void *opaque) {
    pack_context *context = opaque;
    if (++context->entries > 10000 || vault_interrupted) return -1;
    char name[512];
    if (snprintf(name, sizeof(name), "%s%s", relative, directory ? "/" : "") >= (int)sizeof(name) ||
        !archive_safe_name(name, directory)) return -1;
    if (directory) return mz_zip_writer_add_mem(&context->zip, name, NULL, 0, 0) ? 0 : -1;
    FILE *source = path_open(full, "rb");
    uint64_t size;
    if (!source) return -1;
    int result = -1;
    if (!measure_file(source, &size) && size <= VAULT_MAX_BYTES - context->bytes) {
        context->bytes += size;
        if (mz_zip_writer_add_read_buf_callback(&context->zip, name, read_data, source, size,
            NULL, NULL, 0, MZ_DEFAULT_COMPRESSION, NULL, 0, NULL, 0) && !ferror(source)) result = 0;
    }
    fclose(source); return result;
}
int archive_pack(const char *directory, FILE *output) {
    pack_context context; memset(&context, 0, sizeof(context));
    context.zip.m_pWrite = write_data; context.zip.m_pIO_opaque = output;
    if (!mz_zip_writer_init(&context.zip, 0)) return -1;
    int result = walk_tree(directory, pack_entry, &context);
    if (!result && !mz_zip_writer_finalize_archive(&context.zip)) result = -1;
    mz_zip_writer_end(&context.zip);
    return result || fflush(output) || seek_file(output, 0) ? -1 : 0;
}
static int ensure_parents(const char *root, const char *relative) {
    char *copy = malloc(strlen(relative) + 1);
    if (!copy) return -1;
    strcpy(copy, relative); int result = 0;
    for (char *cursor = copy; *cursor; ++cursor) {
        if (*cursor != '/') continue;
        *cursor = 0; char *directory = path_join(root, copy); *cursor = '/';
        if (!directory || (!path_is_directory(directory) && private_mkdir(directory))) result = -1;
        free(directory); if (result) break;
    }
    free(copy); return result;
}
int archive_unpack(FILE *input, const char *directory) {
    uint64_t size, expanded = 0;
    mz_zip_archive zip; memset(&zip, 0, sizeof(zip));
    zip.m_pRead = read_data; zip.m_pIO_opaque = input;
    if (measure_file(input, &size) || !mz_zip_reader_init(&zip, size, 0)) return -1;
    int result = -1;
    mz_uint count = mz_zip_reader_get_num_files(&zip);
    if (count > 10000) goto cleanup;
    for (mz_uint index = 0; index < count; ++index) {
        mz_zip_archive_file_stat info; char name[512];
        mz_uint name_length = mz_zip_reader_get_filename(&zip, index, NULL, 0);
        if (vault_interrupted || name_length < 2 || name_length > sizeof(name) ||
            !mz_zip_reader_file_stat(&zip, index, &info) ||
            mz_zip_reader_get_filename(&zip, index, name, sizeof(name)) != name_length ||
            strlen(name) + 1 != name_length || !archive_safe_name(name, info.m_is_directory) ||
            !info.m_is_supported || info.m_is_encrypted || info.m_uncomp_size > VAULT_MAX_BYTES - expanded) goto cleanup;
        unsigned int kind = (info.m_external_attr >> 16) & 0170000;
        if (kind && kind != (info.m_is_directory ? 0040000U : 0100000U)) goto cleanup;
        if (info.m_is_directory && info.m_uncomp_size) goto cleanup;
        expanded += info.m_uncomp_size;
        if (ensure_parents(directory, name)) goto cleanup;
        if (info.m_is_directory) continue;
        char *output = path_join(directory, name);
        FILE *file = output ? private_create(output) : NULL;
        free(output);
        if (!file) goto cleanup;
        int valid = mz_zip_reader_extract_to_callback(&zip, index, write_data, file, 0) && !flush_file(file);
        if (fclose(file)) valid = 0;
        if (!valid) goto cleanup;
    }
    result = vault_interrupted ? -1 : 0;
cleanup:
    mz_zip_reader_end(&zip); return result;
}