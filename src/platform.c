#include "platform.h"
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <dirent.h>
#endif

volatile int vault_interrupted = 0;
static void on_signal(int number) { (void)number; vault_interrupted = 1; }
void platform_init(void) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
}
char *path_join(const char *parent, const char *child) {
    size_t parent_length = strlen(parent), child_length = strlen(child);
    char *result = malloc(parent_length + child_length + 2);
    if (result) {
        memcpy(result, parent, parent_length);
        result[parent_length] = '/';
        memcpy(result + parent_length + 1, child, child_length + 1);
    }
    return result;
}
#ifdef _WIN32
static wchar_t *wide(const char *text) {
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    wchar_t *result = count ? malloc((size_t)count * sizeof(wchar_t)) : NULL;
    if (result && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, result, count)) {
        free(result); return NULL;
    }
    return result;
}
FILE *path_open(const char *path, const char *mode) {
    wchar_t *wide_path = wide(path), *wide_mode = wide(mode);
    FILE *file = wide_path && wide_mode ? _wfopen(wide_path, wide_mode) : NULL;
    free(wide_path); free(wide_mode); return file;
}
int path_exists(const char *path) {
    wchar_t *name = wide(path);
    DWORD attr = name ? GetFileAttributesW(name) : INVALID_FILE_ATTRIBUTES;
    free(name); return attr != INVALID_FILE_ATTRIBUTES;
}
int path_is_regular(const char *path) {
    wchar_t *name = wide(path);
    DWORD attr = name ? GetFileAttributesW(name) : INVALID_FILE_ATTRIBUTES;
    free(name);
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}
int path_remove(const char *path) {
    wchar_t *name = wide(path);
    int result = name && DeleteFileW(name) ? 0 : -1;
    free(name); return result;
}
static HANDLE restricted_create(const wchar_t *name) {
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;OW)(A;;FA;;;SY)", SDDL_REVISION_1, &descriptor, NULL)) return INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    HANDLE handle = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, &security,
                                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    LocalFree(descriptor); return handle;
}
FILE *private_temp(const char *output, char **name) {
    size_t size = strlen(output) + 80;
    char *candidate = malloc(size);
    if (!candidate) return NULL;
    for (unsigned int attempt = 0; attempt < 100; ++attempt) {
        snprintf(candidate, size, "%s.vault-tmp-%lu-%llu-%u", output,
                 (unsigned long)GetCurrentProcessId(), (unsigned long long)GetTickCount64(), attempt);
        wchar_t *wide_name = wide(candidate);
        HANDLE handle = wide_name ? restricted_create(wide_name) : INVALID_HANDLE_VALUE;
        free(wide_name);
        if (handle != INVALID_HANDLE_VALUE) {
            int descriptor = _open_osfhandle((intptr_t)handle, _O_BINARY | _O_RDWR);
            FILE *file = descriptor < 0 ? NULL : _fdopen(descriptor, "w+b");
            if (!file) {
                if (descriptor < 0) CloseHandle(handle); else _close(descriptor);
                path_remove(candidate); free(candidate); return NULL;
            }
            *name = candidate; return file;
        }
        if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS) break;
    }
    free(candidate); return NULL;
}
int publish_file(const char *temporary, const char *output, int force) {
    wchar_t *source = wide(temporary), *destination = wide(output);
    int result = source && destination && MoveFileExW(source, destination,
        MOVEFILE_WRITE_THROUGH | (force ? MOVEFILE_REPLACE_EXISTING : 0)) ? 0 : -1;
    free(source); free(destination); return result;
}
int flush_file(FILE *file) { return fflush(file) == 0 && _commit(_fileno(file)) == 0 ? 0 : -1; }
int password_read(char *buffer, size_t capacity, const char *prompt) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD original;
    if (!GetConsoleMode(input, &original)) {
        fprintf(stderr, "Password entry requires a terminal; use --key-file for automation.\n"); return -1;
    }
    fprintf(stderr, "%s", prompt); fflush(stderr);
    if (!SetConsoleMode(input, original & ~ENABLE_ECHO_INPUT)) return -1;
    wchar_t text[1024]; DWORD count = 0;
    int result = ReadConsoleW(input, text, 1023, &count, NULL) ? 0 : -1;
    SetConsoleMode(input, original); fprintf(stderr, "\n");
    while (count && (text[count - 1] == L'\r' || text[count - 1] == L'\n')) --count;
    text[count] = 0;
    if (count >= 1021 || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1,
                                            buffer, (int)capacity, NULL, NULL)) result = -1;
    SecureZeroMemory(text, sizeof(text)); return vault_interrupted ? -1 : result;
}
#else
FILE *path_open(const char *path, const char *mode) { return fopen(path, mode); }
int path_exists(const char *path) { struct stat info; return lstat(path, &info) == 0; }
int path_is_regular(const char *path) {
    struct stat info; return lstat(path, &info) == 0 && S_ISREG(info.st_mode);
}
int path_remove(const char *path) { return unlink(path); }
FILE *private_temp(const char *output, char **name) {
    char *candidate = malloc(strlen(output) + 24);
    if (!candidate) return NULL;
    sprintf(candidate, "%s.vault-tmp-XXXXXX", output);
    int descriptor = mkstemp(candidate);
    FILE *file = descriptor < 0 ? NULL : fdopen(descriptor, "w+b");
    if (!file) {
        if (descriptor >= 0) { close(descriptor); unlink(candidate); }
        free(candidate); return NULL;
    }
    *name = candidate; return file;
}
int publish_file(const char *temporary, const char *output, int force) {
    if (force) return rename(temporary, output);
    if (link(temporary, output) != 0) return -1;
    unlink(temporary); return 0;
}
int flush_file(FILE *file) { return fflush(file) == 0 && fsync(fileno(file)) == 0 ? 0 : -1; }
int password_read(char *buffer, size_t capacity, const char *prompt) {
    struct termios original, hidden;
    FILE *terminal = fopen("/dev/tty", "r+");
    if (!terminal || tcgetattr(fileno(terminal), &original) != 0) {
        if (terminal) fclose(terminal);
        fprintf(stderr, "Password entry requires a terminal; use --key-file for automation.\n"); return -1;
    }
    hidden = original; hidden.c_lflag &= (tcflag_t)~ECHO;
    fprintf(terminal, "%s", prompt); fflush(terminal);
    if (tcsetattr(fileno(terminal), TCSAFLUSH, &hidden) != 0) { fclose(terminal); return -1; }
    int result = fgets(buffer, (int)capacity, terminal) ? 0 : -1;
    tcsetattr(fileno(terminal), TCSAFLUSH, &original); fprintf(terminal, "\n");
    if (result == 0 && !strchr(buffer, '\n')) result = -1;
    buffer[strcspn(buffer, "\r\n")] = 0;
    fclose(terminal); return vault_interrupted ? -1 : result;
}
#endif

int path_is_directory(const char *path) {
#ifdef _WIN32
    wchar_t *name = wide(path);
    DWORD attr = name ? GetFileAttributesW(name) : INVALID_FILE_ATTRIBUTES;
    free(name);
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) && !(attr & FILE_ATTRIBUTE_REPARSE_POINT);
#else
    struct stat info; return lstat(path, &info) == 0 && S_ISDIR(info.st_mode);
#endif
}
int path_same(const char *first, const char *second) {
#ifdef _WIN32
    wchar_t *left = wide(first), *right = wide(second);
    HANDLE first_handle = left ? CreateFileW(left, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL) : INVALID_HANDLE_VALUE;
    HANDLE second_handle = right ? CreateFileW(right, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL) : INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION first_info, second_info;
    int result = first_handle != INVALID_HANDLE_VALUE && second_handle != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandle(first_handle, &first_info) && GetFileInformationByHandle(second_handle, &second_info) &&
        first_info.dwVolumeSerialNumber == second_info.dwVolumeSerialNumber &&
        first_info.nFileIndexHigh == second_info.nFileIndexHigh && first_info.nFileIndexLow == second_info.nFileIndexLow;
    if (first_handle != INVALID_HANDLE_VALUE) CloseHandle(first_handle);
    if (second_handle != INVALID_HANDLE_VALUE) CloseHandle(second_handle);
    free(left); free(right); return result;
#else
    struct stat left, right;
    return stat(first, &left) == 0 && stat(second, &right) == 0 && left.st_dev == right.st_dev && left.st_ino == right.st_ino;
#endif
}
static char *canonical_existing(const char *path) {
#ifdef _WIN32
    wchar_t *name = wide(path);
    HANDLE handle = name ? CreateFileW(name, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL) : INVALID_HANDLE_VALUE;
    free(name);
    if (handle == INVALID_HANDLE_VALUE) return NULL;
    DWORD count = GetFinalPathNameByHandleW(handle, NULL, 0, FILE_NAME_NORMALIZED);
    wchar_t *resolved = count ? malloc(((size_t)count + 1) * sizeof(wchar_t)) : NULL;
    char *result = NULL;
    if (resolved && GetFinalPathNameByHandleW(handle, resolved, count + 1, FILE_NAME_NORMALIZED)) {
        int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, resolved, -1, NULL, 0, NULL, NULL);
        result = size ? malloc((size_t)size) : NULL;
        if (result) WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, resolved, -1, result, size, NULL, NULL);
    }
    free(resolved); CloseHandle(handle); return result;
#else
    return realpath(path, NULL);
#endif
}
int path_contains(const char *directory, const char *path) {
    char *root = canonical_existing(directory), *candidate = canonical_existing(path);
    if (!candidate) {
        char *copy = malloc(strlen(path) + 1);
        if (copy) {
            strcpy(copy, path);
            char *separator = strrchr(copy, '/');
#ifdef _WIN32
            char *backslash = strrchr(copy, '\\');
            if (backslash && (!separator || backslash > separator)) separator = backslash;
#endif
            if (separator) {
                char *leaf = malloc(strlen(separator + 1) + 1);
                if (leaf) {
                    strcpy(leaf, separator + 1);
                    if (separator == copy) separator[1] = 0; else *separator = 0;
                    char *parent = canonical_existing(copy);
                    if (parent) { candidate = path_join(parent, leaf); free(parent); }
                    free(leaf);
                }
            } else {
                char *parent = canonical_existing(".");
                if (parent) { candidate = path_join(parent, copy); free(parent); }
            }
            free(copy);
        }
    }
    int result = -1;
    if (root && candidate) {
        size_t length = strlen(root);
        while (length > 1 && (root[length - 1] == '/' || root[length - 1] == '\\')) --length;
        result = 0;
        if (strlen(candidate) >= length) {
            int equal = 1;
            for (size_t index = 0; index < length; ++index) {
                unsigned char left = (unsigned char)root[index], right = (unsigned char)candidate[index];
#ifdef _WIN32
                if (left == '\\') left = '/';
                if (right == '\\') right = '/';
                left = (unsigned char)tolower(left); right = (unsigned char)tolower(right);
#endif
                if (left != right) { equal = 0; break; }
            }
            result = equal && (!candidate[length] || candidate[length] == '/' || candidate[length] == '\\');
        }
    }
    free(root); free(candidate); return result;
}
int private_mkdir(const char *path) {
#ifdef _WIN32
    wchar_t *name = wide(path); PSECURITY_DESCRIPTOR descriptor = NULL;
    int result = -1;
    if (name && ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)", SDDL_REVISION_1, &descriptor, NULL)) {
        SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
        result = CreateDirectoryW(name, &security) ? 0 : -1;
        LocalFree(descriptor);
    }
    free(name); return result;
#else
    return mkdir(path, 0700);
#endif
}
FILE *private_create(const char *path) {
#ifdef _WIN32
    wchar_t *name = wide(path);
    HANDLE handle = name ? restricted_create(name) : INVALID_HANDLE_VALUE;
    free(name);
    if (handle == INVALID_HANDLE_VALUE) return NULL;
    int descriptor = _open_osfhandle((intptr_t)handle, _O_BINARY | _O_RDWR);
    FILE *file = descriptor < 0 ? NULL : _fdopen(descriptor, "w+b");
    if (!file) { if (descriptor < 0) CloseHandle(handle); else _close(descriptor); path_remove(path); }
    return file;
#else
    int descriptor = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    FILE *file = descriptor < 0 ? NULL : fdopen(descriptor, "w+b");
    if (!file && descriptor >= 0) { close(descriptor); unlink(path); }
    return file;
#endif
}
char *private_temp_directory(const char *output) {
    char *name = NULL;
    FILE *placeholder = private_temp(output, &name);
    if (!placeholder) return NULL;
    fclose(placeholder); path_remove(name);
    if (private_mkdir(name) != 0) { free(name); return NULL; }
    return name;
}
int publish_directory(const char *temporary, const char *output) {
#ifdef _WIN32
    return publish_file(temporary, output, 0);
#else
    if (path_exists(output)) return -1;
    return rename(temporary, output);
#endif
}
static int remove_directory(const char *path) {
#ifdef _WIN32
    wchar_t *name = wide(path);
    int result = name && RemoveDirectoryW(name) ? 0 : -1;
    free(name); return result;
#else
    return rmdir(path);
#endif
}
static int visit_tree(const char *root, const char *relative, unsigned int depth,
                      walk_callback callback, void *context, int removing) {
    if (depth > 32 || (!removing && vault_interrupted)) return -1;
    char *full = *relative ? path_join(root, relative) : NULL;
    const char *directory = full ? full : root;
    int result = 0;
#ifdef _WIN32
    char *pattern = path_join(directory, "*");
    wchar_t *search = pattern ? wide(pattern) : NULL;
    WIN32_FIND_DATAW entry;
    HANDLE listing = search ? FindFirstFileW(search, &entry) : INVALID_HANDLE_VALUE;
    free(pattern); free(search);
    if (listing == INVALID_HANDLE_VALUE) { free(full); return -1; }
    do {
        if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")) continue;
        if (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) { result = -1; break; }
        char name[1024];
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, entry.cFileName, -1, name, sizeof(name), NULL, NULL)) {
            result = -1; break;
        }
        int is_directory = (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
    DIR *listing = opendir(directory);
    if (!listing) { free(full); return -1; }
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(listing)) != NULL) {
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
#endif
        char *child_relative = *relative ? path_join(relative, name) : malloc(strlen(name) + 1);
        if (child_relative && !*relative) strcpy(child_relative, name);
        char *child_full = child_relative ? path_join(root, child_relative) : NULL;
        if (!child_full) { free(child_relative); result = -1; break; }
#ifndef _WIN32
        int is_directory = path_is_directory(child_full);
        if (!is_directory && !path_is_regular(child_full)) result = -1;
#endif
        if (!result && !removing) result = callback(child_full, child_relative, is_directory, context);
        if (!result && is_directory) result = visit_tree(root, child_relative, depth + 1, callback, context, removing);
        if (!result && removing) result = is_directory ? remove_directory(child_full) : path_remove(child_full);
        free(child_full); free(child_relative);
        if (result || (!removing && vault_interrupted)) { result = -1; break; }
#ifdef _WIN32
    } while (FindNextFileW(listing, &entry));
    if (!result && GetLastError() != ERROR_NO_MORE_FILES) result = -1;
    FindClose(listing);
#else
        errno = 0;
    }
    if (!result && errno) result = -1;
    closedir(listing);
#endif
    free(full); return result;
}
int walk_tree(const char *root, walk_callback callback, void *context) {
    return path_is_directory(root) ? visit_tree(root, "", 0, callback, context, 0) : -1;
}
int remove_tree(const char *path) {
    if (!path_is_directory(path)) return -1;
    if (visit_tree(path, "", 0, NULL, NULL, 1)) return -1;
    return remove_directory(path);
}