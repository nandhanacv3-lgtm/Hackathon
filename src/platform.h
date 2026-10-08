#ifndef VAULT_PLATFORM_H
#define VAULT_PLATFORM_H
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
extern volatile int vault_interrupted;
void platform_init(void);
FILE *path_open(const char *path, const char *mode);
int path_exists(const char *path);
int path_remove(const char *path);
int path_is_regular(const char *path);
int path_is_directory(const char *path);
int path_same(const char *first, const char *second);
int path_contains(const char *directory, const char *path);
int private_mkdir(const char *path);
FILE *private_create(const char *path);
char *private_temp_directory(const char *output);
int publish_directory(const char *temporary, const char *output);
int remove_tree(const char *path);
typedef int (*walk_callback)(const char *full_path, const char *relative, int directory, void *context);
int walk_tree(const char *root, walk_callback callback, void *context);
FILE *private_temp(const char *output, char **name);
int publish_file(const char *temporary, const char *output, int force);
int flush_file(FILE *file);
int password_read(char *buffer, size_t capacity, const char *prompt);
char *path_join(const char *parent, const char *child);
#endif