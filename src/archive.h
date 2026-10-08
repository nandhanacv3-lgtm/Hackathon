#ifndef VAULT_ARCHIVE_H
#define VAULT_ARCHIVE_H
#include <stdio.h>
int archive_pack(const char *directory, FILE *output);
int archive_unpack(FILE *input, const char *directory);
int archive_safe_name(const char *name, int directory);
#endif