#pragma once
#include "../third_party/mongoose.h"
#include <stddef.h>

int json_get_string(struct mg_str json, const char *path, char *out, size_t outsz);
int json_get_int(struct mg_str json, const char *path, int *outv);

