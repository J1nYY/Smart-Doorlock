#pragma once
#include <stddef.h>

void sha256_bin(const unsigned char *data, size_t len, unsigned char out[32]);
int gen_token(char *token_out, size_t token_out_sz, unsigned char hash_out[32]);

int gen_ticket_id(char *out, size_t outsz);
