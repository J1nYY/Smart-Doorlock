#pragma once
#include <stddef.h>

// PBKDF2-HMAC-SHA256(32 bytes)로 password 검증/생성
int auth_pbkdf2_sha256(const char *password,
                       const unsigned char *salt, size_t salt_len,
                       int iter,
                       unsigned char out_hash[32]);

int auth_verify_password(const char *password,
                         const unsigned char *salt, size_t salt_len,
                         int iter,
                         const unsigned char stored_hash[32]);

