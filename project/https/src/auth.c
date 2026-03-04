#include "../include/auth.h"
#include <openssl/evp.h>
#include <string.h>

// 상수시간 비교(타이밍 공격 완화)
static int ct_memeq(const unsigned char *a, const unsigned char *b, size_t n) {
  unsigned char r = 0;
  for (size_t i = 0; i < n; i++) r |= (unsigned char)(a[i] ^ b[i]);
  return r == 0;
}

int auth_pbkdf2_sha256(const char *password,
                       const unsigned char *salt, size_t salt_len,
                       int iter,
                       unsigned char out_hash[32]) {
  if (!password || !salt || salt_len == 0 || iter <= 0) return 0;

  // PKCS5_PBKDF2_HMAC is OpenSSL stable API
  int ok = PKCS5_PBKDF2_HMAC(password, (int) strlen(password),
                            salt, (int) salt_len,
                            iter,
                            EVP_sha256(),
                            32, out_hash);
  return ok == 1;
}

int auth_verify_password(const char *password,
                         const unsigned char *salt, size_t salt_len,
                         int iter,
                         const unsigned char stored_hash[32]) {
  unsigned char h[32];
  if (!auth_pbkdf2_sha256(password, salt, salt_len, iter, h)) return 0;
  return ct_memeq(h, stored_hash, 32);
}

