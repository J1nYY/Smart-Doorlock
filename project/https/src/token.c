#include "../include/token.h"
#include "../third_party/mongoose.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

void sha256_bin(const unsigned char *data, size_t len, unsigned char out[32]) {
  unsigned int outlen = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { memset(out, 0, 32); return; }
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, data, len);
  EVP_DigestFinal_ex(ctx, out, &outlen);
  EVP_MD_CTX_free(ctx);
}

static void b64url_encode(const unsigned char *in, size_t inlen, char *out, size_t outsz) {
  if (outsz == 0) return;
  size_t n = mg_base64_encode(in, inlen, out, outsz);   // (p, n, buf, buflen)
  if (n >= outsz) n = outsz - 1;
  out[n] = '\0';
  for (size_t i = 0; out[i]; i++) {
    if (out[i] == '+') out[i] = '-';
    else if (out[i] == '/') out[i] = '_';
    else if (out[i] == '=') { out[i] = '\0'; break; }
  }
}

int gen_token(char *token_out, size_t token_out_sz, unsigned char hash_out[32]) {
  unsigned char rnd[32];
  if (RAND_bytes(rnd, (int)sizeof(rnd)) != 1) return 0;
  b64url_encode(rnd, sizeof(rnd), token_out, token_out_sz);
  if (token_out[0] == 0) return 0;
  sha256_bin((unsigned char*)token_out, strlen(token_out), hash_out);
  return 1;
}

int gen_ticket_id(char *out, size_t outsz) {
  unsigned char rnd[16];
  if (RAND_bytes(rnd, (int)sizeof(rnd)) != 1) return 0;
  b64url_encode(rnd, sizeof(rnd), out, outsz); // ~22 chars
  return out[0] != 0;
}

