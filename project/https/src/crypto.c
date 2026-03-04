#include "crypto.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

// base64url(-,_) / base64(+ ,/) 둘 다 허용
int b64url_or_b64_decode(const char *in, unsigned char *out, size_t outcap, size_t *outlen) {
  if (!in || !out || !outlen) return 0;

  // 1) input 복사 및 base64url -> base64 치환
  size_t n = strlen(in);
  if (n == 0) return 0;

  // 패딩 포함했을 때도 버퍼가 충분해야 함
  // 임시 버퍼는 (n + 4) 정도면 충분하지만 넉넉히
  char tmp[8192];
  if (n + 4 >= sizeof(tmp)) return 0;

  memcpy(tmp, in, n);
  tmp[n] = '\0';

  for (size_t i = 0; i < n; i++) {
    if (tmp[i] == '-') tmp[i] = '+';
    else if (tmp[i] == '_') tmp[i] = '/';
  }

  // 2) padding '=' 추가
  size_t pad = (4 - (n % 4)) % 4;
  for (size_t i = 0; i < pad; i++) tmp[n + i] = '=';
  tmp[n + pad] = '\0';
  size_t enc_len = n + pad;

  // 3) decode
  // EVP_DecodeBlock은 출력이 enc_len/4*3 크기 필요
  size_t need = (enc_len / 4) * 3;
  if (need > outcap) return 0;

  int dec = EVP_DecodeBlock(out, (unsigned char *) tmp, (int) enc_len);
  if (dec < 0) return 0;

  // 패딩만큼 실제 길이 조정
  size_t real = (size_t) dec;
  if (pad > 0) real -= pad;

  *outlen = real;
  return 1;
}

// SPKI DER 공개키로 ECDSA/RSA 서명 검증(SHA-256)
int verify_signature_spki_der(const unsigned char *spki, size_t spki_len,
                              const unsigned char *msg, size_t msg_len,
                              const unsigned char *sig, size_t sig_len) {
  if (!spki || spki_len == 0 || !msg || !sig) return 0;

  const unsigned char *p = spki;
  EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, (long) spki_len);
  if (!pub) return 0;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { EVP_PKEY_free(pub); return 0; }

  int ok = 0;
  if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) != 1) goto done;
  if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) != 1) goto done;

  // 성공: 1, 실패: 0, 에러: -1
  {
    int r = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    ok = (r == 1);
  }

done:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pub);
  return ok;
}

