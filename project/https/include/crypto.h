#pragma once
#include <stddef.h>

int b64url_or_b64_decode(const char *in, unsigned char *out, size_t outcap, size_t *outlen);

int verify_signature_spki_der(const unsigned char *spki, size_t spki_len,
                              const unsigned char *msg, size_t msg_len,
                              const unsigned char *sig, size_t sig_len);

