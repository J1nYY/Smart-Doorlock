#include "esp.h"
#include "chal.h"
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#define WIFI_POP_DEBUG 1
extern UART_HandleTypeDef huart2;


extern cb_data_t cb_data;
// cb_data.buf 안에 "+IPD,..."가 섞여 있어도 '['부터 '\n'까지를 한 줄로 뽑아줌
static const char B64URL_TBL[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static size_t base64url_encoded_len(size_t n) {
  size_t full = (n / 3) * 4;
  size_t rem  = n % 3;
  if (rem == 0) return full;
  // rem=1 -> 2 chars, rem=2 -> 3 chars
  return full + (rem + 1);
}
static void dbg_uart(const char *s) {
  HAL_UART_Transmit(&huart2, (uint8_t*)s, (uint16_t)strlen(s), 100);
}

static void dbg_uart_printf(const char *fmt, ...) {
  char b[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(b, sizeof(b), fmt, ap);
  va_end(ap);
  dbg_uart(b);
}

static void dbg_uart_hex(const uint8_t *p, uint16_t n) {
  char t[4];
  for (uint16_t i=0;i<n;i++){
    snprintf(t, sizeof(t), "%02X", p[i]);
    dbg_uart(t);
    dbg_uart(" ");
  }
  dbg_uart("\r\n");
}
//
int base64url_encode(const uint8_t *in, size_t inlen, char *out, size_t outsz) {
  if (!in || !out) return -1;

  size_t need = base64url_encoded_len(inlen) + 1; // + '\0'
  if (outsz < need) return -1;

  size_t i = 0, o = 0;

  // 3바이트씩 처리 -> 4문자
  while (i + 3 <= inlen) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | (uint32_t)in[i+2];
    i += 3;
    out[o++] = B64URL_TBL[(v >> 18) & 0x3F];
    out[o++] = B64URL_TBL[(v >> 12) & 0x3F];
    out[o++] = B64URL_TBL[(v >>  6) & 0x3F];
    out[o++] = B64URL_TBL[(v >>  0) & 0x3F];
  }

  // 남은 1~2바이트 처리 (패딩 '=' 없이)
  size_t rem = inlen - i;
  if (rem == 1) {
    uint32_t v = ((uint32_t)in[i] << 16);
    out[o++] = B64URL_TBL[(v >> 18) & 0x3F];
    out[o++] = B64URL_TBL[(v >> 12) & 0x3F];
  } else if (rem == 2) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8);
    out[o++] = B64URL_TBL[(v >> 18) & 0x3F];
    out[o++] = B64URL_TBL[(v >> 12) & 0x3F];
    out[o++] = B64URL_TBL[(v >>  6) & 0x3F];
  }

  out[o] = '\0';
  return (int)o;
}
int wifi_pop_line(char *out, int out_sz) {
  if (out_sz <= 1) return 0;
  if (cb_data.length == 0) return 0;

  char *buf = (char *)cb_data.buf;
  uint16_t len = cb_data.length;

  char *end = (char *)memchr(buf, '\n', len);
  if (!end) return 0;

  int line_len = (int)(end - buf);      // '\n' 제외
  if (line_len >= out_sz) line_len = out_sz - 1;

  memcpy(out, buf, line_len);
  out[line_len] = 0;

  // CR 제거
  int L = (int)strlen(out);
  if (L > 0 && out[L-1] == '\r') out[L-1] = 0;

  // consume (개행 포함)
  int consumed = (int)((end + 1) - buf);
  int remain = (int)len - consumed;
  if (remain > 0) memmove(cb_data.buf, cb_data.buf + consumed, remain);
  cb_data.length = (uint16_t)((remain > 0) ? remain : 0);
  if (cb_data.length == 0) memset(cb_data.buf, 0, sizeof(cb_data.buf));

  // +IPD면 ':' 뒤만 payload
  if (strstr(out, "+IPD") != NULL) {
    char *colon = strchr(out, ':');
    if (colon && *(colon + 1)) {
      memmove(out, colon + 1, strlen(colon + 1) + 1);
    } else {
      out[0] = 0;
      return 0;
    }
  }
  return 1;
}
int starts_with(const char *s, const char *p) {
  return strncmp(s, p, strlen(p)) == 0;
}

// [KSH_PI]CHAL@12@1@NONCE@30
int parse_chal_line(char *line,
                           uint32_t *door_id, uint32_t *user_id,
                           char *nonce, int nonce_sz,
                           uint32_t *exp) {
  if (!starts_with(line, "[KSH_PI]CHAL@")) return 0;

  char *p = line + strlen("[KSH_PI]CHAL@");
  // door@user@nonce@exp
  char *tok[4] = {0};
  int n = 0;
  tok[n++] = p;
  for (; *p && n < 4; p++) {
    if (*p == '@') { *p = 0; tok[n++] = p + 1; }
  }
  if (n != 4) return 0;
  *user_id = (uint32_t)strtoul(tok[0], NULL, 10);
  *door_id = (uint32_t)strtoul(tok[1], NULL, 10);
  strncpy(nonce, tok[2], nonce_sz - 1);
  nonce[nonce_sz - 1] = 0;
  *exp = (uint32_t)strtoul(tok[3], NULL, 10);
  return 1;
}

// [KSH_PI]OK@OPEN@12@1
int parse_ok_open(char *line, uint32_t door_id, uint32_t user_id) {
  if (!starts_with(line, "[KSH_PI]OK@OPEN@")) return 0;
  char *p = line + strlen("[KSH_PI]OK@OPEN@");
  // door@user
  char *tok[2] = {0};
  int n = 0;
  tok[n++] = p;
  for (; *p && n < 2; p++) {
    if (*p == '@') { *p = 0; tok[n++] = p + 1; }
  }

  if (n != 2) return 0;

  uint32_t u = (uint32_t)strtoul(tok[0], NULL, 10);
  uint32_t d = (uint32_t)strtoul(tok[1], NULL, 10);
  return (d == door_id && u == user_id);
}

void pi_send_line(const char *line_with_nl) {
  // esp_send_data는 TCP로 그대로 전송함
  esp_send_data(line_with_nl);
}
static int is_noise_line(const char *s) {
  if (s[0] == 0) return 1;
  if (strstr(s, "Recv ") != NULL) return 1;
  if (strstr(s, "SEND OK") != NULL) return 1;
  if (strstr(s, "OK") != NULL && s[0] != '[') return 1; // 필요시 조정
  return 0;
}
int pi_wait_line(char *out, int out_sz, uint32_t timeout_ms) {
	uint32_t t0 = HAL_GetTick();
	  while ((HAL_GetTick() - t0) < timeout_ms) {
	    if (!wifi_pop_line(out, out_sz)) { continue; }
	    if (is_noise_line(out)) continue;
	    return 1;
	  }
	  return 0;
}
