#include "../include/json_utils.h"
#include <string.h>
#include <stdlib.h>

static int json_get_token(struct mg_str json, const char *path, const char **tokptr, int *toklen) {
  int len = 0;
  int off = mg_json_get(json, path, &len); // return offset, len via toklen
  if (off < 0 || len <= 0) return 0;
  *tokptr = json.buf + off;
  *toklen = len;
  return 1;
}

// 매우 단순한 문자열 추출(따옴표 제거 + 기본 escape 일부 처리)
int json_get_string(struct mg_str json, const char *path, char *out, size_t outsz) {
  const char *p = NULL;
  int n = 0;
  if (!json_get_token(json, path, &p, &n)) return 0;

  if (n >= 2 && p[0] == '"' && p[n - 1] == '"') { p++; n -= 2; }

  size_t w = 0;
  for (int i = 0; i < n && w + 1 < outsz; i++) {
    char c = p[i];
    if (c == '\\' && i + 1 < n) {
      char d = p[i + 1];
      if (d == '"' || d == '\\' || d == '/') { out[w++] = d; i++; continue; }
      if (d == 'n') { out[w++] = '\n'; i++; continue; }
      if (d == 't') { out[w++] = '\t'; i++; continue; }
      if (d == 'r') { out[w++] = '\r'; i++; continue; }
      out[w++] = d; i++; continue;
    }
    out[w++] = c;
  }
  out[w] = '\0';
  return (w > 0);
}

int json_get_int(struct mg_str json, const char *path, int *outv) {
  const char *p = NULL;
  int n = 0;
  if (!json_get_token(json, path, &p, &n)) return 0;

  char buf[32];
  int m = n < (int)sizeof(buf) - 1 ? n : (int)sizeof(buf) - 1;
  memcpy(buf, p, m);
  buf[m] = '\0';
  *outv = atoi(buf);
  return 1;
}

