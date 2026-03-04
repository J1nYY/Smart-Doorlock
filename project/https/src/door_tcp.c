// src/door_tcp.c
#include "mongoose.h"
#include "door_tcp.h"
#include "db.h"
#include "app.h"      // struct app { MYSQL *db; ... } 같은 것
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include "token.h"
// === 너 프로젝트에 이미 있어야 하는 함수들(없으면 선언/파일 위치에 맞게 include) ===
int db_create_door_nonce(MYSQL *db, long long door_id, const unsigned char nonce_hash[32], int ttl_sec);
int db_get_active_pubkey_spki(MYSQL *db, unsigned long long user_id,
                              unsigned char *out, size_t out_cap, size_t *out_len);

// nonce 생성(원문) + sha256(out_hash32)까지 만들어주는 유틸(너가 기존에 쓰던 것)
int gen_token(char *out_nonce_plain, size_t outcap, unsigned char out_hash32[32]);

// base64url/base64 디코드(너가 HTTPS에서 쓰던 것 재사용)
int b64url_or_b64_decode(const char *in, unsigned char *out, size_t outcap, size_t *outlen);

// SPKI DER public key로 서명 검증(HTTPS에서 쓰던 것 재사용)
int verify_signature_spki_der(const unsigned char *spki, size_t spki_len,
                              const unsigned char *msg, size_t msg_len,
                              const unsigned char *sig, size_t sig_len);

// === 설정 ===
#define KSH_PREFIX      "[KSH_PI]"
#define CH_TTL_SEC      30
#define EXP_FUTURE_MAX  300   // exp가 너무 미래면 거절(초). STM32/폰 시계 오차 고려

static void hex32(const unsigned char in[32], char out[65]) {
  static const char *h = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    out[i * 2] = h[(in[i] >> 4) & 0xF];
    out[i * 2 + 1] = h[in[i] & 0xF];
  }
  out[64] = 0;
}
static void broadcast(struct mg_mgr *mgr, struct mg_connection *skip,
                      const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  for (struct mg_connection *c = mgr->conns; c != NULL; c = c->next) {
    if (c == skip) continue;          // 요청자 제외하고 싶으면
    if (c->is_listening) continue;    // 리슨 소켓 제외
    mg_printf(c, "%s\n", buf);
  }
}
static void send_line(struct mg_connection *c, const char *fmt, ...) {
  char buf[1024];  // 메시지 길이에 맞게 조정
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  // 서버 콘솔에 출력
  fprintf(stdout, "[TCP OUT] %s\n", buf);
  // 실제 전송
  mg_printf(c, "%s\n", buf);
}

static int starts_with(const char *s, size_t n, const char *pfx) {
  size_t m = strlen(pfx);
  return n >= m && memcmp(s, pfx, m) == 0;
}

static int parse_u64_field(const char *s, size_t n, unsigned long long *out) {
  char buf[64];
  if (n == 0 || n >= sizeof(buf)) return 0;
  memcpy(buf, s, n);
  buf[n] = 0;
  char *end = NULL;
  unsigned long long v = strtoull(buf, &end, 10);
  if (end == buf) return 0;
  *out = v;
  return 1;
}

static int parse_i32_field(const char *s, size_t n, int *out) {
  char buf[64];
  if (n == 0 || n >= sizeof(buf)) return 0;
  memcpy(buf, s, n);
  buf[n] = 0;
  char *end = NULL;
  long v = strtol(buf, &end, 10);
  if (end == buf) return 0;
  *out = (int) v;
  return 1;
}

// line: "[KSH_PI]CH@12@1" or "[KSH_PI]SIGN@12@1@<sig>@<exp>"
static void handle_ksh_line(struct app_ctx *app, struct mg_connection *c,
                            const char *line, size_t len) {
  if (!starts_with(line, len, KSH_PREFIX)) return;

  const char *p = line + strlen(KSH_PREFIX);
  size_t rem = len - strlen(KSH_PREFIX);

  // cmd@...
  char cmd[16] = {0};
  size_t i = 0;
  while (i < rem && i < sizeof(cmd) - 1 && p[i] != '@') {
    cmd[i] = p[i];
    i++;
  }
  cmd[i] = 0;

  if (i >= rem || p[i] != '@') {
    send_line(c, KSH_PREFIX "ERR@BAD_FMT");
    return;
  }

  const char *args = p + i + 1;
  size_t args_len = rem - (i + 1);

  // ---------------- CH@user_id@door_id ----------------
  if (strcmp(cmd, "CH") == 0) {
  // args: "<email>@<door_id>"
  const char *a0 = args;
  const char *at1 = memchr(a0, '@', args_len);
  if (!at1) { send_line(c, KSH_PREFIX "ERR@CH@BAD_FMT"); return; }

  // email 파싱
  size_t email_len = (size_t)(at1 - a0);
  if (email_len == 0 || email_len >= 128) {  // 이메일 최대 길이 제한(필요하면 조정)
    send_line(c, KSH_PREFIX "ERR@CH@BAD_EMAIL");
    return;
  }
  char email[128];
  memcpy(email, a0, email_len);
  email[email_len] = 0;

  // door_id 파싱
  const char *a1 = at1 + 1;
  size_t a1_len = args_len - (size_t)(a1 - args);
  int door_id = 0;
  if (!parse_i32_field(a1, a1_len, &door_id) || door_id <= 0) {
    send_line(c, KSH_PREFIX "ERR@CH@BAD_DOOR");
    return;
  }

  // email -> user_id DB 조회
  unsigned long long user_id = 0;
  if (!db_get_user_id_by_email(app->db, email, &user_id) || user_id == 0) {
    send_line(c, KSH_PREFIX "ERR@CH@NO_USER");
    return;
  }

  // nonce 생성 + 해시 저장(door_nonces 테이블)
  char nonce_plain[128];
  unsigned char nonce_hash[32];

  if (!gen_token(nonce_plain, sizeof(nonce_plain), nonce_hash)) {
    send_line(c, KSH_PREFIX "ERR@CH@RAND_FAIL");
    return;
  }

  if (!db_create_door_nonce(app->db, (long long)door_id, nonce_hash, CH_TTL_SEC)) {
    send_line(c, KSH_PREFIX "ERR@CH@DB_FAIL");
    return;
  }

  // STM32가 이 nonce를 NFC로 폰에 전달
  // 응답 포맷: CHAL@user_id@door_id@nonce_plain@ttl
  
  send_line(c, KSH_PREFIX "CHAL@%llu@%d@%s@%d", user_id, door_id, nonce_plain, CH_TTL_SEC);
  return;
}

  // ------------- SIGN@user_id@door_id@SIGN@EXP -------------
  if (strcmp(cmd, "SIGN") == 0) {
    // user_id
    const char *a0 = args;
    const char *at1 = memchr(a0, '@', args_len);
    if (!at1) { send_line(c, KSH_PREFIX "ERR@SIGN@BAD_FMT"); return; }

    unsigned long long user_id = 0;
    if (!parse_u64_field(a0, (size_t)(at1 - a0), &user_id) || user_id == 0) {
      send_line(c, KSH_PREFIX "ERR@SIGN@BAD_USER");
      return;
    }

    // door_id
    const char *a1 = at1 + 1;
    size_t rem1 = args_len - (size_t)(a1 - args);
    const char *at2 = memchr(a1, '@', rem1);
    if (!at2) { send_line(c, KSH_PREFIX "ERR@SIGN@BAD_FMT"); return; }

    int door_id = 0;
    if (!parse_i32_field(a1, (size_t)(at2 - a1), &door_id) || door_id <= 0) {
      send_line(c, KSH_PREFIX "ERR@SIGN@BAD_DOOR");
      return;
    }
char name[128];
if (!db_get_name_by_user_id(app->db, user_id, name) || user_id == 0) {
    fprintf(stdout, "error");
    return;
  }
    // signature b64url
    const char *a2 = at2 + 1;
    size_t rem2 = args_len - (size_t)(a2 - args);
    const char *at3 = memchr(a2, '@', rem2);
    if (!at3) { send_line(c, KSH_PREFIX "ERR@SIGN@BAD_FMT"); return; }

    size_t sig_b64_len = (size_t)(at3 - a2);
    if (sig_b64_len == 0 || sig_b64_len >= 4096) {
      send_line(c, KSH_PREFIX "ERR@SIGN@BAD_SIG");
      return;
    }
    char sig_b64[4096];
    memcpy(sig_b64, a2, sig_b64_len);
    sig_b64[sig_b64_len] = 0;

    // exp
    const char *a3 = at3 + 1;
    size_t a3_len = args_len - (size_t)(a3 - args);
    if (a3_len == 0 || a3_len >= 64) { send_line(c, KSH_PREFIX "ERR@SIGN@BAD_EXP"); return; }
    char expbuf[64];
    memcpy(expbuf, a3, a3_len);
    expbuf[a3_len] = 0;

    time_t exp = (time_t) strtoll(expbuf, NULL, 10);
    time_t now = time(NULL);
    //if (exp < now) { send_line(c, KSH_PREFIX "DENY@EXP"); return; }
    //if (exp > now + EXP_FUTURE_MAX) { send_line(c, KSH_PREFIX "DENY@EXP_FAR"); return; }

    // === DB 트랜잭션 시작 ===
    if (mysql_query(app->db, "START TRANSACTION") != 0) {
      send_line(c, KSH_PREFIX "ERR@DB_TXN");
      return;
    }

    // 1) door_nonces에서 최신 nonce_hash 가져오기(FOR UPDATE)
    long long nonce_row_id = 0;
    unsigned char nonce_hash[32];
    const char *deny = NULL;

    if (!db_fetch_latest_door_nonce_for_update(app->db, (long long)door_id,
                                              &nonce_row_id, nonce_hash, &deny)) {
      mysql_query(app->db, "ROLLBACK");
      send_line(c, KSH_PREFIX "DENY@CH@%s", deny ? deny : "NO_NONCE");
      return;
    }

    // 2) user_id 공개키 로드
    unsigned char spki[2048];
    size_t spki_len = 0;
    if (!db_get_active_pubkey_spki(app->db, user_id, spki, sizeof(spki), &spki_len)) {
      mysql_query(app->db, "ROLLBACK");
      send_line(c, KSH_PREFIX "DENY@NO_KEY");
      return;
    }
    unsigned char h[32];
    sha256_bin(spki, spki_len, h);
    char hh[65]; hex32(h, hh);
    fprintf(stdout, " [DBG] spki_len=%zu spki_sha256=%s\n", spki_len, hh);
    // 3) signature decode
    unsigned char sig[1024];
    size_t sig_len = 0;
    if (!b64url_or_b64_decode(sig_b64, sig, sizeof(sig), &sig_len)) {
      mysql_query(app->db, "ROLLBACK");
      send_line(c, KSH_PREFIX "DENY@BAD_SIG_FMT");
      return;
    }

    // 4) verify message 구성(서버가 nonce_hash hex로 재구성)
    char nh_hex[65];
    hex32(nonce_hash, nh_hex);

    char msg[512];
    snprintf(msg, sizeof(msg),
             "KSH|OPEN|user_id=%llu|door_id=%d|nonce_hash=%s|exp=%lld",
             user_id, door_id, nh_hex, (long long)exp);

    int ok = verify_signature_spki_der(spki, spki_len,
                                       (unsigned char*)msg, strlen(msg),
                                       sig, sig_len);

    if (!ok) {
      // 서명 실패면 nonce를 소비하지 않고 롤백(동일 nonce로 재시도 가능)
      // 보안 강하게 가고 싶으면 여기서 used 처리해도 되지만 UX가 나빠짐
      mysql_query(app->db, "ROLLBACK");
      send_line(c, KSH_PREFIX "DENY@SIG_INVALID");
      return;
    }

    // 5) nonce used 처리
    const char *deny2 = NULL;
    if (!db_mark_door_nonce_used(app->db, nonce_row_id, &deny2)) {
      mysql_query(app->db, "ROLLBACK");
      send_line(c, KSH_PREFIX "DENY@CH@%s", deny2 ? deny2 : "NONCE_USED");
      return;
    }

    mysql_query(app->db, "COMMIT");

    // 6) 성공 응답 (STM32가 여기서 문을 여는 것으로 가정)
    send_line(c, KSH_PREFIX "OK@OPEN@%llu@%d", user_id, door_id);
    broadcast(c->mgr, c, "[KSH_BLE]DOOR@%d", door_id);
    broadcast(c->mgr, c, "[KSH_BLE]NAME@%s", name);
    return;
  }
  
  send_line(c, KSH_PREFIX "ERR@UNKNOWN");
}

// 라인 기반 프로토콜: '\n' 기준으로 처리
static void door_tcp_ev_handler(struct mg_connection *c, int ev, void *ev_data) {
  (void) ev_data;
  struct app_ctx *app = (struct app_ctx *) c->fn_data;

  if (ev == MG_EV_READ) {
    struct mg_iobuf *io = &c->recv;

    for (;;) {
      char *nl = memchr(io->buf, '\n', io->len);
      if (!nl) break;

      size_t linelen = (size_t)(nl - (char*)io->buf);
      // CR 제거
      if (linelen > 0 && ((char*)io->buf)[linelen - 1] == '\r') linelen--;

      handle_ksh_line(app, c, (const char*)io->buf, linelen);

      // 소비
      mg_iobuf_del(io, 0, (size_t)(nl - (char*)io->buf) + 1);
    }
  }
}

void door_tcp_init(struct mg_mgr *mgr, struct app_ctx *app, const char *listen_addr) {
  // 예: "tcp://0.0.0.0:5000"
  mg_listen(mgr, listen_addr, door_tcp_ev_handler, app);
}

