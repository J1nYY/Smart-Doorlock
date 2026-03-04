#include "mongoose.h"

#include <mysql.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// 일부 Mongoose 배포본은 mg_ntoa 프로토타입이 헤더에 없을 수 있어서 선언해둠
// (mongoose.c 안에 구현이 있으면 링크됨)

// ===================== 설정 =====================
static const char *DB_HOST = "127.0.0.1";
static const char *DB_USER = "dooruser";
static const char *DB_PASS = "doorpass";
static const char *DB_NAME = "doorlock";
static unsigned int DB_PORT = 3306;

static const char *LISTEN_ADDR = "https://0.0.0.0:8443";

static const char *TLS_CERT_PATH = "certs/cert.pem";
static const char *TLS_KEY_PATH  = "certs/key.pem";

// ===================== 전역 =====================
static struct mg_str s_cert = {0}, s_key = {0};
static MYSQL *g_db = NULL;

// ===================== SHA256 (OpenSSL 3 EVP) =====================
static void sha256_bin(const unsigned char *data, size_t len, unsigned char out[32]) {
  unsigned int outlen = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { memset(out, 0, 32); return; }

  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, data, len);
  EVP_DigestFinal_ex(ctx, out, &outlen);
  EVP_MD_CTX_free(ctx);
}

// ===================== base64url 토큰 생성 =====================
// 네 mongoose.h 기준: size_t mg_base64_encode(const unsigned char *p, size_t n, char *buf, size_t bufsize)
static void b64url_encode(const unsigned char *in, size_t inlen, char *out, size_t outsz) {
  if (outsz == 0) return;
  size_t n = mg_base64_encode(in, inlen, out, outsz);
  if (n >= outsz) n = outsz - 1;
  out[n] = '\0';

  for (size_t i = 0; out[i]; i++) {
    if (out[i] == '+') out[i] = '-';
    else if (out[i] == '/') out[i] = '_';
    else if (out[i] == '=') { out[i] = '\0'; break; }
  }
}

static int gen_token(char *token_out, size_t token_out_sz, unsigned char hash_out[32]) {
  unsigned char rnd[32];  // 256-bit
  if (RAND_bytes(rnd, (int) sizeof(rnd)) != 1) return 0;
  b64url_encode(rnd, sizeof(rnd), token_out, token_out_sz);
  if (token_out[0] == 0) return 0;
  sha256_bin((unsigned char *) token_out, strlen(token_out), hash_out);
  return 1;
}

// ===================== JSON helper (mg_json_get 기반) =====================
// mg_json_get: return offset, toklen으로 길이
static int json_get_token(struct mg_str json, const char *path, const char **tokptr, int *toklen) {
  int len = 0;
  int off = mg_json_get(json, path, &len);
  if (off < 0 || len <= 0) return 0;
  *tokptr = json.buf + off;
  *toklen = len;
  return 1;
}

static int json_get_string(struct mg_str json, const char *path, char *out, size_t outsz) {
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

static int json_get_int(struct mg_str json, const char *path, int *outv) {
  const char *p = NULL;
  int n = 0;
  if (!json_get_token(json, path, &p, &n)) return 0;

  char buf[32];
  int m = n < (int) sizeof(buf) - 1 ? n : (int) sizeof(buf) - 1;
  memcpy(buf, p, m);
  buf[m] = '\0';

  *outv = atoi(buf);
  return 1;
}

// ===================== DB =====================
static MYSQL *db_connect(void) {
  MYSQL *m = mysql_init(NULL);
  if (!m) return NULL;

  mysql_options(m, MYSQL_SET_CHARSET_NAME, "utf8mb4");
  if (!mysql_real_connect(m, DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT, NULL, 0)) {
    fprintf(stderr, "DB connect error: %s\n", mysql_error(m));
    mysql_close(m);
    return NULL;
  }
  return m;
}

static int db_check_session(MYSQL *db, const char *session_token, unsigned long long *user_id_out) {
  unsigned char h[32];
  sha256_bin((unsigned char *) session_token, strlen(session_token), h);

  const char *sql =
      "SELECT user_id FROM sessions "
      "WHERE session_hash=? AND expires_at > NOW()";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return 0;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  MYSQL_BIND in[1];
  memset(in, 0, sizeof(in));
  in[0].buffer_type = MYSQL_TYPE_BLOB;
  in[0].buffer = h;
  in[0].buffer_length = 32;
  if (mysql_stmt_bind_param(stmt, in) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  unsigned long long uid = 0;
  MYSQL_BIND out[1];
  memset(out, 0, sizeof(out));
  out[0].buffer_type = MYSQL_TYPE_LONGLONG;
  out[0].buffer = &uid;
  if (mysql_stmt_bind_result(stmt, out) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  int ok = 0;
  if (mysql_stmt_execute(stmt) == 0 && mysql_stmt_fetch(stmt) == 0) {
    *user_id_out = uid;
    ok = 1;
  }

  mysql_stmt_close(stmt);
  return ok;
}

static int db_issue_guest_token(MYSQL *db,
                               unsigned long long issuer_user_id,
                               const char *guest_label_or_null,
                               int valid_minutes,
                               int max_uses,
                               const unsigned char token_hash[32]) {
  const char *sql =
      "INSERT INTO door_tokens("
      " token_hash, token_type, issued_by_user_id, guest_label,"
      " valid_from, valid_until, max_uses, status"
      ") VALUES(?, 'GUEST', ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL ? MINUTE), ?, 'ACTIVE')";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return 0;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  MYSQL_BIND b[5];
  memset(b, 0, sizeof(b));

  b[0].buffer_type = MYSQL_TYPE_BLOB;
  b[0].buffer = (void *) token_hash;
  b[0].buffer_length = 32;

  b[1].buffer_type = MYSQL_TYPE_LONGLONG;
  b[1].buffer = &issuer_user_id;

  // my_bool은 mariadb가 typedef char my_bool; 로 정의
  unsigned long glen = guest_label_or_null ? (unsigned long) strlen(guest_label_or_null) : 0;
  my_bool is_null_label = guest_label_or_null ? 0 : 1;

  b[2].buffer_type = MYSQL_TYPE_STRING;
  b[2].buffer = (void *) guest_label_or_null;
  b[2].buffer_length = glen;
  b[2].length = &glen;
  b[2].is_null = &is_null_label;

  b[3].buffer_type = MYSQL_TYPE_LONG;
  b[3].buffer = &valid_minutes;

  b[4].buffer_type = MYSQL_TYPE_LONG;
  b[4].buffer = &max_uses;

  if (mysql_stmt_bind_param(stmt, b) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  int ok = (mysql_stmt_execute(stmt) == 0);
  mysql_stmt_close(stmt);
  return ok;
}

static void db_log(MYSQL *db, long long token_id_or_0, const char *result, const char *reason, const char *ip_or_null) {
  const char *sql =
      "INSERT INTO access_logs(token_id, result, reason, client_ip) VALUES(?, ?, ?, ?)";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(stmt);
    return;
  }

  MYSQL_BIND b[4];
  memset(b, 0, sizeof(b));

  my_bool is_null_token = (token_id_or_0 == 0) ? 1 : 0;
  b[0].buffer_type = MYSQL_TYPE_LONGLONG;
  b[0].buffer = &token_id_or_0;
  b[0].is_null = &is_null_token;

  unsigned long rlen = (unsigned long) strlen(result);
  b[1].buffer_type = MYSQL_TYPE_STRING;
  b[1].buffer = (void *) result;
  b[1].length = &rlen;

  unsigned long blen = (unsigned long) strlen(reason);
  b[2].buffer_type = MYSQL_TYPE_STRING;
  b[2].buffer = (void *) reason;
  b[2].length = &blen;

  my_bool is_null_ip = (ip_or_null == NULL) ? 1 : 0;
  unsigned long iplen = ip_or_null ? (unsigned long) strlen(ip_or_null) : 0;
  b[3].buffer_type = MYSQL_TYPE_STRING;
  b[3].buffer = (void *) ip_or_null;
  b[3].length = &iplen;
  b[3].is_null = &is_null_ip;

  mysql_stmt_bind_param(stmt, b);
  mysql_stmt_execute(stmt);
  mysql_stmt_close(stmt);
}

static int db_verify_and_consume(MYSQL *db, const unsigned char token_hash[32],
                                 long long *token_id_out, const char **deny_reason_out) {
  if (mysql_query(db, "START TRANSACTION") != 0) {
    *deny_reason_out = "DB_TXN";
    return 0;
  }

  const char *sql =
      "SELECT id, status, max_uses, use_count "
      "FROM door_tokens "
      "WHERE token_hash=? "
      "FOR UPDATE";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) goto deny_db;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long) strlen(sql)) != 0) goto deny_db_stmt;

  MYSQL_BIND in[1];
  memset(in, 0, sizeof(in));
  in[0].buffer_type = MYSQL_TYPE_BLOB;
  in[0].buffer = (void *) token_hash;
  in[0].buffer_length = 32;
  if (mysql_stmt_bind_param(stmt, in) != 0) goto deny_db_stmt;

  long long id = 0;
  char status[16] = {0};
  unsigned long status_len = 0;

  int max_uses = 0;
  int use_count = 0;
  my_bool max_is_null = 0;

  MYSQL_BIND out[4];
  memset(out, 0, sizeof(out));
  out[0].buffer_type = MYSQL_TYPE_LONGLONG; out[0].buffer = &id;
  out[1].buffer_type = MYSQL_TYPE_STRING;  out[1].buffer = status; out[1].buffer_length = sizeof(status); out[1].length = &status_len;
  out[2].buffer_type = MYSQL_TYPE_LONG;    out[2].buffer = &max_uses; out[2].is_null = &max_is_null;
  out[3].buffer_type = MYSQL_TYPE_LONG;    out[3].buffer = &use_count;

  if (mysql_stmt_bind_result(stmt, out) != 0) goto deny_db_stmt;
  if (mysql_stmt_execute(stmt) != 0) goto deny_db_stmt;

  if (mysql_stmt_fetch(stmt) != 0) {
    mysql_stmt_close(stmt);
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "NOT_FOUND";
    return 0;
  }
  mysql_stmt_close(stmt);

  status[status_len < sizeof(status) ? status_len : sizeof(status) - 1] = 0;
  if (strcmp(status, "ACTIVE") != 0) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "REVOKED";
    return 0;
  }

  if (!max_is_null && use_count >= max_uses) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "MAX_USES";
    return 0;
  }

  const char *usql =
      "UPDATE door_tokens "
      "SET use_count = use_count + 1, last_used_at = NOW() "
      "WHERE id=? "
      "  AND status='ACTIVE' "
      "  AND valid_from <= NOW() "
      "  AND (valid_until IS NULL OR valid_until >= NOW()) "
      "  AND (max_uses IS NULL OR use_count < max_uses)";

  MYSQL_STMT *u = mysql_stmt_init(db);
  if (!u) goto deny_db;
  if (mysql_stmt_prepare(u, usql, (unsigned long) strlen(usql)) != 0) goto deny_db_u;

  MYSQL_BIND ub[1];
  memset(ub, 0, sizeof(ub));
  ub[0].buffer_type = MYSQL_TYPE_LONGLONG;
  ub[0].buffer = &id;

  if (mysql_stmt_bind_param(u, ub) != 0) goto deny_db_u;
  if (mysql_stmt_execute(u) != 0) goto deny_db_u;

  my_ulonglong affected = mysql_stmt_affected_rows(u);
  mysql_stmt_close(u);

  if (affected != 1) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "EXPIRED_OR_INVALID";
    return 0;
  }

  mysql_query(db, "COMMIT");
  *token_id_out = id;
  return 1;

deny_db_u:
  mysql_stmt_close(u);
deny_db:
  mysql_query(db, "ROLLBACK");
  *deny_reason_out = "DB_ERROR";
  return 0;

deny_db_stmt:
  mysql_stmt_close(stmt);
  goto deny_db;
}

// ===================== HTTP helper =====================
static int get_bearer_token(struct mg_http_message *hm, char *out, size_t outsz) {
  struct mg_str *h = mg_http_get_header(hm, "Authorization");
  if (!h) return 0;

  const char prefix[] = "Bearer ";
  size_t plen = strlen(prefix);
  if (h->len <= plen) return 0;
  if (strncmp(h->buf, prefix, plen) != 0) return 0;

  size_t n = h->len - plen;
  if (n >= outsz) n = outsz - 1;
  memcpy(out, h->buf + plen, n);
  out[n] = '\0';
  return 1;
}

static void reply_json(struct mg_connection *c, int code, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  mg_printf(c, "HTTP/1.1 %d OK\r\nContent-Type: application/json\r\n\r\n", code);
  mg_vprintf(c, fmt, &ap);   // 너 헤더 기준: va_list* 필요
  va_end(ap);
}

// ===================== 이벤트 핸들러 =====================
static void fn(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_ACCEPT) {
    if (c->is_tls) {
      struct mg_tls_opts opts;
      memset(&opts, 0, sizeof(opts));
      opts.cert = s_cert;
      opts.key  = s_key;
      mg_tls_init(c, &opts);
    }
  } else if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

	const char *ip = NULL;   // 이 버전에선 ip 문자열 변환 함수가 없음 → 일단 NULL로 로그


    // POST /api/tokens/issue  (입주민 세션 필요)
    if (mg_match(hm->method, mg_str("POST"), NULL) &&
        mg_match(hm->uri, mg_str("/api/tokens/issue"), NULL)) {

      char session[256];
      if (!get_bearer_token(hm, session, sizeof(session))) {
        db_log(g_db, 0, "DENY", "NO_AUTH", ip);
        reply_json(c, 401, "{\"error\":\"NO_AUTH\"}\n");
        return;
      }

      unsigned long long uid = 0;
      if (!db_check_session(g_db, session, &uid)) {
        db_log(g_db, 0, "DENY", "BAD_SESSION", ip);
        reply_json(c, 401, "{\"error\":\"BAD_SESSION\"}\n");
        return;
      }

      char guest_label[128] = {0};
      int valid_minutes = 10;
      int max_uses = 1;

      (void) json_get_string(hm->body, "$.guest_label", guest_label, sizeof(guest_label));
      if (!json_get_int(hm->body, "$.valid_minutes", &valid_minutes)) valid_minutes = 10;
      if (!json_get_int(hm->body, "$.max_uses", &max_uses)) max_uses = 1;

      if (valid_minutes <= 0) valid_minutes = 10;
      if (valid_minutes > 24 * 60) valid_minutes = 24 * 60;  // 예시 제한
      if (max_uses <= 0) max_uses = 1;
      if (max_uses > 20) max_uses = 20;

      char token_plain[128];
      unsigned char token_hash[32];

      if (!gen_token(token_plain, sizeof(token_plain), token_hash)) {
        db_log(g_db, 0, "DENY", "RAND_FAIL", ip);
        reply_json(c, 500, "{\"error\":\"RAND_FAIL\"}\n");
        return;
      }

      const char *label_or_null = guest_label[0] ? guest_label : NULL;
      if (!db_issue_guest_token(g_db, uid, label_or_null, valid_minutes, max_uses, token_hash)) {
        db_log(g_db, 0, "DENY", "DB_FAIL", ip);
        reply_json(c, 500, "{\"error\":\"DB_FAIL\"}\n");
        return;
      }

      db_log(g_db, 0, "ALLOW", "ISSUED", ip);
      reply_json(c, 200,
                 "{\"token\":\"%s\",\"valid_minutes\":%d,\"max_uses\":%d}\n",
                 token_plain, valid_minutes, max_uses);
      return;
    }

    // POST /api/tokens/verify (게스트/입주민 공통: 토큰만)
    if (mg_match(hm->method, mg_str("POST"), NULL) &&
        mg_match(hm->uri, mg_str("/api/tokens/verify"), NULL)) {

      char token_plain[256] = {0};
      if (!json_get_string(hm->body, "$.token", token_plain, sizeof(token_plain))) {
        db_log(g_db, 0, "DENY", "NO_TOKEN", ip);
        reply_json(c, 400, "{\"error\":\"NO_TOKEN\"}\n");
        return;
      }

      unsigned char th[32];
      sha256_bin((unsigned char *) token_plain, strlen(token_plain), th);

      long long token_id = 0;
      const char *deny_reason = NULL;

      int ok = db_verify_and_consume(g_db, th, &token_id, &deny_reason);
      if (ok) {
        db_log(g_db, token_id, "ALLOW", "OK", ip);
        reply_json(c, 200, "{\"allow\":true}\n");
      } else {
        db_log(g_db, 0, "DENY", deny_reason ? deny_reason : "DENY", ip);
        reply_json(c, 403, "{\"allow\":false,\"reason\":\"%s\"}\n", deny_reason ? deny_reason : "DENY");
      }
      return;
    }

    reply_json(c, 404, "{\"error\":\"NOT_FOUND\"}\n");
  }
}

int main(void) {
  g_db = db_connect();
  if (!g_db) return 1;

  s_cert = mg_file_read(&mg_fs_posix, TLS_CERT_PATH);
  s_key  = mg_file_read(&mg_fs_posix, TLS_KEY_PATH);
  if (s_cert.len == 0 || s_key.len == 0) {
    fprintf(stderr, "Failed to read TLS cert/key: %s , %s\n", TLS_CERT_PATH, TLS_KEY_PATH);
    return 1;
  }

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);

  if (mg_http_listen(&mgr, LISTEN_ADDR, fn, NULL) == NULL) {
    fprintf(stderr, "Failed to listen on %s\n", LISTEN_ADDR);
    return 1;
  }

  printf("Listening on %s\n", LISTEN_ADDR);
  for (;;) mg_mgr_poll(&mgr, 50);

  mg_mgr_free(&mgr);
  mysql_close(g_db);
  mg_free((void *) s_cert.buf);
  mg_free((void *) s_key.buf);
  return 0;
}

