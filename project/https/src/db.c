#include "../include/db.h"
#include "../include/config.h"
#include "../include/token.h"

#include <stdio.h>
#include <string.h>

MYSQL *db_connect(void) {
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

int db_check_session(MYSQL *db, const char *session_token, unsigned long long *user_id_out) {
  unsigned char h[32];
  sha256_bin((unsigned char*)session_token, strlen(session_token), h);

  const char *sql =
      "SELECT user_id FROM sessions "
      "WHERE session_hash=? AND expires_at > NOW()";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return 0;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql)) != 0) { mysql_stmt_close(stmt); return 0; }

  MYSQL_BIND in[1]; memset(in, 0, sizeof(in));
  in[0].buffer_type = MYSQL_TYPE_BLOB;
  in[0].buffer = h;
  in[0].buffer_length = 32;
  if (mysql_stmt_bind_param(stmt, in) != 0) { mysql_stmt_close(stmt); return 0; }

  unsigned long long uid = 0;
  MYSQL_BIND out[1]; memset(out, 0, sizeof(out));
  out[0].buffer_type = MYSQL_TYPE_LONGLONG;
  out[0].buffer = &uid;
  if (mysql_stmt_bind_result(stmt, out) != 0) { mysql_stmt_close(stmt); return 0; }

  int ok = 0;
  if (mysql_stmt_execute(stmt) == 0 && mysql_stmt_fetch(stmt) == 0) {
    *user_id_out = uid;
    ok = 1;
  }
  mysql_stmt_close(stmt);
  return ok;
}

int db_issue_guest_token(MYSQL *db,
                         unsigned long long issuer_user_id,
                         const char *guest_label_or_null,
                         int valid_minutes,
                         int max_uses,
                         const char *ticket_id,
                         const unsigned char token_hash[32]) {
  const char *sql =
      "INSERT INTO door_tokens("
      " token_hash, token_type, issued_by_user_id, guest_label,"
      " valid_from, valid_until, max_uses, status, ticket_id"
      ") VALUES(?, 'GUEST', ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL ? MINUTE), ?, 'ACTIVE', ?)";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return 0;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql)) != 0) { mysql_stmt_close(stmt); return 0; }

  MYSQL_BIND b[6]; memset(b, 0, sizeof(b));

  b[0].buffer_type = MYSQL_TYPE_BLOB;
  b[0].buffer = (void*)token_hash;
  b[0].buffer_length = 32;

  b[1].buffer_type = MYSQL_TYPE_LONGLONG;
  b[1].buffer = &issuer_user_id;

  unsigned long glen = guest_label_or_null ? (unsigned long)strlen(guest_label_or_null) : 0;
  my_bool is_null_label = guest_label_or_null ? 0 : 1;
  b[2].buffer_type = MYSQL_TYPE_STRING;
  b[2].buffer = (void*)guest_label_or_null;
  b[2].buffer_length = glen;
  b[2].length = &glen;
  b[2].is_null = &is_null_label;

  b[3].buffer_type = MYSQL_TYPE_LONG;
  b[3].buffer = &valid_minutes;

  b[4].buffer_type = MYSQL_TYPE_LONG;
  b[4].buffer = &max_uses;

  unsigned long tlen = (unsigned long) strlen(ticket_id);
  b[5].buffer_type = MYSQL_TYPE_STRING;
  b[5].buffer = (void*)ticket_id;
  b[5].length = &tlen;

  if (mysql_stmt_bind_param(stmt, b) != 0) { mysql_stmt_close(stmt); return 0; }
  int ok = (mysql_stmt_execute(stmt) == 0);
  mysql_stmt_close(stmt);
  return ok;
}
// 1) ticket_id -> token_hash(32 bytes) 가져오기
int db_get_token_hash_by_ticket(MYSQL *db, const char *ticket_id, unsigned char out_hash[32]) {
  const char *sql = "SELECT token_hash FROM door_tokens WHERE ticket_id=?";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return 0;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  // input bind
  MYSQL_BIND in[1];
  memset(in, 0, sizeof(in));
  unsigned long tlen = (unsigned long) strlen(ticket_id);
  in[0].buffer_type = MYSQL_TYPE_STRING;
  in[0].buffer = (void *) ticket_id;
  in[0].length = &tlen;

  if (mysql_stmt_bind_param(stmt, in) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  // output bind
  MYSQL_BIND out[1];
  memset(out, 0, sizeof(out));
  unsigned long hlen = 0;
  my_bool is_null = 0;

  out[0].buffer_type = MYSQL_TYPE_BLOB;
  out[0].buffer = out_hash;
  out[0].buffer_length = 32;
  out[0].length = &hlen;
  out[0].is_null = &is_null;

  if (mysql_stmt_bind_result(stmt, out) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  int ok = 0;
  if (mysql_stmt_execute(stmt) == 0 && mysql_stmt_fetch(stmt) == 0) {
    if (!is_null && hlen == 32) ok = 1;
  }

  mysql_stmt_close(stmt);
  return ok;
}


// 2) 도어 nonce 저장(해시만) + TTL 설정
int db_create_door_nonce(MYSQL *db, long long door_id,
                         const unsigned char nonce_hash[32],
                         int ttl_seconds) {
  const char *sql =
      "INSERT INTO door_nonces(door_id, nonce_hash, expires_at) "
      "VALUES(?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return 0;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  MYSQL_BIND b[3];
  memset(b, 0, sizeof(b));

  b[0].buffer_type = MYSQL_TYPE_LONGLONG;
  b[0].buffer = &door_id;

  b[1].buffer_type = MYSQL_TYPE_BLOB;
  b[1].buffer = (void *) nonce_hash;
  b[1].buffer_length = 32;

  b[2].buffer_type = MYSQL_TYPE_LONG;
  b[2].buffer = &ttl_seconds;

  int ok = (mysql_stmt_bind_param(stmt, b) == 0 && mysql_stmt_execute(stmt) == 0);
  mysql_stmt_close(stmt);
  return ok;
}


// 3) token_hash + (door_id, nonce_hash) 둘 다 1회성 소비해야 allow
//    - 한 트랜잭션에서 처리
//    - nonce는 used_at, token은 use_count+1
//    - 둘 중 하나라도 실패하면 ROLLBACK
int db_consume_token_and_nonce(MYSQL *db,
                               const unsigned char token_hash[32],
                               long long door_id,
                               const unsigned char nonce_hash[32],
                               long long *token_id_out,
                               const char **deny_reason_out) {
  *token_id_out = 0;
  *deny_reason_out = "DENY";

  if (mysql_query(db, "START TRANSACTION") != 0) {
    *deny_reason_out = "DB_TXN";
    return 0;
  }

  // ====== (A) nonce row lock + 상태 판별 ======
  // used_at IS NULL / expires_at >= NOW() 를 bool로 받아서 파싱 없이 판별
  const char *sql_nonce =
      "SELECT id, (used_at IS NULL) AS unused, (expires_at >= NOW()) AS not_expired "
      "FROM door_nonces "
      "WHERE door_id=? AND nonce_hash=? "
      "FOR UPDATE";

  MYSQL_STMT *sn = mysql_stmt_init(db);
  if (!sn) goto deny_db;
  if (mysql_stmt_prepare(sn, sql_nonce, (unsigned long) strlen(sql_nonce)) != 0) goto deny_db_sn;

  MYSQL_BIND in_n[2];
  memset(in_n, 0, sizeof(in_n));
  in_n[0].buffer_type = MYSQL_TYPE_LONGLONG;
  in_n[0].buffer = &door_id;

  in_n[1].buffer_type = MYSQL_TYPE_BLOB;
  in_n[1].buffer = (void *) nonce_hash;
  in_n[1].buffer_length = 32;

  if (mysql_stmt_bind_param(sn, in_n) != 0) goto deny_db_sn;

  long long nonce_id = 0;
  int unused = 0;
  int not_expired = 0;

  MYSQL_BIND out_n[3];
  memset(out_n, 0, sizeof(out_n));
  out_n[0].buffer_type = MYSQL_TYPE_LONGLONG;
  out_n[0].buffer = &nonce_id;

  out_n[1].buffer_type = MYSQL_TYPE_LONG;
  out_n[1].buffer = &unused;

  out_n[2].buffer_type = MYSQL_TYPE_LONG;
  out_n[2].buffer = &not_expired;

  if (mysql_stmt_bind_result(sn, out_n) != 0) goto deny_db_sn;
  if (mysql_stmt_execute(sn) != 0) goto deny_db_sn;

  if (mysql_stmt_fetch(sn) != 0) {
    mysql_stmt_close(sn);
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "NONCE_NOT_FOUND";
    return 0;
  }
  mysql_stmt_close(sn);

  if (!unused) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "NONCE_USED";
    return 0;
  }
  if (!not_expired) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "NONCE_EXPIRED";
    return 0;
  }

  // ====== (B) token row lock + 기본 상태 확인 ======
  const char *sql_tok =
      "SELECT id, status, max_uses, use_count "
      "FROM door_tokens "
      "WHERE token_hash=? "
      "FOR UPDATE";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) goto deny_db;
  if (mysql_stmt_prepare(st, sql_tok, (unsigned long) strlen(sql_tok)) != 0) goto deny_db_st;

  MYSQL_BIND in_t[1];
  memset(in_t, 0, sizeof(in_t));
  in_t[0].buffer_type = MYSQL_TYPE_BLOB;
  in_t[0].buffer = (void *) token_hash;
  in_t[0].buffer_length = 32;

  if (mysql_stmt_bind_param(st, in_t) != 0) goto deny_db_st;

  long long token_id = 0;
  char status[16] = {0};
  unsigned long status_len = 0;
  int max_uses = 0;
  int use_count = 0;
  my_bool max_is_null = 0;

  MYSQL_BIND out_t[4];
  memset(out_t, 0, sizeof(out_t));
  out_t[0].buffer_type = MYSQL_TYPE_LONGLONG;
  out_t[0].buffer = &token_id;

  out_t[1].buffer_type = MYSQL_TYPE_STRING;
  out_t[1].buffer = status;
  out_t[1].buffer_length = sizeof(status);
  out_t[1].length = &status_len;

  out_t[2].buffer_type = MYSQL_TYPE_LONG;
  out_t[2].buffer = &max_uses;
  out_t[2].is_null = &max_is_null;

  out_t[3].buffer_type = MYSQL_TYPE_LONG;
  out_t[3].buffer = &use_count;

  if (mysql_stmt_bind_result(st, out_t) != 0) goto deny_db_st;
  if (mysql_stmt_execute(st) != 0) goto deny_db_st;

  if (mysql_stmt_fetch(st) != 0) {
    mysql_stmt_close(st);
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "TOKEN_NOT_FOUND";
    return 0;
  }
  mysql_stmt_close(st);

  status[status_len < sizeof(status) ? status_len : sizeof(status) - 1] = '\0';
  if (strcmp(status, "ACTIVE") != 0) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "TOKEN_REVOKED";
    return 0;
  }
  if (!max_is_null && use_count >= max_uses) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "TOKEN_MAX_USES";
    return 0;
  }

  // ====== (C) nonce consume ======
  const char *u_nonce =
      "UPDATE door_nonces SET used_at=NOW() "
      "WHERE id=? AND used_at IS NULL AND expires_at >= NOW()";

  MYSQL_STMT *un = mysql_stmt_init(db);
  if (!un) goto deny_db;
  if (mysql_stmt_prepare(un, u_nonce, (unsigned long) strlen(u_nonce)) != 0) goto deny_db_un;

  MYSQL_BIND ubn[1];
  memset(ubn, 0, sizeof(ubn));
  ubn[0].buffer_type = MYSQL_TYPE_LONGLONG;
  ubn[0].buffer = &nonce_id;

  if (mysql_stmt_bind_param(un, ubn) != 0) goto deny_db_un;
  if (mysql_stmt_execute(un) != 0) goto deny_db_un;

  my_ulonglong a1 = mysql_stmt_affected_rows(un);
  mysql_stmt_close(un);

  if (a1 != 1) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "NONCE_EXPIRED_OR_RACE";
    return 0;
  }

  // ====== (D) token consume (시간/횟수 조건까지 UPDATE에서 최종 검증) ======
  const char *u_tok =
      "UPDATE door_tokens "
      "SET use_count = use_count + 1, last_used_at = NOW() "
      "WHERE id=? "
      "  AND status='ACTIVE' "
      "  AND valid_from <= NOW() "
      "  AND (valid_until IS NULL OR valid_until >= NOW()) "
      "  AND (max_uses IS NULL OR use_count < max_uses)";

  MYSQL_STMT *ut = mysql_stmt_init(db);
  if (!ut) goto deny_db;
  if (mysql_stmt_prepare(ut, u_tok, (unsigned long) strlen(u_tok)) != 0) goto deny_db_ut;

  MYSQL_BIND ubt[1];
  memset(ubt, 0, sizeof(ubt));
  ubt[0].buffer_type = MYSQL_TYPE_LONGLONG;
  ubt[0].buffer = &token_id;

  if (mysql_stmt_bind_param(ut, ubt) != 0) goto deny_db_ut;
  if (mysql_stmt_execute(ut) != 0) goto deny_db_ut;

  my_ulonglong a2 = mysql_stmt_affected_rows(ut);
  mysql_stmt_close(ut);

  if (a2 != 1) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "TOKEN_EXPIRED_OR_RACE";
    return 0;
  }

  // ====== success ======
  if (mysql_query(db, "COMMIT") != 0) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "DB_COMMIT_FAIL";
    return 0;
  }

  *token_id_out = token_id;
  *deny_reason_out = "OK";
  return 1;

deny_db_un:
  mysql_stmt_close(un);
  goto deny_db;

deny_db_ut:
  mysql_stmt_close(ut);
  goto deny_db;

deny_db_sn:
  mysql_stmt_close(sn);
  goto deny_db;

deny_db_st:
  mysql_stmt_close(st);
  goto deny_db;

deny_db:
  mysql_query(db, "ROLLBACK");
  *deny_reason_out = "DB_ERROR";
  return 0;
}
void db_log(MYSQL *db, long long token_id_or_0, const char *result,
            const char *reason, const char *ip_or_null) {
  const char *sql =
      "INSERT INTO access_logs(token_id, result, reason, client_ip) VALUES(?, ?, ?, ?)";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql)) != 0) { mysql_stmt_close(stmt); return; }

  MYSQL_BIND b[4]; memset(b, 0, sizeof(b));

  my_bool is_null_token = (token_id_or_0 == 0) ? 1 : 0;
  b[0].buffer_type = MYSQL_TYPE_LONGLONG;
  b[0].buffer = &token_id_or_0;
  b[0].is_null = &is_null_token;

  unsigned long rlen = (unsigned long)strlen(result);
  b[1].buffer_type = MYSQL_TYPE_STRING;
  b[1].buffer = (void*)result;
  b[1].length = &rlen;

  unsigned long blen = (unsigned long)strlen(reason);
  b[2].buffer_type = MYSQL_TYPE_STRING;
  b[2].buffer = (void*)reason;
  b[2].length = &blen;

  my_bool is_null_ip = (ip_or_null == NULL) ? 1 : 0;
  unsigned long iplen = ip_or_null ? (unsigned long)strlen(ip_or_null) : 0;
  b[3].buffer_type = MYSQL_TYPE_STRING;
  b[3].buffer = (void*)ip_or_null;
  b[3].length = &iplen;
  b[3].is_null = &is_null_ip;

  mysql_stmt_bind_param(stmt, b);
  mysql_stmt_execute(stmt);
  mysql_stmt_close(stmt);
}

int db_verify_and_consume(MYSQL *db, const unsigned char token_hash[32],
                          long long *token_id_out, const char **deny_reason_out) {
  if (mysql_query(db, "START TRANSACTION") != 0) { *deny_reason_out = "DB_TXN"; return 0; }

  const char *sql =
      "SELECT id, status, max_uses, use_count "
      "FROM door_tokens "
      "WHERE token_hash=? "
      "FOR UPDATE";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) goto deny_db;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql)) != 0) goto deny_db_stmt;

  MYSQL_BIND in[1]; memset(in, 0, sizeof(in));
  in[0].buffer_type = MYSQL_TYPE_BLOB;
  in[0].buffer = (void*)token_hash;
  in[0].buffer_length = 32;
  if (mysql_stmt_bind_param(stmt, in) != 0) goto deny_db_stmt;

  long long id = 0;
  char status[16] = {0};
  unsigned long status_len = 0;
  int max_uses = 0;
  int use_count = 0;
  my_bool max_is_null = 0;

  MYSQL_BIND out[4]; memset(out, 0, sizeof(out));
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

  status[status_len < sizeof(status) ? status_len : sizeof(status)-1] = 0;
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
  if (mysql_stmt_prepare(u, usql, (unsigned long)strlen(usql)) != 0) goto deny_db_u;

  MYSQL_BIND ub[1]; memset(ub, 0, sizeof(ub));
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
int db_create_user(MYSQL *db,
                   const char *email,
                   const char *name,
                   const unsigned char pw_salt[16],
                   const unsigned char pw_hash[32],
                   int pw_iter) {
  const char *sql =
      "INSERT INTO users(email, name, pw_salt, pw_hash, pw_iter) "
      "VALUES(?, ?, ?, ?, ?)";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return 0;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  MYSQL_BIND b[5];
  memset(b, 0, sizeof(b));

  unsigned long elen = (unsigned long) strlen(email);
  b[0].buffer_type = MYSQL_TYPE_STRING;
  b[0].buffer = (void *) email;
  b[0].length = &elen;

  unsigned long nlen = (unsigned long) strlen(name);
  b[1].buffer_type = MYSQL_TYPE_STRING;
  b[1].buffer = (void *) name;
  b[1].length = &nlen;

  b[2].buffer_type = MYSQL_TYPE_BLOB;
  b[2].buffer = (void *) pw_salt;
  b[2].buffer_length = 16;

  b[3].buffer_type = MYSQL_TYPE_BLOB;
  b[3].buffer = (void *) pw_hash;
  b[3].buffer_length = 32;

  b[4].buffer_type = MYSQL_TYPE_LONG;
  b[4].buffer = &pw_iter;

  int ok = 0;
  if (mysql_stmt_bind_param(stmt, b) == 0 && mysql_stmt_execute(stmt) == 0) ok = 1;
  mysql_stmt_close(stmt);
  return ok;
}

int db_get_user_auth_by_email(MYSQL *db,
                              const char *email,
                              unsigned long long *user_id_out,
                              unsigned char pw_salt_out[16],
                              unsigned char pw_hash_out[32],
                              int *pw_iter_out) {
  const char *sql =
      "SELECT id, pw_salt, pw_hash, pw_iter "
      "FROM users WHERE email=?";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return 0;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  MYSQL_BIND in[1];
  memset(in, 0, sizeof(in));
  unsigned long elen = (unsigned long) strlen(email);
  in[0].buffer_type = MYSQL_TYPE_STRING;
  in[0].buffer = (void *) email;
  in[0].length = &elen;

  if (mysql_stmt_bind_param(stmt, in) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  unsigned long long uid = 0;
  unsigned long salt_len = 0, hash_len = 0;
  my_bool salt_is_null = 0, hash_is_null = 0;
  int iter = 0;

  MYSQL_BIND out[4];
  memset(out, 0, sizeof(out));
  out[0].buffer_type = MYSQL_TYPE_LONGLONG;
  out[0].buffer = &uid;

  out[1].buffer_type = MYSQL_TYPE_BLOB;
  out[1].buffer = pw_salt_out;
  out[1].buffer_length = 16;
  out[1].length = &salt_len;
  out[1].is_null = &salt_is_null;

  out[2].buffer_type = MYSQL_TYPE_BLOB;
  out[2].buffer = pw_hash_out;
  out[2].buffer_length = 32;
  out[2].length = &hash_len;
  out[2].is_null = &hash_is_null;

  out[3].buffer_type = MYSQL_TYPE_LONG;
  out[3].buffer = &iter;

  if (mysql_stmt_bind_result(stmt, out) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  int ok = 0;
  if (mysql_stmt_execute(stmt) == 0 && mysql_stmt_fetch(stmt) == 0) {
    if (!salt_is_null && !hash_is_null && salt_len == 16 && hash_len == 32) {
      *user_id_out = uid;
      *pw_iter_out = iter;
      ok = 1;
    }
  }

  mysql_stmt_close(stmt);
  return ok;
}

int db_create_session(MYSQL *db,
                      unsigned long long user_id,
                      const unsigned char session_hash[32],
                      int expires_seconds) {
  const char *sql =
      "INSERT INTO sessions(user_id, session_hash, expires_at) "
      "VALUES(?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))";

  MYSQL_STMT *stmt = mysql_stmt_init(db);
  if (!stmt) return 0;
  if (mysql_stmt_prepare(stmt, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(stmt);
    return 0;
  }

  MYSQL_BIND b[3];
  memset(b, 0, sizeof(b));

  b[0].buffer_type = MYSQL_TYPE_LONGLONG;
  b[0].buffer = &user_id;

  b[1].buffer_type = MYSQL_TYPE_BLOB;
  b[1].buffer = (void *) session_hash;
  b[1].buffer_length = 32;

  b[2].buffer_type = MYSQL_TYPE_LONG;
  b[2].buffer = &expires_seconds;

  int ok = 0;
  if (mysql_stmt_bind_param(stmt, b) == 0 && mysql_stmt_execute(stmt) == 0) ok = 1;
  mysql_stmt_close(stmt);
  return ok;
}
int db_get_user_role(MYSQL *db, unsigned long long user_id, char *role_out, size_t role_out_sz) {
  const char *sql = "SELECT role FROM users WHERE id=?";
  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) return 0;
  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) { mysql_stmt_close(st); return 0; }

  MYSQL_BIND in[1]; memset(in,0,sizeof(in));
  in[0].buffer_type = MYSQL_TYPE_LONGLONG; in[0].buffer = &user_id;
  if (mysql_stmt_bind_param(st, in) != 0) { mysql_stmt_close(st); return 0; }

  unsigned long rlen=0; my_bool is_null=0;
  MYSQL_BIND out[1]; memset(out,0,sizeof(out));
  out[0].buffer_type = MYSQL_TYPE_STRING;
  out[0].buffer = role_out;
  out[0].buffer_length = role_out_sz;
  out[0].length = &rlen;
  out[0].is_null = &is_null;

  if (mysql_stmt_bind_result(st, out) != 0) { mysql_stmt_close(st); return 0; }

  int ok = 0;
  if (mysql_stmt_execute(st)==0 && mysql_stmt_fetch(st)==0 && !is_null) {
    if (rlen >= role_out_sz) rlen = role_out_sz-1;
    role_out[rlen]=0;
    ok = 1;
  }
  mysql_stmt_close(st);
  return ok;
}
int db_get_active_pubkey_spki(MYSQL *db, unsigned long long user_id,
                              unsigned char *out, size_t out_cap, size_t *out_len) {
  const char *sql =
    "SELECT pubkey_spki FROM user_keys "
    "WHERE user_id=? AND is_active=1 "
    "ORDER BY id DESC LIMIT 1";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) return 0;
  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) { mysql_stmt_close(st); return 0; }

  MYSQL_BIND in[1]; memset(in,0,sizeof(in));
  in[0].buffer_type = MYSQL_TYPE_LONGLONG; in[0].buffer = &user_id;
  if (mysql_stmt_bind_param(st, in) != 0) { mysql_stmt_close(st); return 0; }

  unsigned long blen=0; my_bool is_null=0;
  MYSQL_BIND outb[1]; memset(outb,0,sizeof(outb));
  outb[0].buffer_type = MYSQL_TYPE_BLOB;
  outb[0].buffer = out;
  outb[0].buffer_length = out_cap;
  outb[0].length = &blen;
  outb[0].is_null = &is_null;

  if (mysql_stmt_bind_result(st, outb) != 0) { mysql_stmt_close(st); return 0; }

  int ok=0;
  if (mysql_stmt_execute(st)==0 && mysql_stmt_fetch(st)==0 && !is_null) {
    if (blen <= out_cap) { *out_len = blen; ok=1; }
  }
  mysql_stmt_close(st);
  return ok;
}
int db_consume_door_nonce(MYSQL *db, long long door_id,
                          const unsigned char nonce_hash[32],
                          const char **deny_reason_out) {
  if (mysql_query(db, "START TRANSACTION") != 0) { *deny_reason_out="DB_TXN"; return 0; }

  const char *sql =
    "UPDATE door_nonces "
    "SET used_at=NOW() "
    "WHERE door_id=? AND nonce_hash=? "
    "  AND used_at IS NULL "
    "  AND expires_at >= NOW()";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) goto deny_db;
  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) goto deny_db_st;

  MYSQL_BIND b[2]; memset(b,0,sizeof(b));
  b[0].buffer_type = MYSQL_TYPE_LONGLONG; b[0].buffer = &door_id;
  b[1].buffer_type = MYSQL_TYPE_BLOB;     b[1].buffer = (void*)nonce_hash; b[1].buffer_length = 32;

  if (mysql_stmt_bind_param(st, b) != 0) goto deny_db_st;
  if (mysql_stmt_execute(st) != 0) goto deny_db_st;

  my_ulonglong aff = mysql_stmt_affected_rows(st);
  mysql_stmt_close(st);

  if (aff != 1) {
    mysql_query(db, "ROLLBACK");
    *deny_reason_out = "NONCE_USED_OR_EXPIRED";
    return 0;
  }

  mysql_query(db, "COMMIT");
  return 1;

deny_db_st:
  mysql_stmt_close(st);
deny_db:
  mysql_query(db, "ROLLBACK");
  *deny_reason_out = "DB_ERROR";
  return 0;
}
int db_insert_user_key(MYSQL *db,
                       unsigned long long user_id,
                       const char *key_name_or_null,
                       const unsigned char *spki, size_t spki_len) {
  const char *sql =
    "INSERT INTO user_keys(user_id, key_name, pubkey_spki, is_active) "
    "VALUES(?, ?, ?, 1)";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) return 0;
  if (mysql_stmt_prepare(st, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(st); return 0;
  }

  MYSQL_BIND b[3]; memset(b,0,sizeof(b));
  b[0].buffer_type = MYSQL_TYPE_LONGLONG;
  b[0].buffer = &user_id;

  unsigned long nlen = key_name_or_null ? (unsigned long)strlen(key_name_or_null) : 0;
  my_bool name_is_null = key_name_or_null ? 0 : 1;
  b[1].buffer_type = MYSQL_TYPE_STRING;
  b[1].buffer = (void*)key_name_or_null;
  b[1].buffer_length = nlen;
  b[1].length = &nlen;
  b[1].is_null = &name_is_null;

  unsigned long blen = (unsigned long) spki_len;
  b[2].buffer_type = MYSQL_TYPE_BLOB;
  b[2].buffer = (void*)spki;
  b[2].buffer_length = blen;
  b[2].length = &blen;

  int ok = (mysql_stmt_bind_param(st, b) == 0 && mysql_stmt_execute(st) == 0);
  mysql_stmt_close(st);
  return ok;
}
int db_revoke_user_key(MYSQL *db,
                       unsigned long long user_id,
                       long long key_id) {
  const char *sql =
    "UPDATE user_keys SET is_active=0 "
    "WHERE id=? AND user_id=?";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) return 0;
  if (mysql_stmt_prepare(st, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(st); return 0;
  }

  MYSQL_BIND b[2]; memset(b,0,sizeof(b));
  b[0].buffer_type = MYSQL_TYPE_LONGLONG; b[0].buffer = &key_id;
  b[1].buffer_type = MYSQL_TYPE_LONGLONG; b[1].buffer = &user_id;

  if (mysql_stmt_bind_param(st, b) != 0) { mysql_stmt_close(st); return 0; }
  if (mysql_stmt_execute(st) != 0) { mysql_stmt_close(st); return 0; }

  my_ulonglong aff = mysql_stmt_affected_rows(st);
  mysql_stmt_close(st);
  return (aff == 1);
}
int db_list_user_keys_json(MYSQL *db,
                           unsigned long long user_id,
                           char *out, size_t outsz) {
  const char *sql =
    "SELECT id, IFNULL(key_name,''), is_active, created_at "
    "FROM user_keys WHERE user_id=? "
    "ORDER BY id DESC LIMIT 50";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) return 0;
  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) { mysql_stmt_close(st); return 0; }

  MYSQL_BIND in[1]; memset(in,0,sizeof(in));
  in[0].buffer_type = MYSQL_TYPE_LONGLONG; in[0].buffer = &user_id;
  if (mysql_stmt_bind_param(st, in) != 0) { mysql_stmt_close(st); return 0; }

  long long id=0;
  char name[128]={0}; unsigned long name_len=0;
  int active=0;
  char created[32]={0}; unsigned long created_len=0;

  MYSQL_BIND ob[4]; memset(ob,0,sizeof(ob));
  ob[0].buffer_type = MYSQL_TYPE_LONGLONG; ob[0].buffer = &id;
  ob[1].buffer_type = MYSQL_TYPE_STRING;   ob[1].buffer = name; ob[1].buffer_length = sizeof(name); ob[1].length=&name_len;
  ob[2].buffer_type = MYSQL_TYPE_LONG;     ob[2].buffer = &active;
  ob[3].buffer_type = MYSQL_TYPE_STRING;   ob[3].buffer = created; ob[3].buffer_length = sizeof(created); ob[3].length=&created_len;

  if (mysql_stmt_bind_result(st, ob) != 0) { mysql_stmt_close(st); return 0; }
  if (mysql_stmt_execute(st) != 0) { mysql_stmt_close(st); return 0; }

  size_t w = 0;
  w += snprintf(out+w, outsz-w, "{\"keys\":[");
  int first = 1;

  while (mysql_stmt_fetch(st) == 0) {
    name[name_len < sizeof(name) ? name_len : sizeof(name)-1] = 0;
    created[created_len < sizeof(created) ? created_len : sizeof(created)-1] = 0;

    w += snprintf(out+w, outsz-w, "%s{\"id\":%lld,\"name\":\"%s\",\"active\":%d,\"created_at\":\"%s\"}",
                  first ? "" : ",", id, name, active, created);
    first = 0;
    if (w + 128 >= outsz) break;
  }

  w += snprintf(out+w, outsz-w, "]}");
  mysql_stmt_close(st);
  return 1;
}
int db_delete_session(MYSQL *db, const char *session_token) {
  const char *sql = "DELETE FROM sessions WHERE session_hash = UNHEX(SHA2(?,256))";
  // 만약 sessions에 session_hash(32B)로 저장하는 구조라면 위처럼.
  // 만약 session_token 원문/해시 저장 방식이 다르면 WHERE 절만 맞춰주면 됨.
  // (너 코드에서 session_hash를 저장했다면 이게 맞고, token을 직접 저장했다면 token=?로 바꾸면 됨)

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) return 0;
  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) { mysql_stmt_close(st); return 0; }

  MYSQL_BIND b[1]; memset(b,0,sizeof(b));
  unsigned long len = (unsigned long)strlen(session_token);
  b[0].buffer_type = MYSQL_TYPE_STRING;
  b[0].buffer = (void*)session_token;
  b[0].length = &len;

  int ok = 0;
  if (mysql_stmt_bind_param(st, b) == 0 && mysql_stmt_execute(st) == 0) ok = 1;
  mysql_stmt_close(st);
  return ok;
}

int db_delete_all_sessions(MYSQL *db, unsigned long long user_id, int *deleted_out) {
  const char *sql = "DELETE FROM sessions WHERE user_id=?";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) return 0;
  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) { mysql_stmt_close(st); return 0; }

  MYSQL_BIND b[1]; memset(b,0,sizeof(b));
  b[0].buffer_type = MYSQL_TYPE_LONGLONG;
  b[0].buffer = &user_id;

  if (mysql_stmt_bind_param(st, b) != 0) { mysql_stmt_close(st); return 0; }
  if (mysql_stmt_execute(st) != 0) { mysql_stmt_close(st); return 0; }

  my_ulonglong aff = mysql_stmt_affected_rows(st);
  mysql_stmt_close(st);
  if (deleted_out) *deleted_out = (int)aff;
  return 1;
}
int db_fetch_latest_door_nonce_for_update(MYSQL *db, long long door_id,
                                         long long *nonce_row_id_out,
                                         unsigned char out_nonce_hash[32],
                                         const char **deny_reason_out) {
  // 트랜잭션 시작은 호출자(상위 로직)에서 하도록 할 수도 있지만,
  // 여기서는 간단히 이 함수가 START TRANSACTION을 포함하지 않고,
  // "FOR UPDATE"만 수행하게 설계해도 됨.
  const char *sql =
    "SELECT id, nonce_hash "
    "FROM door_nonces "
    "WHERE door_id=? AND used_at IS NULL AND expires_at >= NOW() "
    "ORDER BY id DESC LIMIT 1 FOR UPDATE";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) { *deny_reason_out="DB_STMT"; return 0; }
  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) {
    mysql_stmt_close(st); *deny_reason_out="DB_PREP"; return 0;
  }

  MYSQL_BIND in[1]; memset(in,0,sizeof(in));
  in[0].buffer_type = MYSQL_TYPE_LONGLONG;
  in[0].buffer = &door_id;
  if (mysql_stmt_bind_param(st, in) != 0) {
    mysql_stmt_close(st); *deny_reason_out="DB_BIND"; return 0;
  }

  long long rid = 0;
  unsigned long hlen = 0; my_bool is_null = 0;
  MYSQL_BIND out[2]; memset(out,0,sizeof(out));
  out[0].buffer_type = MYSQL_TYPE_LONGLONG; out[0].buffer = &rid;
  out[1].buffer_type = MYSQL_TYPE_BLOB;     out[1].buffer = out_nonce_hash;
  out[1].buffer_length = 32; out[1].length = &hlen; out[1].is_null = &is_null;

  if (mysql_stmt_bind_result(st, out) != 0) {
    mysql_stmt_close(st); *deny_reason_out="DB_BINDR"; return 0;
  }

  if (mysql_stmt_execute(st) != 0) {
    mysql_stmt_close(st); *deny_reason_out="DB_EXEC"; return 0;
  }

  if (mysql_stmt_fetch(st) != 0 || is_null || hlen != 32) {
    mysql_stmt_close(st);
    *deny_reason_out = "NO_NONCE";
    return 0;
  }

  mysql_stmt_close(st);
  *nonce_row_id_out = rid;
  return 1;
}

int db_mark_door_nonce_used(MYSQL *db, long long nonce_row_id,
                            const char **deny_reason_out) {
  const char *sql =
    "UPDATE door_nonces SET used_at=NOW() "
    "WHERE id=? AND used_at IS NULL AND expires_at >= NOW()";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) { *deny_reason_out="DB_STMT"; return 0; }
  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) {
    mysql_stmt_close(st); *deny_reason_out="DB_PREP"; return 0;
  }

  MYSQL_BIND in[1]; memset(in,0,sizeof(in));
  in[0].buffer_type = MYSQL_TYPE_LONGLONG;
  in[0].buffer = &nonce_row_id;

  if (mysql_stmt_bind_param(st, in) != 0) {
    mysql_stmt_close(st); *deny_reason_out="DB_BIND"; return 0;
  }
  if (mysql_stmt_execute(st) != 0) {
    mysql_stmt_close(st); *deny_reason_out="DB_EXEC"; return 0;
  }

  my_ulonglong aff = mysql_stmt_affected_rows(st);
  mysql_stmt_close(st);

  if (aff != 1) { *deny_reason_out="NONCE_RACE_OR_EXPIRED"; return 0; }
  return 1;
}
int db_get_user_id_by_email(MYSQL *db, const char *email, unsigned long long *user_id_out) {
  const char *sql = "SELECT id FROM users WHERE email=? LIMIT 1";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) return 0;
  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) {
    mysql_stmt_close(st);
    return 0;
  }

  MYSQL_BIND in[1]; memset(in, 0, sizeof(in));
  unsigned long elen = (unsigned long) strlen(email);
  in[0].buffer_type = MYSQL_TYPE_STRING;
  in[0].buffer = (void*) email;
  in[0].length = &elen;

  if (mysql_stmt_bind_param(st, in) != 0) { mysql_stmt_close(st); return 0; }

  unsigned long long uid = 0;
  my_bool is_null = 0;
  MYSQL_BIND out[1]; memset(out, 0, sizeof(out));
  out[0].buffer_type = MYSQL_TYPE_LONGLONG;
  out[0].buffer = &uid;
  out[0].is_null = &is_null;

  if (mysql_stmt_bind_result(st, out) != 0) { mysql_stmt_close(st); return 0; }
  if (mysql_stmt_execute(st) != 0) { mysql_stmt_close(st); return 0; }

  int ok = 0;
  if (mysql_stmt_fetch(st) == 0 && !is_null) {
    *user_id_out = uid;
    ok = 1;
  }
  mysql_stmt_close(st);
  return ok;
}
int db_get_name_by_user_id(MYSQL *db,
                           unsigned long long user_id,
                           char *name_out) {
  const char *sql = "SELECT name FROM users WHERE id=? LIMIT 1";

  MYSQL_STMT *st = mysql_stmt_init(db);
  if (!st) return 0;

  if (mysql_stmt_prepare(st, sql, (unsigned long) strlen(sql)) != 0) {
    mysql_stmt_close(st);
    return 0;
  }

  // ---- input bind: id ----
  MYSQL_BIND in[1];
  memset(in, 0, sizeof(in));

  in[0].buffer_type = MYSQL_TYPE_LONGLONG;
  in[0].buffer = (void *) &user_id;
  in[0].is_unsigned = 1;

  if (mysql_stmt_bind_param(st, in) != 0) {
    mysql_stmt_close(st);
    return 0;
  }

  // ---- output bind: name ----
  name_out[0] = '\0';

  MYSQL_BIND out[1];
  memset(out, 0, sizeof(out));

  unsigned long out_len = 0;
  my_bool is_null = 0;

  out[0].buffer_type   = MYSQL_TYPE_STRING;
  out[0].buffer        = (void *) name_out;
  out[0].buffer_length = (unsigned long) (100 + 1);
  out[0].length        = &out_len;
  out[0].is_null       = &is_null;

  if (mysql_stmt_bind_result(st, out) != 0) { mysql_stmt_close(st); return 0; }
  if (mysql_stmt_execute(st) != 0)          { mysql_stmt_close(st); return 0; }

  int ok = 0;
  int rc = mysql_stmt_fetch(st);

  if ((rc == 0 || rc == MYSQL_DATA_TRUNCATED) && !is_null) {
    // out_len 기준으로 널 종료 보장
    if (out_len > 100) out_len = 100;
    name_out[out_len] = '\0';
    ok = 1;
  }

  mysql_stmt_close(st);
  return ok;
}
