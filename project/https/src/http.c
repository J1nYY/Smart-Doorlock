#include "../include/http.h"
#include "../include/db.h"
#include "../include/json_utils.h"
#include "../include/token.h"
#include "../include/config.h"
#include "../include/auth.h"
#include <openssl/rand.h>


#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
// ====== 추가: app ctx 전역 보관 ======
static struct app_ctx *s_app = NULL;

void http_set_app_ctx(struct app_ctx *app) {
  s_app = app;
}
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

static void reply_html(struct mg_connection *c, int code, const char *html) {
  mg_http_reply(c, code,
    "Content-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n",
    "%s", html);
}
static void reply_json(struct mg_connection *c, int code, const char *fmt, ...) {
  char buf[2048];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  mg_http_reply(c, code,
                "Content-Type: application/json\r\n"
                "Connection: close\r\n",
                "%s", buf);
}
//spkiDER
static int b64url_decode(const char *in, unsigned char *out, size_t outcap, size_t *outlen) {
  char tmp[2048];
  size_t inlen = strlen(in);
  if (inlen == 0 || inlen >= sizeof(tmp)) return 0;

  // base64url -> base64
  memcpy(tmp, in, inlen);
  tmp[inlen] = '\0';
  for (size_t i = 0; i < inlen; i++) {
    if (tmp[i] == '-') tmp[i] = '+';
    else if (tmp[i] == '_') tmp[i] = '/';
  }

  // '=' padding 복구
  size_t pad_added = 0;
  while ((inlen + pad_added) % 4 != 0) {
    tmp[inlen + pad_added] = '=';
    pad_added++;
    if (inlen + pad_added + 1 >= sizeof(tmp)) return 0;
  }
  tmp[inlen + pad_added] = '\0';

  int dec = EVP_DecodeBlock(out, (unsigned char *) tmp, (int) (inlen + pad_added));
  if (dec < 0) return 0;

  // ★ 중요: EVP_DecodeBlock은 padding 고려 없이 길이를 줄 때가 있어서,
  // 우리가 추가한 '=' 개수만큼 실제 길이를 빼준다 (1개면 -1, 2개면 -2)
  size_t real = (size_t) dec;
  if (pad_added > 0) {
    if (real < pad_added) return 0;
    real -= pad_added;
  }

  if (real > outcap) return 0;
  *outlen = real;
  return 1;
}
static int b64url_or_b64_decode(const char *in, unsigned char *out, size_t outcap, size_t *outlen) {
  // base64url(-,_) / base64(+ ,/) 둘 다 허용
  char tmp[4096];
  size_t n = strlen(in);
  if (n >= sizeof(tmp)) return 0;

  memcpy(tmp, in, n);
  tmp[n]=0;

  for (size_t i=0;i<n;i++){
    if (tmp[i]=='-') tmp[i]='+';
    else if (tmp[i]=='_') tmp[i]='/';
  }
  while (n % 4 != 0) tmp[n++]='=';
  tmp[n]=0;

  int dec = EVP_DecodeBlock(out, (unsigned char*)tmp, (int)n);
  if (dec < 0) return 0;
  if ((size_t)dec > outcap) return 0;

  // EVP_DecodeBlock은 패딩까지 포함한 길이를 반환할 수 있어 trailing '='에 따른 실제 길이 조정
  // '=' 개수만큼 줄여줌
  size_t pad = 0;
  if (n >= 2 && tmp[n-1]=='=') pad++;
  if (n >= 2 && tmp[n-2]=='=') pad++;
  *outlen = (size_t)dec - pad;
  return 1;
}
static int verify_signature_spki_der(const unsigned char *spki, size_t spki_len,
                                     const unsigned char *msg, size_t msg_len,
                                     const unsigned char *sig, size_t sig_len) {
  const unsigned char *p = spki;
  EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, (long)spki_len);
  if (!pub) return 0;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { EVP_PKEY_free(pub); return 0; }

  int ok = 0;
  int type = EVP_PKEY_base_id(pub);

  if (type == EVP_PKEY_ED25519) {
    // Ed25519는 digest 없이 원문 검증
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pub) == 1 &&
        EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1) ok = 1;
  } else {
    // EC/ECDSA 등: SHA-256 digest 사용(안드로이드 keystore 기본과 잘 맞음)
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) == 1 &&
        EVP_DigestVerifyUpdate(ctx, msg, msg_len) == 1 &&
        EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) ok = 1;
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pub);
  return ok;
}
//event handler(api)
void http_ev_handler(struct mg_connection *c, int ev, void *ev_data) {
  (void) c;  // unused 경고 방지용(필요하면 지워도 됨)
  if (s_app == NULL) return;         // 안전장치
  struct app_ctx *app = s_app;       // 기존 fn_data 대신 전역 사용

  if (ev == MG_EV_ACCEPT) {
    if (c->is_tls) {
      struct mg_tls_opts opts;
      memset(&opts, 0, sizeof(opts));
      opts.cert = app->cert;
      opts.key  = app->key;
      mg_tls_init(c, &opts);
    }
    return;
  }

  if (ev != MG_EV_HTTP_MSG) return;

  struct mg_http_message *hm = (struct mg_http_message *) ev_data;

  // mg_ntoa가 없는 버전이라 IP는 기록하지 않음
  const char *ip = NULL;

  // POST /api/tokens/issue
  if (mg_match(hm->method, mg_str("POST"), NULL) &&
      mg_match(hm->uri, mg_str("/api/tokens/issue"), NULL)) {

    char session[256];
    if (!get_bearer_token(hm, session, sizeof(session))) {
      db_log(app->db, 0, "DENY", "NO_AUTH", ip);
      reply_json(c, 401, "{\"error\":\"NO_AUTH\"}\n");
      return;
    }

    unsigned long long uid = 0;
    if (!db_check_session(app->db, session, &uid)) {
      db_log(app->db, 0, "DENY", "BAD_SESSION", ip);
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
    if (valid_minutes > 24 * 60) valid_minutes = 24 * 60;
    if (max_uses <= 0) max_uses = 1;
    if (max_uses > 20) max_uses = 20;

    char ticket_id[64];
    if (!gen_ticket_id(ticket_id, sizeof(ticket_id))) {
      reply_json(c, 500, "{\"error\":\"RAND_FAIL\"}\n");
      return;
    }

    char token_plain[128];
    unsigned char token_hash[32];
    if (!gen_token(token_plain, sizeof(token_plain), token_hash)) {
      reply_json(c, 500, "{\"error\":\"RAND_FAIL\"}\n");
      return;
    }

    const char *label_or_null = guest_label[0] ? guest_label : NULL;
    if (!db_issue_guest_token(app->db, uid, label_or_null, valid_minutes, max_uses,ticket_id, token_hash)) {
      db_log(app->db, 0, "DENY", "DB_FAIL", ip);
      reply_json(c, 500, "{\"error\":\"DB_FAIL\"}\n");
      return;
    }

    db_log(app->db, 0, "ALLOW", "ISSUED", ip);
    reply_json(c, 200,
    "{\"ticket\":\"%s\",\"visit_url\":\"%s/v?t=%s\",\"valid_minutes\":%d,\"max_uses\":%d}\n",
    ticket_id, PUBLIC_BASE_URL, ticket_id, valid_minutes, max_uses);
    return;
  }
  // POST /api/resident/open
if (mg_match(hm->method, mg_str("POST"), NULL) &&
    mg_match(hm->uri, mg_str("/api/resident/open"), NULL)) {

  int door_id_i=0;
  int user_id_i=0;
  char door_nonce_plain[256]={0};
  char sig_b64u[2048]={0};

  if (!json_get_int(hm->body, "$.door_id", &door_id_i) ||
      !json_get_int(hm->body, "$.user_id", &user_id_i) ||
      !json_get_string(hm->body, "$.door_nonce", door_nonce_plain, sizeof(door_nonce_plain)) ||
      !json_get_string(hm->body, "$.signature", sig_b64u, sizeof(sig_b64u))) {
    reply_json(c, 400, "{\"error\":\"BAD_REQUEST\"}\n");
    return;
  }

  // 1) role 체크
  char role[16]={0};
  if (!db_get_user_role(app->db, (unsigned long long)user_id_i, role, sizeof(role))) {
    reply_json(c, 403, "{\"allow\":false,\"reason\":\"NO_USER\"}\n");
    return;
  }
  if (strcmp(role,"RESIDENT")!=0 && strcmp(role,"STAFF")!=0 && strcmp(role,"ADMIN")!=0) {
    reply_json(c, 403, "{\"allow\":false,\"reason\":\"ROLE_DENY\"}\n");
    return;
  }

  // 2) 공개키 로드
  unsigned char spki[2048];
  size_t spki_len=0;
  if (!db_get_active_pubkey_spki(app->db, (unsigned long long)user_id_i, spki, sizeof(spki), &spki_len)) {
    reply_json(c, 403, "{\"allow\":false,\"reason\":\"NO_KEY\"}\n");
    return;
  }

  // 3) signature 디코드
  unsigned char sig[1024];
  size_t sig_len=0;
  if (!b64url_decode(sig_b64u, sig, sizeof(sig), &sig_len)) {
    reply_json(c, 400, "{\"allow\":false,\"reason\":\"BAD_SIG_FORMAT\"}\n");
    return;
  }

  // 4) 서명 메시지 생성 + verify
  char msg[512];
  snprintf(msg, sizeof(msg),
           "OPEN|door_id=%d|nonce=%s|user_id=%d",
           door_id_i, door_nonce_plain, user_id_i);

  if (!verify_signature_spki_der(spki, spki_len,
                                 (unsigned char*)msg, strlen(msg),
                                 sig, sig_len)) {
    reply_json(c, 403, "{\"allow\":false,\"reason\":\"SIG_INVALID\"}\n");
    return;
  }

  // 5) nonce 소비(1회성)
  unsigned char nonce_hash[32];
  sha256_bin((unsigned char*)door_nonce_plain, strlen(door_nonce_plain), nonce_hash);

  const char *deny=NULL;
  if (!db_consume_door_nonce(app->db, (long long)door_id_i, nonce_hash, &deny)) {
    reply_json(c, 403, "{\"allow\":false,\"reason\":\"%s\"}\n", deny?deny:"NONCE_DENY");
    return;
  }

  // 6) 실제 문 열기(여기서 도어 컨트롤러로 신호)
  // TODO: gpio/ble/serial open
  reply_json(c, 200, "{\"allow\":true}\n");
  return;
}

  // POST /api/tokens/verify
  if (mg_match(hm->method, mg_str("POST"), NULL) &&
      mg_match(hm->uri, mg_str("/api/tokens/verify"), NULL)) {

    char token_plain[256] = {0};
    if (!json_get_string(hm->body, "$.token", token_plain, sizeof(token_plain))) {
      db_log(app->db, 0, "DENY", "NO_TOKEN", ip);
      reply_json(c, 400, "{\"error\":\"NO_TOKEN\"}\n");
      return;
    }

    unsigned char th[32];
    sha256_bin((unsigned char*)token_plain, strlen(token_plain), th);

    long long token_id = 0;
    const char *deny_reason = NULL;
    int ok = db_verify_and_consume(app->db, th, &token_id, &deny_reason);

    if (ok) {
      db_log(app->db, token_id, "ALLOW", "OK", ip);
      reply_json(c, 200, "{\"allow\":true}\n");
    } else {
      db_log(app->db, 0, "DENY", deny_reason ? deny_reason : "DENY", ip);
      reply_json(c, 403, "{\"allow\":false,\"reason\":\"%s\"}\n",
                 deny_reason ? deny_reason : "DENY");
    }
    return;
  }
  // POST /api/signup  { "email": "...", "name": "...", "password": "..." }
  if (mg_match(hm->method, mg_str("POST"), NULL) &&
      mg_match(hm->uri, mg_str("/api/signup"), NULL)) {

    char email[256] = {0};
    char name[128] = {0};
    char password[256] = {0};

    if (!json_get_string(hm->body, "$.email", email, sizeof(email)) ||
        !json_get_string(hm->body, "$.password", password, sizeof(password))) {
      db_log(app->db, 0, "DENY", "BAD_REQ", ip);
      reply_json(c, 400, "{\"error\":\"BAD_REQUEST\"}\n");
      return;
    }
    if (!json_get_string(hm->body, "$.name", name, sizeof(name))) {
      // name 없으면 email을 name으로 쓰자(최소 구현)
      strncpy(name, email, sizeof(name) - 1);
    }

    unsigned char salt[16];
    if (RAND_bytes(salt, (int) sizeof(salt)) != 1) {
      reply_json(c, 500, "{\"error\":\"RAND_FAIL\"}\n");
      return;
    }

    int iter = 120000;  // 기본값
    unsigned char pw_hash[32];
    if (!auth_pbkdf2_sha256(password, salt, sizeof(salt), iter, pw_hash)) {
      reply_json(c, 500, "{\"error\":\"HASH_FAIL\"}\n");
      return;
    }

    // 같은 이메일이면 UNIQUE로 실패(여기선 단순히 DB_FAIL로 처리)
    if (!db_create_user(app->db, email, name, salt, pw_hash, iter)) {
      reply_json(c, 409, "{\"error\":\"USER_EXISTS_OR_DB_FAIL\"}\n");
      return;
    }

    db_log(app->db, 0, "ALLOW", "SIGNED_UP", ip);
    reply_json(c, 200, "{\"ok\":true}\n");
    return;
  }
  // POST /api/login  { "email": "...", "password": "..." }
  if (mg_match(hm->method, mg_str("POST"), NULL) &&
      mg_match(hm->uri, mg_str("/api/login"), NULL)) {

    char email[256] = {0};
    char password[256] = {0};

    if (!json_get_string(hm->body, "$.email", email, sizeof(email)) ||
        !json_get_string(hm->body, "$.password", password, sizeof(password))) {
      db_log(app->db, 0, "DENY", "BAD_REQ", ip);
      reply_json(c, 400, "{\"error\":\"BAD_REQUEST\"}\n");
      return;
    }

    unsigned long long uid = 0;
    unsigned char salt[16];
    unsigned char stored_hash[32];
    int iter = 0;

    if (!db_get_user_auth_by_email(app->db, email, &uid, salt, stored_hash, &iter)) {
      db_log(app->db, 0, "DENY", "BAD_CRED", ip);
      reply_json(c, 401, "{\"error\":\"BAD_CREDENTIALS\"}\n");
      return;
    }

    if (!auth_verify_password(password, salt, sizeof(salt), iter, stored_hash)) {
      db_log(app->db, 0, "DENY", "BAD_CRED", ip);
      reply_json(c, 401, "{\"error\":\"BAD_CREDENTIALS\"}\n");
      return;
    }

    // 세션 토큰 발급: gen_token() 사용 (plain 반환, hash는 SHA256(plain))
    // token.c의 gen_token은 "token_hash"가 SHA256(token_plain)이라 세션에도 그대로 사용 가능
    char session_token[128];
    unsigned char session_hash[32];
    if (!gen_token(session_token, sizeof(session_token), session_hash)) {
      reply_json(c, 500, "{\"error\":\"RAND_FAIL\"}\n");
      return;
    }

    // 만료: 7일(604800초) 예시
    int expires_seconds = 7 * 24 * 60 * 60;

    if (!db_create_session(app->db, uid, session_hash, expires_seconds)) {
      reply_json(c, 500, "{\"error\":\"DB_FAIL\"}\n");
      return;
    }

    db_log(app->db, 0, "ALLOW", "LOGGED_IN", ip);
    reply_json(c, 200,
               "{\"session_token\":\"%s\",\"expires_in\":%d}\n",
               session_token, expires_seconds);
    return;
  }
  //GET /v?t=<ticket>

// GET /v?t=...
if (mg_match(hm->method, mg_str("GET"), NULL) && mg_match(hm->uri, mg_str("/v"), NULL)) {
  // ticket은 JS가 location.search에서 읽게 두면 됨(서버에서 굳이 파싱 안 해도 OK)
  const char *page =
"<!doctype html><html lang=\"ko\"><meta charset=\"utf-8\"/>"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
"<title>방문자 출입</title>"
"<body style=\"font-family:system-ui; padding:16px;\">"
"<h2>방문자 출입</h2>"
"<p>1) 아래 버튼을 누른 뒤, <b>문 앞 NFC 태그</b>에 폰을 대세요.</p>"
"<button id=\"scan\" style=\"font-size:18px; padding:12px 16px;\">NFC 태그 스캔</button>"
"<pre id=\"log\" style=\"white-space:pre-wrap; background:#f5f5f5; padding:12px; margin-top:12px;\"></pre>"
"<script>"
"const log = (s)=>{document.getElementById('log').textContent += s+'\\n';};"
"const qs = new URLSearchParams(location.search);"
"const ticket = qs.get('t');"
"if(!ticket){ log('티켓(t)이 없습니다. URL을 확인하세요.'); }"
"async function openDoor(doorId, doorNonce){"
"  const body = { ticket: ticket, door_id: doorId, door_nonce: doorNonce };"
"  const r = await fetch('/api/visitor/open',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});"
"  const txt = await r.text();"
"  log('서버 응답('+r.status+'): '+txt);"
"}"
"function parsePayload(s){"
"  // NFC Text 레코드에 JSON을 넣는 방식 권장: {\"door_id\":1,\"door_nonce\":\"...\"}"
"  try{"
"    const j = JSON.parse(s);"
"    if(j && j.door_id && j.door_nonce) return {door_id: Number(j.door_id), door_nonce: String(j.door_nonce)};"
"  }catch(e){}"
"  // fallback: 'door_id=1;door_nonce=xxx'"
"  const m1 = /door_id\\s*=\\s*(\\d+)/.exec(s);"
"  const m2 = /door_nonce\\s*=\\s*([A-Za-z0-9_\\-]+)/.exec(s);"
"  if(m1 && m2) return {door_id:Number(m1[1]), door_nonce:m2[1]};"
"  return null;"
"}"
"document.getElementById('scan').addEventListener('click', async ()=>{"
"  if(!ticket){ alert('티켓이 없습니다'); return; }"
"  if(!('NDEFReader' in window)){"
"    log('이 브라우저는 Web NFC를 지원하지 않습니다. (Android Chrome 필요)');"
"    return;"
"  }"
"  try{"
"    const reader = new NDEFReader();"
"    await reader.scan();"
"    log('스캔 시작: 태그에 폰을 대세요...');"
"    reader.onreading = (ev)=>{"
"      for (const rec of ev.message.records){"
"        if(rec.recordType === 'text'){"
"          const dec = new TextDecoder(rec.encoding || 'utf-8');"
"          const s = dec.decode(rec.data);"
"          log('태그 텍스트: '+s);"
"          const p = parsePayload(s);"
"          if(!p){ log('태그 포맷이 올바르지 않습니다.'); return; }"
"          openDoor(p.door_id, p.door_nonce);"
"          return;"
"        }"
"      }"
"      log('text 레코드를 찾지 못했습니다.');"
"    };"
"    reader.onreadingerror = ()=> log('태그 읽기 실패');"
"  }catch(e){"
"    log('NFC 에러: '+e);"
"  }"
"});"
"</script></body></html>";
  reply_html(c, 200, page);
  return;
}
  // GET /api/door/challenge?door_id=1
if (mg_match(hm->method, mg_str("GET"), NULL) &&
    mg_match(hm->uri, mg_str("/api/door/challenge"), NULL)) {

  struct mg_str *hk = mg_http_get_header(hm, "X-Door-Key");
  if (!hk || mg_strcmp(*hk, mg_str(DOOR_API_KEY))!=0) {
    reply_json(c, 401, "{\"error\":\"NO_DOOR_AUTH\"}\n");
    return;
  }

  char door_id_s[32] = {0};
  mg_http_get_var(&hm->query, "door_id", door_id_s, sizeof(door_id_s));
  long long door_id = atoll(door_id_s);
  if (door_id <= 0) { reply_json(c, 400, "{\"error\":\"BAD_DOOR_ID\"}\n"); return; }

  char door_nonce[128];
  unsigned char nonce_hash[32];
  if (!gen_token(door_nonce, sizeof(door_nonce), nonce_hash)) {
    reply_json(c, 500, "{\"error\":\"RAND_FAIL\"}\n");
    return;
  }

  if (!db_create_door_nonce(app->db, door_id, nonce_hash, DOOR_CHALLENGE_TTL_SEC)) {
    reply_json(c, 500, "{\"error\":\"DB_FAIL\"}\n");
    return;
  }

  reply_json(c, 200,
    "{\"door_id\":%lld,\"door_nonce\":\"%s\",\"ttl\":%d}\n",
    door_id, door_nonce, DOOR_CHALLENGE_TTL_SEC);
  return;
}
  //POST /api/visitor/open
if (mg_match(hm->method, mg_str("POST"), NULL) &&
    mg_match(hm->uri, mg_str("/api/visitor/open"), NULL)) {

  char ticket[64] = {0};
  char door_nonce_plain[256] = {0};
  int door_id_i = 0;

  if (!json_get_string(hm->body, "$.ticket", ticket, sizeof(ticket)) ||
      !json_get_string(hm->body, "$.door_nonce", door_nonce_plain, sizeof(door_nonce_plain)) ||
      !json_get_int(hm->body, "$.door_id", &door_id_i)) {
    reply_json(c, 400, "{\"error\":\"BAD_REQUEST\"}\n");
    return;
  }

  if (door_id_i <= 0) { reply_json(c, 400, "{\"error\":\"BAD_DOOR_ID\"}\n"); return; }

  unsigned char token_hash[32];
  if (!db_get_token_hash_by_ticket(app->db, ticket, token_hash)) {
    reply_json(c, 403, "{\"allow\":false,\"reason\":\"BAD_TICKET\"}\n");
    return;
  }

  unsigned char nonce_hash[32];
  sha256_bin((unsigned char*)door_nonce_plain, strlen(door_nonce_plain), nonce_hash);

  long long token_id = 0;
  const char *deny = NULL;

  int ok = db_consume_token_and_nonce(app->db, token_hash, (long long)door_id_i,
                                      nonce_hash, &token_id, &deny);
  if (ok) {
    // TODO: 여기서 실제 문 열기(도어 컨트롤러로 신호)
    reply_json(c, 200, "{\"allow\":true}\n");
  } else {
    reply_json(c, 403, "{\"allow\":false,\"reason\":\"%s\"}\n", deny ? deny : "DENY");
  }
  return;
}
  // POST /api/keys/register
if (mg_match(hm->method, mg_str("POST"), NULL) &&
    mg_match(hm->uri, mg_str("/api/keys/register"), NULL)) {

  char session[256];
  if (!get_bearer_token(hm, session, sizeof(session))) {
    reply_json(c, 401, "{\"error\":\"NO_AUTH\"}\n");
    return;
  }

  unsigned long long uid = 0;
  if (!db_check_session(app->db, session, &uid)) {
    reply_json(c, 401, "{\"error\":\"BAD_SESSION\"}\n");
    return;
  }

  char key_name[128] = {0};
  char pub_b64[4096] = {0};

  (void) json_get_string(hm->body, "$.key_name", key_name, sizeof(key_name));
  if (!json_get_string(hm->body, "$.pubkey_spki_b64", pub_b64, sizeof(pub_b64))) {
    reply_json(c, 400, "{\"error\":\"BAD_REQUEST\"}\n");
    return;
  }

  unsigned char spki[2048];
  size_t spki_len = 0;
  if (!b64url_or_b64_decode(pub_b64, spki, sizeof(spki), &spki_len) || spki_len < 32) {
    reply_json(c, 400, "{\"error\":\"BAD_KEY_FORMAT\"}\n");
    return;
  }

  const char *name_or_null = key_name[0] ? key_name : NULL;
  if (!db_insert_user_key(app->db, uid, name_or_null, spki, spki_len)) {
    reply_json(c, 500, "{\"error\":\"DB_FAIL\"}\n");
    return;
  }

  reply_json(c, 200, "{\"ok\":true}\n");
  return;
}
  //POST /api/keys/revoke
if (mg_match(hm->method, mg_str("POST"), NULL) &&
    mg_match(hm->uri, mg_str("/api/keys/revoke"), NULL)) {

  char session[256];
  if (!get_bearer_token(hm, session, sizeof(session))) {
    reply_json(c, 401, "{\"error\":\"NO_AUTH\"}\n");
    return;
  }

  unsigned long long uid = 0;
  if (!db_check_session(app->db, session, &uid)) {
    reply_json(c, 401, "{\"error\":\"BAD_SESSION\"}\n");
    return;
  }

  int key_id_i = 0;
  if (!json_get_int(hm->body, "$.key_id", &key_id_i) || key_id_i <= 0) {
    reply_json(c, 400, "{\"error\":\"BAD_REQUEST\"}\n");
    return;
  }

  if (!db_revoke_user_key(app->db, uid, (long long)key_id_i)) {
    reply_json(c, 404, "{\"error\":\"NOT_FOUND\"}\n");
    return;
  }

  reply_json(c, 200, "{\"ok\":true}\n");
  return;
}
  //GET /api/keys/list
if (mg_match(hm->method, mg_str("GET"), NULL) &&
    mg_match(hm->uri, mg_str("/api/keys/list"), NULL)) {

  char session[256];
  if (!get_bearer_token(hm, session, sizeof(session))) {
    reply_json(c, 401, "{\"error\":\"NO_AUTH\"}\n");
    return;
  }

  unsigned long long uid = 0;
  if (!db_check_session(app->db, session, &uid)) {
    reply_json(c, 401, "{\"error\":\"BAD_SESSION\"}\n");
    return;
  }

  char json[4096];
  if (!db_list_user_keys_json(app->db, uid, json, sizeof(json))) {
    reply_json(c, 500, "{\"error\":\"DB_FAIL\"}\n");
    return;
  }

  reply_json(c, 200, "%s\n", json);
  return;
}
//api/logout
if (mg_match(hm->method, mg_str("POST"), NULL) &&
    mg_match(hm->uri, mg_str("/api/logout"), NULL)) {

  char session[256];
  if (!get_bearer_token(hm, session, sizeof(session))) {
    reply_json(c, 401, "{\"error\":\"NO_AUTH\"}\n");
    return;
  }

  // 세션이 유효하든 아니든, 결과는 ok:true로 줘도 됨(정보노출 줄이기)
  (void) db_delete_session(app->db, session);
  reply_json(c, 200, "{\"ok\":true}\n");
  return;
}

  reply_json(c, 404, "{\"error\":\"NOT_FOUND\"}\n");
}

