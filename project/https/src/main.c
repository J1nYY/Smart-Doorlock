#include "../include/app.h"
#include "../include/config.h"
#include "../include/db.h"
#include "../include/http.h"
#include "../include/door_tcp.h"

#include <stdio.h>

int main(void) {
  struct app_ctx app;
  app.db = NULL;
  app.cert = mg_str("");
  app.key  = mg_str("");

  // 1) DB 연결
  app.db = db_connect();
  if (!app.db) return 1;

  // 2) TLS cert/key 로드
  app.cert = mg_file_read(&mg_fs_posix, TLS_CERT_PATH);
  app.key  = mg_file_read(&mg_fs_posix, TLS_KEY_PATH);
  if (app.cert.len == 0 || app.key.len == 0) {
    fprintf(stderr, "Failed to read TLS cert/key: %s , %s\n", TLS_CERT_PATH, TLS_KEY_PATH);
    return 1;
  }

  // 3) 서버 시작
  // http 모듈에 app 주입
  http_set_app_ctx(&app);

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);

  if (mg_http_listen(&mgr, LISTEN_ADDR, http_ev_handler, &app) == NULL) {
    fprintf(stderr, "Failed to listen on %s\n", LISTEN_ADDR);
    return 1;
  }
  door_tcp_init(&mgr, &app, "tcp://0.0.0.0:5000");
  printf("Listening on %s\n", LISTEN_ADDR);

  for (;;) mg_mgr_poll(&mgr, POLL_MS);

  // (도달 거의 안 함)
  mg_mgr_free(&mgr);
  mysql_close(app.db);
  mg_free((void*)app.cert.buf);
  mg_free((void*)app.key.buf);
  return 0;
}

