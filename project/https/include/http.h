#pragma once
#include "../third_party/mongoose.h"
#include "app.h"

// app context를 http 모듈에 주입
void http_set_app_ctx(struct app_ctx *app);
// Mongoose 이벤트 핸들러
void http_ev_handler(struct mg_connection *c, int ev, void *ev_data);

