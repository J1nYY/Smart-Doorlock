// include/door_tcp.h
#pragma once
#include "mongoose.h"

struct app_ctx;  // app.h에 정의된 struct app forward 선언

// listen_addr 예) "tcp://0.0.0.0:9001"
void door_tcp_init(struct mg_mgr *mgr, struct app_ctx *app, const char *listen_addr);
