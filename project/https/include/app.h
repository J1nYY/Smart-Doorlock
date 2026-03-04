#pragma once

#include "../third_party/mongoose.h"
#include <mysql.h>

struct app_ctx {
  MYSQL *db;
  struct mg_str cert;
  struct mg_str key;
};

