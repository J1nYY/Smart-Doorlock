#pragma once

// DB 설정
#define DB_HOST "127.0.0.1"
#define DB_USER "dooruser"
#define DB_PASS "doorpass"
#define DB_NAME "doorlock"
#define DB_PORT 3306

// HTTPS 리스너
#define LISTEN_ADDR "https://0.0.0.0:8443"

// TLS 파일 경로
#define TLS_CERT_PATH "certs/cert.pem"
#define TLS_KEY_PATH  "certs/key.pem"

// 이벤트 루프 poll 주기(ms)
#define POLL_MS 50

#define PUBLIC_BASE_URL "https://127.0.0.1:8443"   // 외부 접속 IP/도메인으로 바꿔

#define DOOR_CHALLENGE_TTL_SEC 120
#define DOOR_API_KEY "door1-key"
