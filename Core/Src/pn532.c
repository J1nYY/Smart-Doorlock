#include "pn532.h"
#include <string.h>
#include "uart.h"
#define PN532_I2C_ADDR_7BIT  (0x24)
#define PN532_I2C_ADDR       (PN532_I2C_ADDR_7BIT << 1)

#define PREAMBLE    0x00
#define STARTCODE1  0x00
#define STARTCODE2  0xFF
#define POSTAMBLE   0x00

#define HOSTTOPN532 0xD4
#define PN532TOHOST 0xD5

#define CMD_SAMCONFIG            0x14
#define CMD_INLISTPASSIVETARGET  0x4A
#define CMD_INDATAEXCHANGE       0x40

static void dbg_write(const char *s) {
  HAL_UART_Transmit(&huart2, (uint8_t*)s, (uint16_t)strlen(s), 200);
}

static bool i2c_write_raw(pn532_t *d, const uint8_t *buf, uint16_t len) {
  uint8_t tmp[300];
  if (len + 1 > sizeof(tmp)) return false;
  tmp[0] = 0x00; // I2C write prefix
  memcpy(&tmp[1], buf, len);
  return HAL_I2C_Master_Transmit(d->hi2c, PN532_I2C_ADDR, tmp, len + 1, 200) == HAL_OK;
}

static bool i2c_read_raw(pn532_t *d, uint8_t *buf, uint16_t len) {
  return HAL_I2C_Master_Receive(d->hi2c, PN532_I2C_ADDR, buf, len, 1000) == HAL_OK;
}

static bool wait_ready(pn532_t *d, uint16_t timeout_ms) {
	  uint32_t t0 = HAL_GetTick();
	  while ((HAL_GetTick() - t0) < timeout_ms) {
	    uint8_t st = 0x00;
	    if (i2c_read_raw(d, &st, 1)) {
	      if (st == 0x01) {
	        d->irq_ready = 0;
	        return true;
	      }
	    }
	    HAL_Delay(2);
	  }
	  return false;
	}

static uint16_t build_frame(uint8_t cmd, const uint8_t *params, uint8_t params_len,
                            uint8_t *out, uint16_t out_max) {
  // frame: 00 00 FF LEN LCS TFI CMD ... DCS 00
  uint8_t len = (uint8_t)(2 + params_len); // TFI+CMD + params
  if (out_max < (uint16_t)(8 + params_len)) return 0;

  uint16_t idx = 0;
  out[idx++] = PREAMBLE;
  out[idx++] = STARTCODE1;
  out[idx++] = STARTCODE2;
  out[idx++] = len;
  out[idx++] = (uint8_t)(0x00 - len);      // LCS

  out[idx++] = HOSTTOPN532;                // TFI
  out[idx++] = cmd;

  uint8_t sum = (uint8_t)(HOSTTOPN532 + cmd);
  for (uint8_t i = 0; i < params_len; i++) {
    out[idx++] = params[i];
    sum = (uint8_t)(sum + params[i]);
  }

  out[idx++] = (uint8_t)(0x00 - sum);      // DCS
  out[idx++] = POSTAMBLE;
  return idx;
}


static bool read_ack(pn532_t *d, uint16_t timeout_ms) {
	  if (!wait_ready(d, timeout_ms)) return false;

	  uint8_t buf[7]; // status + 6
	  if (!i2c_read_raw(d, buf, sizeof(buf))) return false;

	  if (buf[0] != 0x01) return false;

	  static const uint8_t ack[] = {0x00,0x00,0xFF,0x00,0xFF,0x00};
	  bool ok = (memcmp(&buf[1], ack, sizeof(ack)) == 0);

	  d->irq_ready = 0;
	  return ok;
	}

static bool read_response_frame(pn532_t *d, uint8_t expected_cmd,
                                uint8_t *out, uint8_t *out_len,
                                uint16_t timeout_ms) {
  if (!wait_ready(d, timeout_ms)) return false;

  // ★ 중요: 한번에 넉넉히 읽기
  // status(1) + frame(최대 수십~수백 바이트) 를 한 번에 받는다
  static uint8_t buf[300];              // 스택 말고 static으로 (STM32 스택 보호)
  memset(buf, 0, sizeof(buf));

  if (!i2c_read_raw(d, buf, sizeof(buf))) return false;
  if (buf[0] != 0x01) return false;     // status

  uint8_t *f = &buf[1];                 // frame 시작
  // frame: 00 00 FF LEN LCS TFI CMD ... DCS 00
  if (!(f[0]==0x00 && f[1]==0x00 && f[2]==0xFF)) return false;

  uint8_t len = f[3];
  uint8_t lcs = f[4];
  if ((uint8_t)(len + lcs) != 0x00) return false;  // LEN+LCS 체크(간단)

  uint8_t tfi = f[5];
  uint8_t cmd = f[6];

  if (tfi != PN532TOHOST) return false;
  if (cmd != (uint8_t)(expected_cmd + 1)) return false;

  // payload 길이 = LEN - (TFI+CMD=2)
  if (len < 2) return false;
  uint8_t payload_len = (uint8_t)(len - 2);
  if (payload_len > *out_len) return false;

  // payload는 f[7]부터
  memcpy(out, &f[7], payload_len);
  *out_len = payload_len;

  d->irq_ready = 0;
  return true;
}



static bool send_cmd_and_read(pn532_t *d, uint8_t cmd,
                              const uint8_t *params, uint8_t params_len,
                              uint8_t *resp, uint8_t *resp_len,
                              uint16_t timeout_ms) {
  uint8_t frame[128];
  uint16_t flen = build_frame(cmd, params, params_len, frame, sizeof(frame));
  if (flen == 0) return false;

  d->irq_ready = 0;
  if (!i2c_write_raw(d, frame, flen)) return false;

  d->irq_ready = 0;
  if (!read_ack(d, timeout_ms)) return false;

  d->irq_ready = 0;
  return read_response_frame(d, cmd, resp, resp_len, timeout_ms);
}
bool pn532_init(pn532_t *d) {
  // reset toggle
  HAL_GPIO_WritePin(d->rst_port, d->rst_pin, GPIO_PIN_RESET);
  HAL_Delay(20);
  HAL_GPIO_WritePin(d->rst_port, d->rst_pin, GPIO_PIN_SET);
  HAL_Delay(50);
  d->irq_ready = 0;
  return true;
}

bool pn532_sam_config(pn532_t *d) {
  // SAMConfiguration: [mode=1][timeout=0x14][irq=1]
  uint8_t params[] = {0x01, 0x14, 0x01};
  uint8_t resp[32];
  uint8_t rlen = sizeof(resp);
  return send_cmd_and_read(d, CMD_SAMCONFIG, params, sizeof(params), resp, &rlen, 500);
}

bool pn532_in_list_passive_target(pn532_t *d, uint16_t timeout_ms) {
  // [maxTg=1][brTy=0 (TypeA 106)]
  uint8_t params[] = {0x01, 0x00};
  uint8_t resp[32];
  uint8_t rlen = sizeof(resp);

  if (!send_cmd_and_read(d, CMD_INLISTPASSIVETARGET, params, sizeof(params), resp, &rlen, timeout_ms))
    return false;

  // resp[0] = NbTg
  return (rlen >= 1 && resp[0] >= 1);
}

bool pn532_in_data_exchange(pn532_t *d, uint8_t tg,
                            const uint8_t *data, uint8_t data_len,
                            uint8_t *resp, uint8_t *resp_len,
                            uint16_t timeout_ms) {
  uint8_t params[1 + 255];
  if ((uint16_t)data_len + 1 > sizeof(params)) return false;

  params[0] = tg;
  memcpy(&params[1], data, data_len);

  uint8_t tmp[255];
  uint8_t tlen = sizeof(tmp);

  if (!send_cmd_and_read(d, CMD_INDATAEXCHANGE, params, (uint8_t)(data_len + 1), tmp, &tlen, timeout_ms))
    return false;

  // tmp[0] status: 0x00 success
  if (tlen < 1 || tmp[0] != 0x00) return false;

  uint8_t payload_len = (uint8_t)(tlen - 1);
  if (payload_len > *resp_len) return false;

  memcpy(resp, &tmp[1], payload_len);
  *resp_len = payload_len;
  return true;
}

