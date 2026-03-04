#pragma once
#include "stm32f4xx_hal.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct {
  I2C_HandleTypeDef *hi2c;
  GPIO_TypeDef *rst_port;
  uint16_t rst_pin;
  volatile uint8_t irq_ready;   // EXTI callback에서 set
} pn532_t;

bool pn532_init(pn532_t *d);
bool pn532_sam_config(pn532_t *d);

// 폰(타깃) 감지
bool pn532_in_list_passive_target(pn532_t *d, uint16_t timeout_ms);

// APDU 전송/응답 수신
bool pn532_in_data_exchange(pn532_t *d, uint8_t tg,
                            const uint8_t *data, uint8_t data_len,
                            uint8_t *resp, uint8_t *resp_len,
                            uint16_t timeout_ms);
