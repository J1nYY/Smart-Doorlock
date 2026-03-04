/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Smart Automatic Door with WiFi Control
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include "pn532.h"
#include <string.h>
#include <stdlib.h>
#include "esp.h" // [중요] esp.h 및 esp.c가 프로젝트에 있어야 함
#include <stdarg.h>
#include "chal.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

#ifdef __GNUC__
/* With GCC, small printf (option LD Linker->Libraries->Small printf
   set to 'Yes') calls __io_putchar() */
#define PUTCHAR_PROTOTYPE int __io_putchar(int ch)
#else
#define PUTCHAR_PROTOTYPE int fputc(int ch, FILE *f)
#endif /* __GNUC__ */
#define ARR_CNT 5
#define CMD_SIZE 50

#define SERVO_OPEN_PULSE  1500  // 90도
#define SERVO_CLOSE_PULSE 600   // 0도
const int OPEN_DIST = 5;        // 열림 거리 (cm)
const int CLOSE_DIST = 10;      // 닫힘 거리 (cm)

// ESP 통신용 버퍼 크기 정의 (esp.h에 없을 경우 대비)
#ifndef ARR_CNT
#define ARR_CNT 5
#endif
#ifndef MAX_ESP_COMMAND_LEN
#define MAX_ESP_COMMAND_LEN 100
#endif
// INS 정의
#define INS_GET_CAPS  0x01
#define INS_CHAL      0x20
#define INS_GET_SIG   0x21
// TG는 InListPassiveTarget에서 1개만 잡으면 보통 0x01
#define TG_1 0x01
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
I2C_HandleTypeDef hi2c2;

TIM_HandleTypeDef htim2;

UART_HandleTypeDef huart1;
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
// --- 서보 & 센서 변수 ---
int dist1 = 0;
int dist2 = 0;
int currentPulse = SERVO_CLOSE_PULSE;
char msg[100];
uint32_t lastDetectTime = 0;

// --- WiFi(ESP) 관련 변수 ---
extern cb_data_t cb_data;   // esp.c에 정의된 수신 버퍼
char strBuff[MAX_ESP_COMMAND_LEN]; // 명령 처리용 임시 버퍼

// 타이머 대체 변수
uint32_t lastCheckTime = 0;
// nfc
static pn532_t nfc;
static const uint8_t SELECT_APDU[] = {
  0x00,0xA4,0x04,0x00,0x07, 0xF0,0x01,0x02,0x03,0x04,0x05,0x06
};
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_TIM2_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_I2C2_Init(void);
/* USER CODE BEGIN PFP */
void esp_event(char * recvBuf); // WiFi 명령 처리 함수
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */


// 1. 마이크로초 딜레이 (DWT 사용)
void delay_us(volatile uint32_t us) {
    uint32_t count_start = DWT->CYCCNT;
    uint32_t count_target = us * (SystemCoreClock / 1000000);
    while ((DWT->CYCCNT - count_start) < count_target);
}

// 2. 초음파 센서 거리 측정
int readDistance(GPIO_TypeDef* TrigPort, uint16_t TrigPin, GPIO_TypeDef* EchoPort, uint16_t EchoPin) {
    HAL_GPIO_WritePin(TrigPort, TrigPin, GPIO_PIN_RESET);
    delay_us(2);
    HAL_GPIO_WritePin(TrigPort, TrigPin, GPIO_PIN_SET);
    delay_us(10);
    HAL_GPIO_WritePin(TrigPort, TrigPin, GPIO_PIN_RESET);

    uint32_t timeout = 0;
    while(HAL_GPIO_ReadPin(EchoPort, EchoPin) == GPIO_PIN_RESET) {
        if(timeout++ > 100000) return 999;
    }

    uint32_t startTick = DWT->CYCCNT;
    while(HAL_GPIO_ReadPin(EchoPort, EchoPin) == GPIO_PIN_SET);
    uint32_t endTick = DWT->CYCCNT;

    uint32_t duration_us = (endTick - startTick) / (SystemCoreClock / 1000000);
    int distance = duration_us / 58;

    if (distance > 300 || distance <= 0) return 999;
    return distance;
}

// 3. 서보모터 동작 함수
void moveServo(int pulse) {
    __HAL_TIM_SET_COMPARE(&htim2, TIM_CHANNEL_1, pulse);
    currentPulse = pulse;
}

// 4. WiFi 이벤트 처리 함수
void esp_event(char * recvBuf)
{
    int i = 0;
    char * pToken;
    char * pArray[ARR_CNT] = {0};
    char sendBuf[100] = {0};

    // 개행 문자 제거
    strBuff[strlen(recvBuf)-1] = '\0';

    // 디버그 출력
    sprintf(msg, "WiFi RX: %s\r\n", recvBuf);
    HAL_UART_Transmit(&huart2, (uint8_t*)msg, strlen(msg), 100);

    // 파싱: [ID]CMD@VALUE
    pToken = strtok(recvBuf, "[@]");
    while(pToken != NULL)
    {
        pArray[i] = pToken;
        if(++i >= ARR_CNT) break;
        pToken = strtok(NULL, "[@]");
    }

    if(pArray[1] != NULL && !strcmp(pArray[1], "SERVO"))
    {
        if(pArray[2] != NULL && !strcmp(pArray[2], "OPEN"))
        {
            moveServo(SERVO_OPEN_PULSE);
            sprintf(sendBuf, "[%s]DOOR@OPENED\n", pArray[0]);
        }
        else if(pArray[2] != NULL && !strcmp(pArray[2], "CLOSE"))
        {
            moveServo(SERVO_CLOSE_PULSE);
            sprintf(sendBuf, "[%s]DOOR@CLOSED\n", pArray[0]);
        }
    }
    else if(pArray[1] != NULL && !strncmp(pArray[1], " New conn", 8)) return;
    else if(pArray[1] != NULL && !strncmp(pArray[1], " Already log", 8))
    {
        esp_client_conn();
        return;
    }

    if(strlen(sendBuf) > 0) esp_send_data(sendBuf);
}
//pn532
static void uart(const char *s) {
  HAL_UART_Transmit(&huart2, (uint8_t*)s, strlen(s), 100);
}
static void uart_printf(const char *fmt, ...) {
  char buf[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  uart(buf);
}
static void uart_hex(const uint8_t *b, uint16_t n) {
  char tmp[4];
  for (uint16_t i = 0; i < n; i++) {
    snprintf(tmp, sizeof(tmp), "%02X", b[i]);
    uart(tmp);
    uart(" ");
  }
  uart("\r\n");
}
static void uart_print_sw(const uint8_t *resp, uint8_t rlen) {
  if (rlen < 2) {
    uart("SW=<none>\r\n");
    return;
  }
  uart_printf("SW=%02X %02X\r\n", resp[rlen-2], resp[rlen-1]);
}
static void hex(const uint8_t *b, uint8_t n) {
  char buf[4];
  for (uint8_t i=0;i<n;i++){
    snprintf(buf,sizeof(buf),"%02X", b[i]);
    uart(buf);
    uart(" ");
  }
  uart("\r\n");
}
static int sw9000(const uint8_t *resp, uint8_t len) {
  return (len >= 2 && resp[len-2]==0x90 && resp[len-1]==0x00);
}
// ====== 간단 nonce 생성 (RNG 있으면 교체 추천) ======
static uint32_t xorshift32(uint32_t *s) {
  uint32_t x = *s;
  x ^= x << 13; x ^= x >> 17; x ^= x << 5;
  *s = x;
  return x;
}
static void make_nonce16(uint8_t out[16]) {
  static uint32_t seed = 0x12345678;
  for (int i=0;i<16;i+=4) {
    uint32_t r = xorshift32(&seed);
    out[i+0] = (uint8_t)(r >> 24);
    out[i+1] = (uint8_t)(r >> 16);
    out[i+2] = (uint8_t)(r >> 8);
    out[i+3] = (uint8_t)(r);
  }
}

// exp(Unix seconds) - 테스트로 고정값도 가능
static void write_u32_be(uint8_t out[4], uint32_t v) {
  out[0] = (uint8_t)(v >> 24);
  out[1] = (uint8_t)(v >> 16);
  out[2] = (uint8_t)(v >> 8);
  out[3] = (uint8_t)(v);
}

// ====== APDU helper: Case3 (Lc+Data) 전송 ======
static int apdu_send_case3(uint8_t ins, uint8_t p1, uint8_t p2,
                           const uint8_t *data, uint8_t lc,
                           uint8_t *resp, uint8_t *rlen,
                           uint16_t timeout_ms) {
  uint8_t apdu[5 + 255];
  uint8_t idx = 0;
  apdu[idx++] = 0x00;
  apdu[idx++] = ins;
  apdu[idx++] = p1;
  apdu[idx++] = p2;
  apdu[idx++] = lc;
  if (lc > 0 && data != NULL) {
    memcpy(&apdu[idx], data, lc);
    idx += lc;
  }
  int ok =pn532_in_data_exchange(&nfc, TG_1, apdu, idx, resp, rlen, timeout_ms);
  if (!ok) {
      uart("  -> pn532_in_data_exchange FAILED\r\n");
      return 0;
   }
  uart("  -> resp: ");
  return 1;
}

// ====== APDU helper: “Lc=0”로 보내기 (안전) ======
static int apdu_send_lc0(uint8_t ins, uint8_t p1, uint8_t p2,
                         uint8_t *resp, uint8_t *rlen,
                         uint16_t timeout_ms) {
  // 00 INS P1 P2 00
  uint8_t apdu[5] = {0x00, ins, p1, p2, 0x00};

  uart_printf("[APDU TX] INS=%02X P1=%02X P2=%02X timeout=%u ms : ",
              ins, p1, p2, (unsigned)timeout_ms);
  uart_hex(apdu, sizeof(apdu));

  uint8_t max = *rlen;   // 호출자가 준 버퍼 최대치
  int ok = pn532_in_data_exchange(&nfc, TG_1, apdu, sizeof(apdu), resp, rlen, timeout_ms);

  uart_printf("[APDU RX] ok=%d respLen=%u (max=%u)\r\n", ok, (unsigned)*rlen, (unsigned)max);

  if (!ok) {
    uart("  -> pn532_in_data_exchange FAILED\r\n");
    return 0;
  }

  uart("  -> resp: ");
  uart_hex(resp, *rlen);
  uart_print_sw(resp, *rlen);

  if (ins == INS_GET_CAPS) {
     if (parse_ch_email_and_store(resp, *rlen)) {
       uart_printf("  -> saved email: %s\r\n", g_user_email);
     } else {
       uart("  -> GET_CAPS: no email parsed\r\n");
     }
   }

  return 1;
}

// ====== GET_SIG 수집 ======
static int get_sig_collect(uint8_t *sig, uint16_t *sig_len) {
  const uint16_t MAX_SIG = 256;
  const int MAX_TRIES_PER_CHUNK = 30;
  const uint8_t MAX_CHUNKS = 32;

  uint16_t total = 0;
  uint16_t filled = 0;

  for (uint8_t chunk = 0; chunk < MAX_CHUNKS; chunk++) {
    for (int t = 0; t < MAX_TRIES_PER_CHUNK; t++) {
      uint8_t resp[255];
      memset(resp, 0, sizeof(resp));
      uint8_t rlen = sizeof(resp);

      if (!apdu_send_lc0(INS_GET_SIG, chunk, 0x00, resp, &rlen, 600)) {
        uart("GET_SIG exchange fail\r\n");
        return 0;
      }
      if (!sw9000(resp, rlen)) {
        uart("GET_SIG SW not OK\r\n");
        return 0;
      }

      uint8_t dataLen = (rlen >= 2) ? (uint8_t)(rlen - 2) : 0;
      if (dataLen == 0) { HAL_Delay(10); continue; }

      // PEND/DONE/ERR
      if (dataLen == 4 && memcmp(resp, "PEND", 4) == 0) { HAL_Delay(20); continue; }
      if (dataLen == 4 && memcmp(resp, "DONE", 4) == 0) {
        *sig_len = filled;
        return (filled > 0);
      }
      if (dataLen >= 3 && memcmp(resp, "ERR", 3) == 0) {
        uart("GET_SIG got ERR\r\n");
        return 0;
      }

      if (chunk == 0) {
        // 1) DER 시작(0x30) 위치 찾기
        int der_off = -1;
        for (int i = 0; i < dataLen; i++) {
          if (resp[i] == 0x30) { der_off = i; break; }
        }
        if (der_off < 0) {
          uart("FAIL: no DER(0x30) in chunk0\r\n");
          return 0;
        }
        if (der_off + 2 > dataLen) {
          uart("FAIL: chunk0 too short for DER header\r\n");
          return 0;
        }

        // 2) DER 길이 계산
        uint16_t der_total = 0;
        uint8_t L = resp[der_off + 1];

        if (L < 0x80) {
          der_total = (uint16_t)(2 + L);
        } else if (L == 0x81) {
          if (der_off + 3 > dataLen) return 0;
          der_total = (uint16_t)(3 + resp[der_off + 2]);
        } else if (L == 0x82) {
          if (der_off + 4 > dataLen) return 0;
          der_total = (uint16_t)(4 + ((resp[der_off + 2] << 8) | resp[der_off + 3]));
        } else {
          uart("FAIL: DER len form unsupported\r\n");
          return 0;
        }

        if (der_total == 0 || der_total > MAX_SIG) {
          uart_printf("FAIL: bad DER total=%u\r\n", der_total);
          return 0;
        }

        total = der_total;

        // 3) chunk0에서 DER 데이터 복사(der_off부터)
        uint16_t take = (uint16_t)(dataLen - der_off);
        if (take > total) take = total;
        memcpy(sig, &resp[der_off], take);
        filled = take;

      } else {
        // 이후 chunk들은 “순수 이어붙이기”
        if (total == 0) { uart("FAIL: total==0 on chunk>0\r\n"); return 0; }

        uint16_t take = dataLen;
        if (filled + take > total) take = (uint16_t)(total - filled);
        memcpy(sig + filled, resp, take);
        filled += take;
      }

      if (filled >= total) {
        *sig_len = total;
        return 1;
      }

      break; // 다음 chunk로
    }
  }

  uart("FAIL: chunks exhausted\r\n");
  return 0;
}



// ====== EXTI 콜백: PN532 IRQ ready ======
void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin) {
  if (GPIO_Pin == IRQ_Pin) {
    nfc.irq_ready = 1;
  }
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */
    int ret = 0;
    uint32_t door_id = DOOR_ID;
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_TIM2_Init();
  MX_USART1_UART_Init();
  MX_USART2_UART_Init();
  MX_I2C2_Init();
  /* USER CODE BEGIN 2 */

    // 1. DWT 초기화
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    // 2. WiFi(ESP) 초기화 (huart1 사용 확인 필수)
    printf("Start System - WiFi Door\r\n");
    ret |= drv_uart_init();
    ret |= drv_esp_init();

    if(ret != 0) {
        char *err = "ESP Init Failed.\r\n";
        HAL_UART_Transmit(&huart2, (uint8_t*)err, strlen(err), 100);
    } else {
        AiotClient_Init(); // 서버 접속
    }

    // 3. 서보 시작
    HAL_TIM_PWM_Start(&htim2, TIM_CHANNEL_1);
    moveServo(SERVO_CLOSE_PULSE);
    HAL_Delay(500);

    char *bootMsg = "System Ready!\r\n";
    HAL_UART_Transmit(&huart2, (uint8_t*)bootMsg, strlen(bootMsg), 100);
    //nfc
    nfc.hi2c = &hi2c2;
	nfc.rst_port = RSTO_GPIO_Port;
	nfc.rst_pin  = RSTO_Pin;
	nfc.irq_ready = 0;

	pn532_init(&nfc);
	if (!pn532_sam_config(&nfc)) {
	uart("PN532 SAMConfig failed\r\n");
	while (1) {}
	}

	uart("Ready. Tap phone...\r\n");

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
      while (1)
      {

            // 1. ESP 재접속 체크 (10초 주기)
            if (HAL_GetTick() - lastCheckTime > 500)
            {
                lastCheckTime = HAL_GetTick();
                static int secCounter = 0;
                secCounter++;
                if(secCounter % 10 == 0) {
                    if(esp_get_status() != 0) {
                        HAL_UART_Transmit(&huart2, (uint8_t*)"Connecting...\r\n", 15, 100);
                        esp_client_conn();
                    }
                }
            }

            // 2. 센서 제어
            dist1 = readDistance(TRIG1_GPIO_Port, TRIG1_Pin, ECHO1_GPIO_Port, ECHO1_Pin);
            HAL_Delay(10);
            dist2 = readDistance(TRIG2_GPIO_Port, TRIG2_Pin, ECHO2_GPIO_Port, ECHO2_Pin);


            // [사람 없음 - 닫힘 조건]
            if (dist1 > CLOSE_DIST) {

                // 마지막 감지 후 10초 지났는지 확인
              if (HAL_GetTick() - lastDetectTime > 5000) {

                    if (currentPulse != SERVO_CLOSE_PULSE) {
                        moveServo(SERVO_CLOSE_PULSE);

                        char *logMsg = "Sensor: Clear! Door CLOSE\r\n";
                        HAL_UART_Transmit(&huart2, (uint8_t*)logMsg, strlen(logMsg), 100);
                        esp_send_data("[KSH_STM]DOOR@CLOSED\n");
                    }
                }
            }
            //3.nfc
            if (!pn532_in_list_passive_target(&nfc, 500)) {
                  HAL_Delay(50);
                  continue;
                }
                uart("Phone detected\r\n");
/*
            if (!(pn532_in_list_passive_target(&nfc, 500)&&dist1 < OPEN_DIST)) {
                               HAL_Delay(50);
                               continue;
                            }
                            */

                // 1) SELECT
                {
                  uint8_t resp[255];
                  uint8_t rlen = sizeof(resp);
                  if (!pn532_in_data_exchange(&nfc, TG_1, SELECT_APDU, sizeof(SELECT_APDU), resp, &rlen, 300)) {

                    continue;
                  }
                  uart("SELECT resp: "); hex(resp, rlen);
                  if (!sw9000(resp, rlen)) {
                    uart("SELECT SW not OK\r\n");
                    continue;
                  }
                }

                // 2) GET_CAPS -> "ch" 확인
                {
                  uint8_t resp[255];
                  uint8_t rlen = sizeof(resp);
                  if (!apdu_send_lc0(INS_GET_CAPS, 0x00, 0x00, resp, &rlen, 10000)) {
                    uart("GET_CAPS fail\r\n");
                    continue;
                  }
                  if (!sw9000(resp, rlen)) {
                    uart("GET_CAPS SW not OK\r\n");
                    continue;
                  }
                  uint8_t dataLen = (uint8_t)(rlen - 2);
                  uart("CAPS: "); hex(resp, dataLen);

                  if (!(dataLen> 2 && resp[0] == 'c' && resp[1] == 'h')) {
                    uart("CAPS not ch -> stop\r\n");
                    continue;
                  }
                }

                // 3) CHAL: nonce(16) + exp(4) 전송
                char line[256];
                char nonceStr[128] = {0};
                uint32_t exp = 0,user_id;

                // 3-1) CH 요청 전송
                {
                  char tx[64];
                  snprintf(tx, sizeof(tx), "[KSH_PI]CH@%s@%u\n",g_user_email, (unsigned)door_id );
                  uart("PI -> CH\r\n");
                  pi_send_line(tx);
                }
                if(strstr((char *)cb_data.buf, "+IPD") && cb_data.buf[cb_data.length-1] == '\n')
                            {
                                strcpy(strBuff, strchr((char *)cb_data.buf, '['));
                                memset(cb_data.buf, 0x0, sizeof(cb_data.buf));
                                cb_data.length = 0;
                                esp_event(strBuff);
                            }
                // 3-2) CHAL 응답 대기

                {
                  uint32_t t0 = HAL_GetTick();
                  int got = 0;
                  while ((HAL_GetTick() - t0) < 4000) {
                    if (!pi_wait_line(line, sizeof(line), 1000)) {;continue;}

                    // CHAL이면 파싱
                    if (parse_chal_line(line, &door_id, &user_id, nonceStr, sizeof(nonceStr), &exp)) {

                      if (door_id == DOOR_ID) { got = 1; break; }
                      continue; // 다른 door/user면 무시
                    }

                  }

                  if (!got) {
                    uart("PI CHAL timeout\r\n");
                    continue; // NFC 흐름 전체 재시도
                  }

                  uart_printf("PI CHAL OK: door=%u user=%u exp=%lu nonce=%s\r\n",
                              (unsigned)door_id, (unsigned)user_id, (unsigned long)exp, nonceStr);
                }

                // ===== 4) 폰에 SIGN_REQ 전송 =====
                // payload: door(4BE) | user(4BE) | exp(4BE) | nonce_len(1) | nonce_str(bytes)
                {
                  uint8_t data[4 + 4 + 4 + 1 + 200];
                  uint8_t nonceLen = (uint8_t)strnlen(nonceStr, 200);
                  if (nonceLen == 0) { uart("nonce empty\r\n"); continue; }

                  uint8_t idx = 0;
                  write_u32_be(&data[idx], (uint32_t)door_id); idx += 4;
                  write_u32_be(&data[idx], (uint32_t)user_id); idx += 4;
                  write_u32_be(&data[idx], (uint32_t)exp);     idx += 4;
                  data[idx++] = nonceLen;
                  memcpy(&data[idx], nonceStr, nonceLen);
                  idx += nonceLen;

                  uint8_t resp[255];
                  uint8_t rlen = sizeof(resp);

                  // INS_CHAL(0x20)을 "SIGN_REQ"로 쓰는 중이면 그대로 사용
                  if (!apdu_send_case3(INS_CHAL, 0x00, 0x00, data, idx, resp, &rlen, 1000)) {
                    uart("SIGN_REQ exchange fail\r\n");
                    continue;
                  }
                  if (!sw9000(resp, rlen)) {
                    uart("SIGN_REQ SW not OK\r\n");
                    continue;
                  }
                  uart("SIGN_REQ ACK OK\r\n");
                }


                // 4) GET_SIG: 서명 DER 받아오기
                uint8_t sig[256];
                uint16_t sigLen = 0;

                if (!get_sig_collect(sig, &sigLen)) {
                  uart("GET_SIG failed\r\n");
                  HAL_Delay(300);
                  continue;
                }

                uart("SIG len: ");
                char tmp[32];
                snprintf(tmp, sizeof(tmp), "%u\r\n", (unsigned)sigLen);
                uart(tmp);
                uart("SIG DER: "); hex(sig, (uint8_t)sigLen);
                // 6) PI로 SIGN 전송 (base64url)
                char sigB64[512];
                if (base64url_encode(sig, (int)sigLen, sigB64, sizeof(sigB64)) < 0) {
                  uart("b64url encode fail\r\n");
                  continue;
                }

                {
                  char tx[768];
                  char t[64];
                  snprintf(t, sizeof(t), "EXP=%lu\r\n", (unsigned long)exp);
                  uart(t);

                  snprintf(tx, sizeof(tx),
                           "[KSH_PI]SIGN@%u@%u@%s@%lu\n",
                           (unsigned)user_id, (unsigned)door_id, sigB64, (unsigned long)exp);
                  uart("TX: ");
                  uart(tx);
                  uart("\r\n");
                  uart("PI -> SIGN\r\n");
                  pi_send_line(tx);
                }
                // 7) PI OK 대기
                {
                  uint32_t t0 = HAL_GetTick();
                  int ok = 0;
                  while ((HAL_GetTick() - t0) < 4000) {
                    if (!pi_wait_line(line, sizeof(line), 400)) continue;
                    if (parse_ok_open(line, door_id,user_id )) { ok = 1; break; }
                  }
                  if (!ok) { uart("PI OK timeout\r\n"); continue; }
                }
                uart("DONE\r\n");
                uart("OPEN!\r\n");
                moveServo(SERVO_OPEN_PULSE);
                lastDetectTime=HAL_GetTick();
                HAL_Delay(40);
      }

    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_BYPASS;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV4;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief I2C2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_I2C2_Init(void)
{

  /* USER CODE BEGIN I2C2_Init 0 */

  /* USER CODE END I2C2_Init 0 */

  /* USER CODE BEGIN I2C2_Init 1 */

  /* USER CODE END I2C2_Init 1 */
  hi2c2.Instance = I2C2;
  hi2c2.Init.ClockSpeed = 100000;
  hi2c2.Init.DutyCycle = I2C_DUTYCYCLE_2;
  hi2c2.Init.OwnAddress1 = 0;
  hi2c2.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
  hi2c2.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
  hi2c2.Init.OwnAddress2 = 0;
  hi2c2.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
  hi2c2.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
  if (HAL_I2C_Init(&hi2c2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN I2C2_Init 2 */

  /* USER CODE END I2C2_Init 2 */

}

/**
  * @brief TIM2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_TIM2_Init(void)
{

  /* USER CODE BEGIN TIM2_Init 0 */

  /* USER CODE END TIM2_Init 0 */

  TIM_MasterConfigTypeDef sMasterConfig = {0};
  TIM_OC_InitTypeDef sConfigOC = {0};

  /* USER CODE BEGIN TIM2_Init 1 */

  /* USER CODE END TIM2_Init 1 */
  htim2.Instance = TIM2;
  htim2.Init.Prescaler = 84-1;
  htim2.Init.CounterMode = TIM_COUNTERMODE_UP;
  htim2.Init.Period = 19999;
  htim2.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;
  htim2.Init.AutoReloadPreload = TIM_AUTORELOAD_PRELOAD_DISABLE;
  if (HAL_TIM_PWM_Init(&htim2) != HAL_OK)
  {
    Error_Handler();
  }
  sMasterConfig.MasterOutputTrigger = TIM_TRGO_RESET;
  sMasterConfig.MasterSlaveMode = TIM_MASTERSLAVEMODE_DISABLE;
  if (HAL_TIMEx_MasterConfigSynchronization(&htim2, &sMasterConfig) != HAL_OK)
  {
    Error_Handler();
  }
  sConfigOC.OCMode = TIM_OCMODE_PWM1;
  sConfigOC.Pulse = 0;
  sConfigOC.OCPolarity = TIM_OCPOLARITY_HIGH;
  sConfigOC.OCFastMode = TIM_OCFAST_DISABLE;
  if (HAL_TIM_PWM_ConfigChannel(&htim2, &sConfigOC, TIM_CHANNEL_1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN TIM2_Init 2 */

  /* USER CODE END TIM2_Init 2 */
  HAL_TIM_MspPostInit(&htim2);

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 38400;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, TRIG1_Pin|LD2_Pin|TRIG2_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(RSTO_GPIO_Port, RSTO_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : B1_Pin */
  GPIO_InitStruct.Pin = B1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pins : TRIG1_Pin LD2_Pin TRIG2_Pin */
  GPIO_InitStruct.Pin = TRIG1_Pin|LD2_Pin|TRIG2_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  /*Configure GPIO pin : ECHO1_Pin */
  GPIO_InitStruct.Pin = ECHO1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(ECHO1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : ECHO2_Pin */
  GPIO_InitStruct.Pin = ECHO2_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(ECHO2_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : RSTO_Pin */
  GPIO_InitStruct.Pin = RSTO_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(RSTO_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : IRQ_Pin */
  GPIO_InitStruct.Pin = IRQ_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_PULLDOWN;
  HAL_GPIO_Init(IRQ_GPIO_Port, &GPIO_InitStruct);

  /* EXTI interrupt init*/
  HAL_NVIC_SetPriority(EXTI15_10_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(EXTI15_10_IRQn);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

// 필요시 추가
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
