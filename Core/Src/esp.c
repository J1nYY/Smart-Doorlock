//서울기술교육센터 AIOT & Embedded System
//2024-04-16 By KSH
//Updated for Motor Project (UART1 for ESP)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"  // [중요] HAL 및 핀 정의 포함
#include "esp.h"

// --- 전역 변수 및 핸들러 선언 ---
static char ip_addr[16];
static char response[MAX_ESP_RX_BUFFER];


char g_user_email[EMAIL_MAX] = {0};
uint8_t g_user_email_len = 0;
// UART 핸들러 (main.c에 정의된 것을 가져옴)
extern UART_HandleTypeDef huart1; // ESP-01 (WiFi)
extern UART_HandleTypeDef huart2; // PC Debug

// 수신 버퍼 관련 변수
volatile unsigned char rx2Flag = 0;
volatile char rx2Data[50];
uint8_t cdata; // UART2 수신용 1바이트

static uint8_t data; // UART1 수신용 1바이트
cb_data_t cb_data;   // ESP 수신 데이터 구조체

// ----------------------------------------------------------------
// 내부 함수 (Static)
// ----------------------------------------------------------------

static int esp_at_command(uint8_t *cmd, uint8_t *resp, uint16_t *length, int16_t time_out)
{
    *length = 0;
    memset(resp, 0x00, MAX_UART_RX_BUFFER);
    memset(&cb_data, 0x00, sizeof(cb_data_t));

    // [수정] huart1 사용
    if(HAL_UART_Transmit(&huart1, (uint8_t*)cmd, strlen((char *)cmd), 100) != HAL_OK)
        return -1;

    while(time_out > 0)
    {
        if(cb_data.length >= MAX_UART_RX_BUFFER)
            return -2;
        else if(strstr((char *)cb_data.buf, "ERROR") != NULL)
            return -3;
        else if(strstr((char *)cb_data.buf, "OK") != NULL)
        {
            memcpy(resp, cb_data.buf, cb_data.length);
            *length = cb_data.length;
            return 0;
        }
        time_out -= 10;
        HAL_Delay(10);
    }
    return -4;
}

static int esp_reset(void)
{
    uint16_t length = 0;
    if(esp_at_command((uint8_t *)"AT+RST\r\n", (uint8_t *)response, &length, 1000) != 0)
    {
    	return -1;
    }
    else
    	HAL_Delay(500);	// reboot 대기
    return 0;
}

static int esp_get_ip_addr(uint8_t is_debug)
{
    if(strlen(ip_addr) != 0)
    {
        if(strcmp(ip_addr, "0.0.0.0") == 0)
            return -1;
    }
    else
    {
        uint16_t length;
        if(esp_at_command((uint8_t *)"AT+CIPSTA?\r\n", (uint8_t *)response, &length, 1000) != 0)
            printf("ip_state command fail\r\n");
        else
        {
            char *line = strtok(response, "\r\n");

            if(is_debug)
            {
                for(int i = 0 ; i < length ; i++)
                    printf("%c", response[i]);
            }

            while(line != NULL)
            {
                if(strstr(line, "ip:") != NULL)
                {
                    char *ip;

                    strtok(line, "\"");
                    ip = strtok(NULL, "\"");
                    if(strcmp(ip, "0.0.0.0") != 0)
                    {
                        memset(ip_addr, 0x00, sizeof(ip_addr));
                        memcpy(ip_addr, ip, strlen(ip));
                        return 0;
                    }
                }
                line = strtok(NULL, "\r\n");
            }
        }
        return -1;
    }
    return 0;
}

static int request_ip_addr(uint8_t is_debug)
{
    uint16_t length = 0;

    if(esp_at_command((uint8_t *)"AT+CIFSR\r\n", (uint8_t *)response, &length, 1000) != 0)
        printf("request ip_addr command fail\r\n");
    else
    {
        char *line = strtok(response, "\r\n");

        if(is_debug)
        {
            for(int i = 0 ; i < length ; i++)
                printf("%c", response[i]);
        }

        while(line != NULL)
        {
            if(strstr(line, "CIFSR:STAIP") != NULL)
            {
                char *ip;

                strtok(line, "\"");
                ip = strtok(NULL, "\"");
                if(strcmp(ip, "0.0.0.0") != 0)
                {
                    memset(ip_addr, 0x00, sizeof(ip_addr));
                    memcpy(ip_addr, ip, strlen(ip));
                    return 0;
                }
            }
            line = strtok(NULL, "\r\n");
        }
    }
    return -1;
}

// ----------------------------------------------------------------
// 외부 공개 함수
// ----------------------------------------------------------------
int parse_ch_email_and_store(const uint8_t *resp, uint8_t rlen) {
  // 최소: 'c''h' + SW(2)
  if (rlen < 4) return 0;

  // SW 체크
  if (resp[rlen - 2] != 0x90 || resp[rlen - 1] != 0x00) return 0;

  uint8_t dlen = (uint8_t)(rlen - 2);   // payload 길이
  if (dlen < 2) return 0;

  // prefix "ch"
  if (resp[0] != 'c' || resp[1] != 'h') return 0;

  uint8_t emlen = (uint8_t)(dlen - 2);  // 이메일 길이
  if (emlen >= EMAIL_MAX) emlen = EMAIL_MAX - 1;

  memcpy(g_user_email, &resp[2], emlen);
  g_user_email[emlen] = '\0';
  g_user_email_len = emlen;

  // (선택) 최소 검증: '@' 포함 여부
  if (strchr(g_user_email, '@') == NULL) {
    // 이메일이 아닐 수도 있으니 필요하면 실패 처리
    // return 0;
  }

  return 1;
}
int esp_client_conn()
{
	char at_cmd[MAX_ESP_COMMAND_LEN] = {0, };
    uint16_t length = 0;
    // esp.h에 정의된 DST_IP, DST_PORT 사용
	sprintf(at_cmd,"AT+CIPSTART=\"TCP\",\"%s\",%d\r\n", DST_IP, DST_PORT);
	esp_at_command((uint8_t *)at_cmd,(uint8_t *)response, &length, 1000);

    // 로그인 정보 전송
	esp_send_data("["LOGID":"PASSWD"]");
	return 0;
}

int esp_get_status()
{
	uint16_t length = 0;
	esp_at_command((uint8_t *)"AT+CIPSTATUS\r\n",(uint8_t *)response, &length, 1000);

    if(strstr((char *)response, "STATUS:3") != NULL)
    {
    	return 0; // Connected
    }
	return -1;
}

int drv_esp_init(void)
{
    memset(ip_addr, 0x00, sizeof(ip_addr));
    // [수정] huart1 인터럽트 시작
    HAL_UART_Receive_IT(&huart1, &data, 1);

    return esp_reset();
}

void reset_func()
{
	printf("esp reset... ");
	if(esp_reset() == 0)
			printf("OK\r\n");
	else
			printf("fail\r\n");
}

void version_func()
{
  uint16_t length = 0;
  printf("esp firmware version\r\n");
  if(esp_at_command((uint8_t *)"AT+GMR\r\n", (uint8_t *)response, &length, 1000) != 0)
      printf("ap scan command fail\r\n");
  else
  {
      for(int i = 0 ; i < length ; i++)
          printf("%c", response[i]);
  }
}

void ap_conn_func(char *ssid, char *passwd)
{
  uint16_t length = 0;
  char at_cmd[MAX_ESP_COMMAND_LEN] = {0, };
  if(ssid == NULL || passwd == NULL)
  {
      printf("invalid command : ap_conn <ssid> <passwd>\r\n");
      return;
  }
  if(esp_at_command((uint8_t *)"AT+CWMODE=1\r\n", (uint8_t *)response, &length, 1000) != 0)
      printf("Station mode fail\r\n");
  sprintf(at_cmd, "AT+CWJAP=\"%s\",\"%s\"\r\n", ssid,passwd);
  if(esp_at_command((uint8_t *)at_cmd, (uint8_t *)response, &length, 6000) != 0)
      printf("ap scan command fail : %s\r\n",at_cmd);
}

void ip_state_func()
{
  uint16_t length = 0;
  if(esp_at_command((uint8_t *)"AT+CWJAP?\r\n", (uint8_t *)response, &length, 1000) != 0)
      printf("ap connected info command fail\r\n");
  else
  {
      for(int i = 0 ; i < length ; i++)
          printf("%c", response[i]);
  }
  printf("\r\n");

  if(esp_get_ip_addr(1) == 0)
      printf("ip_addr = [%s]\r\n", ip_addr);
}

// ----------------------------------------------------------------
// 인터럽트 콜백 (데이터 수신)
// ----------------------------------------------------------------
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
    // [수정] USART1 (ESP) 데이터 수신
    if(huart->Instance == USART1)
    {
        if(cb_data.length < MAX_ESP_RX_BUFFER)
        {
            cb_data.buf[cb_data.length++] = data;
        }
        HAL_UART_Receive_IT(huart, &data, 1);
    }
    // [수정] USART2 (Debug/PC) 데이터 수신
    else if(huart->Instance == USART2)
    {
    	static int i=0;
    	rx2Data[i] = cdata;
    	if(rx2Data[i] == '\r')
    	{
    		rx2Data[i] = '\0';
    		rx2Flag = 1;
    		i = 0;
    	}
    	else
    	{
    		i++;
    	}
    	HAL_UART_Receive_IT(huart, &cdata,1);
    }
}

void AiotClient_Init()
{
//	reset_func();
//	version_func();
    // esp.h에 정의된 SSID, PASS 사용
	ap_conn_func(SSID, PASS);
//	ip_state_func();
	request_ip_addr(1);
	esp_client_conn();
	esp_get_status();
}

void esp_send_data(char *data)
{
	char at_cmd[MAX_ESP_COMMAND_LEN] = {0, };
	uint16_t length = 0;
	sprintf(at_cmd,"AT+CIPSEND=%d\r\n",strlen(data));
	if(esp_at_command((uint8_t *)at_cmd,(uint8_t *)response, &length, 1000) == 0)
	{
		esp_at_command((uint8_t *)data,(uint8_t *)response, &length, 1000);
	}
}

// ----------------------------------------------------------------
// UART2 (PC Debug) 관련 함수
// ----------------------------------------------------------------
int drv_uart_init(void)
{
    HAL_UART_Receive_IT(&huart2, &cdata, 1);
    return 0;
}

int drv_uart_tx_buffer(uint8_t *buf, uint16_t size)
{
    if(HAL_UART_Transmit(&huart2, buf, size, 100) != HAL_OK)
        return -1;

    return 0;
}

// printf 사용을 위한 재정의
int __io_putchar(int ch)
{
    if(HAL_UART_Transmit(&huart2, (uint8_t *)&ch, 1, 10) == HAL_OK)
        return ch;
    return -1;
}
