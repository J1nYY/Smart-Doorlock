

int wifi_pop_bracket_line(char *out, int out_sz);

int starts_with(const char *s, const char *p);


int parse_chal_line(char *line,
                           uint32_t *door_id, uint32_t *user_id,
                           char *nonce, int nonce_sz,
                           uint32_t *exp);


int parse_ok_open(char *line, uint32_t door_id, uint32_t user_id);

void pi_send_line(const char *line_with_nl);

int pi_wait_line(char *out, int out_sz, uint32_t timeout_ms);
int base64url_encode(const uint8_t *in, size_t inlen, char *out, size_t outsz);
