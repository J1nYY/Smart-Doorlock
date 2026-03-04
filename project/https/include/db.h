#pragma once

#include <mysql.h>

MYSQL *db_connect(void);

int db_check_session(MYSQL *db, const char *session_token, unsigned long long *user_id_out);

int db_issue_guest_token(MYSQL *db,
                         unsigned long long issuer_user_id,
                         const char *guest_label_or_null,
                         int valid_minutes,
                         int max_uses,
                         const char *ticket_id,
                         const unsigned char token_hash[32]);

int db_get_token_hash_by_ticket(MYSQL *db, const char *ticket_id, unsigned char out_hash[32]);

int db_create_door_nonce(MYSQL *db, long long door_id,
                         const unsigned char nonce_hash[32],
                         int ttl_seconds);

int db_consume_token_and_nonce(MYSQL *db,
                               const unsigned char token_hash[32],
                               long long door_id,
                               const unsigned char nonce_hash[32],
                               long long *token_id_out,
                               const char **deny_reason_out);
void db_log(MYSQL *db, long long token_id_or_0, const char *result,
            const char *reason, const char *ip_or_null);

int db_verify_and_consume(MYSQL *db, const unsigned char token_hash[32],
                          long long *token_id_out, const char **deny_reason_out);

int db_create_user(MYSQL *db,
                   const char *email,
                   const char *name,
                   const unsigned char pw_salt[16],
                   const unsigned char pw_hash[32],
                   int pw_iter);

int db_get_user_auth_by_email(MYSQL *db,
                              const char *email,
                              unsigned long long *user_id_out,
                              unsigned char pw_salt_out[16],
                              unsigned char pw_hash_out[32],
                              int *pw_iter_out);

int db_create_session(MYSQL *db,
                      unsigned long long user_id,
                      const unsigned char session_hash[32],
                      int expires_seconds);
int db_get_user_role(MYSQL *db, unsigned long long user_id, char *role_out, size_t role_out_sz);

int db_get_active_pubkey_spki(MYSQL *db, unsigned long long user_id,
                              unsigned char *out, size_t out_cap, size_t *out_len);

int db_consume_door_nonce(MYSQL *db, long long door_id,
                          const unsigned char nonce_hash[32],
                          const char **deny_reason_out);

int db_insert_user_key(MYSQL *db,
                       unsigned long long user_id,
                       const char *key_name_or_null,
                       const unsigned char *spki, size_t spki_len);

int db_revoke_user_key(MYSQL *db,
                       unsigned long long user_id,
                       long long key_id);

int db_list_user_keys_json(MYSQL *db,
                           unsigned long long user_id,
                           char *out, size_t outsz);
int db_delete_session(MYSQL *db, const char *session_token);
int db_delete_all_sessions(MYSQL *db, unsigned long long user_id, int *deleted_out);
int db_fetch_latest_door_nonce_for_update(MYSQL *db, long long door_id,
                                         long long *nonce_row_id_out,
                                         unsigned char out_nonce_hash[32],
                                         const char **deny_reason_out);

int db_mark_door_nonce_used(MYSQL *db, long long nonce_row_id,
                            const char **deny_reason_out);

int db_get_user_id_by_email(MYSQL *db, const char *email, unsigned long long *user_id_out);
int db_get_name_by_user_id(MYSQL *db,unsigned long long user_id,char *name_out);