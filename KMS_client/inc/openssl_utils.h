#ifndef OPENSSL_UTILS_H
#define OPENSSL_UTILS_H

/* ___OPENSSL_LIBRARIES_START___ */
#include <openssl/evp.h>
#include <openssl/rand.h>
/* ___OPENSSL_LIBRARIES_END___ */

typedef struct s_keys
{
    uint8_t key[17];
    uint8_t iv[17];
} t_keys;

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 1024
#endif

/* ___FUNCTIONS_START___ */
int encrypt_operation(const EVP_CIPHER * algo_mode, uint8_t *plainText, uint8_t *cipherText, int plainText_len, uint8_t *key, uint8_t *iv);
int decrypt_operation(const EVP_CIPHER * algo_mode, uint8_t *plaintext, uint8_t *ciphertext, int ciphertext_len, uint8_t *key, uint8_t *iv);
int encrypt_payload(uint8_t *buffer, int buffer_len, uint8_t *to_send_data);
t_keys get_session_key(void);
/* ___FUNCTIONS_END___ */

#endif