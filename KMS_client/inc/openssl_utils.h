#ifndef OPENSSL_UTILS_H
# define OPENSSL_UTILS_H

/* ___OPENSSL_LIBRARIES_START___ */
#  include <openssl/evp.h>
#  include <openssl/rand.h>
/* ___OPENSSL_LIBRARIES_END___ */

typedef struct s_keys
{
    uint8_t key[16];
    uint8_t iv[16];
} t_keys;

#  ifndef BUFFER_SIZE
#   define BUFFER_SIZE 1024
#  endif

/* ___FUNCTIONS_START___ */

int encrypt_payload(uint8_t *buffer, int buffer_len, uint8_t *data);
t_keys get_session_key(void);
int do_encrypt_payload(uint8_t *plaintext, int plaintext_len, uint8_t *key, uint8_t *iv, uint8_t *ciphertext);
/* ___FUNCTIONS_END___ */

#endif