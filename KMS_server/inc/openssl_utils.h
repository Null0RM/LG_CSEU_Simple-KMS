#ifndef OPENSSL_UTILS_H
#define OPENSSL_UTILS_H

#ifndef COMMON_H
#include "common.h"
#endif
/* ___OPENSSL_LIBRARIES_START___ */
#include <openssl/evp.h>
#include <openssl/rand.h>
/* ___OPENSSL_LIBRARIES_END___ */

typedef struct s_keys
{
    uint8_t key[16];
    uint8_t iv[16];
} t_keys;

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 1024
#endif

# ifndef OPERATION_FAILURE
#  define OPERATION_FAILURE 0x00000099
# endif
/* ___FUNCTION_START___ */

int encrypt_operation(const EVP_CIPHER *algo_mode, uint8_t *plainText, uint8_t *cipherText, int cipherText_len, uint8_t *key, uint8_t *iv);
int decrypt_operation(const EVP_CIPHER *algo_mode, uint8_t *plainText, uint8_t *cipherText, int cipherText_len, uint8_t *key, uint8_t *iv);
/* ___FUNCTION_END___ */

#endif