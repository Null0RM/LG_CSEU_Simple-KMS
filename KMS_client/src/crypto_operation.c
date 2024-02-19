#include "../inc/openssl_utils.h"

int encrypt_operation(const EVP_CIPHER * algo_mode, uint8_t *plainText, uint8_t *cipherText, int plainText_len, uint8_t *key, uint8_t *iv) {
    fprintf(stdout, "crypto_operation:encrypt_payload() start\n");
    
    int len = 0;
    int final_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("crypto_operation:EVP_CIPHER_CTX_new()");
        exit(1);
    }
    if (1 != EVP_EncryptInit_ex(ctx, algo_mode, NULL, key, iv)) {
        perror("crypto_operation:EVP_EncryptInit_ex()");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, plainText, &len, cipherText, plainText_len)) {
        perror("crypto_operation:EVP_EncryptUpdate()");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, plainText + len, &final_len)) {
        perror("crypto_operation:EVP_EncryptFinal_ex()");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    len += final_len;
    EVP_CIPHER_CTX_free(ctx);
    
    fprintf(stdout, "crypto_operation:encrypt_payload() end\n");
    return len;
}

int decrypt_operation(const EVP_CIPHER * algo_mode, uint8_t *plaintext, uint8_t *ciphertext, int ciphertext_len, uint8_t *key, uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        perror("crypto_operation:decrypt_payload:EVP_CIPHER_CTX_new()");
        exit(1);
    }

    if(1 != EVP_DecryptInit_ex(ctx, algo_mode, NULL, key, iv))
    {
        perror("crypto_operation:decrypt_payload:EVP_DecryptInit_ex()");
        exit(1);
    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        perror("crypto_operation:decrypt_payload:EVP_DecryptUpdate()");
        exit(1);
    }
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        perror("crypto_operation:decrypt_payload:EVP_DecryptFinal_ex()");
        exit(1);
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}