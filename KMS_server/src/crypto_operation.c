#include "../inc/openssl_utils.h"

int encrypt_payload(const EVP_CIPHER * algo_mode, uint8_t *plainText, uint8_t *cipherText, int cipherText_len, uint8_t *key, uint8_t *iv) {
    fprintf(stdout, "mq_recv:encrypt_payload() start\n");
    
    int len = 0;
    int final_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("mq_recv:EVP_CIPHER_CTX_new()");
        exit(1);
    }
    if (1 != EVP_EncryptInit_ex(ctx, algo_mode, NULL, key, iv)) {
        perror("mq_recv:EVP_EncryptInit_ex()");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, plainText, &len, cipherText, cipherText_len)) {
        perror("mq_recv:EVP_EncryptUpdate()");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, plainText + len, &final_len)) {
        perror("mq_recv:EVP_EncryptFinal_ex()");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    len += final_len;
    EVP_CIPHER_CTX_free(ctx);
    
    fprintf(stdout, "mq_recv:encrypt_payload() end\n");
    return len;
}

int decrypt_payload(const EVP_CIPHER * algo_mode, uint8_t *plainText, uint8_t *cipherText, int cipherText_len, uint8_t *key, uint8_t *iv)
{
    printf("mq_recv:decrypt_payload() start\n");
    
    int len = 0;
    int final_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("mq_recv:EVP_CIPHER_CTX_new()");
        exit(1);
    }
    if (1 != EVP_DecryptInit_ex(ctx, algo_mode, NULL, key, iv)) {
        perror("mq_recv:EVP_DecryptInit_ex()");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    if (1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherText_len)) {
        perror("mq_recv:EVP_DecryptUpdate()");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plainText + len, &final_len)) {
        perror("mq_recv:EVP_DecryptFinal_ex()");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }
    len += final_len;
    EVP_CIPHER_CTX_free(ctx);
    
    printf("mq_recv:decrypt_payload() end\n");
    return len;
}
