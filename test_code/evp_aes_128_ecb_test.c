#include "../KMS_server/inc/openssl_utils.h"
#include "../KMS_server/inc/common.h"

static uint8_t hard_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                                0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

uint8_t *encrypt(uint8_t *plainText, int plainText_len) {

    uint8_t *cipherText;   
    int len = 0;

    printf("key_derivation:encrypt_response() start\n");

    int cipherText_len = (plainText_len - plainText_len % 16 + 16 + 1);
    cipherText = (uint8_t *)malloc(cipherText_len * sizeof(uint8_t));
    if (!cipherText) {
        perror("malloc()");
        exit(1);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new()");
        exit(1);
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hard_key, NULL)) {
        perror("EVP_EncryptInit_ex()");
        exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainText_len)) {
        perror("EVP_EncryptUpdate()");
        exit(1);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len)) {
        perror("EVP_EncryptFinal_ex()");
        exit(-1);
    }

    EVP_CIPHER_CTX_free(ctx);

    printf("key_derivation:encrypt_response() end\n");

    return (cipherText);
}

uint8_t *decrypt(uint8_t *cipherText, int cipherText_len) {
    uint8_t *plainText;
    int len = 0;

    int plainText_len = (cipherText_len - cipherText_len % 16 + 16 + 1);
    plainText = (uint8_t *)malloc(plainText_len * sizeof(uint8_t));
    if (!plainText) {
        perror("malloc()");
        exit(1);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new()");
        exit(1);
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hard_key, NULL)) {
        perror("EVP_DecryptInit_ex()");
        exit(1);
    }

    if (1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherText_len)) {
        perror("EVP_DecryptUpdate()");
        exit(-1);
    }

    int final_len = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, plainText + len, &final_len)) {
        perror("EVP_DecryptFinal_ex()");
        exit(-1);
    }

    EVP_CIPHER_CTX_free(ctx);

    return plainText;
}

int main(void)
{
    uint8_t *plainText = malloc(50);
    strcpy(plainText, "aaaaaaaaaabbbbbbaaaaaaaaaabbbbbbccc");
    int plainText_len = strlen(plainText);
    printf("%s, len:%ld\n", plainText, strlen(plainText));

    char *cipher = encrypt(plainText, plainText_len);
    printf("%s, len(%ld)\n", cipher, strlen(cipher));     
    plainText = decrypt(cipher, strlen(cipher));
    printf("%s, len(%ld)\n", plainText, strlen(plainText));

    free(plainText);
}