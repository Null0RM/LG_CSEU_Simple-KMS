#include "../inc/openssl_utils.h"
#include "../inc/common.h"

int do_encrypt_payload(uint8_t *cipherText, uint8_t *plainText, int plainText_len, t_keys keys) 
{
    printf("encrypt_payload:do_encrypt_payload() start\n");

    int len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("encrypt_payload:EVP_CIPHER_CTX_new()");
        exit(1);
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keys.key, keys.iv)) {
        perror("encrypt_payload:EVP_EncryptInit_ex()");
        exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainText_len)) {
        perror("encrypt_payload:EVP_EncryptUpdate()");
        exit(1);
    }

    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &final_len)) {
        perror("encrypt_payload:EVP_EncryptFinal_ex()");
        exit(-1);
    }
    len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    printf("encrypt_payload:do_encrypt_payload() end\n");

    return len;
}

t_keys get_session_key(void)
{
    printf("encrypt_payload:get_session_key() start\n");
    int     fd;
    t_keys  ret_key;
    uint8_t buffer[BUFFER_SIZE];
    uint8_t *idx;
    
    if ((fd = open("../recvd/sessionKey.txt", O_RDONLY)) < 0)
    {
        perror("encrypt_paylaod:open()");
        exit(1);
    }
    if (read(fd, buffer, BUFFER_SIZE) < 0)
    {
        perror("encrypt_payload:read()");
        exit(1);
    }
    idx = strstr(buffer, "key: ");
    strncpy(ret_key.key, idx, 16);
    idx = strstr(buffer, "iv: ");
    strncpy(ret_key.iv, idx, 16);

    close(fd);
    printf("encrypt_payload:get_session_key() end\n");
    return (ret_key);
}

int encrypt_payload(uint8_t * cipherText, uint8_t * buffer, int buffer_len)
{
    printf("encrypt_payload: start\n"); 
    
    int ret;
    t_keys session_key = get_session_key();
    
    ret = do_encrypt_payload(cipherText, buffer, buffer_len, session_key);

    printf("encrypt_payload: end\n");
    
    return ret;
}
