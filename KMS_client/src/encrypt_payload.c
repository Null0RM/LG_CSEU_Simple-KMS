#include "../inc/openssl_utils.h"
#include "../inc/common.h"

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
    memcpy(ret_key.key, idx + 5, 16);
    ret_key.key[16] = '\0';
    idx = strstr(buffer, "iv: ");
    memcpy(ret_key.iv, idx + 4, 16);
    ret_key.iv[16] = '\0';

    close(fd);
    printf("encrypt_payload:get_session_key() end\n");
    return (ret_key);
}

int encrypt_payload(uint8_t *buffer, int buffer_len, uint8_t *to_send_data)
{
    printf("encrypt_payload: start\n"); 
    
    int ret;
    t_keys session_key = get_session_key();
    ret = encrypt_operation(EVP_aes_128_cbc(), buffer, to_send_data, buffer_len, session_key.key, session_key.iv);
    printf("encrypt_payload: end\n");
    return ret;
}
