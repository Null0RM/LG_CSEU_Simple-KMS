#include "../inc/operation.h"

int dec_payload(uint8_t *plainText, uint8_t *cipherText, int cipherText_len, t_keys keys) {
    printf("mq_recv:dec_payload() start\n");
    
    int len = 0;
    int final_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("mq_recv:EVP_CIPHER_CTX_new()");
        exit(1);
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keys.key, keys.iv)) {
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
    
    printf("mq_recv:dec_payload() end\n");
    return len;
}

t_keys get_session_key()
{
    printf("mq_recv:get_session_key() start\n");
    int     fd;
    t_keys  ret_key;
    uint8_t buffer[BUFFER_SIZE];
    uint8_t *idx;
     
    if ((fd = open("../security_data/session_key_list.txt", O_RDONLY)) < 0)
    {
        perror("mq_recv:open()");
        exit(1);
    }
    if (read(fd, buffer, BUFFER_SIZE) < 0)
    {
        perror("mq_recv:read()");
        exit(1);
    }
    idx = strstr(buffer, "key: ");
    strncpy(ret_key.key, idx, 16);
    idx = strstr(buffer, "iv: ");
    strncpy(ret_key.iv, idx, 16);

    close(fd);  
    printf("mq_recv:get_session_key() end\n");
    return (ret_key);
}

uint8_t *mq_recv_payload(key_t key, int *recv_len, int *oper_type)
{
    fprintf(stdout, "mq_recv:mq_recv_payload() start\n");

    int         msqid;
    t_data      recv_data;
    uint8_t     *cipherText = NULL;
    uint8_t     *newCipherText = NULL;
    int         prev_size = 0;

    cipherText = (uint8_t *)malloc(BUFFER_SIZE);
    if (!cipherText)
    {
        perror("mq_recv:malloc()");
        exit(1);
    }
    if (-1 == (msqid = msgget(key, IPC_CREAT | 0666)))
    {
        perror("mq_recv:msgget()");
        exit(1);
    }
    while (1)
    {
        printf("recvdata_len: %ld\n", sizeof(recv_data));
        if (-1 == (msgrcv(msqid, &recv_data, sizeof(recv_data) - sizeof(long), 0, 0)))
        {
            perror("mq_recv:msgrcv()");
            exit(1);
        }
        printf("recvddata_len: %ld\n", sizeof(recv_data));
        *oper_type = recv_data.data_type;
        newCipherText = (uint8_t *)realloc(cipherText, prev_size + recv_data.data_len);
        if (!newCipherText)
        {
            fprintf(stderr, "mq_recv:realloc() failed\n");
            exit(1);
        }
        cipherText = newCipherText;
        memcpy(&cipherText[prev_size], recv_data.data_buf, recv_data.data_len);
        prev_size += recv_data.data_len;

        if (recv_data.data_fin == 1)
        {
            *recv_len = prev_size;
            break;
        }
    }
    if (-1 == msgctl(msqid, IPC_RMID, 0))
    {
        perror("mq_recv:msgctl()");
        exit(1);
    }
    fprintf(stdout, "mq_recv:mq_recv_payload() end\n");

    return (cipherText);
}

void * mq_recv(key_t key, int *flag)
{
    printf("mq_recv start\n");

    int     recv_len = 0;
    int     oper_len = 0;
    int     oper_type = 0;
    t_keys  session_key;
    uint8_t *cipherText;
    uint8_t *operation;
    void    *struct_oper;
    
    session_key = get_session_key();
    cipherText = mq_recv_payload(key, &recv_len, flag);
    if (!cipherText)
    {
        perror("mq_recv:mq_recv_payload()");
        exit(1);
    }

    operation = (uint8_t *)malloc(recv_len + 1);
    if (!operation)
    {
        perror("mq_recv:malloc()");
        exit(1);
    }
    operation[recv_len] = '\0';
    oper_len = dec_payload(operation, cipherText, recv_len, session_key);
    free(cipherText);

    struct_oper = deserialize_tlv(operation, oper_len, *flag);
    free(operation);

    printf("mq_recv end\n");

    return (struct_oper);
}
