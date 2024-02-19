#include "../inc/mq.h"
#include "../inc/operation.h"


int do_encrypt_data(uint8_t *cipherText, uint8_t *plainText, int plainText_len, t_keys keys) 
{
    printf("mq_send:do_encrypt_data() start\n");

    int len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("mq_send:EVP_CIPHER_CTX_new()");
        exit(1);
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keys.key, keys.iv)) {
        perror("mq_send:EVP_EncryptInit_ex()");
        exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainText_len)) {
        perror("mq_send:EVP_EncryptUpdate()");
        exit(1);
    }

    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &final_len)) {
        perror("mq_send:EVP_EncryptFinal_ex()");
        exit(-1);
    }
    len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    printf("mq_send:do_encrypt_data() end\n");

    return len;
}   

int do_mq_send(t_data send_data, key_t key)
{
    int msqid;

    if (-1 == (msqid = msgget(key, IPC_CREAT | 0666)))
    {
        perror("mq_send:msgget()");
        exit(1);
    }
    if (-1 == msgsnd(msqid, &send_data, sizeof(t_data) - sizeof(long), 0))
    {
        perror("mq_send:msgsnd()");
        exit(1);
    }

    return 1;
}

int mq_send(uint8_t *to_send, key_t key, int len)
{
    fprintf(stdout, "mq_send start\n");

    t_data  send_data;
    t_keys  session_key;
    uint8_t cipher[BUFFER_SIZE] = {};

    session_key = get_session_key();
    send_data.data_type = OPERATION_CREATEKEY;
    send_data.data_len = encrypt_operation(EVP_aes_128_cbc(), to_send, cipher, len, session_key.key, session_key.iv);
    memcpy(send_data.data_buf, cipher, send_data.data_len);
    if (!do_mq_send(send_data, key))
    {
        fprintf(stderr, "mq_send:send failed\n");
        exit(1);
    }

    fprintf(stdout, "mq_send end\n");
    return EXIT_SUCCESS;
}
