#include "../inc/command_send.h"
#include "../inc/openssl_utils.h"

static void    logging(int length, uint8_t * data, uint8_t * str)
{
    fprintf(stdout, "%s\n", str);
    for(int i = 0; i < length; i++)
        fprintf(stdout, "%02x ", data[i]);
    fprintf(stdout, "\n");
}

uint8_t * mq_recv_data(key_t key, int *recv_len, int *oper_type)
{
    // fprintf(stdout, "mq_recv:mq_recv_data() end\n");
    t_data  recv_data;
    int     msqid;
    uint8_t *cipherText;

    if (-1 == (msqid = msgget(key, IPC_CREAT | 0666)))
    {
        perror("mq_recv:msgget()");
        exit(1);
    }
    if (-1 == (msgrcv(msqid, &recv_data, sizeof(t_data) - sizeof(long), 0, 0)))
    {
        perror("mq_recv:msgrcv()");
        exit(1);
    }
    if (-1 == msgctl(msqid, IPC_RMID, 0))
    {
        perror("mq_recv:msgctl()");
        exit(1);
    }
    
    if (recv_data.data_type == OPERATION_FAILURE)
    {
        fprintf(stdout, "server operation failed\n");
        exit(1);
    }
    *oper_type = recv_data.data_type;
    *recv_len = recv_data.data_len;
    cipherText = (uint8_t *)malloc(sizeof(uint8_t) * *recv_len + 1);
    if (!cipherText)
    {
        perror("mq_recv:malloc()");
        exit(1);
    }
    cipherText[*recv_len] = '\0';
    memcpy(cipherText, recv_data.data_buf, *recv_len);

    // fprintf(stdout, "mq_recv:mq_recv_data() end\n");

    return cipherText;
}

int    mq_recv(key_t key)
{
    t_data  recv_data;
    t_keys  session_key;
    uint8_t *cipherText;
    uint8_t *plainText;
    int     cipher_len;
    int     oper_type;
    int     result_len;
    void    *result;

    cipherText = mq_recv_data(key, &cipher_len, &oper_type);
    if (!cipherText)
    {
        fprintf(stdout, "mq_recv:cipherText failed\n");
        exit(1);
    }
    plainText = (uint8_t *)malloc(sizeof(uint8_t) * cipher_len + 1);
    if (!plainText)
    {
        fprintf(stdout, "mq_recv:malloc()");
        exit(1);
    }
    plainText[cipher_len] = '\0';

    session_key = get_session_key();
    result_len = decrypt_operation(EVP_aes_128_cbc(), plainText, cipherText, cipher_len, session_key.key, session_key.iv);
    free(cipherText);
    
    if (deserialize_tlv(plainText, oper_type, result_len) == EXIT_FAILURE)
    {
        fprintf(stderr, "failed process");
        exit(EXIT_FAILURE);
    }
    free(plainText);
    
    return (EXIT_SUCCESS);
}
