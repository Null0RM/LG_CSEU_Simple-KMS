#include "../inc/mq.h"
#include "../inc/operation.h"

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

int mq_send(uint8_t *to_send, key_t key, int len, int oper_type)
{
    fprintf(stdout, "mq_send start\n");

    t_data  send_data;
    t_keys  session_key;
    uint8_t cipher[BUFFER_SIZE] = {};

    logging(len, to_send, ">>send_data_serial");

    session_key = get_session_key();
    send_data.data_type = oper_type;
    if (oper_type != OPERATION_FAILURE)
    {
        send_data.data_len = encrypt_operation(EVP_aes_128_cbc(), cipher, to_send, len, session_key.key, session_key.iv);
        memcpy(send_data.data_buf, cipher, send_data.data_len);
    }
    if (!do_mq_send(send_data, key))
    {
        fprintf(stderr, "mq_send:send failed\n");
        exit(1);
    }

    fprintf(stdout, "mq_send end\n");
    return EXIT_SUCCESS;
}
