#include "../inc/command_send.h"

int mq_send_data(t_data *data, key_t key)
{
    int msqid;

    fprintf(stdout, "data.data_type: %ld\n", data->data_type);
    fprintf(stdout, "data.data_seq: %d\n", data->data_seq);
    fprintf(stdout, "data.data_len: %d\n", data->data_len);
    fprintf(stdout, "data.data_fin: %d\n", data->data_fin);
    if (-1 == (msqid = msgget(key, IPC_CREAT | 0666)))
    {
        perror("mq_send:mq_send_data:msgget()");
        exit(1);
    }
    if (-1 == msgsnd(msqid, data, sizeof(data) - sizeof(long), 0))
    {
        perror("mq_send:mq_send_data:msgsnd()");
        exit(1);
    }

    return EXIT_SUCCESS;
}

int mq_send(uint8_t *payload, int payload_len, int flag, key_t key)
{
    printf("mq_send start\n");
    t_data send_data;
    uint8_t buffer[BUFFER_SIZE];
    int cpy_len = BUFFER_SIZE;

    send_data.data_type = flag;
    send_data.data_seq = 0;
    send_data.data_fin = 0;
    while (payload_len > 0)
    {
        if (BUFFER_SIZE >= payload_len)
        {
            cpy_len = payload_len;
            send_data.data_fin = 1;
        }
        memcpy(buffer, payload + BUFFER_SIZE * send_data.data_seq, cpy_len);
        send_data.data_len = encrypt_payload(buffer, cpy_len, send_data.data_buf);
        if (!mq_send_data(&send_data, key))
        {
            fprintf(stderr, "mq_send:mq_send_data:failed\n");
            exit(1);
        }
        payload_len -= BUFFER_SIZE;
        send_data.data_seq++;
    }

    printf("mq_send end\n");
}
