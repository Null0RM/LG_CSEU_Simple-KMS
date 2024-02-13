#include "../inc/command_send.h"

void init_send_data(t_data *data)
{
    for(int i = 0; i < sizeof(data->data_buf); i++)
        data->data_buf[i] = 0;
}

int mq_send_createKey(t_operation *oper, key_t key)
{
    printf("mq_send:mq_send_createKey() start\n");
    
    int     msqid;
    uint8_t cipher[BUFFER_SIZE];
    t_data  send_data;

    init_send_data(&send_data);
    send_data.data_type = OPERATION_CREATEKEY;
    send_data.data_seq = 0;
    send_data.data_fin = 1;
    send_data.data_len = serialize(oper, cipher);
    for(int i = 0; i < BUFFER_SIZE; i++)
        send_data.data_buf[i] = 0;
    memcpy(send_data.data_buf, cipher, send_data.data_len);

    for(int i = 0; i < send_data.data_len; i++)
        printf("%02x ", cipher[i]);
    printf("\n");

    printf("senddata_len: %ld", sizeof(send_data));
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
    printf("mq_send:mq_send_createKey() end\n");

    return (COMMAND_SUCCESS);
}

int mq_send_encrypt(t_operation *oper, key_t key)
{
    printf("mq_send:mq_send_encrypt() start\n");
    
    printf("mq_send:mq_send_encrypt() end\n");
    return (COMMAND_SUCCESS);
}

int mq_send_decrypt(t_operation *oper, key_t key)
{
    printf("mq_send:mq_send_decrypt() start\n");

    printf("mq_send:mq_send_decrypt() end\n");
    return (COMMAND_SUCCESS);
}

int mq_send(t_operation *oper, key_t key)
{
    printf("mq_send start\n");

    int ret;

    if (oper->operation_type == OPERATION_CREATEKEY)
        ret = mq_send_createKey(oper, key);
    else if (oper->operation_type == OPERATION_ENCRYPT)
        ret = mq_send_encrypt(oper, key);
    else if (oper->operation_type == OPERATION_DECRYPT)
        ret = mq_send_decrypt(oper, key);
    else
    {
        printf("mq_send invalid operation type\n");
        exit(1);
    }
    printf("mq_send end\n");

    return (ret);
}

 