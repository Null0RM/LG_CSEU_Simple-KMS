#include "../inc/command_send.h"

void init_send_data(t_data *data)
{
    for(int i = 0; i < sizeof(data->data_buf); i++)
        data->data_buf[i] = 0;
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

int mq_send(uint8_t *payload, int payload_len, key_t key)
{
    printf("mq_send start\n");

    encrypt_payload(payload);
    printf("mq_send end\n");
}
