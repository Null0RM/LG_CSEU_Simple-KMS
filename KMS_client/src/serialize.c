#include "../inc/command_send.h"
#include "../inc/openssl_utils.h"

void    serialize_createKey(t_operation *oper, uint8_t *buffer)
{
    printf("serialize:serialize_createKey() start\n");
    size_t      size = sizeof(oper);
    t_createKey *createKey = oper->operation_buf;
    int         idx = 0;

    buffer[idx++] = TYPE_ISMAC;
    buffer[idx++] = sizeof(int);
    memcpy(buffer + idx, &(createKey->createKey_isMAC), sizeof(int));
    idx += sizeof(int);

    buffer[idx++] = TYPE_ALGO;
    buffer[idx++] = sizeof(int);
    memcpy(buffer + idx, &(createKey->createKey_algo), sizeof(int));
    idx += sizeof(int);

    buffer[idx++] = TYPE_MODE;
    buffer[idx++] = sizeof(int);
    memcpy(buffer + idx, &(createKey->createKey_mode), sizeof(int));
    idx += sizeof(int);

    oper->operation_len = idx;

    printf("serialize:serialize_createKey() end\n");
}

int serialize(t_operation *oper, uint8_t *cipher)
{
    printf("serialize start\n");

    uint8_t buffer[BUFFER_SIZE];
    int     ret;
    if (oper->operation_type == OPERATION_CREATEKEY)
    {
        serialize_createKey(oper, buffer);
        ret = encrypt_payload(cipher, buffer, oper->operation_len);
        for(int i = 0; i < oper->operation_len; i++)
            printf("%02x ", buffer[i]);
        printf("\n");
    }
    else if (oper->operation_type == OPERATION_ENCRYPT)
    {

    }
    else if (oper->operation_type == OPERATION_DECRYPT)
    {

    }
    else
    {
        //error
    }

    printf("serialize end\n");

    return (ret);
}
