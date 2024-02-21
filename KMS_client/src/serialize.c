#include "../inc/command_send.h"
#include "../inc/openssl_utils.h"

void storeLE16(uint8_t *buffer, uint16_t value) {
    buffer[0]= value & 0xFF;
    buffer[1]= (value >> 8) & 0xFF;
}

void storeLE32(uint8_t *buffer, uint32_t value) {
    buffer[0]= value & 0xFF;
    buffer[1]= (value >> 8) & 0xFF;
    buffer[2]= (value >> 16) & 0xFF;
    buffer[3]= (value >> 24) & 0xFF;
}

uint8_t *serialize_createKey(t_operation *oper, uint8_t *ret)
{
    // printf("serialize:serialize_createKey() start\n");

    t_createKey *createKey = oper->operation_buf;
    int         idx = 0;

    storeLE16(ret + idx, TYPE_ISMAC);
    idx += 2;
    storeLE32(ret + idx, sizeof(int));
    idx += 4;
    memcpy(ret + idx, &(createKey->createKey_isMAC), sizeof(int));
    idx += sizeof(int);

    storeLE16(ret + idx, TYPE_ALGO);
    idx += 2;
    storeLE32(ret + idx, sizeof(int));
    idx += 4;
    memcpy(ret + idx, &(createKey->createKey_algo), sizeof(int));
    idx += sizeof(int);

    storeLE16(ret + idx, TYPE_MODE);
    idx += 2;
    storeLE32(ret + idx, sizeof(int));
    idx += 4;
    memcpy(ret + idx, &(createKey->createKey_mode), sizeof(int));
    idx += sizeof(int);
    
    oper->operation_len = idx;

    // printf("serialize:serialize_createKey() end\n");
}   

void    serialize_enc_dec(t_operation *oper, uint8_t *ret)
{
    // printf("serialize:serialize_createKey() start\n");
    t_enc_dec *enc_dec = oper->operation_buf;
    int idx = 0;

    storeLE16(ret + idx, TYPE_ISMAC);
    idx += 2;
    storeLE32(ret + idx, sizeof(int));
    idx += 4;
    memcpy(ret + idx, &(enc_dec->enc_dec_isMAC), sizeof(int));
    idx += sizeof(int);

    storeLE16(ret + idx, TYPE_ALGO);
    idx += 2;
    storeLE32(ret + idx, sizeof(int));
    idx += 4;
    memcpy(ret + idx, &(enc_dec->enc_dec_algo), sizeof(int));
    idx += sizeof(int);

    storeLE16(ret + idx, TYPE_MODE);
    idx += 2;
    storeLE32(ret + idx, sizeof(int));
    idx += 4;
    memcpy(ret + idx, &(enc_dec->enc_dec_mode), sizeof(int));
    idx += sizeof(int);

    storeLE16(ret + idx, TYPE_KEY);
    idx += 2;
    storeLE32(ret + idx, enc_dec->key_len);
    idx += 4;
    memcpy(ret + idx, enc_dec->key, enc_dec->key_len);
    idx += enc_dec->key_len;

    storeLE16(ret + idx, TYPE_IV);
    idx += 2;
    storeLE32(ret + idx, 16);
    idx += 4;
    memcpy(ret + idx, enc_dec->iv, 16);
    idx += 16;

    storeLE16(ret + idx, TYPE_INPUT_DATA);
    idx += 2;
    storeLE32(ret + idx, enc_dec->data_len);
    idx += 4;
    memcpy(ret + idx, enc_dec->input_data, enc_dec->data_len);
    idx += enc_dec->data_len;

    // clear allocated data
    free(enc_dec->key);
    free(enc_dec->iv);
    free(enc_dec->input_data);
    free(oper->operation_buf);

    // printf("serialize:serialize_createKey() end\n");
}

uint8_t *serialize(t_operation *oper, int payload_len)
{
    // printf("serialize start\n");

    uint8_t *ret;
    
    ret = (uint8_t *)malloc(payload_len);
    if (!ret)
    {
        perror("serialize:malloc()");
        exit(1);
    }

    if (oper->operation_type == OPERATION_CREATEKEY)
        serialize_createKey(oper, ret);
    else if (oper->operation_type == OPERATION_ENCRYPT || oper->operation_type == OPERATION_DECRYPT)
        serialize_enc_dec(oper, ret);

    // printf("serialize end\n");

    return (ret);
}
