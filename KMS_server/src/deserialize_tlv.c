#include "../inc/operation.h"

t_operation *deserialize_createKey(uint8_t *data, int   oper_len)
{
    printf("deserialize:deserialize_createKey() start\n");

    t_createKey *createKey = malloc(sizeof(t_createKey));
    int idx = 0;

    while (idx < oper_len) {
        uint16_t type = *(uint16_t *)(data + idx);
        idx += 2;
        uint32_t length = *(uint32_t *)(data + idx);
        idx += 4;

        switch (type) {
            case TYPE_ISMAC:
                createKey->createKey_isMAC = *(int *)(data + idx);
                break;
            case TYPE_ALGO:
                createKey->createKey_algo = *(int *)(data + idx);
                break;
            case TYPE_MODE:
                createKey->createKey_mode = *(int *)(data + idx);
                break;
            default:
                printf("Unknown type: %d\n", type);
                break;
        }

        idx += length;
    }

    t_operation *oper = malloc(sizeof(t_operation));
    oper->operation_buf = createKey;
    oper->operation_len = idx;
    oper->operation_type = OPERATION_CREATEKEY;

    printf("deserialize:deserialize_createKey() end\n");

    return oper;
}

t_operation *deserialize_enc_dec(uint8_t *data, int   oper_len, int oper_type)
{
    fprintf(stdout, "deserialize:deserialize_enc_dec() start\n");

    t_enc_dec *enc_dec = malloc(sizeof(t_enc_dec));
    int idx = 0;

    while (idx < oper_len) {
        uint16_t type = *(uint16_t *)(data + idx);
        idx += 2;
        uint32_t length = *(uint32_t *)(data + idx);
        idx += 4;

        printf("type: %hd\n", type);
        switch (type) {
            case TYPE_ISMAC:
                enc_dec->enc_dec_isMAC = *(int *)(data + idx);
                break;
            case TYPE_ALGO:
                enc_dec->enc_dec_algo = *(int *)(data + idx);
                break;
            case TYPE_MODE:
                enc_dec->enc_dec_mode = *(int *)(data + idx);
                break;
            case TYPE_KEY:
                if (enc_dec->enc_dec_algo == ALGO_AES128)
                {
                    enc_dec->key = (uint8_t *)malloc(17);
                    memcpy(enc_dec->key, data + idx, 16);
                    enc_dec->key[16] = '\0';
                }    
                else
                {
                    enc_dec->key = (uint8_t *)malloc(33);
                    memcpy(enc_dec->key, data + idx, 32);
                    enc_dec->key[32] = '\0';
                }   
                break;
            case TYPE_IV:
                if (enc_dec->enc_dec_isMAC == ISMAC_HMAC)
                    enc_dec->iv = NULL;
                else
                {
                    enc_dec->iv = (uint8_t *)malloc(17);
                    memcpy(enc_dec->iv, data + idx, 16);
                    enc_dec->iv[16] = '\0';
                }      
                break;
            case TYPE_INPUT_DATA:
                {
                    enc_dec->data_len = oper_len - idx;
                    printf("data_len : %d\n", enc_dec->data_len);
                    enc_dec->input_data = (uint8_t *)malloc(enc_dec->data_len + 1);
                    memcpy(enc_dec->input_data, data + idx, enc_dec->data_len);
                    enc_dec->input_data[enc_dec->data_len] = '\0';
                }
                break;
            default:
                printf("Unknown type: %d\n", type);
                break;
        }

        idx += length;
    }

    t_operation *oper = malloc(sizeof(t_operation));
    oper->operation_buf = enc_dec;
    oper->operation_len = idx;
    oper->operation_type = oper_type;
    
    //logging
    t_enc_dec *tmp = (t_enc_dec *)malloc(sizeof(t_enc_dec));
    tmp = (t_enc_dec *)(oper->operation_buf);
    logging(enc_dec->data_len, tmp->input_data, ">> operation_enc_dec: ");

    fprintf(stdout, "deserialize:deserialize_enc_dec() end\n");
    return oper;
}

void    *deserialize_tlv(uint8_t *oper, int oper_len, int oper_type)
{
    fprintf(stdout, "deserialize start\n");
    int     idx = 0;
    int     data_len;
    uint8_t type;
    void * struct_oper = NULL;

    if (oper_type == OPERATION_CREATEKEY)
        struct_oper = deserialize_createKey(oper, oper_len);
    else if (oper_type == OPERATION_ENCRYPT || oper_type == OPERATION_DECRYPT)
        struct_oper = deserialize_enc_dec(oper, oper_len, oper_type);
    else
    {
        fprintf(stdout, "Invalid oper_type\n");
        exit(1);
    }
    
    fprintf(stdout, "deserialize end\n");

    return (struct_oper);
}
