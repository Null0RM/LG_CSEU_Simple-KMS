#include "../inc/operation.h"

void    *deserialize_tlv(uint8_t *oper, int oper_len, int oper_type)
{
    fprintf(stdout, "deserialize start\n");
    int     idx = 0;
    int     data_len;
    uint8_t type;
    void    *struct_oper = NULL;

    if (oper_type == OPERATION_CREATEKEY)
    {
        t_createKey *tmp = (t_createKey *)malloc(sizeof(t_createKey));
        if (!tmp)
        {
            fprintf(stderr, "deserialize_tlv:malloc()");
            exit(1);
        }
        struct_oper = tmp;

        while (idx < oper_len)
        {
            type = oper[idx++];

            if (type == TYPE_ISMAC) {
                data_len = oper[idx++];
                memcpy(&tmp->createKey_isMAC, oper + idx, data_len);
                idx += data_len;
            }
            else if (type == TYPE_ALGO){
                data_len = oper[idx++];
                memcpy(&tmp->createKey_algo, oper + idx, data_len);
                idx += data_len;
            }
            else if (type == TYPE_MODE){
                data_len = oper[idx++];
                memcpy(&tmp->createKey_mode, oper + idx, data_len);
                idx += data_len;
            }
        }
    }
    else if (oper_type == OPERATION_ENCRYPT || oper_type == OPERATION_DECRYPT)
    {
        t_enc_dec *tmp = (t_enc_dec *)malloc(sizeof(t_enc_dec));
        if (!tmp)
        {
            perror("deserialize_tlv:malloc()");
            exit(1);
        }
        struct_oper = tmp;
        
        while (idx < oper_len)
        {
            type = oper[idx++];

            switch(type)
            {
                case TYPE_ISMAC:
                    data_len = oper[idx++];
                    memcpy(&tmp->enc_dec_isMAC, oper + idx, data_len);
                    idx += data_len;
                    break;
                case TYPE_ALGO:
                    data_len = oper[idx++];
                    memcpy(&tmp->enc_dec_algo, oper + idx, data_len);
                    idx += data_len;
                    break;                
                case TYPE_MODE:
                    data_len = oper[idx++];
                    memcpy(&tmp->enc_dec_mode, oper + idx, data_len);
                    idx += data_len;
                    break;                
                case TYPE_KEY:
                    data_len = oper[idx++];
                    tmp->key = (uint8_t *)malloc(data_len);
                    memcpy(&tmp->key, oper + idx, data_len);
                    idx += data_len;
                    break;                
                case TYPE_IV:
                    data_len = oper[idx++];
                    tmp->iv = (uint8_t *)malloc(data_len);
                    memcpy(&tmp->iv, oper + idx, data_len);
                    idx += data_len;
                    break;                
                case TYPE_INPUT_DATA:
                    data_len = oper[idx];
                    memcpy(&tmp->input_data, oper, sizeof(int));
                    idx += sizeof(int);
                    tmp->input_data = (uint8_t *)malloc(data_len);
                    memcpy(&tmp->input_data, oper + idx, data_len);
                    idx += data_len;
                    break;                
                default:
                {
                    fprintf(stderr, "Invalid Operation\n");
                    exit(1);
                }
            }
        }
    }
    else
    {
        fprintf(stdout, "Invalid oper_type\n");
        exit(1);
    }

    fprintf(stdout, "deserialize end\n");

    return (struct_oper);
}

