#include "../inc/operation.h"
#include "../inc/openssl_utils.h"

int do_op_createKey(t_createKey *oper, uint8_t *buffer)
{
    fprintf(stdout, "do_op:do_op_createKey() start\n");
    int     idx = 0;
    RAND_status();

    buffer[idx++] = TYPE_ISMAC;
    buffer[idx++] = sizeof(int);
    memcpy(buffer + idx, &(oper->createKey_isMAC), sizeof(int));
    idx += sizeof(int);

    buffer[idx++] = TYPE_ALGO;
    buffer[idx++] = sizeof(int);
    memcpy(buffer + idx, &(oper->createKey_algo), sizeof(int));
    idx += sizeof(int);

    buffer[idx++] = TYPE_MODE;
    buffer[idx++] = sizeof(int);
    memcpy(buffer + idx, &(oper->createKey_mode), sizeof(int));
    idx += sizeof(int);

    buffer[idx++] = TYPE_KEY;
    if (oper->createKey_algo == ALGO_AES128)
    {
        buffer[idx++] = 0x10;
        RAND_bytes(buffer + idx, 0x10);
        idx += 0x10;
    }
    else if (oper->createKey_algo ==ALGO_AES256 || 
        oper->createKey_algo == ALGO_SHA3_256 || 
    oper->createKey_algo == ALGO_SHA_256)
    {
        buffer[idx++] = 0x20;
        RAND_bytes(buffer + idx, 0x20);
        idx += 0x20;
    }
    else
    {
        fprintf(stdout, "do_op:type error\n");
        exit(1);
    }
    buffer[idx++] = TYPE_IV;
    buffer[idx++] = 0x10;
    RAND_bytes(buffer + idx, 0x10); 
    idx += 0x10;
    
    fprintf(stdout, "do_op:do_op_createKey() end\n");
    return idx;
}

uint8_t *do_op_encrypt_do(t_enc_dec *oper)
{
    uint8_t *serial;
    int     result_len;

    result_len = oper->input_len;
    serial = (uint8_t *)malloc(result_len);

    if (oper->enc_dec_isMAC == ISMAC_NONE)
    {
        if (oper->enc_dec_algo == ALGO_AES128) {
            if (oper->enc_dec_mode == MODE_CBC) {
                encrypt_payload(EVP_aes_128_cbc(), serial, oper->input_data, oper->input_len, oper->key, oper->iv);
            }
            else if (oper->enc_dec_mode == MODE_CTR) {}
        }
        else if (oper->enc_dec_algo == ALGO_AES256) {
            if (oper->enc_dec_mode == MODE_CBC) {}
            else if (oper->enc_dec_mode == MODE_CTR) {}
        }
    }
    else if (oper->enc_dec_isMAC == ISMAC_CMAC)
    {
        if (oper->enc_dec_algo == ALGO_AES128) {
            if (oper->enc_dec_mode == MODE_CBC) {}
            else if (oper->enc_dec_mode == MODE_CTR) {}
        }
        else if (oper->enc_dec_algo == ALGO_AES256) {}
    }
    else if (oper->enc_dec_isMAC == ISMAC_HMAC)
    {
        if (oper->enc_dec_algo == ALGO_SHA_256) {}
        else if (oper->enc_dec_algo == ALGO_SHA3_256) {}
    }
    else
    {
        //else logic
    }

    return (serial);
}

uint8_t *do_op_encrypt(t_enc_dec *oper, uint8_t *buffer)
{
    fprintf(stdout, "do_op:do_op_createKey() start\n");
    char    *serial;
    int     idx = 0;
    int     res_len;

    buffer[idx++] = TYPE_ISMAC;
    buffer[idx++] = sizeof(int);
    memcpy(buffer + idx, &(oper->enc_dec_isMAC), sizeof(int));
    idx += sizeof(int);

    buffer[idx++] = TYPE_ALGO;
    buffer[idx++] = sizeof(int);
    memcpy(buffer + idx, &(oper->enc_dec_algo), sizeof(int));
    idx += sizeof(int);

    buffer[idx++] = TYPE_MODE;
    buffer[idx++] = sizeof(int);
    memcpy(buffer + idx, &(oper->enc_dec_mode), sizeof(int));
    idx += sizeof(int);

    serial = do_op_encrypt_do(oper);

    fprintf(stdout, "do_op:do_op_createKey() end\n");
}

uint8_t    *do_op(void *struct_oper, int oper_type, int *len)
{
    fprintf(stdout, "do_op start\n");
    uint8_t     *serial;
    uint8_t     buffer[BUFFER_SIZE];

    if (oper_type == OPERATION_CREATEKEY) {
        t_createKey *tmp = (t_createKey *)struct_oper;
        *len = do_op_createKey(struct_oper, buffer);
        serial = (uint8_t *)malloc(sizeof(uint8_t) * *len + 1);
        memcpy(serial, buffer, *len);
    }
    else if (oper_type == OPERATION_ENCRYPT) {
        t_enc_dec *tmp = (t_enc_dec *)struct_oper;
        serial = do_op_encrypt(struct_oper, buffer);
    }
    else if (oper_type == OPERATION_DECRYPT) {}
    else {}

    fprintf(stdout, "do_op end\n");

    return (serial);
}