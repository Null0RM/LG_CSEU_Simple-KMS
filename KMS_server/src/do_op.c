#include "../inc/operation.h"
#include "../inc/openssl_utils.h"

int do_op_createKey(t_createKey *oper, uint8_t *buffer)
{
    fprintf(stdout, "do_op:do_op_createKey() start\n");
    int     idx = 0;
    RAND_status();
    
    storeLE16(buffer + idx, TYPE_ISMAC);
    idx += 2;
    fprintf(stdout, "set TYPE success\n");
    storeLE32(buffer + idx, sizeof(int));
    idx += 4;
    fprintf(stdout, "set LEN success\n");
    memcpy(buffer + idx, &(oper->createKey_isMAC), sizeof(int));
    idx += sizeof(int);
    fprintf(stdout, "do_op_createKey:serialize_isMAC:success %d\n", oper->createKey_isMAC);

    storeLE16(buffer + idx, TYPE_ALGO);
    idx += 2;
    fprintf(stdout, "set TYPE success\n");
    storeLE32(buffer + idx, sizeof(int));
    idx += 4;
    fprintf(stdout, "set LEN success\n");
    memcpy(buffer + idx, &(oper->createKey_algo), sizeof(int));
    idx += sizeof(int);
    fprintf(stdout, "do_op_createKey:serialize_algo:success %d\n", oper->createKey_algo);

    storeLE16(buffer + idx, TYPE_MODE);
    idx += 2;
    fprintf(stdout, "set TYPE success\n");
    storeLE32(buffer + idx, sizeof(int));
    idx += 4;
    fprintf(stdout, "set LEN success\n");
    memcpy(buffer + idx, &(oper->createKey_mode), sizeof(int));
    idx += sizeof(int);
    fprintf(stdout, "do_op_createKey:serialize_mode:success %d\n", oper->createKey_mode);

    logging(30, buffer, ">>send_data_buffer:");

    storeLE16(buffer + idx, TYPE_KEY);
    idx += 2;
    fprintf(stdout, "set TYPE success\n");
    if (oper->createKey_algo == ALGO_AES128)
    {
        storeLE32(buffer + idx, 0x10);
        idx += sizeof(int);
        fprintf(stdout, "set LEN success\n");
        RAND_bytes(buffer + idx, 0x10);
        idx += 0x10;
    }
    else if (oper->createKey_algo ==ALGO_AES256 || 
        oper->createKey_algo == ALGO_SHA3_256 || 
    oper->createKey_algo == ALGO_SHA_256)
    {
        storeLE32(buffer + idx, 0x20);
        idx += sizeof(int);
        fprintf(stdout, "set LEN success\n");
        RAND_bytes(buffer + idx, 0x20);
        idx += 0x20;
    }
    else
    {
        fprintf(stdout, "do_op:type error\n");
        exit(1);
    }
    if (oper->createKey_isMAC != ISMAC_HMAC)
    {
        storeLE16(buffer + idx, TYPE_IV);
        idx += 2;
        fprintf(stdout, "set TYPE success\n");
        storeLE32(buffer + idx, 0x10);
        idx += 4;
        fprintf(stdout, "set LEN success\n");
        RAND_bytes(buffer + idx, 0x10); 
        idx += 0x10;
    }

    fprintf(stdout, "do_op:do_op_createKey() end\n");

    return idx;
}

uint8_t *do_op_encrypt(t_enc_dec *oper)
{
    uint8_t *serial;
    int     result_len;

    result_len = oper->data_len;
    serial = (uint8_t *)malloc(result_len);

    if (oper->enc_dec_isMAC == ISMAC_NONE)
    {
        if (oper->enc_dec_algo == ALGO_AES128) {
            if (oper->enc_dec_mode == MODE_CBC) {
                if (encrypt_operation(EVP_aes_128_cbc(), serial, oper->input_data, oper->data_len, oper->key, oper->iv) == OPERATION_FAILURE)
                    return 0;

            }
            else if (oper->enc_dec_mode == MODE_CTR) {
                if (encrypt_operation(EVP_aes_128_ctr(), serial, oper->input_data, oper->data_len, oper->key, oper->iv) == OPERATION_FAILURE)
                    return 0;
            }
        }
        else if (oper->enc_dec_algo == ALGO_AES256) {
            if (oper->enc_dec_mode == MODE_CBC) {
                if (encrypt_operation(EVP_aes_256_cbc(), serial, oper->input_data, oper->data_len, oper->key, oper->iv) == OPERATION_FAILURE)
                    return 0;
            }
            else if (oper->enc_dec_mode == MODE_CTR) {
                if (encrypt_operation(EVP_aes_256_ctr(), serial, oper->input_data, oper->data_len, oper->key, oper->iv) == OPERATION_FAILURE)
                    return 0;
            }
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
        fprintf(stdout, "invalid algorithm input\n");
        exit(1);
    }

    return (serial);
}

uint8_t *do_op_decrypt(t_enc_dec *oper)
{
    uint8_t *serial;
    int     result_len;

    result_len = oper->data_len;
    serial = (uint8_t *)malloc(result_len);

    if (oper->enc_dec_isMAC == ISMAC_NONE)
    {
        if (oper->enc_dec_algo == ALGO_AES128) {
            if (oper->enc_dec_mode == MODE_CBC) {
                if (decrypt_operation(EVP_aes_128_cbc(), serial, oper->input_data, oper->data_len, oper->key, oper->iv) == OPERATION_FAILURE)
                    return 0;
            }
            else if (oper->enc_dec_mode == MODE_CTR) {
                if (decrypt_operation(EVP_aes_128_ctr(), serial, oper->input_data, oper->data_len, oper->key, oper->iv) == OPERATION_FAILURE)
                    return 0;
            }
        }
        else if (oper->enc_dec_algo == ALGO_AES256) {
            if (oper->enc_dec_mode == MODE_CBC) {
                if (decrypt_operation(EVP_aes_256_cbc(), serial, oper->input_data, oper->data_len, oper->key, oper->iv) == OPERATION_FAILURE)
                    return 0;
            }
            else if (oper->enc_dec_mode == MODE_CTR) {
                if (decrypt_operation(EVP_aes_256_ctr(), serial, oper->input_data, oper->data_len, oper->key, oper->iv) == OPERATION_FAILURE)
                    return 0;
            }
        }
    }

    return (serial);
}

uint8_t    *do_op(t_operation *struct_oper, int oper_type, int *len)
{
    fprintf(stdout, "do_op start\n");
    uint8_t     *serial;
    uint8_t     *buffer;

    if (oper_type == OPERATION_CREATEKEY) {
        buffer = (uint8_t *)malloc(BUFFER_SIZE);
        *len = do_op_createKey((t_createKey *)(struct_oper->operation_buf), buffer);
        serial = (uint8_t *)malloc(*len + 1);
        memcpy(serial, buffer, *len);
    }
    else if (oper_type == OPERATION_ENCRYPT) {
        printf("do_op:encrytion_ready\n");
        t_enc_dec *tmp = (t_enc_dec *)(struct_oper->operation_buf);
        if (!tmp)
        {
            perror("align t_enc_dec");
            exit(1);
        }
        buffer = (uint8_t *)malloc(tmp->data_len);
        if (!buffer)
        {
            perror("do_op:malloc()");
            exit(1);
        }
        buffer = do_op_encrypt(tmp);
        if (!buffer)
        {
            fprintf(stdout, "do_op:do_op_encrypt() failure\n");
            return 0;
        }
        *len = tmp->data_len + 16 - tmp->data_len % 16;

        logging(*len, buffer, ">> do_op:buffer");
        serial = (uint8_t *)malloc(*len + 1);
        memcpy(serial, buffer, *len);
        printf("do_op:encrytion_done\n");
    }
    else if (oper_type == OPERATION_DECRYPT) {
        printf("do_op:decryption_ready\n");
        t_enc_dec *tmp = (t_enc_dec *)(struct_oper->operation_buf);
        if (!tmp)
        {
            perror("align t_enc_dec");
            exit(1);
        }
        buffer = (uint8_t *)malloc(tmp->data_len);
        if (!buffer)
        {
            perror("do_op:malloc()");
            exit(1);
        }
        buffer = do_op_decrypt(tmp);
        if (!buffer)
        {
            perror("do_op:do_op_decrypt()");
            exit(1);
        }
        *len = tmp->data_len;

        logging(*len, buffer, ">> do_op:buffer");
        serial = (uint8_t *)malloc(*len + 1);
        memcpy(serial, buffer, *len);
        printf("do_op:decryption_done\n");
    }
    else {
        fprintf(stdout, "oper_type_error\n");
        exit(1);
    }
    
    free(buffer);
    fprintf(stdout, "do_op end\n");

    return (serial);
}
