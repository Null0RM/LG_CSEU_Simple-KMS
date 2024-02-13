#include "../inc/command_send.h"

void    get_time(uint8_t * timeString)
{
    time_t      current_time;
    struct tm   *local_time;

    current_time = time(NULL);
    local_time = localtime(&current_time);

    strftime(timeString, 20, "%Y-%m-%d-%H:%M:%S", local_time);
    printf("get_time: %s\n", timeString);
}

int deserialize_and_store(uint8_t * response, int fd, int response_len)
{
    int     response_idx = 0;
    int     buffer_len = 0;
    uint8_t type;
    int     data_len;
    int     tmp;
    uint8_t buffer[BUFFER_SIZE] = {};

    while (response_idx < response_len)
    {
        type = response[response_idx++];

        if (type == TYPE_ISMAC) {
            data_len = response[response_idx++];
            memcpy(&tmp, response + response_idx, data_len);
            if (tmp == ISMAC_NONE)
            {
                strncat(buffer, "not_mac_key\n", 13);
                buffer_len += 12;
            }
            else if (tmp == ISMAC_HMAC)
            {    
                strncat(buffer, "HMAC_key\n", 10);
                buffer_len += 9;
            }
            else if (tmp == ISMAC_CMAC)
            {    
                strncat(buffer, "CMAC_key\n", 10);
                buffer_len += 9;
            }
            else
            {
                fprintf(stderr, "deserialize_tlv:type_ismac error\n");
                exit(1);
            }
            response_idx += data_len;
        }
        else if (type == TYPE_ALGO) {
            data_len = response[response_idx++];
            memcpy(&tmp, response + response_idx, data_len);
            if (tmp == ALGO_AES128)
            {
                strncat(buffer, "algo: aes-128\n", 15);
                buffer_len += 14;
            }
            else if (tmp == ALGO_AES256)
            {    
                strncat(buffer, "algo: aes-256\n", 15);
                buffer_len += 14;
            }
            else if (tmp == ALGO_SHA_256)
            {    
                strncat(buffer, "algo: sha-256\n", 15);
                buffer_len += 14;
            }
            else if (tmp == ALGO_SHA3_256)
            {    
                strncat(buffer, "algo: sha3-256\n", 16);
                buffer_len += 15;
            }
            else
            {
                fprintf(stderr, "deserialize_tlv:type_algo error\n");
                exit(1);
            }
            response_idx += data_len;
        }
        else if (type == TYPE_MODE) {
            data_len = response[response_idx++];
            memcpy(&tmp, response + response_idx, data_len);
            if (tmp == MODE_NONE) {}
            else if (tmp == MODE_CBC)
            {    
                strncat(buffer, "mode: cbc\n", 11);
                buffer_len += 10;
            }
            else if (tmp == MODE_CTR)
            {    
                strncat(buffer, "mode: ctr\n", 11);
                buffer_len += 10;
            }
            else
            {
                fprintf(stderr, "deserialize_tlv:type_mode error\n");
                exit(1);
            }
            response_idx += data_len;
        }
        else if (type == TYPE_KEY) {
            data_len = response[response_idx++];
            strncat(buffer, "received key: ", 15);
            strncat(buffer, response + response_idx, data_len + 1);
            strncat(buffer, "\n", 2);
            buffer_len += data_len + 14;
            response_idx += data_len;
        }
        else if (type == TYPE_IV) {
            data_len = response[response_idx++];
            strncat(buffer, "received IV: ", 14);
            strncat(buffer, response + response_idx, data_len + 1);
            strncat(buffer, "\n", 2);
            buffer_len += data_len + 13;
            response_idx += data_len;
        }
    }
    write(fd, buffer, buffer_len);
    close(fd);
}

int deserialize_tlv(uint8_t   *plainText, int oper_type, int response_len)
{    
    int     fd;
    uint8_t timeString[20];
    uint8_t *fileName;

    get_time(timeString);
    if (oper_type == OPERATION_CREATEKEY){
        fileName = (uint8_t *)malloc(strlen("../recvd/createKey-") + 20);
        if (!fileName)
        {
            fprintf(stderr, "deserialize_tlv:make file type failed\n");
            exit(1);
        }
        memcpy(fileName, "../recvd/createKey-", strlen("../recvd/createKey-"));
        memcpy(fileName + strlen("../recvd/createKey-"), timeString, 20);
        if (-1 == (fd = open(fileName, O_CREAT | O_WRONLY, 0644)))
        {
            perror("deserialize_tlv:file create failed");
            exit(1);
        }
        deserialize_and_store(plainText, fd, response_len);
        printf("key file \"%s\": generated.\n", fileName);
        free(fileName);
    }
    else if (oper_type == OPERATION_ENCRYPT) {}
    else if (oper_type == OPERATION_DECRYPT) {}
    else {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}