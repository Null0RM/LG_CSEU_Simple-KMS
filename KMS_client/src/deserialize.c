#include "../inc/command_send.h"

void    get_time(uint8_t * timeString)
{
    time_t      current_time;
    struct tm   *local_time;

    current_time = time(NULL);
    local_time = localtime(&current_time);

    strftime(timeString, 20, "%Y-%m-%d-%H:%M:%S", local_time);
    // printf("get_time: %s\n", timeString);
}

int deserialize_and_store(uint8_t * response, int fd, int response_len)
{
    int         response_idx = 0;
    uint16_t    type;
    uint32_t    length;
    int         tmp;

    while (response_idx < response_len)
    {
        type = *(uint16_t *)(response + response_idx);
        response_idx += 2;
        length = *(uint32_t *)(response + response_idx);
        response_idx += 4;
        
        // printf("type: %hd\n", type);
        switch (type) {
            case TYPE_ISMAC:
                tmp = *(int *)(response + response_idx);
                if (tmp == ISMAC_NONE)
                    write(fd, "not mac key\n", strlen("not mac key\n"));
                else if (tmp == ISMAC_CMAC)
                    write(fd, "cmac key\n", strlen("cmac key\n"));
                else if (tmp == ISMAC_HMAC)
                    write(fd, "hmac key\n", strlen("hmac key\n"));
                else
                    fprintf(stdout, "deserialize:deserialize_and_store:mac type error");
                break;
            case TYPE_ALGO:
                tmp = *(int *)(response + response_idx);
                if (tmp == ALGO_AES128)
                    write(fd, "algo: AES 128\n", strlen("algo: AES 128\n"));
                else if (tmp == ALGO_AES256)
                    write(fd, "algo: AES 256\n", strlen("algo: AES 256\n"));
                else if (tmp == ALGO_SHA3_256)
                    write(fd, "algo: SHA3-256\n", strlen("algo: SHA3-256\n"));
                else if (tmp == ALGO_SHA_256)
                    write(fd, "algo: SHA-256\n", strlen("algo: SHA-256\n"));
                else
                    fprintf(stdout, "deserialize:deserialize_and_store:algo type error\n\n");
                break;
            case TYPE_MODE:
                tmp = *(int *)(response + response_idx);
                if (tmp == MODE_NONE)
                    write(fd, "mode: no mode applied\n", strlen("mode: no mode applied\n"));
                else if (tmp == MODE_CBC)
                    write(fd, "mode: CBC\n", strlen("mode: CBC\n"));
                else if (tmp == MODE_CTR)
                    write(fd, "mode: CTR\n", strlen("mode: CTR\n"));
                else
                    fprintf(stdout, "deserialize:deserialize_and_store:mode type error\n");
                break;
            case TYPE_KEY:
                write(fd, "KEY: ", strlen("KEY: "));
                write(fd, response + response_idx, length); 
                write(fd, "\n", 1);
                break;
            case TYPE_IV:
                write(fd, "IV: ", strlen("IV: "));
                write(fd, response + response_idx, length); 
                write(fd, "\n", 1);
                break;           
            default:
                fprintf(stdout, "deserialize:deserialize_and_store:type error\n");
                exit(1);
        }
        response_idx += length; 
    }
    close(fd);

    return (1);
}

int store(uint8_t * response, int fd, int response_len)
{
    write(fd, response, response_len);
    close(fd);

    return (1);
}

int deserialize_tlv(uint8_t   *plainText, int oper_type, int response_len) {    
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
        if (-1 == (fd = open(fileName, O_CREAT | O_WRONLY, 0666)))
        {
            perror("deserialize_tlv:file create failed");
            exit(1);
        }
        deserialize_and_store(plainText, fd, response_len);
        printf("\nkey file \"%s\": generated.\n", fileName);
        free(fileName);
    }
    else if (oper_type == OPERATION_ENCRYPT) {
        fileName = (uint8_t *)malloc(strlen("../recvd/encrypt-") + 20);
        if (!fileName)
        {
            fprintf(stderr, "deserialize_tlv:make file type failed\n");
            exit(1);
        }
        memcpy(fileName, "../recvd/encrypt-", strlen("../recvd/encrypt-"));
        memcpy(fileName + strlen("../recvd/encrypt-"), timeString, 20);
        if (-1 == (fd = open(fileName, O_CREAT | O_WRONLY, 0666)))
        {
            perror("deserialize_tlv:file create failed");
            exit(1);
        }
        store(plainText, fd, response_len);
        printf("\nencrypted file \"%s\": generated.\n", fileName);
        free(fileName);
    }
    else if (oper_type == OPERATION_DECRYPT) {
        fileName = (uint8_t *)malloc(strlen("../recvd/decrypt-") + 20);
        if (!fileName)
        {
            fprintf(stderr, "deserialize_tlv:make file type failed\n");
            exit(1);
        }
        memcpy(fileName, "../recvd/decrypt-", strlen("../recvd/decrypt-"));
        memcpy(fileName + strlen("../recvd/decrypt-"), timeString, 20);
        if (-1 == (fd = open(fileName, O_CREAT | O_WRONLY, 0666)))
        {
            perror("deserialize_tlv:file create failed");
            exit(1);
        }
        store(plainText, fd, response_len);
        printf("\ndecrypted file \"%s\": generated.\n", fileName);
        free(fileName);
    }
    else {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
