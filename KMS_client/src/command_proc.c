#include "../inc/command_send.h"

void command_help()
{
    int     fd;
    char    buf[BUFFER_SIZE];
    int     read_bytes = 1; 

    fd = open("../help.txt", O_RDONLY);
    if (!fd)
    {
        perror("file open() failed");
        exit(1);
    }
    while (read_bytes)
    {
        read_bytes = read(fd, buf, BUFFER_SIZE);
        if (read_bytes == -1)
        {
            perror("file read() failed");
            exit(1);
        }
        if (!read_bytes)
            break;
        buf[read_bytes] = '\0';
        printf("%s", buf);
    }
    close(fd);
}

void command_decryption(t_operation *oper, key_t key)
{
    int choose;
    
    printf("\n<Choose decryption algorithm type>\n");
    printf("1. AES128_CBC\t     2. AES128_CTR\n");
    printf("3. AES256_CBC\t     4. AES256_CTR\n");

    printf("command_proc:command_decryption() start\n");

    oper->operation_type = OPERATION_DECRYPT;
    oper->operation_buf = (t_enc_dec *)malloc(sizeof(t_enc_dec));
    t_enc_dec *enc_dec = oper->operation_buf;

    scanf("%d", &choose);
    switch(choose)
    {
        case 1:
            enc_dec->enc_dec_mode = MODE_CBC;
        case 2: 
            enc_dec->enc_dec_isMAC = ISMAC_NONE;
            enc_dec->enc_dec_algo = ALGO_AES128;
            if (choose == 2)
                enc_dec->enc_dec_mode = MODE_CTR;
            break;
        case 3: 
            enc_dec->enc_dec_mode = MODE_CBC;
        case 4:
            enc_dec->enc_dec_isMAC = ISMAC_NONE;
            enc_dec->enc_dec_algo = ALGO_AES256;
            if (choose == 4)
                enc_dec->enc_dec_mode = MODE_CTR;
            break;
        default:
            printf("Invalid input. please choose [help]\n");
            exit(1);
    }

    // key -> file or txt
    // iv -> file or txt 
    // input_type -> file or txt
    // input_data -? file or txt

    oper->operation_len = sizeof(oper->operation_buf);
}

void command_encryption(t_operation *oper, key_t key)
{
    int choose;
    
    printf("\n<Choose encryption algorithm type>\n");
    printf("1. AES128_CBC\t     2. AES128_CTR\n");
    printf("3. AES256_CBC\t     4. AES256_CTR\n");
    printf("5. HMAC_SHA-256\t     6. HMAC_SHA3-256\n");
    printf("7. CMAC_AES128_CBC   8. CMAC_AES128_CTR\n>> ");

    printf("command_proc:command_encryption() start\n");

    oper->operation_type = OPERATION_ENCRYPT;
    oper->operation_buf = (t_enc_dec *)malloc(sizeof(t_enc_dec));
    t_enc_dec *enc_dec = oper->operation_buf;

    scanf("%d", &choose);
    switch(choose)
    {
        case 1:
            enc_dec->enc_dec_mode = MODE_CBC;
        case 2: 
            enc_dec->enc_dec_isMAC = ISMAC_NONE;
            enc_dec->enc_dec_algo = ALGO_AES128;
            if (choose == 2)
                enc_dec->enc_dec_mode = MODE_CTR;
            break;
        case 3: 
            enc_dec->enc_dec_mode = MODE_CBC;
        case 4:
            enc_dec->enc_dec_isMAC = ISMAC_NONE;
            enc_dec->enc_dec_algo = ALGO_AES256;
            if (choose == 4)
                enc_dec->enc_dec_mode = MODE_CTR;
            break;
        case 5: 
            enc_dec->enc_dec_algo = ALGO_SHA_256;
        case 6:
            enc_dec->enc_dec_isMAC = ISMAC_HMAC;
            if (choose == 6)
                enc_dec->enc_dec_algo = ALGO_SHA3_256;
            enc_dec->enc_dec_mode = MODE_NONE;
            break;
        case 7: 
            enc_dec->enc_dec_mode = MODE_CBC;
        case 8: 
            enc_dec->enc_dec_isMAC = ISMAC_CMAC;
            enc_dec->enc_dec_algo = ALGO_AES128;
            if (choose == 8)
                enc_dec->enc_dec_mode = MODE_CTR;
            break;
        default:
            printf("Invalid input. please choose [help]\n");
            exit(1);
    }

    // key -> file or txt
    // iv -> file or txt 
    // input_type -> file or txt
    // input_data -? file or txt

    oper->operation_len = sizeof(oper->operation_buf);
}

void command_create_key(t_operation *oper, key_t key)
{
    int choose;
    
    printf("\n<Choose create key algorithm type>\n");
    printf("1. AES128_CBC\t     2. AES128_CTR\n");
    printf("3. AES256_CBC\t     4. AES256_CTR\n");
    printf("5. HMAC_SHA-256\t     6. HMAC_SHA3-256\n");
    printf("7. CMAC_AES128_CBC   8. CMAC_AES128_CTR\n>> ");

    printf("command_proc:command_create_key() start\n");

    oper->operation_type = OPERATION_CREATEKEY;
    oper->operation_buf = (t_createKey *)malloc(sizeof(t_createKey));
    t_createKey *createKey = oper->operation_buf;

    scanf("%d", &choose);
    switch(choose)
    {
        case 1:
            createKey->createKey_mode = MODE_CBC;
        case 2: 
            createKey->createKey_isMAC = ISMAC_NONE;
            createKey->createKey_algo = ALGO_AES128;
            if (choose == 2)
                createKey->createKey_mode = MODE_CTR;
            break;
        case 3: 
            createKey->createKey_mode = MODE_CBC;
        case 4:
            createKey->createKey_isMAC = ISMAC_NONE;
            createKey->createKey_algo = ALGO_AES256;
            if (choose == 4)
                createKey->createKey_mode = MODE_CTR;
            break;
        case 5: 
            createKey->createKey_algo = ALGO_SHA_256;
        case 6:
            createKey->createKey_isMAC = ISMAC_HMAC;
            if (choose == 6)
                createKey->createKey_algo = ALGO_SHA3_256;
            createKey->createKey_mode = MODE_NONE;
            break;
        case 7: 
            createKey->createKey_mode = MODE_CBC;
        case 8: 
            createKey->createKey_isMAC = ISMAC_CMAC;
            createKey->createKey_algo = ALGO_AES128;
            if (choose == 8)
                createKey->createKey_mode = MODE_CTR;
            break;
        default:
            printf("Invalid input. please choose [help]\n");
            exit(1);
    }
    oper->operation_len = sizeof(oper->operation_buf);

    printf("\noperation_type: %ld\n", oper->operation_type);
    printf("operation_len: %d\n", oper->operation_len);
    printf("operation_buf:\n");
    printf("isMAC: %d\n", ((t_createKey *)oper->operation_buf)->createKey_isMAC);
    printf("algo: %d\n", ((t_createKey *)oper->operation_buf)->createKey_algo);
    printf("mode: %d\n\n", ((t_createKey *)oper->operation_buf)->createKey_mode);

    if (mq_send(oper, key) != COMMAND_SUCCESS)
    {
        printf("send createKey messsage failed\n");
        exit(1);
    }

    printf("command_proc:command_create_key() end\n");
}

int command_proc(key_t key)
{
    int choose;
    t_operation oper;

    printf("\n<Choose operation>\n");
    printf("1. create key\n");
    printf("2. encryption\n");
    printf("3. decryption\n");
    printf("4. help\n>> ");
    
    printf("command_proc start\n");

    scanf("%d", &choose);
    switch (choose)
    {
        case 1:
            command_create_key(&oper, key);
            break;
        case 2:
            command_encryption(&oper, key);
            break;
        case 3:
            command_decryption(&oper, key);
            break;
        case 4:
            command_help();
            break;
        default:
            printf("Invalid input. please choose [help]\n");
            exit(1);
    }

    printf("command_proc end\n");

    return COMMAND_SUCCESS;
}