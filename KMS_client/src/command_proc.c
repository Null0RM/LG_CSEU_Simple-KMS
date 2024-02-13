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

int command_decryption(t_operation *oper, key_t key)
{
    int choose;
    int payload_len = 0;
    
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

    return (payload_len);
}

void    encryption_menu_1(void)
{
    fprintf(stdout, "\n<Choose encryption algorithm type>\n");
    fprintf(stdout, "1. AES128_CBC\t     2. AES128_CTR\n");
    fprintf(stdout, "3. AES256_CBC\t     4. AES256_CTR\n");
    fprintf(stdout, "5. HMAC_SHA-256\t     6. HMAC_SHA3-256\n");
    fprintf(stdout, "7. CMAC_AES128_CBC   8. CMAC_AES128_CTR\n>> ");
}

void    encryption_menu_2(void)
{
    fprintf(stdout, "\n<How would you enter a key?>\n");
    fprintf(stdout, "1. plain key text\n");
    fprintf(stdout, "2. key file\n");
}

uint8_t *input_plain_key_text(int type, int key_size)
{
    fprintf(stdout, "command_proc:input_plain_key_IV_text:start\n");

    uint8_t *ret;
    int    ret_size;

    if (type == TYPE_KEY)
    {
        fprintf(stdout, "input plain key: ");
        ret_size = key_size;
    }
    else if (type == TYPE_IV)
    {
        fprintf(stdout, "input plain IV: ");
        ret_size = 128;
    }

    ret = (uint8_t *)malloc(ret_size/8 + 1);
    if (!ret)
    {
        perror("command_proc:input_plain_key_text:malloc()");
        exit(1);
    }
    while(getchar()!='\n');

    fgets(ret, ret_size / 8, stdin);
    ret[ret_size/8] = '\0';

    fprintf(stdout, "command_proc:input_plain_key_IV_text:end\n");
    return (ret);
}

int input_plain_key_file(int   key_size, t_enc_dec *enc_dec)
{
    fprintf(stdout, "command_proc:input_plain_key_file:start\n");

    int     fd;
    int     read_bytes;
    uint8_t *ret;
    uint8_t *pointer;
    uint8_t file_name[BUFFER_SIZE];
    uint8_t tmp[BUFFER_SIZE];

    enc_dec->key = (uint8_t *)malloc(key_size/8 + 1);
    if (!enc_dec->key)
    {
        perror("command_proc:input_plain_key_file:malloc()");
        exit(1);
    }

    fprintf(stdout, "input key file path\n> ");
    
    while(getchar()!='\n');
    fgets(file_name, BUFFER_SIZE, stdin);
    file_name[strcspn(file_name, "\n")] = '\0';
    
    if ((fd = open(file_name, O_RDONLY)) == -1)
    {
        perror("command_proc:input_plain_key_file:open()");
        exit(1);
    }
    if ((read_bytes = read(fd, tmp, BUFFER_SIZE)) == -1)
    {
        perror("command_proc:input_plain_key_file:read()");
        exit(1);        
    }

    pointer = strstr(tmp, "received key");
    memcpy(enc_dec->key, pointer + strlen("received key: "), key_size / 8);
    enc_dec->key[key_size - 1] = '\0';

    if ((pointer = strstr(tmp, "received IV: ")) > 0)
    {
        memcpy(enc_dec->iv, pointer + strlen("received IV: "), 16);
        enc_dec->iv[16] = '\0';
    }

    close(fd);
    fprintf(stdout, "command_proc:input_plain_key_file:end\n");
    return (EXIT_SUCCESS);
} 

void    encryption_menu_3(void)
{
    fprintf(stdout, "\n<Choose type for encryption target>\n");
    fprintf(stdout, "1. plain text\n");
    fprintf(stdout, "2. raw file\n");    
}

uint8_t *input_encryption_target_text(void)
{
    fprintf(stdout, "command_proc:input_encryption_target_text:start\n");

    uint8_t buffer[BUFFER_SIZE];
    uint8_t *ret = NULL;
    int     total_size = 0;
    int     size = 0;

    fprintf(stdout, "type your plain text\n>> ");
    while (1) {
        while(getchar()!='\n'); 
        fgets(buffer, BUFFER_SIZE, stdin);
        size = strlen(buffer);
        total_size += size;
        if (ret == NULL)
        {
            ret = (uint8_t *)malloc(total_size + 1);
            if (!ret)
            {
                perror("command_proc:input_encryption_target_text:malloc()");
                exit(1);
            }
            memcpy(ret, buffer, total_size + 1);
        }
        else {
            ret = (uint8_t *)realloc(ret, total_size + 1);
            if (!ret)
            {
                perror("command_proc:input_encryption_target_text:realloc()");
                exit(1);
            }
            strncat(ret, buffer, size + 1);
        }
        if (buffer[size - 1] == '\n'){
            *(ret + total_size - 1) = 0;
            break;
        }
    }

    fprintf(stdout, "command_proc:input_encryption_target_text:end\n");
    return (ret);
}

int command_encryption(t_operation *oper, key_t key)
{
    int     choose;
    int     key_size;
    int     data_len = 0;

    printf("\ncommand_proc:command_encryption() start\n");

    oper->operation_type = OPERATION_ENCRYPT;
    oper->operation_buf = (t_enc_dec *)malloc(sizeof(t_enc_dec));
    t_enc_dec *enc_dec = oper->operation_buf;
    
    encryption_menu_1();
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
            key_size = 128;
            data_len += (6 + sizeof(int)) * 3;
            break;
        case 3: 
            enc_dec->enc_dec_mode = MODE_CBC;
        case 4:
            enc_dec->enc_dec_isMAC = ISMAC_NONE;
            enc_dec->enc_dec_algo = ALGO_AES256;
            if (choose == 4)
                enc_dec->enc_dec_mode = MODE_CTR;
            key_size = 256;
            data_len += (6 + sizeof(int)) * 3;
            break;
        case 5: 
            enc_dec->enc_dec_algo = ALGO_SHA_256;
        case 6:
            enc_dec->enc_dec_isMAC = ISMAC_HMAC;
            if (choose == 6)
                enc_dec->enc_dec_algo = ALGO_SHA3_256;
            enc_dec->enc_dec_mode = MODE_NONE;
            key_size = 256;
            data_len += (6 + sizeof(int)) * 3;
            break;
        case 7: 
            enc_dec->enc_dec_mode = MODE_CBC;
        case 8: 
            enc_dec->enc_dec_isMAC = ISMAC_CMAC;
            enc_dec->enc_dec_algo = ALGO_AES128;
            if (choose == 8)
                enc_dec->enc_dec_mode = MODE_CTR;
            key_size = 128;
            data_len += (6 + sizeof(int)) * 3;
            break;
        default:
            printf("Invalid input. please choose [help]\n");
            exit(1);
    }
    
    encryption_menu_2();
    scanf("%d", &choose);
    enc_dec->key_len = key_size / 8;
    data_len += (6 + enc_dec->key_len);
    data_len += (6 + 16);
    switch(choose)
    {

        case 1:
            enc_dec->key = input_plain_key_text(TYPE_KEY, key_size);
            if (enc_dec->enc_dec_mode == MODE_NONE)
                enc_dec->iv = NULL;
            else
                enc_dec->iv = input_plain_key_text(TYPE_IV, key_size);
            break;
        case 2:
            // parse_plain_key_file(key_size, &enc_dec);
            break;
        default:
            printf("Invalid input. please choose [help]\n");
            exit(1);            
    }

    encryption_menu_3();
    scanf("%d", &choose);
    data_len += 6;
    switch(choose)
    {
        case 1:
            enc_dec->input_data = input_encryption_target_text();
            break;
        case 2:
            // enc_dec->input_data = input_encryption_target_file();
            break;
        default:
            printf("Invalid input. please choose [help]\n");
            exit(1);       
    }
    enc_dec->data_len = strlen(enc_dec->input_data);
    data_len += enc_dec->data_len;
    
    printf("\ncommand_proc:command_encryption() start\n");

    return (data_len);
}

void    create_key_menu_1(void)
{
    fprintf(stdout, "\n<Choose create key algorithm type>\n");
    fprintf(stdout, "1. AES128_CBC\t     2. AES128_CTR\n");
    fprintf(stdout, "3. AES256_CBC\t     4. AES256_CTR\n");
    fprintf(stdout, "5. HMAC_SHA-256\t     6. HMAC_SHA3-256\n");
    fprintf(stdout, "7. CMAC_AES128_CBC   8. CMAC_AES128_CTR\n>> ");
}

int command_create_key(t_operation *oper, key_t key)
{    
    printf("command_proc:command_create_key() start\n");
    
    int choose;
    oper->operation_buf = (t_createKey *)malloc(sizeof(t_createKey));
    t_createKey *createKey = oper->operation_buf;
    oper->operation_type = OPERATION_CREATEKEY;

    create_key_menu_1();
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

    return (oper->operation_len);
}

void    choose_operation_menu(void)
{
    fprintf(stdout, "\n<Choose operation>\n");
    fprintf(stdout, "1. create key\n");
    fprintf(stdout, "2. encryption\n");
    fprintf(stdout, "3. decryption\n");
    fprintf(stdout, "4. help\n>> ");
}

int command_proc(key_t key)
{
    int         choose;
    t_operation oper;
    uint8_t     *payload;
    int         payload_len;

    printf("command_proc start\n");
    
    choose_operation_menu();
    scanf("%d", &choose);
    switch (choose)
    {
        case 1:
            payload_len = command_create_key(&oper, key);
            oper.operation_type = OPERATION_CREATEKEY;
            break;
        case 2:
            payload_len = command_encryption(&oper, key);
            oper.operation_type = OPERATION_ENCRYPT;
            break;
        case 3:
            payload_len = command_decryption(&oper, key);
            oper.operation_type = OPERATION_DECRYPT;
            break;
        case 4:
            command_help();
            break;
        default:
            printf("Invalid input. please choose [help]\n");
            exit(1);
    }
    payload = serialize(&oper, payload_len);
    for(int i = 0; i < payload_len; i++)
    {
        printf("%02X ", payload[i]);
    }
    mq_send(payload, payload_len, oper.operation_type, key);

    printf("command_proc end\n");
    return COMMAND_SUCCESS;
}
