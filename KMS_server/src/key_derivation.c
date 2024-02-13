#include "../inc/common.h"
#include "../inc/mq.h"
#include "../inc/openssl_utils.h"
/*
세션 key, iv를 생성 및 저장한 후 client에게 전송한다. 
전송 시 key sniffing의 위험이 있기 때문에 이를 AES_128_ECB로 암호화해서 전송.

만들어야 할 것: AES_128 key, iv
암호화해야 할 대상: key, iv 이걸 암호화할 key는?: hard_key
*/

static uint8_t hard_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};


uint8_t *encrypt_response(uint8_t *plainText, int plainText_len, int *response_len) {
    uint8_t *cipherText;
    int len = 0;

    printf("key_derivation:encrypt_response() plainLength: %d start\n", plainText_len);
    printf("%s\n", plainText);

    int cipherText_len = plainText_len + 16 - plainText_len % 16;
    cipherText = (uint8_t *)malloc(cipherText_len + 1);
    if (!cipherText) {
        perror("malloc()");
        exit(1);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new()");
        exit(1);
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hard_key, NULL)) {
        perror("EVP_EncryptInit_ex()");
        exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainText_len)) {
        perror("EVP_EncryptUpdate()");
        exit(1);
    }

    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &final_len)) {
        perror("EVP_EncryptFinal_ex()");
        exit(-1);
    }
    len += final_len;
    *response_len = len;
    EVP_CIPHER_CTX_free(ctx);

    printf("key_derivation:encrypt_response() cipherLength:%d end\n", cipherText_len);

    return cipherText;
}

uint8_t    *make_response(uint8_t *key, uint8_t *iv, t_data data, int *response_len)
{
    RAND_status();

    uint8_t    *tmp_response;
    uint8_t    *ret;
    int         fd;
    int         plain_len;

    printf("key_derivation:make_response() start\n");

    RAND_bytes(key, 16);
    RAND_bytes(iv, 16);

    plain_len = strlen(data.data_buf) + 45; // key, iv, string
    tmp_response = (uint8_t *)malloc(sizeof(uint8_t) * plain_len);
    fd = open("../security_data/session_key_list.txt", O_WRONLY);
    if (!fd)
    {
        perror("key_derivation open() failed");
        exit(1);
    }
    sprintf(tmp_response, "%s\nkey: %s\niv: %s", data.data_buf, key, iv);
    write(fd, tmp_response, plain_len);
    ret = encrypt_response(tmp_response, plain_len, response_len);

    close(fd);
    free(tmp_response);
    printf("key_derivation:make_response() end\n");

    return ret;
}

void    send_response(t_data data)
{
    uint8_t key[17];
    uint8_t iv[17];
    t_data  re_data;
    int     msqid;
    uint8_t *response;
    int     response_len;

    printf("key_derivation:send_response() start\n");

    response = make_response(key, iv, data, &response_len);
    re_data.data_type = CK_SEND_SESSION_KEY; // PKCS#11 을 한번 따라보았다.
    re_data.data_len = response_len;
    memcpy(re_data.data_buf, response, response_len);

    if (-1 == (msqid = msgget((key_t)5678, IPC_CREAT | 0666)))
    {
        perror("key_derivation msgget() failed");
        exit(1);
    }

    if (-1 == (msgsnd(msqid, &re_data, sizeof(t_data) - sizeof(long), 0)))
    {
        perror("key_derivation msgsnd() failed");
        exit(1);
    }

    printf("key_derivation:send_response() end\n");
    free(response);
}

int verify_uid(t_data data)
{
    int read_bytes = 0;
    uint8_t buf[BUFFER_SIZE];
    int fd;

    printf("key_derivation:verify_uid() start\n");
    fd = open("../security_data/uid_list.txt", O_RDONLY);
    if (!fd)
    {
        perror("key_derivation open() failed");
        exit(1);
    }
    while ((read_bytes = read(fd, buf, BUFFER_SIZE)) > 0)
    {
        if (strstr(buf, data.data_buf))
        {
            printf("key_derivation:verift_uid() end\n");
            return (1);
        }
    }
    printf("User info not found\n");
    printf("key_derivation:verift_uid() end\n");
    return (0);
}

t_data    get_request()
{
    int     msqid;
    int     check = 0;
    t_data  ret;

    printf("key_derivation:get_request() start\n");
    if (-1 == (msqid = msgget((key_t)1234, IPC_CREAT | 0666)))
    {
        perror("key_derivation msgget() failed");
        exit(1);
    }
    if (-1 == (check = msgrcv(msqid, &ret, sizeof(t_data) - sizeof(long), 0, 0)))
    {
        perror("key_derivation msgrcv() failed");
        exit(1);
    }
    if (-1 == msgctl(msqid, IPC_RMID, 0))
    {
        perror("mq_recv:msgctl()");
        exit(1);
    }
    printf("key_derivation:get_request() end\n");

    return ret;
}

void    key_derivation()
{
    printf("*** key_derivation start ***\n");
    t_data data = get_request();
    if (strlen(data.data_buf) == 0)
    {
        printf("get_request failed\n");
        exit(1);
    }

    if (!verify_uid(data))
    {
        printf("user info not found\n");
        exit(1);
    }
    send_response(data);
    
    printf("*** key_derivation end ***\n");
}
