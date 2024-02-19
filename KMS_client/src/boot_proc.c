/*
system 함수 호출 등을 이용해
하위 프로세스 실행하는 것도 괜찮지않을까?
예를 들어 RSA 키교환이라든지 그런거 있잖아유 ㅎ
*/

#include "../inc/mq.h"
#include "../inc/openssl_utils.h"

static uint8_t hard_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                                0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

void    write_response(char *key)
{
    // printf("write_response() start\n");

    int fd = open("../recvd/sessionKey.txt", O_CREAT | O_WRONLY, 0644);
    if (!fd)
    {
        perror("boot_proc open() failed");
        exit(1);
    }
    write(fd, key, strlen(key));
    close(fd);

    // printf("write_response() end\n");
}

void    recv_response() 
{
    int     msqid;
    t_data  data;
    int     check = 0;
    uint8_t *key;
    uint8_t *tmp_data;

    // printf("boot_proc:recv_response() start\n");
    tmp_data = (uint8_t *)malloc(strlen(data.data_buf));
    if (-1 == (msqid = msgget((key_t)5678, IPC_CREAT | 0666)))
    {
        perror("boot_proc:msgget()");
        exit(1);
    }
    if (-1 == (check = msgrcv(msqid, &data, sizeof(t_data) - sizeof(long), 0, 0)))
    {
        perror("boot_proc:msgrcv()");
        exit(1);
    }
    if (-1 == msgctl(msqid, IPC_RMID, 0))
    {
        perror("mq_recv:msgctl()");
        exit(1);
    }
    if (!(key = malloc(data.data_len + 1)))
    {
        perror("boot_proc:recv_response:malloc()");
        exit(1);
    }
    decrypt_operation(EVP_aes_128_ecb(), key, data.data_buf, data.data_len, hard_key, NULL);
    write_response(key);
    free(key);
}

void    send_request()
{
    int     msqid = 0;
    t_data  data;
    uid_t   uid = getuid();

    // printf("boot_proc:send_request() start\n");
    data.data_type = CK_GET_SESSION_KEY;
    sprintf(data.data_buf, "uid=%-12d", uid);
    data.data_len = strlen(data.data_buf);

    if (-1 == (msqid = msgget((key_t)1234, IPC_CREAT | 0666)))
    {
        perror("boot_proc msgget() failed");
        exit(1);
    }
    if (-1 == (msgsnd(msqid, &data, sizeof(t_data) - sizeof(long), 0)))
    {
        perror("boot_proc msgsnd() failed");
        exit(1);
    }
    // printf("boot_proc:send_request msqid=%d end\n", msqid);
}

int boot_proc()
{
    // printf("*** boot_proc start ***\n");

    send_request();
    recv_response();

    // printf("*** boot_proc end ***\n");

    return (1);
}
