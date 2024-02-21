#include "../inc/operation.h"

void    logging(int length, uint8_t * data, uint8_t * str)
{
    fprintf(stdout, "%s\n", str);
    for(int i = 0; i < length; i++)
        fprintf(stdout, "%02x ", data[i]);
    fprintf(stdout, "\n");
}

t_keys get_session_key()
{
    printf("mq_recv:get_session_key() start\n");
    int fd;
    t_keys ret_key;
    uint8_t buffer[BUFFER_SIZE];
    uint8_t *idx;

    if ((fd = open("../security_data/session_key_list.txt", O_RDONLY)) < 0)
    {
        perror("mq_recv:open()");
        exit(1);
    }
    if (read(fd, buffer, BUFFER_SIZE) < 0)
    {
        perror("mq_recv:read()");
        exit(1);
    }
    idx = strstr(buffer, "key: ");
    memcpy(ret_key.key, idx + 5, 16);
    idx = strstr(buffer, "iv: ");
    memcpy(ret_key.iv, idx + 4, 16);

    close(fd);
    printf("mq_recv:get_session_key() end\n");

    return (ret_key);
}

uint8_t *mq_recv_payload(key_t key, int *recv_len, int *oper_type, t_keys session_key)
{
    /*
    key: mq session key ID
    recv_len: received data length
    oper_type: operation type
    */
    fprintf(stdout, "mq_recv:mq_recv_payload() start\n");
  
    int tmp_length;
    int msqid;
    t_data recv_data;
    uint8_t *payload = NULL;
    uint8_t *newPayload = NULL;
    uint8_t tmp_data[BUFFER_SIZE] = {};
    int prev_size = 0;

    if (-1 == (msqid = msgget(key, IPC_CREAT | 0666)))
    {
        perror("mq_recv:msgget()");
        exit(1);
    }
    while (1)
    {
        fprintf(stdout, "receiving message from client...\n");
        if (-1 == (msgrcv(msqid, &recv_data, sizeof(t_data) - sizeof(long), 0, 0)))
        {
            perror("mq_recv:msgrcv()");
            exit(1);
        }
        printf("recvdata.data_len: %d\n", recv_data.data_len);
        *oper_type = recv_data.data_type;

        // 정해진 size만큼 payload를 저장할 공간을 할당하는 코드
        if (payload == NULL)
        {
            payload = (uint8_t *)malloc(recv_data.data_len);
            if (!payload)
            {
                perror("mq_recv:mq_recv_payload:malloc()");
                exit(1);
            }
        }
        else
        {
            newPayload = (uint8_t *)realloc(payload, prev_size + recv_data.data_len);
            if (!newPayload)
            {
                perror("mq_recv:mq_recv_payload:realloc()");
                exit(1);
            }
            payload = newPayload; // 이렇게 해야 heap 영역 공간 부족 이슈를 해결할 수 있다.
        }
        
        logging(recv_data.data_len, recv_data.data_buf, "recvd data");

        tmp_length = decrypt_operation(EVP_aes_128_cbc(), tmp_data, recv_data.data_buf, recv_data.data_len, session_key.key, session_key.iv);
        
        logging(tmp_length, tmp_data, ">>decrypted message");
        memcpy(payload + prev_size, tmp_data, tmp_length);
        prev_size += tmp_length;

        if (recv_data.data_fin == 1)
        {
            *recv_len = prev_size;
            break;
        }
    }
    if (-1 == msgctl(msqid, IPC_RMID, 0))
    {
        perror("mq_recv:msgctl()");
        exit(1);
    }

    fprintf(stdout, "mq_recv:mq_recv_payload() end\n");
    return (payload);
}

void * mq_recv(key_t key, int *oper_type)
{
    printf("mq_recv start\n");

    int oper_len = 0;
    t_keys session_key;
    uint8_t *payload;
    void *struct_oper;

    session_key = get_session_key();
    payload = mq_recv_payload(key, &oper_len, oper_type, session_key);
    if (!payload)
    {
        perror("mq_recv:mq_recv_payload()");
        exit(1);
    }
    struct_oper = deserialize_tlv(payload, oper_len, *oper_type);
    
    free(payload);
    printf("mq_recv end\n");
    return (struct_oper);
}
