#include "../inc/KMS_client.h"

int main()
{
    printf("session start\n");

    key_t key_send_command = (key_t)319974;
    key_t key_recv_result = (key_t)319975;
    // key derivation
    printf("Loging in...\n");
    if (!boot_proc())
    {
        perror("verify failed");
        exit(0);
    }
    printf("session key derivation success\n");
    // command process
    command_proc(key_send_command);
    mq_recv(key_recv_result);
    printf("session end\n");

} 