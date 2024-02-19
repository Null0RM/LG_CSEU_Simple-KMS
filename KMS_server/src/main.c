#include "../inc/KMS_server.h"

int main(int argc, char **argv)
{
    int     cnt = 0;
    key_t   key_recv_command = (key_t)319974;
    key_t   key_send_result = (key_t)319975;
    void    *struct_oper;
    int     oper_type;
    int     len = 0;

    while(1)
    {
        printf("***** start process #%d *****\n", cnt);

        key_derivation();

        struct_oper = mq_recv(key_recv_command, &oper_type);
        uint8_t *serial = do_op(struct_oper, oper_type, &len);

        mq_send(serial, key_send_result, len);
        
        free(serial);
        printf("***** end process #%d *****\n\n", cnt++);
    }
}