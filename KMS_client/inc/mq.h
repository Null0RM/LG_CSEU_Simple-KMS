#ifndef MQ_H
# define MQ_H

#include "../inc/common.h"

/* ___MESSAGE_QUEUE_START___ */
// include library files
#  include <sys/types.h>
#  include <sys/ipc.h>
#  include <sys/msg.h>
// define&typedef macros of mq send/recv data

#  define BUFFER_SIZE 1024 // buffer size

#  define CK_GET_SESSION_KEY 0x00000001
#  define CK_SEND_SESSION_KEY 0x20000000

typedef struct s_data
{
    long    data_type;
    int     data_seq;
    int     data_len;
    int     data_fin;
    uint8_t data_buf[BUFFER_SIZE];
} t_data;

/* ___MESSAGE_QUEUE_END___ */

/* ___FUNCTION_START___ */
int mq_recv(key_t key);
int boot_proc(void);

#endif