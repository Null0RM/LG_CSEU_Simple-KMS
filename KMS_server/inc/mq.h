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

/**
 * @fn MQ를 통해 data를 수신하여 해당 data를 return 하는 함수
 * @date 20240129
 * @param[in] void
 * @param[out] data
*/
t_data    get_request(); 
/**
 * @fn key와 IV를 만드는 함수
*/
uint8_t    *make_response(uint8_t *key, uint8_t *iv, t_data data, int *response_len);
/**
 * @fn random값을 만들어 response에 저장하고, response를 다시 client로 보내주는 역할을 함.
 * @date 20240129
*/
void    send_response(t_data data);
/**
 * @fn open "../security_data/uid_list.txt" and check if their exists requester's UID
 * @date 20240129
*/
int    verify_uid(t_data data);
void    key_derivation();

int mq_send(uint8_t *to_send, key_t key, int len, int oper_type);

/* ___FUNCTION_END___ */

#endif