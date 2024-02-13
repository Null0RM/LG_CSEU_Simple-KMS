#include <stdio.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <sys/ipc.h>

int main(void)
{
    int msqid;
    
    printf("process start\n");
    for(int i = 0; i < 10000; i++)
    {
        msqid = msgget((key_t)i, IPC_CREAT | 0666);
        if (msqid == -1)
            printf("%d ", i);
        msgctl(msqid, IPC_RMID, 0);
    }
    printf("\nprocess finish\n");
}
