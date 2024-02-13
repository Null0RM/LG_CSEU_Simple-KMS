#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define BUFFER_SIZE 5


uint8_t *input_encryption_target_text(void)
{
    fprintf(stdout, "command_proc:input_encryption_target_text:start\n");

    uint8_t buffer[BUFFER_SIZE];
    uint8_t *ret = NULL;
    int     total_size = 0;
    int     size = 0;

    while (1) {
        fgets(buffer, BUFFER_SIZE, stdin);
        size = strlen(buffer);
        total_size += size;
        if (ret == NULL)
        {
            ret = (uint8_t *)malloc(total_size + 1);
            memcpy(ret, buffer, total_size + 1);
        }
        else {
            ret = (uint8_t *)realloc(ret, total_size + 1);
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
int main(void)
{
    uint8_t *p;
    p = input_encryption_target_text();
    printf("%s", p);
}