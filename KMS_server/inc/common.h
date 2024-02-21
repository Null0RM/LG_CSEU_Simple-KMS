#ifndef COMMON_H
# define COMMON_H

#  include <stdio.h>
#  include <string.h>
#  include <stdlib.h>
#  include <fcntl.h>
#  include <unistd.h>
#  include <stdint.h>
#  include <time.h>

void    logging(int length, uint8_t * data, uint8_t * str);

#endif