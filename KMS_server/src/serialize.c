#include "../inc/operation.h"

void storeLE16(uint8_t *buffer, uint16_t value) {
    buffer[0]= value & 0xFF;
    buffer[1]= (value >> 8) & 0xFF;
}

void storeLE32(uint8_t *buffer, uint32_t value) {
    buffer[0]= value & 0xFF;
    buffer[1]= (value >> 8) & 0xFF;
    buffer[2]= (value >> 16) & 0xFF;
    buffer[3]= (value >> 24) & 0xFF;
}
