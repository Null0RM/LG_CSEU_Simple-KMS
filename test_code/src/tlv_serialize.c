#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    int id;
    uint8_t name[100];
    float score;
} t_data;

void serialize_tlv(const t_data* data, char* buffer, int* length) {
    int offset = 0;

    // ID 태그와 길이를 저장
    buffer[offset++]= 'I';
    buffer[offset++]= 'D';
    buffer[offset++]= sizeof(int);
    memcpy(buffer + offset, &(data->id), sizeof(int));
    offset += sizeof(int);

    // Name 태그와 길이를 저장
    buffer[offset++]= 'N';
    buffer[offset++]= 'M';
    buffer[offset++]= strlen(data->name);
    memcpy(buffer + offset, data->name, strlen(data->name));
    offset += strlen(data->name);

    // Score 태그와 길이를 저장
    buffer[offset++]= 'S';
    buffer[offset++]= 'C';
    buffer[offset++]= sizeof(float);
    memcpy(buffer + offset, &(data->score), sizeof(float));
    offset += sizeof(float);

    *length = offset;
}

void deserialize_tlv(const uint8_t* buffer, int length, t_data* data) {
    int offset = 0;

    while (offset < length) {
        uint8_t tag[2];
        tag[0]= buffer[offset++];
        tag[1]= buffer[offset++];

        int tag_length = buffer[offset++];
        if (tag_length <= 0) {
            break;
        }

        if (tag[0]== 'I' && tag[1]== 'D') {
            memcpy(&(data->id), buffer + offset, tag_length);
        } else if (tag[0]== 'N' && tag[1]== 'M') {
            memcpy(data->name, buffer + offset, tag_length);
            data->name[tag_length]= '\0';
        } else if (tag[0]== 'S' && tag[1]== 'C') {
            memcpy(&(data->score), buffer + offset, tag_length);
        }

        offset += tag_length;
    }
}

int main() {
    t_data original_data;
    original_data.id = 1;
    strcpy(original_data.name, "John");
    original_data.score = 95.5;

    // 직렬화된 데이터를 저장할 버퍼
    uint8_t buffer[256];
    int length;

    // 구조체를 TLV 형식으로 직렬화하여 버퍼에 저장
    serialize_tlv(&original_data, buffer, &length);

    // 직렬화된 데이터를 출력
    printf("Serialized Data: ");
    for (int i = 0; i < length; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");

    // 직렬화된 데이터를 역직렬화하여 구조체로 변환
    t_data deserialized_data;
    deserialize_tlv(buffer, length, &deserialized_data);

    // 역직렬화된 데이터 출력
    printf("Deserialized Data:\n");
    printf("ID: %d\n", deserialized_data.id);
    printf("Name: %s\n", deserialized_data.name);
    printf("Score: %.2f\n", deserialized_data.score);

    return 0;
}