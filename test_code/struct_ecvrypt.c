#include <stdio.h>
#include <stdint.h>


// int main(void)
// {
//     uint8_t hex_data[32] = {0x2a, 0x00, 0x00, 0x00, 0xc3, 0xf5, 0x48, 0x40, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x00, 0x00, 0x00};
    
//     printf("%d\n", (int)hex_data[0]);
//     printf("%f\n", (float)*(hex_data + 4));
//     printf("%s\n", (char *)(hex_data + 8));
// }

#include < stdio.h>
#include < stdlib.h>
#include < string.h>
#include < openssl/evp.h>

// 암호화에 사용할 키와 IV (Initialization Vector)
#define KEY_SIZE 32
#define IV_SIZE 16

// 암호화 함수
int encrypt_struct(const void* plaintext, size_t plaintext_len, const unsigned char* key, const unsigned char* iv, void* ciphertext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

    // 암호화 컨텍스트 생성
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    // 암호화 초기화
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 암호화 수행
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // 암호화 마무리
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // 암호화 컨텍스트 해제
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// 예제 구조체
struct example_struct {
    int value1;
    float value2;
    char value3[16];
};

int main() {
    // 암호화에 사용할 키와 IV 생성
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    // 암호화할 struct
    struct example_struct plaintext;
    plaintext.value1 = 42;
    plaintext.value2 = 3.14;
    strncpy(plaintext.value3, "Hello, World!", sizeof(plaintext.value3));

    // 암호화된 struct를 저장할 버퍼
    unsigned char ciphertext[sizeof(struct example_struct)];

    // struct 암호화
    int ciphertext_len = encrypt_struct(&plaintext, sizeof(struct example_struct), key, iv, ciphertext);
    if (ciphertext_len == -1) {
        printf("암호화 실패\n");
        return 1;
    }

    // 암호화된 struct 출력
    printf("암호화된 struct:\n");
    for (int i = 0; i <  ciphertext_len; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    return 0;
}