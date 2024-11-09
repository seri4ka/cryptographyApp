#ifndef AES_H
#define AES_H

#include <stddef.h>  // Для определения типа size_t

extern "C" {
    __declspec(dllexport) void generateAESKey(unsigned char* key, size_t keySize);
    __declspec(dllexport) void generateIV(unsigned char* iv, size_t ivSize);
    __declspec(dllexport) int aesEncrypt(const char* plaintext, size_t plaintextLen, const unsigned char* key, const unsigned char* iv, unsigned char* encrypted);
    __declspec(dllexport) int aesDecrypt(const unsigned char* ciphertext, size_t ciphertextLen, const unsigned char* key, const unsigned char* iv, char* decrypted);
}

#endif // AES_H