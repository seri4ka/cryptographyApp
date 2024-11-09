#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stddef.h>

extern "C" {
    __declspec(dllexport) void blowfishInit(const unsigned char* key, size_t keySize);
    __declspec(dllexport) int blowfishEncrypt(const unsigned char* plaintext, size_t plaintextLen, unsigned char* encrypted);
    __declspec(dllexport) int blowfishDecrypt(const unsigned char* ciphertext, size_t ciphertextLen, unsigned char* decrypted);
}

#endif // BLOWFISH_H
