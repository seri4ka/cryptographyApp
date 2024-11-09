#ifndef RSA_H
#define RSA_H

#include <stddef.h>

extern "C" {
    __declspec(dllexport) void generateRSAKey(const char* publicKeyFile, const char* privateKeyFile);
    __declspec(dllexport) int rsaEncrypt(const char* message, const char* publicKeyFile, unsigned char* encrypted, size_t encryptedSize);
    __declspec(dllexport) int rsaDecrypt(const unsigned char* encrypted, size_t encryptedLen, const char* privateKeyFile, char* decrypted, size_t decryptedSize);
    __declspec(dllexport) int base64Encode(const unsigned char* input, size_t inputLen, char* encoded, size_t encodedSize);
    __declspec(dllexport) int base64Decode(const char* encoded, unsigned char* decoded, size_t decodedSize);
}

#endif // RSA_H

