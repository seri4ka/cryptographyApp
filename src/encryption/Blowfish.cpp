#include "Blowfish.h"
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

static BF_KEY bfKey;  // Храним ключ для использования в функциях шифрования и дешифрования

extern "C" {
    __declspec(dllexport) void blowfishInit(const unsigned char* key, size_t keySize) {
        if (keySize > 16) {
            throw std::runtime_error("Длина ключа не должна превышать 16 байт для Blowfish");
        }
        BF_set_key(&bfKey, static_cast<int>(keySize), key);
    }

    __declspec(dllexport) int blowfishEncrypt(const unsigned char* plaintext, size_t plaintextLen, unsigned char* encrypted) {
        if (!plaintext || !encrypted) {
            return -1; // Ошибка, если указатели неверны
        }

        unsigned char iv[BF_BLOCK];
        if (!RAND_bytes(iv, BF_BLOCK)) {
            return -1;  // Ошибка генерации IV
        }
        memcpy(encrypted, iv, BF_BLOCK);  // Копируем IV в начало зашифрованного текста

        int num = 0;
        BF_cfb64_encrypt(plaintext, encrypted + BF_BLOCK, plaintextLen, &bfKey, iv, &num, BF_ENCRYPT);

        return static_cast<int>(plaintextLen + BF_BLOCK);  // Длина зашифрованных данных
    }

    __declspec(dllexport) int blowfishDecrypt(const unsigned char* ciphertext, size_t ciphertextLen, unsigned char* decrypted) {
        if (ciphertextLen <= BF_BLOCK) {
            return -1; // Ошибка, если зашифрованный текст слишком короткий для содержимого
        }

        unsigned char iv[BF_BLOCK];
        memcpy(iv, ciphertext, BF_BLOCK);  // Извлекаем IV из зашифрованного текста

        int num = 0;
        BF_cfb64_encrypt(ciphertext + BF_BLOCK, decrypted, ciphertextLen - BF_BLOCK, &bfKey, iv, &num, BF_DECRYPT);

        return static_cast<int>(ciphertextLen - BF_BLOCK);  // Длина расшифрованных данных
    }
}


