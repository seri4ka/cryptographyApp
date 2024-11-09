#include "AES.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring>

void generateAESKey(unsigned char* key, size_t keySize) {
    if (keySize >= AES_BLOCK_SIZE) {
        RAND_bytes(key, AES_BLOCK_SIZE);
    }
}

void generateIV(unsigned char* iv, size_t ivSize) {
    if (ivSize >= AES_BLOCK_SIZE) {
        RAND_bytes(iv, AES_BLOCK_SIZE);
    }
}

int aesEncrypt(const char* plaintext, size_t plaintextLen, const unsigned char* key, const unsigned char* iv, unsigned char* encrypted) {
    AES_KEY encryptKey;
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv, AES_BLOCK_SIZE);

    if (AES_set_encrypt_key(key, 128, &encryptKey) < 0) {
        return -1;  // Ошибка установки ключа
    }

    // Шифруем данные
    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(plaintext), encrypted, plaintextLen, &encryptKey, ivCopy, AES_ENCRYPT);
    return ((plaintextLen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE; // Возвращаем размер зашифрованного текста
}

int aesDecrypt(const unsigned char* ciphertext, size_t ciphertextLen, const unsigned char* key, const unsigned char* iv, char* decrypted) {
    AES_KEY decryptKey;
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv, AES_BLOCK_SIZE);

    if (AES_set_decrypt_key(key, 128, &decryptKey) < 0) {
        return -1;  // Ошибка установки ключа
    }

    AES_cbc_encrypt(ciphertext, reinterpret_cast<unsigned char*>(decrypted), ciphertextLen, &decryptKey, ivCopy, AES_DECRYPT);

    // Убираем padding, если он был добавлен
    int paddingLength = decrypted[ciphertextLen - 1];
    if (paddingLength <= AES_BLOCK_SIZE) {
        decrypted[ciphertextLen - paddingLength] = '\0';
    }

    return ciphertextLen - paddingLength;  // Возвращаем фактический размер расшифрованного текста
}


