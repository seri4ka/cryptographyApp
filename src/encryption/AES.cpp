#include "AES.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <stdexcept>
#include <vector>

// Размер ключа AES (128, 192, или 256 бит)
const int AES_KEY_LENGTH = 256; // для AES-256

// Функция для генерации случайного ключа AES
std::vector<unsigned char> generateAESKey() {
    std::vector<unsigned char> key(AES_KEY_LENGTH / 8);
    if (!RAND_bytes(key.data(), AES_KEY_LENGTH / 8)) {
        throw std::runtime_error("Ошибка при генерации ключа AES");
    }
    return key;
}

// Функция для генерации случайного вектора инициализации (IV)
std::vector<unsigned char> generateIV() {
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    if (!RAND_bytes(iv.data(), AES_BLOCK_SIZE)) {
        throw std::runtime_error("Ошибка при генерации IV");
    }
    return iv;
}

// Функция AES шифрования
std::vector<unsigned char> aesEncrypt(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    AES_KEY encryptKey;
    if (AES_set_encrypt_key(key.data(), AES_KEY_LENGTH, &encryptKey) < 0) {
        throw std::runtime_error("Ошибка при установке ключа AES");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int numBlocks = 0;

    AES_cfb128_encrypt(
        reinterpret_cast<const unsigned char*>(plaintext.c_str()),
        ciphertext.data(),
        plaintext.size(),
        &encryptKey,
        const_cast<unsigned char*>(iv.data()),
        &numBlocks,
        AES_ENCRYPT
    );

    ciphertext.resize(plaintext.size()); // обрезка лишнего
    return ciphertext;
}

// Функция AES дешифрования
std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    AES_KEY decryptKey;
    if (AES_set_decrypt_key(key.data(), AES_KEY_LENGTH, &decryptKey) < 0) {
        throw std::runtime_error("Ошибка при установке ключа AES");
    }

    std::vector<unsigned char> decryptedText(ciphertext.size());
    int numBlocks = 0;

    AES_cfb128_encrypt(
        ciphertext.data(),
        decryptedText.data(),
        ciphertext.size(),
        &decryptKey,
        const_cast<unsigned char*>(iv.data()),
        &numBlocks,
        AES_DECRYPT
    );

    return std::string(decryptedText.begin(), decryptedText.end());
}
