#include "Blowfish.h"
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <stdexcept>

Blowfish::Blowfish(const std::string& key) {
    // Установим ключ для Blowfish (до 16 байт)
    size_t keyLength = key.size() > sizeof(key_) ? sizeof(key_) : key.size();
    memcpy(key_, key.data(), keyLength);
    if (keyLength < sizeof(key_)) {
        memset(key_ + keyLength, 0, sizeof(key_) - keyLength);
    }
}

std::string Blowfish::encrypt(const std::string& plaintext) {
    BF_KEY bfKey;
    BF_set_key(&bfKey, sizeof(key_), key_);

    std::vector<unsigned char> encrypted(plaintext.size() + BF_BLOCK);
    unsigned char iv[BF_BLOCK] = { 0 };  // Инициализационный вектор (можно сгенерировать рандомно)

    int num = 0;
    BF_cfb64_encrypt(reinterpret_cast<const unsigned char*>(plaintext.data()),
        encrypted.data(), plaintext.size(), &bfKey, iv, &num, BF_ENCRYPT);

    return std::string(encrypted.begin(), encrypted.end());
}

std::string Blowfish::decrypt(const std::string& ciphertext) {
    BF_KEY bfKey;
    BF_set_key(&bfKey, sizeof(key_), key_);

    std::vector<unsigned char> decrypted(ciphertext.size());
    unsigned char iv[BF_BLOCK] = { 0 };  // Инициализационный вектор

    int num = 0;
    BF_cfb64_encrypt(reinterpret_cast<const unsigned char*>(ciphertext.data()),
        decrypted.data(), ciphertext.size(), &bfKey, iv, &num, BF_DECRYPT);

    return std::string(decrypted.begin(), decrypted.end());
}
