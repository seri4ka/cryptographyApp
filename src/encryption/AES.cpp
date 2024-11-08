#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <stdexcept>

std::vector<unsigned char> generateAESKey() {
    std::vector<unsigned char> key(AES_BLOCK_SIZE); // Используем 128-битный ключ
    if (!RAND_bytes(key.data(), AES_BLOCK_SIZE)) {
        throw std::runtime_error("Ошибка генерации AES ключа.");
    }
    return key;
}

std::vector<unsigned char> generateIV() {
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    if (!RAND_bytes(iv.data(), AES_BLOCK_SIZE)) {
        throw std::runtime_error("Ошибка генерации IV.");
    }
    return iv;
}

std::vector<unsigned char> aesEncrypt(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    AES_KEY encryptKey;
    if (AES_set_encrypt_key(key.data(), 128, &encryptKey) < 0) {
        throw std::runtime_error("Ошибка установки AES ключа для шифрования.");
    }

    int encryptedSize = ((plaintext.size() / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    std::vector<unsigned char> encrypted(encryptedSize);

    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv.data(), AES_BLOCK_SIZE);

    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(plaintext.data()), encrypted.data(),
        plaintext.size(), &encryptKey, ivCopy, AES_ENCRYPT);

    return encrypted;
}

std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    AES_KEY decryptKey;
    if (AES_set_decrypt_key(key.data(), 128, &decryptKey) < 0) {
        throw std::runtime_error("Ошибка установки AES ключа для дешифрования.");
    }

    std::vector<unsigned char> decrypted(ciphertext.size());
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv.data(), AES_BLOCK_SIZE);

    AES_cbc_encrypt(ciphertext.data(), decrypted.data(), ciphertext.size(), &decryptKey, ivCopy, AES_DECRYPT);

    int paddingLength = decrypted.back();
    if (paddingLength <= AES_BLOCK_SIZE) {
        decrypted.resize(decrypted.size() - paddingLength);
    }

    return std::string(decrypted.begin(), decrypted.end());
}

