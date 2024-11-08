#include "AES.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <stdexcept>
#include <vector>

// ������ ����� AES (128, 192, ��� 256 ���)
const int AES_KEY_LENGTH = 256; // ��� AES-256

// ������� ��� ��������� ���������� ����� AES
std::vector<unsigned char> generateAESKey() {
    std::vector<unsigned char> key(AES_KEY_LENGTH / 8);
    if (!RAND_bytes(key.data(), AES_KEY_LENGTH / 8)) {
        throw std::runtime_error("������ ��� ��������� ����� AES");
    }
    return key;
}

// ������� ��� ��������� ���������� ������� ������������� (IV)
std::vector<unsigned char> generateIV() {
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    if (!RAND_bytes(iv.data(), AES_BLOCK_SIZE)) {
        throw std::runtime_error("������ ��� ��������� IV");
    }
    return iv;
}

// ������� AES ����������
std::vector<unsigned char> aesEncrypt(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    AES_KEY encryptKey;
    if (AES_set_encrypt_key(key.data(), AES_KEY_LENGTH, &encryptKey) < 0) {
        throw std::runtime_error("������ ��� ��������� ����� AES");
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

    ciphertext.resize(plaintext.size()); // ������� �������
    return ciphertext;
}

// ������� AES ������������
std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    AES_KEY decryptKey;
    if (AES_set_decrypt_key(key.data(), AES_KEY_LENGTH, &decryptKey) < 0) {
        throw std::runtime_error("������ ��� ��������� ����� AES");
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
