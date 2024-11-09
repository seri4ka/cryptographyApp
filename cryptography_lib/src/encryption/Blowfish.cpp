#include "Blowfish.h"
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <stdexcept>

Blowfish::Blowfish(const std::string& key) {
    // ������������� ���� ��� Blowfish (�� 16 ����)
    size_t keyLength = key.size() > sizeof(key_) ? sizeof(key_) : key.size();
    memcpy(key_, key.data(), keyLength);
    if (keyLength < sizeof(key_)) {
        memset(key_ + keyLength, 0, sizeof(key_) - keyLength);
    }
}

std::string Blowfish::encrypt(const std::string& plaintext) {
    BF_KEY bfKey;
    BF_set_key(&bfKey, sizeof(key_), key_);

    // �������������� IV ���������� �������
    unsigned char iv[BF_BLOCK];
    if (!RAND_bytes(iv, BF_BLOCK)) {
        throw std::runtime_error("�� ������� ������������� ��������� IV");
    }

    // ������� ������ ��� ������������ ������
    std::vector<unsigned char> encrypted(BF_BLOCK + plaintext.size());
    std::copy(iv, iv + BF_BLOCK, encrypted.begin()); // ��������� IV � ������ �������������� ������

    // �������
    int num = 0;
    BF_cfb64_encrypt(reinterpret_cast<const unsigned char*>(plaintext.data()),
        encrypted.data() + BF_BLOCK, plaintext.size(), &bfKey, iv, &num, BF_ENCRYPT);

    return std::string(encrypted.begin(), encrypted.end());
}

std::string Blowfish::decrypt(const std::string& ciphertext) {
    BF_KEY bfKey;
    BF_set_key(&bfKey, sizeof(key_), key_);

    if (ciphertext.size() < BF_BLOCK) {
        throw std::runtime_error("�������� ������������� �����");
    }

    // ��������� IV �� �������������� ������
    unsigned char iv[BF_BLOCK];
    std::copy(ciphertext.begin(), ciphertext.begin() + BF_BLOCK, iv);

    // ������� ������ ��� ��������������� ������
    std::vector<unsigned char> decrypted(ciphertext.size() - BF_BLOCK);

    int num = 0;
    BF_cfb64_encrypt(reinterpret_cast<const unsigned char*>(ciphertext.data() + BF_BLOCK),
        decrypted.data(), ciphertext.size() - BF_BLOCK, &bfKey, iv, &num, BF_DECRYPT);

    return std::string(decrypted.begin(), decrypted.end());
}

