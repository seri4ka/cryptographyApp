#include "Blowfish.h"
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

static BF_KEY bfKey;  // ������ ���� ��� ������������� � �������� ���������� � ������������

extern "C" {
    __declspec(dllexport) void blowfishInit(const unsigned char* key, size_t keySize) {
        if (keySize > 16) {
            throw std::runtime_error("����� ����� �� ������ ��������� 16 ���� ��� Blowfish");
        }
        BF_set_key(&bfKey, static_cast<int>(keySize), key);
    }

    __declspec(dllexport) int blowfishEncrypt(const unsigned char* plaintext, size_t plaintextLen, unsigned char* encrypted) {
        if (!plaintext || !encrypted) {
            return -1; // ������, ���� ��������� �������
        }

        unsigned char iv[BF_BLOCK];
        if (!RAND_bytes(iv, BF_BLOCK)) {
            return -1;  // ������ ��������� IV
        }
        memcpy(encrypted, iv, BF_BLOCK);  // �������� IV � ������ �������������� ������

        int num = 0;
        BF_cfb64_encrypt(plaintext, encrypted + BF_BLOCK, plaintextLen, &bfKey, iv, &num, BF_ENCRYPT);

        return static_cast<int>(plaintextLen + BF_BLOCK);  // ����� ������������� ������
    }

    __declspec(dllexport) int blowfishDecrypt(const unsigned char* ciphertext, size_t ciphertextLen, unsigned char* decrypted) {
        if (ciphertextLen <= BF_BLOCK) {
            return -1; // ������, ���� ������������� ����� ������� �������� ��� �����������
        }

        unsigned char iv[BF_BLOCK];
        memcpy(iv, ciphertext, BF_BLOCK);  // ��������� IV �� �������������� ������

        int num = 0;
        BF_cfb64_encrypt(ciphertext + BF_BLOCK, decrypted, ciphertextLen - BF_BLOCK, &bfKey, iv, &num, BF_DECRYPT);

        return static_cast<int>(ciphertextLen - BF_BLOCK);  // ����� �������������� ������
    }
}


