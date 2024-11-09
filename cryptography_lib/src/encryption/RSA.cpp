#include "RSA.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>

// Функция для кодирования в base64
std::string base64Encode(const std::string& input) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, input.data(), static_cast<int>(input.size())); // приведение типа
    BIO_flush(bio);
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

// Функция для декодирования из base64
std::string base64Decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size())); // приведение типа
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    std::vector<char> decoded(encoded.size());
    int decodedLength = BIO_read(bio, decoded.data(), static_cast<int>(encoded.size())); // приведение типа
    BIO_free_all(bio);
    return std::string(decoded.data(), decodedLength);
}

// Функция для генерации RSA-ключей
void generateRSAKey(const std::string& publicKeyFile, const std::string& privateKeyFile) {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    if (RSA_generate_key_ex(rsa, 2048, e, NULL) != 1) {
        std::cerr << "Ошибка генерации RSA ключей" << std::endl;
        BN_free(e);
        RSA_free(rsa);
        return;
    }

    // Используем EVP_PKEY для совместимости с OpenSSL 3.0
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    BIO* publicKey = BIO_new_file(publicKeyFile.c_str(), "w+");
    BIO* privateKey = BIO_new_file(privateKeyFile.c_str(), "w+");

    PEM_write_bio_PUBKEY(publicKey, pkey);
    PEM_write_bio_PrivateKey(privateKey, pkey, NULL, NULL, 0, NULL, NULL);

    BIO_free_all(publicKey);
    BIO_free_all(privateKey);
    EVP_PKEY_free(pkey);
    BN_free(e);
    // `rsa` освобождать не нужно, так как он уже освобожден вместе с `pkey`
}

// Загрузка публичного ключа
EVP_PKEY* loadPublicKey(const std::string& publicKeyFile) {
    FILE* file = fopen(publicKeyFile.c_str(), "rb");
    if (!file) {
        std::cerr << "Не удалось открыть файл с публичным ключом." << std::endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);
    return pkey;
}

// Загрузка приватного ключа
EVP_PKEY* loadPrivateKey(const std::string& privateKeyFile) {
    FILE* file = fopen(privateKeyFile.c_str(), "rb");
    if (!file) {
        std::cerr << "Не удалось открыть файл с приватным ключом." << std::endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return pkey;
}

// Шифрование сообщения
std::string rsaEncrypt(const std::string& message, const std::string& publicKeyFile) {
    EVP_PKEY* pkey = loadPublicKey(publicKeyFile);
    if (!pkey) return "";

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);  // Извлечение RSA из EVP_PKEY
    int rsaLen = RSA_size(rsa);
    std::string encrypted(rsaLen, '\0');

    int result = RSA_public_encrypt(
        static_cast<int>(message.size()),
        reinterpret_cast<const unsigned char*>(message.c_str()),
        reinterpret_cast<unsigned char*>(&encrypted[0]),
        rsa, RSA_PKCS1_PADDING
    );

    EVP_PKEY_free(pkey);  // Освобождаем `pkey`, который включает `rsa`

    if (result == -1) {
        std::cerr << "Ошибка шифрования: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return "";
    }
    return encrypted;
}

// Дешифрование сообщения
std::string rsaDecrypt(const std::string& encrypted, const std::string& privateKeyFile) {
    EVP_PKEY* pkey = loadPrivateKey(privateKeyFile);
    if (!pkey) return "";

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);  // Извлечение RSA из EVP_PKEY
    int rsaLen = RSA_size(rsa);
    std::string decrypted(rsaLen, '\0');

    int result = RSA_private_decrypt(
        static_cast<int>(encrypted.size()),
        reinterpret_cast<const unsigned char*>(encrypted.c_str()),
        reinterpret_cast<unsigned char*>(&decrypted[0]),
        rsa, RSA_PKCS1_PADDING
    );

    EVP_PKEY_free(pkey);  // Освобождаем `pkey`, который включает `rsa`

    if (result == -1) {
        std::cerr << "Ошибка дешифрования: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return "";
    }
    decrypted.resize(result);
    return decrypted;
}


