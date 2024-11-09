#include "RSA.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>

static std::string staticEncrypted;
static std::string staticDecrypted;
static std::string staticEncoded;
static std::string staticDecoded;

const char* base64Encode(const char* input) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, input, static_cast<int>(strlen(input)));
    BIO_flush(bio);
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    staticEncoded.assign(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return staticEncoded.c_str();
}

const char* base64Decode(const char* encoded) {
    BIO* bio = BIO_new_mem_buf(encoded, static_cast<int>(strlen(encoded)));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    std::vector<char> decoded(strlen(encoded));
    int decodedLength = BIO_read(bio, decoded.data(), static_cast<int>(strlen(encoded)));
    BIO_free_all(bio);
    staticDecoded.assign(decoded.data(), decodedLength);
    return staticDecoded.c_str();
}

void generateRSAKey(const char* publicKeyFile, const char* privateKeyFile) {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    if (RSA_generate_key_ex(rsa, 2048, e, NULL) != 1) {
        std::cerr << "Ошибка генерации RSA ключей" << std::endl;
        BN_free(e);
        RSA_free(rsa);
        return;
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    BIO* publicKey = BIO_new_file(publicKeyFile, "w+");
    BIO* privateKey = BIO_new_file(privateKeyFile, "w+");

    PEM_write_bio_PUBKEY(publicKey, pkey);
    PEM_write_bio_PrivateKey(privateKey, pkey, NULL, NULL, 0, NULL, NULL);

    BIO_free_all(publicKey);
    BIO_free_all(privateKey);
    EVP_PKEY_free(pkey);
    BN_free(e);
}

EVP_PKEY* loadPublicKey(const char* publicKeyFile) {
    FILE* file = fopen(publicKeyFile, "rb");
    if (!file) {
        std::cerr << "Не удалось открыть файл с публичным ключом." << std::endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);
    return pkey;
}

EVP_PKEY* loadPrivateKey(const char* privateKeyFile) {
    FILE* file = fopen(privateKeyFile, "rb");
    if (!file) {
        std::cerr << "Не удалось открыть файл с приватным ключом." << std::endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return pkey;
}

const char* rsaEncrypt(const char* message, const char* publicKeyFile) {
    EVP_PKEY* pkey = loadPublicKey(publicKeyFile);
    if (!pkey) return "";

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    int rsaLen = RSA_size(rsa);
    staticEncrypted.resize(rsaLen);

    int result = RSA_public_encrypt(
        static_cast<int>(strlen(message)),
        reinterpret_cast<const unsigned char*>(message),
        reinterpret_cast<unsigned char*>(&staticEncrypted[0]),
        rsa, RSA_PKCS1_PADDING
    );

    EVP_PKEY_free(pkey);

    if (result == -1) {
        std::cerr << "Ошибка шифрования: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return "";
    }
    return staticEncrypted.c_str();
}

const char* rsaDecrypt(const char* encrypted, const char* privateKeyFile) {
    EVP_PKEY* pkey = loadPrivateKey(privateKeyFile);
    if (!pkey) return "";

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    int rsaLen = RSA_size(rsa);
    staticDecrypted.resize(rsaLen);

    int result = RSA_private_decrypt(
        static_cast<int>(strlen(encrypted)),
        reinterpret_cast<const unsigned char*>(encrypted),
        reinterpret_cast<unsigned char*>(&staticDecrypted[0]),
        rsa, RSA_PKCS1_PADDING
    );

    EVP_PKEY_free(pkey);

    if (result == -1) {
        std::cerr << "Ошибка дешифрования: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return "";
    }
    staticDecrypted.resize(result);
    return staticDecrypted.c_str();
}



