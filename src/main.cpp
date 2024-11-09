#include "encryption/RSA.h"
#include "encryption/Blowfish.h"
#include "encryption/AES.h"
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

int main() {
    // Настройки консоли для поддержки кириллицы
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setlocale(LC_ALL, "");

    // ---------- Тестирование RSA ----------
    std::string publicKeyFile = "public.pem";
    std::string privateKeyFile = "private.pem";

    generateRSAKey(publicKeyFile, privateKeyFile);
    std::cout << "RSA ключи сгенерированы и сохранены в файлы: " << publicKeyFile << " и " << privateKeyFile << std::endl;

    std::string rsaMessage = "Hello, RSA encryption!";
    std::string encryptedRSA = rsaEncrypt(rsaMessage, publicKeyFile);
    std::string encodedEncryptedRSA = base64Encode(encryptedRSA);
    std::cout << "RSA зашифрованное сообщение (base64): " << encodedEncryptedRSA << std::endl;

    std::string decodedEncryptedRSA = base64Decode(encodedEncryptedRSA);
    std::string decryptedRSA = rsaDecrypt(decodedEncryptedRSA, privateKeyFile);
    std::cout << "RSA расшифрованное сообщение: " << decryptedRSA << std::endl;

    // ---------- Тестирование Blowfish ----------
    Blowfish blowfish("my_secret_key");
    std::string blowfishMessage = "Hello, Blowfish encryption!";
    std::string encryptedBlowfish = blowfish.encrypt(blowfishMessage);
    std::string encodedEncryptedBlowfish = base64Encode(encryptedBlowfish);
    std::cout << "Blowfish зашифрованное сообщение (base64): " << encodedEncryptedBlowfish << std::endl;

    std::string decodedEncryptedBlowfish = base64Decode(encodedEncryptedBlowfish);
    std::string decryptedBlowfish = blowfish.decrypt(decodedEncryptedBlowfish);
    std::cout << "Blowfish расшифрованное сообщение: " << decryptedBlowfish << std::endl;

    // ---------- Тестирование AES ----------
    std::string aesMessage = "Hello, AES encryption!";
    auto aesKey = generateAESKey();
    auto aesIV = generateIV();

    auto aesEncrypted = aesEncrypt(aesMessage, aesKey, aesIV);
    std::string aesEncodedEncryptedMessage = base64Encode(std::string(aesEncrypted.begin(), aesEncrypted.end()));
    std::cout << "AES зашифрованное сообщение (base64): " << aesEncodedEncryptedMessage << std::endl;

    auto aesDecodedEncryptedMessage = base64Decode(aesEncodedEncryptedMessage);
    std::vector<unsigned char> aesEncryptedData(aesDecodedEncryptedMessage.begin(), aesDecodedEncryptedMessage.end());
    std::string aesDecryptedMessage = aesDecrypt(aesEncryptedData, aesKey, aesIV);
    std::cout << "AES расшифрованное сообщение: " << aesDecryptedMessage << std::endl;

    return 0;
}
