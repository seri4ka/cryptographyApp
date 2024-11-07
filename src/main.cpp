#include "encryption/RSA.h"
#include "encryption/Blowfish.h"  // Подключаем Blowfish
#include <iostream>
#include <string>
#include <windows.h> // для установки кодировки

int main() {
    // Настройки консоли для поддержки кириллицы
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setlocale(LC_ALL, "");

    // ---------- Тестирование RSA ----------
    std::string publicKeyFile = "public.pem";
    std::string privateKeyFile = "private.pem";

    // Генерация RSA-ключей
    generateRSAKey(publicKeyFile, privateKeyFile);
    std::cout << "RSA ключи сгенерированы и сохранены в файлы: " << publicKeyFile << " и " << privateKeyFile << std::endl;

    std::string rsaMessage = "Привет, RSA шифрование!";
    // Шифрование RSA
    std::string encryptedRSA = rsaEncrypt(rsaMessage, publicKeyFile);
    std::string encodedEncryptedRSA = base64Encode(encryptedRSA);
    std::cout << "RSA зашифрованное сообщение (base64): " << encodedEncryptedRSA << std::endl;

    // Декодирование и дешифровка RSA
    std::string decodedEncryptedRSA = base64Decode(encodedEncryptedRSA);
    std::string decryptedRSA = rsaDecrypt(decodedEncryptedRSA, privateKeyFile);
    std::cout << "RSA расшифрованное сообщение: " << decryptedRSA << std::endl;

    // ---------- Тестирование Blowfish ----------
    Blowfish blowfish("my_secret_key");  // Инициализация Blowfish с ключом
    std::string blowfishMessage = "Привет, Blowfish шифрование!";

    // Шифрование Blowfish
    std::string encryptedBlowfish = blowfish.encrypt(blowfishMessage);
    std::string encodedEncryptedBlowfish = base64Encode(encryptedBlowfish);
    std::cout << "Blowfish зашифрованное сообщение (base64): " << encodedEncryptedBlowfish << std::endl;

    // Декодирование и дешифровка Blowfish
    std::string decodedEncryptedBlowfish = base64Decode(encodedEncryptedBlowfish);
    std::string decryptedBlowfish = blowfish.decrypt(decodedEncryptedBlowfish);
    std::cout << "Blowfish расшифрованное сообщение: " << decryptedBlowfish << std::endl;

    return 0;
}


