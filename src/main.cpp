#include "encryption/RSA.h"
#include <iostream>
#include <string>
#include <windows.h> // для установки кодировки


int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setlocale(LC_ALL, "");

    std::string publicKeyFile = "public.pem";
    std::string privateKeyFile = "private.pem";

    // Генерация ключей
    generateRSAKey(publicKeyFile, privateKeyFile);
    std::cout << "Ключи сгенерированы и сохранены в файлы: " << publicKeyFile << " и " << privateKeyFile << std::endl;

    std::string message = "Привет, RSA шифрование!";

    // Шифрование
    std::string encryptedMessage = rsaEncrypt(message, publicKeyFile);
    std::string encodedEncryptedMessage = base64Encode(encryptedMessage);
    std::cout << "Зашифрованное сообщение (base64): " << encodedEncryptedMessage << std::endl;

    // Декодирование и дешифровка
    std::string decodedEncryptedMessage = base64Decode(encodedEncryptedMessage);
    std::string decryptedMessage = rsaDecrypt(decodedEncryptedMessage, privateKeyFile);
    std::cout << "Расшифрованное сообщение: " << decryptedMessage << std::endl;

    return 0;
}


