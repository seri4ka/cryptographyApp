#include "encryption/RSA.h"
#include <iostream>
#include <string>
#include <windows.h> // ��� ��������� ���������


int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setlocale(LC_ALL, "");

    std::string publicKeyFile = "public.pem";
    std::string privateKeyFile = "private.pem";

    // ��������� ������
    generateRSAKey(publicKeyFile, privateKeyFile);
    std::cout << "����� ������������� � ��������� � �����: " << publicKeyFile << " � " << privateKeyFile << std::endl;

    std::string message = "������, RSA ����������!";

    // ����������
    std::string encryptedMessage = rsaEncrypt(message, publicKeyFile);
    std::string encodedEncryptedMessage = base64Encode(encryptedMessage);
    std::cout << "������������� ��������� (base64): " << encodedEncryptedMessage << std::endl;

    // ������������� � ����������
    std::string decodedEncryptedMessage = base64Decode(encodedEncryptedMessage);
    std::string decryptedMessage = rsaDecrypt(decodedEncryptedMessage, privateKeyFile);
    std::cout << "�������������� ���������: " << decryptedMessage << std::endl;

    return 0;
}


