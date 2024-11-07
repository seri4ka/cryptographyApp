#include "encryption/RSA.h"
#include "encryption/Blowfish.h"  // ���������� Blowfish
#include <iostream>
#include <string>
#include <windows.h> // ��� ��������� ���������

int main() {
    // ��������� ������� ��� ��������� ���������
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setlocale(LC_ALL, "");

    // ---------- ������������ RSA ----------
    std::string publicKeyFile = "public.pem";
    std::string privateKeyFile = "private.pem";

    // ��������� RSA-������
    generateRSAKey(publicKeyFile, privateKeyFile);
    std::cout << "RSA ����� ������������� � ��������� � �����: " << publicKeyFile << " � " << privateKeyFile << std::endl;

    std::string rsaMessage = "������, RSA ����������!";
    // ���������� RSA
    std::string encryptedRSA = rsaEncrypt(rsaMessage, publicKeyFile);
    std::string encodedEncryptedRSA = base64Encode(encryptedRSA);
    std::cout << "RSA ������������� ��������� (base64): " << encodedEncryptedRSA << std::endl;

    // ������������� � ���������� RSA
    std::string decodedEncryptedRSA = base64Decode(encodedEncryptedRSA);
    std::string decryptedRSA = rsaDecrypt(decodedEncryptedRSA, privateKeyFile);
    std::cout << "RSA �������������� ���������: " << decryptedRSA << std::endl;

    // ---------- ������������ Blowfish ----------
    Blowfish blowfish("my_secret_key");  // ������������� Blowfish � ������
    std::string blowfishMessage = "������, Blowfish ����������!";

    // ���������� Blowfish
    std::string encryptedBlowfish = blowfish.encrypt(blowfishMessage);
    std::string encodedEncryptedBlowfish = base64Encode(encryptedBlowfish);
    std::cout << "Blowfish ������������� ��������� (base64): " << encodedEncryptedBlowfish << std::endl;

    // ������������� � ���������� Blowfish
    std::string decodedEncryptedBlowfish = base64Decode(encodedEncryptedBlowfish);
    std::string decryptedBlowfish = blowfish.decrypt(decodedEncryptedBlowfish);
    std::cout << "Blowfish �������������� ���������: " << decryptedBlowfish << std::endl;

    return 0;
}


