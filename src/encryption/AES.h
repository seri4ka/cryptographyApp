#ifndef AES_H
#define AES_H

#include <vector>
#include <string>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT std::vector<unsigned char> generateAESKey();
EXPORT std::vector<unsigned char> generateIV();
EXPORT std::vector<unsigned char> aesEncrypt(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);
EXPORT std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);

#endif // AES_H

