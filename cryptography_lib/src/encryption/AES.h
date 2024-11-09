#ifndef AES_H
#define AES_H

#include <vector>
#include <string>

std::vector<unsigned char> generateAESKey();
std::vector<unsigned char> generateIV();
std::vector<unsigned char> aesEncrypt(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);
std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);

#endif // AES_H
