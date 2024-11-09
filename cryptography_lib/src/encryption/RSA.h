#ifndef RSA_H
#define RSA_H

#include <string>

void generateRSAKey(const std::string& publicKeyFile, const std::string& privateKeyFile);
std::string rsaEncrypt(const std::string& message, const std::string& publicKeyFile);
std::string rsaDecrypt(const std::string& encrypted, const std::string& privateKeyFile);
std::string base64Encode(const std::string& input);
std::string base64Decode(const std::string& encoded);

#endif // RSA_ENCRYPTION_H

