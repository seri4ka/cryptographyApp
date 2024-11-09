#ifndef RSA_H
#define RSA_H

#include <string>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT void generateRSAKey(const std::string& publicKeyFile, const std::string& privateKeyFile);
EXPORT std::string rsaEncrypt(const std::string& message, const std::string& publicKeyFile);
EXPORT std::string rsaDecrypt(const std::string& encrypted, const std::string& privateKeyFile);
EXPORT std::string base64Encode(const std::string& input);
EXPORT std::string base64Decode(const std::string& encoded);

#endif // RSA_H

