#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <string>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

class EXPORT Blowfish {
public:
    Blowfish(const std::string& key);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

private:
    unsigned char key_[16];
};

#endif // BLOWFISH_H

