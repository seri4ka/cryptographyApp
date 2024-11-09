#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <string>

class Blowfish {
public:
    Blowfish(const std::string& key);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

private:
    unsigned char key_[16];
};

#endif // BLOWFISH_H
