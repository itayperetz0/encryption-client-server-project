#ifndef RSA_KEY_GENERATOR_H
#define RSA_KEY_GENERATOR_H

#include <iostream>
#include "../cryptopp/rsa.h"
#include "../cryptopp/osrng.h"
#include "../cryptopp/base64.h"

class RSAKeyGenerator {
public:
    RSAKeyGenerator();

    void GenerateKeys(unsigned int keySize);

    CryptoPP::RSA::PrivateKey GetPrivateKey() const;
    CryptoPP::RSA::PublicKey GetPublicKey() const;

private:
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;
};

#endif // RSA_KEY_GENERATOR_H