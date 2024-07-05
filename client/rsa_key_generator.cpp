#include "rsa_key_generator.hpp"

using namespace CryptoPP;

RSAKeyGenerator::RSAKeyGenerator() {}

void RSAKeyGenerator::GenerateKeys(unsigned int keySize) {
    AutoSeededRandomPool rng;

    privateKey.GenerateRandomWithKeySize(rng, keySize);
    publicKey = CryptoPP::RSA::PublicKey(privateKey);
}

CryptoPP::RSA::PrivateKey RSAKeyGenerator::GetPrivateKey() const {
    return privateKey;
}

CryptoPP::RSA::PublicKey RSAKeyGenerator::GetPublicKey() const {
    return publicKey;
}