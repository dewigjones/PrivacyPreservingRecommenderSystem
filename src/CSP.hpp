#pragma once
#include <cryptopp/elgamal.h>
#include <cryptopp/osrng.h>
#include "Ratings.hpp"

class CSP {

int generateKeysFHE();
bool generateKeysAHE();
int encryptAHE(int input);
int decryptAHE(int input);

// Keep track of the AHE scheme (ElGamal)
CryptoPP::AutoSeededRandomPool rng;
CryptoPP::ElGamalKeys::PrivateKey ahe_PrivateKey;
CryptoPP::ElGamalKeys::PublicKey ahe_PublicKey;
CryptoPP::ElGamal::Decryptor ahe_Decryptor;
CryptoPP::ElGamal::Encryptor ahe_Encryptor;

public:

int generateKeys();
CryptoPP::ElGamalKeys::PublicKey getPublicKeyAHE();

CSP(){ 
    generateKeysAHE();
}

};