#include "CSP.hpp"


int CSP::generateKeys(){
    return 2;
}

///@brief getter for ElGamal AHE public key
CryptoPP::ElGamalKeys::PublicKey CSP::getPublicKeyAHE()
{
    return ahe_PublicKey;
}

/// @brief Generates the Keys and populates the variables for AHE scheme
/// @return Result status - true if successfull
bool CSP::generateKeysAHE(){
    ahe_Decryptor.AccessKey().GenerateRandomWithKeySize(rng, 2048);
    ahe_PrivateKey = ahe_Decryptor.AccessKey();
    ahe_Encryptor = CryptoPP::ElGamal::Encryptor(ahe_Decryptor);

    return true;
}