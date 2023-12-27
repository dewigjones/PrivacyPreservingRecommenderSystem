#pragma once
#include "Ratings.hpp"
#include "CSP.hpp"
#include <cryptopp/elgamal.h>
#include <cryptopp/osrng.h>
#include <vector>

class User {
    std::vector<PlainRating> ratings;
    std::vector<EncryptedRatingAHE> ahe_encryptedRatings;
    
    // Keep track of the AHE scheme (ElGamal)
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ElGamalKeys::PrivateKey ahe_PrivateKey;
    CryptoPP::ElGamalKeys::PublicKey ahe_PublicKey;
    CryptoPP::ElGamalKeys::PublicKey ahe_CSPPublicKey;
    CryptoPP::ElGamal::Decryptor ahe_Decryptor;
    CryptoPP::ElGamal::Encryptor ahe_Encryptor;
    
    public:
    
    User(CSP csp){
        ahe_CSPPublicKey = csp.getPublicKeyAHE();
        ahe_Encryptor =  CryptoPP::ElGamal::Encryptor(ahe_CSPPublicKey);  
    };

    bool encryptRatingsAHE();
    bool uploadRatings();    

};