#pragma once
#include "seal/seal.h"
#include <cryptopp/elgamal.h>
class PlainRating {
public:
    int userID;
    int itemID;
    int rating;
};

class EncryptedRating {

public:
    seal::Ciphertext userID;
    seal::Ciphertext itemID;
    seal::Ciphertext rating;
};

class EncryptedRatingAHE {

public:
    int userID;
    int itemID;
    CryptoPP::SecByteBlock rating;

    ///@brief Constructor for AHE Encrypted Rating Class
    EncryptedRatingAHE(int userid, int itemid, CryptoPP::SecByteBlock rating) : userID(userid), itemID(itemid), rating(rating) {};
};