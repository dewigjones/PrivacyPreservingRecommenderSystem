#pragma once
#include "seal/seal.h"

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