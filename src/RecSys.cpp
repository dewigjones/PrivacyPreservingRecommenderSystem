#include "RecSys.hpp"

int RecSys::generateMask(){
    return 0;
}

///@brief Generates a random mask for use with the ElGamalAHE scheme - Upload Phase
///@return byte cast implicitly as uint8_t of random mask
uint8_t RecSys::generateMaskAHE() {
    return rng.GenerateByte();
}

///@brief Upload rating from user, using CSP to convert from AHE to FHE
bool RecSys::uploadRating(EncryptedRatingAHE rating) {
    //Add Mask
    rating.rating = rating.rating + (CryptoPP::SecByteBlock) generateMaskAHE();
    //Get FHE rating and add to vector
    ratings.push_back(CSPInstance->convertRatingAHEtoFHE(rating));
    return true;
}

bool RecSys::gradientDescent()
{
    //Steps 1-2  (Component-Wise Multiplication and Rating Addition)
    for(auto rating : ratings) {

    }
    return true;
}
