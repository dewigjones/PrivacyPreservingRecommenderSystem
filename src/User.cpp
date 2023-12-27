#include "User.hpp"

///@brief Encrypt all the ratings in User's class
bool User::encryptRatingsAHE()
{
    //Go through all stored ratings
    for(auto pt : ratings){
        
        //Setup enc and plaintext variables
        CryptoPP::SecByteBlock ratingEnc;
        CryptoPP::SecByteBlock rating(sizeof(pt.rating));
        *rating = pt.rating;

        //Encrypt
        ahe_Encryptor.Encrypt( rng, rating, rating.size(), ratingEnc );

        //Add the encrypted rating to the vector
        ahe_encryptedRatings.push_back(EncryptedRatingAHE(pt.userID, pt.itemID, ratingEnc));
    }
    return true;
}

bool User::uploadRatings()
{
    
    return true;
}
