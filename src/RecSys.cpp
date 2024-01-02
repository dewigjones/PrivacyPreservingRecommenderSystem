#include "RecSys.hpp"

/// @brief Generate Random Mask for FHE encoded plaintext/ciphertexts
/// @return seal Plaintext mask
seal::Plaintext RecSys::generateMaskFHE(){
    std::vector<uint64_t> maskVector(sealSlotCount, 0ULL);
    for(int i = 0; i < sealSlotCount; i++) {
        maskVector[i] = distr(gen);
    }
    seal::Plaintext mask;
    sealBatchEncoder.encode(maskVector, mask);
    return mask;
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

bool
 RecSys::gradientDescent()
{
    //Steps 1-2  (Component-Wise Multiplication and Rating Addition)
    std::vector<std::vector<seal::Plaintext>> epsilonMask(RecSys::U.size(), std::vector<seal::Plaintext>(RecSys::V.size()));
    for(int i = 0; i < RecSys::U.size(); i++) {
        for(int j = 0; j < RecSys::V.size(); j++){
            //f[i][j] = U[i] * V[j]
            sealEvaulator.multiply(RecSys::U.at(i), RecSys::V.at(j), RecSys::f[i][j]);
            
            //Scale the rating to the same alpha number of integer bits as U and V
            seal::Ciphertext scaledRating;
            sealEvaulator.multiply_plain(RecSys::r[i][j], twoToTheAlpha, scaledRating);

            //Subtract scaled rating from f
            sealEvaulator.sub_inplace(RecSys::f[i][j], scaledRating);

            //Add the mask
            epsilonMask[i][j] = generateMaskFHE();
            sealEvaulator.add_plain_inplace(RecSys::f[i][j], epsilonMask[i][j]);
        }
    }

    //Steps 3-4 (Summation)
    std::vector<std::vector<seal::Ciphertext>> RPrimePrime = CSPInstance->sumF(RecSys::f);

    return true;
}
