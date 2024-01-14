#include "RecSys.hpp"

/// @brief Generate Random Mask for FHE encoded plaintext/ciphertexts
/// @return Mask as uint64_t vector
std::vector<uint64_t> RecSys::generateMaskFHE() {
  std::vector<uint64_t> maskVector(sealSlotCount, 0ULL);
  for (int i = 0; i < sealSlotCount; i++) {
    maskVector[i] = distr(gen);
  }
  return maskVector;
}

///@brief Generates a random mask for use with the ElGamalAHE scheme - Upload
/// Phase
///@return byte cast implicitly as uint8_t of random mask
uint8_t RecSys::generateMaskAHE() {
  return rng.GenerateByte();
}

///@brief Upload rating from user, using CSP to convert from AHE to FHE
bool RecSys::uploadRating(EncryptedRatingAHE rating) {
  // Add Mask
  rating.rating = rating.rating + (CryptoPP::SecByteBlock)generateMaskAHE();
  // Get FHE rating and add to vector
  ratings.push_back(CSPInstance->convertRatingAHEtoFHE(rating));
  return true;
}

bool RecSys::gradientDescent() {
  // Steps 1-2  (Component-Wise Multiplication and Rating Addition)
  std::vector<std::vector<std::vector<uint64_t>>> epsilonMask(
      users.size(), std::vector<std::vector<uint64_t>>(movies.size()));
  for (auto [i,j] : M) {
    // f[i][j] = U[i] * V[j]
    sealEvaluator.multiply(RecSys::U[i][j], RecSys::V[i][j], RecSys::f[i][j]);

    // Scale the rating to the same alpha number of integer bits as U and V
    seal::Ciphertext scaledRating;
    sealEvaluator.multiply_plain(RecSys::r[i][j], twoToTheAlpha,
                                  scaledRating);

    // Subtract scaled rating from f
    sealEvaluator.sub_inplace(RecSys::f[i][j], scaledRating);

    // Add the mask
    epsilonMask[i][j] = generateMaskFHE();
    seal::Plaintext mask;
    sealBatchEncoder.encode(epsilonMask[i][j], mask);
    sealEvaluator.add_plain_inplace(RecSys::f[i][j], mask);
  }

  // Steps 3-4 (Summation)
  std::vector<std::vector<seal::Ciphertext>> RPrimePrime =
      CSPInstance->sumF(RecSys::f);

  // Steps 5-7 (Component-Wise Multiplication and Addition)
  // Step 5 - Remove mask by summing it and then subtracting
  std::vector<std::vector<std::vector<uint64_t>>> epsilonMaskSum(
      users.size(), std::vector<std::vector<uint64_t>>(movies.size()));
  for(auto [i, j] : M) {
    // Calculate sum for i and j entry
    uint64_t kSum = 0;
    for (int k = 0; k < d; k++) {
      kSum += epsilonMask[i][j][k];
    }
    // Set all of i and j entry to sum
    for (int k = 0; k < d; k++) {
      epsilonMaskSum[i][j][k] = kSum * pow(2,alpha);
    }
    // Encode and subtract sum of mask
    seal::Plaintext epsilonMaskSumPlaintext;
    sealBatchEncoder.encode(epsilonMaskSum[i][j], epsilonMaskSumPlaintext);
    sealEvaluator.sub_plain(RPrimePrime[i][j], epsilonMaskSumPlaintext,
                            RecSys::R[i][j]);
  }

  // Steps 6-7 - Calculate U Gradient , V Gradient, U', V' and add Masks
  std::vector<std::vector<seal::Ciphertext>> UGradientPrime, VGradientPrime, UPrime, VPrime;
  for(auto [i, j] : M) {
    //Encode user and item
    std::vector<uint64_t> userEncodingVector(sealSlotCount, 0ULL), itemEncodingVector(sealSlotCount, 0ULL);
    seal::Plaintext encodedUser, encodedItem;
    userEncodingVector[0] = users[i];
    itemEncodingVector[0] = movies[j];
    sealBatchEncoder.encode(userEncodingVector, encodedUser);
    sealBatchEncoder.encode(itemEncodingVector, encodedItem);

    // UGradient'[i][j] = v[i][j] * R[i][j] + twoToTheAlpha * lambda * UHat[i][j]
    seal::Ciphertext UHatLambdaMul, VHatLambdaMul;
    sealEvaluator.multiply_plain(RecSys::R[i][j], encodedItem, UGradientPrime[i][j]);
    sealEvaluator.multiply_plain(UHat[i][j], scaledLambda, UHatLambdaMul);
    sealEvaluator.add_inplace(UGradientPrime[i][j], UHatLambdaMul);

    // VGradient'[i][j] = u[j] * R[i][j] + twoToTheAlpha * lambda * VHat[i][j]
    sealEvaluator.multiply_plain(RecSys::R[i][j], encodedUser, VGradientPrime[i][j]);
    sealEvaluator.multiply_plain(UHat[i][j], scaledLambda, VHatLambdaMul);
    sealEvaluator.add_inplace(UGradientPrime[i][j], VHatLambdaMul);

    // TODO(Check #1 scaling (alpha, beta))
    // U'[i][j] = twoToTheAlphaPlusBeta * UHat[i][j] - gamma * twoToTheBeta *
    // UGradient'[i][j] 
    seal::Ciphertext gammaUGradient, gammaVGradient;
    sealEvaluator.multiply_plain(UHat[i][j], twoToTheAlphaPlusBeta, UPrime[i][j]);
    sealEvaluator.multiply_plain(UGradientPrime[i][j], scaledGamma, gammaUGradient);
    sealEvaluator.sub_inplace(UPrime[i][j], gammaUGradient);

    // V'[i] = twoToTheAlphaPlusBeta * VHat[i] - gamma *
    // twoToTheBeta * VGradient'[i]
    sealEvaluator.multiply_plain(VHat[i][j], twoToTheAlphaPlusBeta, VPrime[i][j]);
    sealEvaluator.multiply_plain(VGradientPrime[i][j], scaledGamma, gammaVGradient);
    sealEvaluator.sub_inplace(VPrime[i][j], gammaVGradient);
  }
  // Step 7 - Generate and add masks
  std::vector<std::vector<std::vector<uint64_t>>> UGradientPrimeMaskEncodingVector, VGradientPrimeMaskEncodingVector, UPrimeMaskEncodingVector, VPrimeMaskEncodingVector;
  std::vector<std::vector<seal::Plaintext>> UGradientPrimeMask, VGradientPrimeMask, UPrimeMask, VPrimeMask;
  for(auto [i, j] : M){
    UPrimeMaskEncodingVector[i][j] = generateMaskFHE();
    UGradientPrimeMaskEncodingVector[i][j] = generateMaskFHE();
    sealBatchEncoder.encode(UGradientPrimeMaskEncodingVector[i][j], UGradientPrimeMask[i][j]);
    sealBatchEncoder.encode(UPrimeMaskEncodingVector[i][j], UPrimeMask[i][j]);

    sealEvaluator.add_plain_inplace(UGradientPrime[i][j], UGradientPrimeMask[i][j]);
    sealEvaluator.add_plain_inplace(UPrime[i][j], UPrimeMask[i][j]);

    VPrimeMaskEncodingVector[i][j] = generateMaskFHE();
    VGradientPrimeMaskEncodingVector[i][j] = generateMaskFHE();
    sealBatchEncoder.encode(VGradientPrimeMaskEncodingVector[i][j], VGradientPrimeMask[i][j]);
    sealBatchEncoder.encode(VPrimeMaskEncodingVector[i][j], VPrimeMask[i][j]);

    sealEvaluator.add_plain_inplace(VGradientPrime[i][j], VGradientPrimeMask[i][j]);
    sealEvaluator.add_plain_inplace(VPrime[i][j], VPrimeMask[i][j]);
  }
  return true;
}
