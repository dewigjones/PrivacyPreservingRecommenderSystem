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
  std::vector<std::vector<uint64_t>> epsilonMask(
      RecSys::M.size(), std::vector<uint64_t>());
  for (int i = 0; i < RecSys::M.size(); i++) {
    // f[i] = U[i] * V[i]
    sealEvaluator.multiply(RecSys::U[i], RecSys::V[i], RecSys::f[i]);

    // Scale the rating to the same alpha number of integer bits as U and V
    seal::Ciphertext scaledRating;
    sealEvaluator.multiply_plain(RecSys::r[i], twoToTheAlpha,
                                  scaledRating);

    // Subtract scaled rating from f
    sealEvaluator.sub_inplace(RecSys::f[i], scaledRating);

    // Add the mask
    epsilonMask[i] = generateMaskFHE();
    seal::Plaintext mask;
    sealBatchEncoder.encode(epsilonMask[i], mask);
    sealEvaluator.add_plain_inplace(RecSys::f[i], mask);
  }

  // Steps 3-4 (Summation)
  std::vector<seal::Ciphertext> RPrimePrime =
      CSPInstance->sumF(RecSys::f);

  // Steps 5-7 (Component-Wise Multiplication and Addition)
  // Step 5 - Remove mask by summing it and then subtracting
  std::vector<std::vector<uint64_t>> epsilonMaskSum(
      RecSys::M.size(), std::vector<uint64_t>());
  for(int i = 0; i < RecSys::M.size(); i++) {
    // Calculate sum for i entry
    uint64_t jSum = 0;
    for (int j = 0; j < d; j++) {
      jSum += epsilonMask[i][j];
    }
    // Set all of i and j entry to sum
    for (int j = 0; j < d; j++) {
      epsilonMaskSum[i][j] = jSum * pow(2,alpha);
    }
    // Encode and subtract sum of mask
    seal::Plaintext epsilonMaskSumPlaintext;
    sealBatchEncoder.encode(epsilonMaskSum[i], epsilonMaskSumPlaintext);
    sealEvaluator.sub_plain(RPrimePrime[i], epsilonMaskSumPlaintext,
                            RecSys::R[i]);
  }

  // Steps 6-7 - Calculate U Gradient , V Gradient, U', V' and add Masks
  std::vector<seal::Ciphertext> UGradientPrime, VGradientPrime, UPrime, VPrime;
  for(int i = 0; i < RecSys::M.size(); i++) {

    // UGradient'[i] = v[i] * R[i][j] + twoToTheAlpha * lambda * UHat[i][j]
    seal::Ciphertext UHatLambdaMul, VHatLambdaMul;
    sealEvaluator.multiply(RecSys::R[i], RecSys::V[i], UGradientPrime[i]);
    sealEvaluator.multiply_plain(UHat[i], scaledLambda, UHatLambdaMul);
    sealEvaluator.add_inplace(UGradientPrime[i], UHatLambdaMul);

    // VGradient'[i] = u * R[i][j] + twoToTheAlpha * lambda * VHat[i][j]
    sealEvaluator.multiply(RecSys::R[i], RecSys::U[i], VGradientPrime[i]);
    sealEvaluator.multiply_plain(UHat[i], scaledLambda, VHatLambdaMul);
    sealEvaluator.add_inplace(UGradientPrime[i], VHatLambdaMul);

    // TODO(Check #1 scaling (alpha, beta))
    // U'[i] = twoToTheAlphaPlusBeta * UHat[i] - gamma * twoToTheBeta *
    // UGradient'[i] 
    seal::Ciphertext gammaUGradient, gammaVGradient;
    sealEvaluator.multiply_plain(UHat[i], twoToTheAlphaPlusBeta, UPrime[i]);
    sealEvaluator.multiply_plain(UGradientPrime[i], scaledGamma, gammaUGradient);
    sealEvaluator.sub_inplace(UPrime[i], gammaUGradient);

    // V'[i] = twoToTheAlphaPlusBeta * VHat[i] - gamma *
    // twoToTheBeta * VGradient'[i]
    sealEvaluator.multiply_plain(VHat[i], twoToTheAlphaPlusBeta, VPrime[i]);
    sealEvaluator.multiply_plain(VGradientPrime[i], scaledGamma, gammaVGradient);
    sealEvaluator.sub_inplace(VPrime[i], gammaVGradient);
  }
  // Step 7 - Generate and add masks
  std::vector<std::vector<uint64_t>> UGradientPrimeMaskEncodingVector, VGradientPrimeMaskEncodingVector, UPrimeMaskEncodingVector, VPrimeMaskEncodingVector;
  std::vector<seal::Plaintext> UGradientPrimeMask, VGradientPrimeMask, UPrimeMask, VPrimeMask;
  for(int i = 0; i < RecSys::M.size(); i++){
    UPrimeMaskEncodingVector[i] = generateMaskFHE();
    UGradientPrimeMaskEncodingVector[i] = generateMaskFHE();
    sealBatchEncoder.encode(UGradientPrimeMaskEncodingVector[i], UGradientPrimeMask[i]);
    sealBatchEncoder.encode(UPrimeMaskEncodingVector[i], UPrimeMask[i]);

    sealEvaluator.add_plain_inplace(UGradientPrime[i], UGradientPrimeMask[i]);
    sealEvaluator.add_plain_inplace(UPrime[i], UPrimeMask[i]);

    VPrimeMaskEncodingVector[i] = generateMaskFHE();
    VGradientPrimeMaskEncodingVector[i] = generateMaskFHE();
    sealBatchEncoder.encode(VGradientPrimeMaskEncodingVector[i], VGradientPrimeMask[i]);
    sealBatchEncoder.encode(VPrimeMaskEncodingVector[i], VPrimeMask[i]);

    sealEvaluator.add_plain_inplace(VGradientPrime[i], VGradientPrimeMask[i]);
    sealEvaluator.add_plain_inplace(VPrime[i], VPrimeMask[i]);
  }
  return true;
}
