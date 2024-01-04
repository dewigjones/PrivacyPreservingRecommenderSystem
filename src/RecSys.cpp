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
      RecSys::U.size(), std::vector<std::vector<uint64_t>>(RecSys::V.size()));
  for (int i = 0; i < RecSys::U.size(); i++) {
    for (int j = 0; j < RecSys::V.size(); j++) {
      // f[i][j] = U[i] * V[j]
      sealEvaluator.multiply(RecSys::U.at(i), RecSys::V.at(j), RecSys::f[i][j]);

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
  }

  // Steps 3-4 (Summation)
  std::vector<std::vector<seal::Ciphertext>> RPrimePrime =
      CSPInstance->sumF(RecSys::f);

  // Steps 5-7 (Component-Wise Multiplication and Addition)
  // Step 5 - Remove mask by summing it and then subtracting
  std::vector<std::vector<std::vector<uint64_t>>> epsilonMaskSum(
      RecSys::U.size(), std::vector<std::vector<uint64_t>>(RecSys::V.size()));
  for (int i = 0; i < epsilonMask.size(); i++) {
    for (int j = 0; j < epsilonMask[i].size(); j++) {
      // Calculate sum for i and j entry
      uint64_t kSum = 0;
      for (int k = 0; k < d; k++) {
        kSum += epsilonMask[i][j][k];
      }
      // Set all of i and j entry to sum
      for (int k = 0; k < d; k++) {
        epsilonMaskSum[i][j][k] = kSum;
      }
      // Encode and subtract sum of mask
      seal::Plaintext epsilonMaskSumPlaintext;
      sealBatchEncoder.encode(epsilonMaskSum[i][j], epsilonMaskSumPlaintext);
      sealEvaluator.sub_plain(RPrimePrime[i][j], epsilonMaskSumPlaintext,
                              RecSys::R[i][j]);
    }
  }

  // Steps 6-7 - Calculate U Gradient , V Gradient, U', V' and add Masks
  for (int i = 0; i < RecSys::U.size(); i++) {
    for (int j = 0; j < RecSys::V.size(); j++) {
      // UGradient'[i] = v[j] * R[i][j] + twoToTheAlpha * lambda * UHat[i]
      // VGradient'[j] = u[j] * R[i][j] + twoToTheAlpha * lambda * VHat[j]

      // TODO(Check #1 scaling (alpha, beta))
      // U'[i] = twoToTheAlphaPlusBeta * UHat[i] - gamma * twoToTheBeta *
      // UGradient'[i] V'[i] = twoToTheAlphaPlusBeta * VHat[i] - gamma *
      // twoToTheBeta * VGradient'[i]
    }
  }
  return true;
}
