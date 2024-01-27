#include "RecSys.hpp"
#include <seal/ciphertext.h>
#include <seal/plaintext.h>
#include <sys/types.h>
#include <cstdint>
#include <memory>
#include <vector>
#include "MessageHandler.hpp"

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
  int curEpoch = 0;
  while (curEpoch++ < maxEpochs && !stoppingCriterionCheckResult) {
    // Steps 1-2  (Component-Wise Multiplication and Rating Addition)
    std::vector<std::vector<uint64_t>> epsilonMask(RecSys::M.size(),
                                                   std::vector<uint64_t>());
    for (int i = 0; i < RecSys::M.size(); i++) {
      // f[i] = U[i] * V[i]
      sealEvaluator.multiply(RecSys::U[i], RecSys::V[i], RecSys::f[i]);

      // Scale the rating to the same alpha number of integer bits as U and V
      seal::Ciphertext scaledRating;
      sealEvaluator.multiply_plain(RecSys::r[i], twoToTheAlpha, scaledRating);

      // Subtract scaled rating from f
      sealEvaluator.sub_inplace(RecSys::f[i], scaledRating);

      // Add the mask
      epsilonMask[i] = generateMaskFHE();
      seal::Plaintext mask;
      sealBatchEncoder.encode(epsilonMask[i], mask);
      sealEvaluator.add_plain_inplace(RecSys::f[i], mask);
    }

    // Steps 3-4 (Summation)
    std::vector<seal::Ciphertext> RPrimePrime = CSPInstance->sumF(RecSys::f);

    // Steps 5-7 (Component-Wise Multiplication and Addition)
    // Step 5 - Remove mask by summing it and then subtracting
    std::vector<std::vector<uint64_t>> epsilonMaskSum(RecSys::M.size(),
                                                      std::vector<uint64_t>());
    for (int i = 0; i < RecSys::M.size(); i++) {
      // Calculate sum for i entry
      uint64_t jSum = 0;
      for (int j = 0; j < d; j++) {
        jSum += epsilonMask[i][j];
      }
      // Set all of i and j entry to sum
      for (int j = 0; j < d; j++) {
        epsilonMaskSum[i][j] = jSum * static_cast<uint64_t>(pow(2, alpha));
      }
      // Encode and subtract sum of mask
      seal::Plaintext epsilonMaskSumPlaintext;
      sealBatchEncoder.encode(epsilonMaskSum[i], epsilonMaskSumPlaintext);
      sealEvaluator.sub_plain(RPrimePrime[i], epsilonMaskSumPlaintext,
                              RecSys::R[i]);
    }

    // Steps 6-7 - Calculate U Gradient , V Gradient, U', V' and add Masks
    std::vector<seal::Ciphertext> UGradientPrime, VGradientPrime, UPrime,
        VPrime;
    for (int i = 0; i < RecSys::M.size(); i++) {
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
      sealEvaluator.multiply_plain(UGradientPrime[i], scaledGamma,
                                   gammaUGradient);
      sealEvaluator.sub_inplace(UPrime[i], gammaUGradient);

      // V'[i] = twoToTheAlphaPlusBeta * VHat[i] - gamma *
      // twoToTheBeta * VGradient'[i]
      sealEvaluator.multiply_plain(VHat[i], twoToTheAlphaPlusBeta, VPrime[i]);
      sealEvaluator.multiply_plain(VGradientPrime[i], scaledGamma,
                                   gammaVGradient);
      sealEvaluator.sub_inplace(VPrime[i], gammaVGradient);
    }
    // Step 7 - Generate and add masks
    std::vector<std::vector<uint64_t>> UGradientPrimeMaskEncodingVector,
        VGradientPrimeMaskEncodingVector, UPrimeMaskEncodingVector,
        VPrimeMaskEncodingVector;
    std::vector<seal::Plaintext> UGradientPrimeMask, VGradientPrimeMask,
        UPrimeMask, VPrimeMask;
    std::vector<uint64_t> UMaskSum(sealSlotCount, 0ULL),
        VMaskSum(sealSlotCount, 0ULL), UGradientMaskSum(sealSlotCount, 0ULL),
        VGradientMaskSum(sealSlotCount, 0ULL);
    for (int i = 0; i < RecSys::M.size(); i++) {
      UPrimeMaskEncodingVector[i] = generateMaskFHE();
      UGradientPrimeMaskEncodingVector[i] = generateMaskFHE();
      sealBatchEncoder.encode(UGradientPrimeMaskEncodingVector[i],
                              UGradientPrimeMask[i]);
      sealBatchEncoder.encode(UPrimeMaskEncodingVector[i], UPrimeMask[i]);

      sealEvaluator.add_plain_inplace(UGradientPrime[i], UGradientPrimeMask[i]);
      sealEvaluator.add_plain_inplace(UPrime[i], UPrimeMask[i]);

      VPrimeMaskEncodingVector[i] = generateMaskFHE();
      VGradientPrimeMaskEncodingVector[i] = generateMaskFHE();
      sealBatchEncoder.encode(VGradientPrimeMaskEncodingVector[i],
                              VGradientPrimeMask[i]);
      sealBatchEncoder.encode(VPrimeMaskEncodingVector[i], VPrimeMask[i]);

      sealEvaluator.add_plain_inplace(VGradientPrime[i], VGradientPrimeMask[i]);
      sealEvaluator.add_plain_inplace(VPrime[i], VPrimeMask[i]);
      for (int j = 0; j < sealSlotCount; j++) {
        UMaskSum[j] += UPrimeMaskEncodingVector[i][j];
        VMaskSum[j] += VPrimeMaskEncodingVector[i][j];
        UGradientMaskSum[j] += UGradientPrimeMaskEncodingVector[i][j];
        VGradientMaskSum[j] += VGradientPrimeMaskEncodingVector[i][j];
      }
    }

    // Step 8
    auto [UPrimePrime, UHatPrimePrime] =
        CSPInstance->calculateNewUandUHat(UPrime);
    auto [VPrimePrime, VHatPrimePrime] =
        CSPInstance->calculateNewVandVHat(VPrime);
    // Step 9
    std::vector<seal::Ciphertext> UGradientPrimePrime =
        CSPInstance->calculateNewUGradient(UGradientPrime);
    std::vector<seal::Ciphertext> VGradientPrimePrime =
        CSPInstance->calculateNewVGradient(VGradientPrime);

    // Step 10 - Remove masks
    // Sum masks
    seal::Plaintext UMaskSumPlain, VMaskSumPlain, UGradientMaskSumPlain,
        VGradientMaskSumPlain;
    sealBatchEncoder.encode(UMaskSum, UMaskSumPlain);
    sealBatchEncoder.encode(VMaskSum, VMaskSumPlain);
    sealBatchEncoder.encode(UGradientMaskSum, UGradientMaskSumPlain);
    sealBatchEncoder.encode(VGradientMaskSum, VGradientMaskSumPlain);
    for (int i = 0; i < UPrimePrime.size(); i++) {
      sealEvaluator.sub_plain(UPrimePrime[i], UMaskSumPlain, U[i]);
      sealEvaluator.sub_plain(UHatPrimePrime[i], UMaskSumPlain, UHat[i]);
    }
    for (int i = 0; i < VPrimePrime.size(); i++) {
      sealEvaluator.sub_plain(VPrimePrime[i], VMaskSumPlain, V[i]);
      sealEvaluator.sub_plain(VHatPrimePrime[i], VMaskSumPlain, VHat[i]);
    }
    for (int i = 0; i < UGradientPrimePrime.size(); i++) {
      sealEvaluator.sub_plain(UGradientPrimePrime[i], UGradientMaskSumPlain,
                              UGradient[i]);
    }
    for (int i = 0; i < VGradientPrimePrime.size(); i++) {
      sealEvaluator.sub_plain(VGradientPrimePrime[i], VGradientMaskSumPlain,
                              VGradient[i]);
    }
    stoppingCriterionCheckResult =
        RecSys::stoppingCriterionCheck(UGradient, VGradient);
  }
  return true;
}

/// @brief Check if either the user or item gradient is less than the threshold
bool RecSys::stoppingCriterionCheck(
    const std::vector<seal::Ciphertext>& UGradientParam,
    const std::vector<seal::Ciphertext>& VGradientParam) {
  std::vector<seal::Ciphertext> UGradientSquare, VGradientSquare;
  std::vector<std::vector<uint64_t>> UGradientSquareMaskVector,
      VGradientSquareMaskVector;
  // Square UGradient and mask
  for (int i = 0; i < UGradientParam.size(); i++) {
    sealEvaluator.square(UGradientParam[i], UGradientSquare[i]);

    // Generate and add mask
    UGradientSquareMaskVector[i] = generateMaskFHE();
    seal::Plaintext UGradientSquareMaskPlaintext;
    sealBatchEncoder.encode(UGradientSquareMaskVector[i],
                            UGradientSquareMaskPlaintext);
    sealEvaluator.add_plain_inplace(UGradientSquare[i],
                                    UGradientSquareMaskPlaintext);
  }

  // Square VGradient and mask
  for (int i = 0; i < VGradientParam.size(); i++) {
    sealEvaluator.square(VGradientParam[i], VGradientSquare[i]);
    VGradientSquareMaskVector[i] = generateMaskFHE();

    // Generate and add mask
    VGradientSquareMaskVector[i] = generateMaskFHE();
    seal::Plaintext VGradientSquareMaskPlaintext;
    sealBatchEncoder.encode(VGradientSquareMaskVector[i],
                            VGradientSquareMaskPlaintext);
    sealEvaluator.add_plain_inplace(VGradientSquare[i],
                                    VGradientSquareMaskPlaintext);
  }

  // Sum mask vectors
  std::vector<uint64_t> UMaskSum(sealSlotCount, 0ULL),
      VMaskSum(sealSlotCount, 0ULL), Su, Sv;

  for (int i = 0; i < UGradientSquareMaskVector.size(); i++) {
    for (int j = 0; j < sealSlotCount; j++) {
      UMaskSum[j] += UGradientSquareMaskVector[i][j];
    }
  }
  for (int i = 0; i < VGradientSquareMaskVector.size(); i++) {
    for (int j = 0; j < sealSlotCount; j++) {
      VMaskSum[j] += VGradientSquareMaskVector[i][j];
    }
  }

  // Calculate threshold vectors
  for (int i = 0; i < sealSlotCount; i++) {
    Su[i] = UMaskSum[i] + threshold;
    Sv[i] = VMaskSum[i] + threshold;
  }

  // Get stopping criterion bool pair
  std::pair<bool, bool> stoppingCriterionPair =
      CSPInstance->calculateStoppingVector(UGradientSquare, VGradientSquare, Su,
                                           Sv);

  // Return true if either the user or item gradient is less than the threshold
  return (stoppingCriterionPair.first || stoppingCriterionPair.second);
}

/// RecSys Constructor
RecSys::RecSys(std::shared_ptr<CSP> csp,
               std::shared_ptr<MessageHandler> messagehandler,
               const seal::SEALContext& sealcontext)
    : MessageHandlerInstance(messagehandler),
      CSPInstance(csp),
      gen(rd()),
      sealContext(sealcontext),
      sealEvaluator(sealcontext),
      sealBatchEncoder(sealcontext) {
  // Save slot count
  sealSlotCount = sealBatchEncoder.slot_count();

  // Encode 2^alpha
  std::vector<uint64_t> twoToTheAlphaEncodingVector(sealSlotCount, 0ULL),
      scaledLambdaEncodingVector(sealSlotCount, 0ULL);
  for (int i = 0; i < sealSlotCount; i++) {
    twoToTheAlphaEncodingVector[i] = static_cast<uint64_t>(pow(2, alpha));
    scaledLambdaEncodingVector[i] =
        static_cast<uint64_t>(pow(2, alpha) * lambda);
  }
  sealBatchEncoder.encode(twoToTheAlphaEncodingVector, twoToTheAlpha);
  sealBatchEncoder.encode(scaledLambdaEncodingVector, scaledLambda);

  // Encode 2^beta
  std::vector<uint64_t> twoToTheBetaEncodingVector(sealSlotCount, 0ULL),
      scaledGammaEncodingVector(sealSlotCount, 0ULL);
  for (int i = 0; i < sealSlotCount; i++) {
    twoToTheBetaEncodingVector[i] = static_cast<uint64_t>(pow(2, beta));
    scaledGammaEncodingVector[i] = static_cast<uint64_t>(pow(2, beta) * gamma);
  }
  sealBatchEncoder.encode(twoToTheBetaEncodingVector, twoToTheBeta);
  sealBatchEncoder.encode(scaledGammaEncodingVector, scaledGamma);

  // Encode 2^(alpha+beta)
  std::vector<uint64_t> twoToTheAlphaPlusBetaEncodingVector(sealSlotCount,
                                                            0ULL);
  for (int i = 0; i < sealSlotCount; i++) {
    twoToTheAlphaPlusBetaEncodingVector[i] =
        static_cast<uint>(pow(2, alpha + beta));
  }
  sealBatchEncoder.encode(twoToTheAlphaPlusBetaEncodingVector,
                          twoToTheAlphaPlusBeta);
}

/// @brief Set the space of ratings
void RecSys::setM(const std::vector<std::pair<int, int>> providedM) {
  M = providedM;
}

/// Set the encrypted ratings vector
void RecSys::setRatings(const std::vector<seal::Ciphertext> providedRatings) {
  r = providedRatings;
}