#include "RecSys.hpp"
#include <seal/ciphertext.h>
#include <seal/plaintext.h>
#include <sys/types.h>
#include <cstdint>
#include <iostream>
#include <memory>
#include <set>
#include <vector>
#include "MessageHandler.hpp"

/// @brief Generate Random Mask for FHE encoded plaintext/ciphertexts
/// @return Mask as uint64_t vector
std::vector<uint64_t> RecSys::generateMaskFHE() {
  std::vector<uint64_t> maskVector(sealSlotCount, 0ULL);
  for (int i = 0; i < sealSlotCount; i++) {
    maskVector[i] = distr(gen) % 2 ^ 60;
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
    std::vector<std::vector<uint64_t>> epsilonMaskSum(
        RecSys::M.size(), std::vector<uint64_t>(sealSlotCount));
    for (int i = 0; i < RecSys::M.size(); i++) {
      // Calculate sum for i entry
      uint64_t jSum = 0;
      for (int j = 0; j < sealSlotCount; j++) {
        jSum += epsilonMask[i][j];
      }
      // Set all of i and j entry to sum
      for (int j = 0; j < sealSlotCount; j++) {
        epsilonMaskSum[i][j] = jSum << alpha;
      }
      // Encode and subtract sum of mask
      seal::Plaintext epsilonMaskSumPlaintext;
      sealBatchEncoder.encode(epsilonMaskSum[i], epsilonMaskSumPlaintext);
      sealEvaluator.sub_plain(RPrimePrime[i], epsilonMaskSumPlaintext,
                              RecSys::R[i]);
    }

    // Steps 6-7 - Calculate U Gradient , V Gradient, U', V' and add Masks
    std::vector<seal::Ciphertext> UGradientPrime(RecSys::M.size()),
        VGradientPrime(RecSys::M.size()), UPrime(RecSys::M.size()),
        VPrime(RecSys::M.size());
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
    std::vector<std::vector<uint64_t>> UGradientPrimeMaskEncodingVector(
        RecSys::M.size()),
        VGradientPrimeMaskEncodingVector(RecSys::M.size()),
        UPrimeMaskEncodingVector(RecSys::M.size()),
        VPrimeMaskEncodingVector(RecSys::M.size());
    std::vector<seal::Plaintext> UGradientPrimeMask(RecSys::M.size()),
        VGradientPrimeMask(RecSys::M.size()), UPrimeMask(RecSys::M.size()),
        VPrimeMask(RecSys::M.size());
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
    UGradient.resize(UGradientPrimePrime.size());
    VGradient.resize(VGradientPrimePrime.size());
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
  std::vector<seal::Ciphertext> UGradientSquare(UGradientParam.size()),
      VGradientSquare(VGradientParam.size());
  std::vector<std::vector<uint64_t>> UGradientSquareMaskVector(
      UGradientParam.size()),
      VGradientSquareMaskVector(VGradientParam.size());
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
      VMaskSum(sealSlotCount, 0ULL), Su(sealSlotCount), Sv(sealSlotCount);

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
               const seal::SEALContext& sealcontext,
               std::vector<std::pair<int, int>> providedM)
    : MessageHandlerInstance(messagehandler),
      CSPInstance(csp),
      gen(rd()),
      sealContext(sealcontext),
      sealEvaluator(sealcontext),
      sealBatchEncoder(sealcontext),
      M(providedM),
      f(providedM.size()),
      R(providedM.size()),
      UGradient(providedM.size()),
      VGradient(providedM.size()) {
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
    twoToTheAlphaPlusBetaEncodingVector[i] = 1 << (alpha + beta);
  }
  sealBatchEncoder.encode(twoToTheAlphaPlusBetaEncodingVector,
                          twoToTheAlphaPlusBeta);
}

///@brief get the encrypted predictions of all films for user i
std::vector<seal::Ciphertext> RecSys::computePredictions(int user) {
  // Mask and send UHat and VHat
  std::vector<std::vector<uint64_t>> UHatMask(UHat.size()),
      VHatMask(VHat.size());
  std::vector<seal::Ciphertext> maskedUHat(UHat.size()),
      maskedVHat(VHat.size());

  for (int i = 0; i < UHat.size(); i++) {
    UHatMask[i] = generateMaskFHE();

    seal::Plaintext maskPlain;
    sealBatchEncoder.encode(UHatMask[i], maskPlain);
    sealEvaluator.add_plain(UHat[i], maskPlain, maskedUHat[i]);
  }
  for (int i = 0; i < VHat.size(); i++) {
    VHatMask[i] = generateMaskFHE();

    seal::Plaintext maskPlain;
    sealBatchEncoder.encode(VHatMask[i], maskPlain);
    sealEvaluator.add_plain(VHat[i], maskPlain, maskedVHat[i]);
  }

  // Get masked ui and v vectors from CSP
  auto [UVector, VVector] =
      CSPInstance->calculateUiandVVectors(user, maskedUHat, maskedVHat);

  // Remove mask and multiply
  seal::Plaintext uMaskEntryPlain;
  for (int i = 0; i < RecSys::M.size(); i++) {
    if (M.at(i).first == user) {
      sealBatchEncoder.encode(UHatMask.at(i), uMaskEntryPlain);
      break;
    }
  }
  for (int i = 0; i < UVector.size(); i++) {
    sealEvaluator.sub_plain_inplace(UVector.at(i), uMaskEntryPlain);
  }
  // Keep track of order that the items are found to remove correct mask
  std::set<int> observedItems{};
  int index = 0;
  for (int i = 0; i < RecSys::M.size(); i++) {
    if (observedItems.find(M.at(i).second) == observedItems.end()) {
      observedItems.insert(M.at(i).second);
      seal::Plaintext plainRes;
      sealBatchEncoder.encode(VHatMask.at(i), plainRes);
      sealEvaluator.sub_plain_inplace(VVector.at(index++), plainRes);
    }
  }

  // Multiply the two resultant vectors
  std::vector<seal::Ciphertext> dDimensionalMultiplication(UVector.size());
  for (int i = 0; i < UVector.size(); i++) {
    sealEvaluator.multiply(UVector.at(i), VVector.at(i),
                           dDimensionalMultiplication[i]);
  }

  // Get masked entry wise sum from CSP

  // Remove entrywise sum of mask

  // return result
}

/// @brief Set the space of ratings
void RecSys::setM(const std::vector<std::pair<int, int>> providedM) {
  M = providedM;
  RecSys::f.reserve(M.size());
}

/// Set the encrypted ratings vector
void RecSys::setRatings(const std::vector<seal::Ciphertext> providedRatings) {
  r = providedRatings;
}

/// Set the embedding vectors
void RecSys::setEmbeddings(const std::vector<seal::Ciphertext> providedU,
                           const std::vector<seal::Ciphertext> providedV,
                           const std::vector<seal::Ciphertext> providedUHat,
                           const std::vector<seal::Ciphertext> providedVHat) {
  U = providedU;
  V = providedV;
  UHat = providedUHat;
  VHat = providedVHat;
}