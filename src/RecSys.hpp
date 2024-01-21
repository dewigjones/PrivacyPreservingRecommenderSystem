#pragma once
#include <math.h>
#include <seal/ciphertext.h>
#include <seal/seal.h>
#include "CSP.hpp"
#include "Ratings.hpp"

// AHE libraries
#include <cryptopp/osrng.h>

// Include libraries for FHE mask rng
#include <limits>
#include <random>
#include <vector>

class RecSys {
  // Values and Variables
  CSP* CSPInstance;
  CryptoPP::AutoSeededRandomPool rng;
  std::vector<EncryptedRating> ratings;
  std::vector<int> users;
  std::vector<int> movies;

  // Random Number Generation for FHE mask
  // Inspired by
  // https://stackoverflow.com/questions/22883840/c-get-random-number-from-0-to-max-long-long-integer
  std::random_device rd;
  std::mt19937_64 gen;
  std::uniform_int_distribution<unsigned long long> distr;

  // SEAL values and Variables
  seal::SEALContext sealContext;
  seal::Evaluator sealEvaluator;
  seal::BatchEncoder sealBatchEncoder;
  size_t sealSlotCount;

  // Parameters for RS
  int d;               // Dimension of profiles
  int alpha;           // Number of integer bits for real numbers
  int beta;            // Number of fractional bits for real numbers
  int gamma;           // Number of bits for gradient descent computation
  int lambda;          // Learning rate
  int threshold;       // Threshold for stopping criterion
  int maxEpochs = 10;  // Maximum number of iterations for gradient descent -
                       // regardless of if stopping criterion met

  // Intermediate values for gradient descent
  std::vector<std::pair<int, int>> M;
  std::vector<seal::Ciphertext> R, r, f, U, V, UHat, VHat, UGradient, VGradient;
  seal::Plaintext twoToTheAlpha, twoToTheBeta, twoToTheAlphaPlusBeta,
      scaledLambda, scaledGamma;
  bool stoppingCriterionCheckResult = false;
  // Functions
  std::vector<uint64_t> generateMaskFHE();
  uint8_t generateMaskAHE();
  bool stoppingCriterionCheck(const std::vector<seal::Ciphertext> UGradient,
                              const std::vector<seal::Ciphertext> VGradient);

 public:
  RecSys(CSP* csp, const seal::SEALContext sealcontext)
      : CSPInstance(csp),
        sealContext(sealcontext),
        sealEvaluator(sealcontext),
        sealBatchEncoder(sealcontext),
        gen(rd()) {
    // Save slot count
    sealSlotCount = sealBatchEncoder.slot_count();

    // Encode 2^alpha
    std::vector<uint64_t> twoToTheAlphaEncodingVector(sealSlotCount, 0ULL),
        scaledLambdaEncodingVector(sealSlotCount, 0ULL);
    for (int i = 0; i < sealSlotCount; i++) {
      twoToTheAlphaEncodingVector[i] = (unsigned long long)pow(2, alpha);
      scaledLambdaEncodingVector[i] =
          (unsigned long long)pow(2, alpha) * lambda;
    }
    sealBatchEncoder.encode(twoToTheAlphaEncodingVector, twoToTheAlpha);
    sealBatchEncoder.encode(scaledLambdaEncodingVector, scaledLambda);

    // Encode 2^beta
    std::vector<uint64_t> twoToTheBetaEncodingVector(sealSlotCount, 0ULL),
        scaledGammaEncodingVector(sealSlotCount, 0ULL);
    for (int i = 0; i < sealSlotCount; i++) {
      twoToTheBetaEncodingVector[i] = (unsigned long long)pow(2, beta);
      scaledGammaEncodingVector[i] = (unsigned long long)pow(2, beta) * gamma;
    }
    sealBatchEncoder.encode(twoToTheBetaEncodingVector, twoToTheBeta);
    sealBatchEncoder.encode(scaledGammaEncodingVector, scaledGamma);

    // Encode 2^(alpha+beta)
    std::vector<uint64_t> twoToTheAlphaPlusBetaEncodingVector(sealSlotCount,
                                                              0ULL);
    for (int i = 0; i < sealSlotCount; i++) {
      twoToTheAlphaPlusBetaEncodingVector[i] =
          (unsigned long long)pow(2, alpha + beta);
    }
    sealBatchEncoder.encode(twoToTheAlphaPlusBetaEncodingVector,
                            twoToTheAlphaPlusBeta);
  }

  bool uploadRating(EncryptedRatingAHE rating);
  int getPredictedRating(int userID, int itemID);
  std::vector<EncryptedRating> getPredictiedRatings(int userID);
  bool gradientDescent();
};