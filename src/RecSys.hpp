#pragma once
#include <math.h>
#include <seal/ciphertext.h>
#include <seal/seal.h>
#include <memory>
#include <vector>
#include "CSP.hpp"
#include "MessageHandler.hpp"
#include "Ratings.hpp"

// AHE libraries
#include <cryptopp/osrng.h>

// Include libraries for FHE mask rng
#include <limits>
#include <random>

class RecSys {
  // Values and Variables
  std::shared_ptr<CSP> CSPInstance;
  std::shared_ptr<MessageHandler> MessageHandlerInstance;
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

  // SEAL values and variables
  seal::SEALContext sealContext;
  seal::Evaluator sealEvaluator;
  seal::BatchEncoder sealBatchEncoder;
  size_t sealSlotCount;

  // Parameters for RS
  int d;               // Dimension of profiles
  int alpha = 20;      // Number of integer bits for real numbers
  int beta = 20;       // Number of fractional bits for real numbers
  int gamma = 20;      // Number of bits for gradient descent computation
  int lambda = 18;     // Learning rate
  int threshold = 10;  // Threshold for stopping criterion
  int maxEpochs = 15;  // Maximum number of iterations for gradient descent -
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
  bool stoppingCriterionCheck(
      const std::vector<seal::Ciphertext>& UGradientParam,
      const std::vector<seal::Ciphertext>& VGradientParam);

 public:
  RecSys(std::shared_ptr<CSP> csp,
         std::shared_ptr<MessageHandler> messagehandler,
         const seal::SEALContext& sealcontext,
         std::vector<std::pair<int, int>> providedM);

  bool uploadRating(EncryptedRatingAHE rating);
  int getPredictedRating(int userID, int itemID);
  std::vector<EncryptedRating> getPredictiedRatings(int userID);
  bool gradientDescent();
  std::vector<seal::Ciphertext> computePredictions(int user);
  void setM(const std::vector<std::pair<int, int>> providedM);
  void setRatings(const std::vector<seal::Ciphertext> providedRatings);
  void setEmbeddings(const std::vector<seal::Ciphertext> providedU,
                     const std::vector<seal::Ciphertext> providedV,
                     const std::vector<seal::Ciphertext> providedUHat,
                     const std::vector<seal::Ciphertext> providedVHat);
};