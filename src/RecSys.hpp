#pragma once
#include "Ratings.hpp"
#include "CSP.hpp"
#include <math.h>
#include <seal/seal.h>

//AHE libraries
#include <cryptopp/osrng.h>

//Include libraries for FHE mask rng
#include <random>
#include <limits>

class RecSys {
  //Values and Variables
  CSP* CSPInstance;
  CryptoPP::AutoSeededRandomPool rng;
  std::vector<EncryptedRating> ratings;
  std::vector<int> users;
  std::vector<int> movies;

  //Random Number Generation for FHE mask
  //Inspired by https://stackoverflow.com/questions/22883840/c-get-random-number-from-0-to-max-long-long-integer  
  std::random_device rd;
  std::mt19937_64 gen;
  std::uniform_int_distribution<unsigned long long> distr;

  //SEAL values and Variables
  seal::SEALContext sealContext;
  seal::Evaluator sealEvaulator;
  seal::BatchEncoder sealBatchEncoder;
  size_t sealSlotCount;

  //Parameters for RS
  int d; //Dimension of profiles
  int alpha; //Number of integer bits for real numbers
  int beta; //Number of fractional bits for real numbers
  int gamma; //Number of bits for gradient descent computation

  //Intermediate values for gradient descent
  std::vector<seal::Ciphertext> RPrime;
  std::vector<std::pair<int, int>> M;
  std::vector<seal::Ciphertext> U,V, UHat, VHat;
  std::vector<std::vector<seal::Ciphertext>> f, r; 
  seal::Plaintext twoToTheAlpha;
  
  //Functions
  seal::Plaintext generateMaskFHE();
  uint8_t generateMaskAHE();
public:
  RecSys(CSP *csp, seal::SEALContext sealcontext) : CSPInstance(csp),sealContext(sealcontext), sealEvaulator(sealcontext), sealBatchEncoder(sealcontext), gen(rd()) {
    //Save slot count
    sealSlotCount = sealBatchEncoder.slot_count();

    //Encode 2^alpha    
    std::vector<uint64_t> twoToTheAlphaEncodingVector(sealSlotCount, 0ULL); 
    twoToTheAlphaEncodingVector[0] = (unsigned long long) pow(2,alpha);
    sealBatchEncoder.encode(twoToTheAlphaEncodingVector, twoToTheAlpha);
  }

  bool uploadRating(EncryptedRatingAHE rating);
  int getPredictedRating(int userID, int itemID);
  std::vector<EncryptedRating> getPredictiedRatings(int userID);  
  bool gradientDescent();
};