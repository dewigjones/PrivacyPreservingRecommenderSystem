#pragma once
#include "Ratings.hpp"
#include "CSP.hpp"
#include <seal/seal.h>
#include <cryptopp/osrng.h>

class RecSys {
  //Values and Variables
  CSP* CSPInstance;
  CryptoPP::AutoSeededRandomPool rng;
  std::vector<EncryptedRating> ratings;
  std::vector<int> users;
  std::vector<int> movies;

  //SEAL values and Variables
  seal::SEALContext sealContext;
  seal::Evaluator sealEvaulator;

  //Parameters for RS
  int d; //Dimension of profiles
  int alpha; //Number of integer bits for real numbers
  int beta; //Number of fractional bits for real numbers
  int gamma; //Number of bits for gradient descent computation

  //Intermediate values for gradient descent
  std::vector<seal::Ciphertext> RPrime;
  std::vector<std::pair<int, int>> M;
  std::vector<seal::Ciphertext> U,V, UHat, VHat;
  std::vector<std::vector<seal::Ciphertext>> f; 
  
  //Functions
  int generateMask();
  uint8_t generateMaskAHE();
public:
  RecSys(CSP *csp, seal::SEALContext sealcontext) : CSPInstance(csp),sealContext(sealcontext), sealEvaulator(sealcontext) {}
  bool uploadRating(EncryptedRatingAHE rating);
  int getPredictedRating(int userID, int itemID);
  std::vector<EncryptedRating> getPredictiedRatings(int userID);  
  bool gradientDescent();
};