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

  //Parameters for RS
  int d; //Dimension of profiles
  int alpha; //Number of integer bits for real numbers
  int beta; //Number of fractional bits for real numbers
  int gamma; //Number of bits for gradient descent computation

  //Intermediate values for gradient descent
  std::vector<seal::Ciphertext> RPrime;
  std::vector<std::pair<int, int>> M;
  std::vector<std::pair<int, seal::Ciphertext>> U,V, UHat, VHat;
  
  //Functions
  int generateMask();
  uint8_t generateMaskAHE();
public:
  RecSys(CSP *csp) : CSPInstance(csp) {}
  bool uploadRating(EncryptedRatingAHE rating);
  int getPredictedRating(int userID, int itemID);
  std::vector<EncryptedRating> getPredictiedRatings(int userID);  
  bool gradientDescent();
};