#pragma once
#include "Ratings.hpp"
#include "CSP.hpp"
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

  //Functions
  int generateMask();
  uint8_t generateMaskAHE();
public:
  RecSys(CSP *csp) : CSPInstance(csp) {}
  bool uploadRating(EncryptedRatingAHE rating);
  int getPredictedRating(int userID, int itemID);
  std::vector<EncryptedRating> getPredictiedRatings(int userID);  
  int gradientDescent();
};