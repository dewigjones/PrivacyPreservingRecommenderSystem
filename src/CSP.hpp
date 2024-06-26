#pragma once
#include <cryptopp/elgamal.h>
#include <cryptopp/osrng.h>
#include <math.h>
#include <seal/ciphertext.h>
#include <seal/seal.h>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>
#include "MessageHandler.hpp"
#include "Ratings.hpp"

class CSP {
  int generateKeysFHE();
  bool generateKeysAHE();
  int encryptAHE(int input);
  int decryptAHE(int input);

  // Keep track of the AHE scheme (ElGamal)
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::ElGamalKeys::PrivateKey ahe_PrivateKey;
  CryptoPP::ElGamalKeys::PublicKey ahe_PublicKey;
  CryptoPP::ElGamal::Decryptor ahe_Decryptor;
  CryptoPP::ElGamal::Encryptor ahe_Encryptor;

  // SEAL FHE values and variables
  std::shared_ptr<MessageHandler> messageHandlerInstance;
  seal::SEALContext sealContext;
  seal::PublicKey sealHpk;
  seal::SecretKey sealPrivateKey;
  seal::Encryptor sealEncryptor;
  seal::Decryptor sealDecryptor;
  seal::BatchEncoder sealBatchEncoder;
  size_t sealSlotCount;

  // Algorithmic parameters
  int alpha = 20;
  int beta = 20;
  int twoPowerAlpha;
  int twoPowerBeta;

  // Rating space information
  std::vector<std::pair<int, int>> M;

 public:
  int generateKeys();
  CryptoPP::ElGamalKeys::PublicKey getPublicKeyAHE();
  EncryptedRating convertRatingAHEtoFHE(EncryptedRatingAHE rating);
  std::vector<seal::Ciphertext> sumF(std::vector<seal::Ciphertext> f);

  std::vector<std::vector<uint64_t>> aggregateUser(
      std::vector<std::vector<uint64_t>> A);
  std::vector<std::vector<uint64_t>> aggregateItem(
      std::vector<std::vector<uint64_t>> A);
  std::vector<std::vector<uint64_t>> reconstituteUser(
      std::vector<std::vector<uint64_t>> A);
  std::vector<std::vector<uint64_t>> reconstituteItem(
      std::vector<std::vector<uint64_t>> A);

  std::pair<std::vector<seal::Ciphertext>, std::vector<seal::Ciphertext>>
  calculateNewUandUHat(std::vector<seal::Ciphertext> maskedUPrime);
  std::pair<std::vector<seal::Ciphertext>, std::vector<seal::Ciphertext>>
  calculateNewVandVHat(std::vector<seal::Ciphertext> maskedVPrime);
  std::vector<seal::Ciphertext> calculateNewUGradient(
      std::vector<seal::Ciphertext> maskedUGradientPrime);
  std::vector<seal::Ciphertext> calculateNewVGradient(
      std::vector<seal::Ciphertext> maskedVGradientPrime);

  std::pair<std::vector<seal::Ciphertext>, std::vector<seal::Ciphertext>>
  calculateUiandVVectors(int requestedUser,
                         std::vector<seal::Ciphertext> maskedUHat,
                         std::vector<seal::Ciphertext> maskedVHat);

  std::pair<bool, bool> calculateStoppingVector(
      std::vector<seal::Ciphertext> maskedUGradientSquare,
      std::vector<seal::Ciphertext> maskedVGradientSquare,
      std::vector<uint64_t> Su,
      std::vector<uint64_t> Sv);

  std::vector<seal::Ciphertext> reducePredictionVector(
      std::vector<seal::Ciphertext> predictionVector);

  CSP(std::shared_ptr<MessageHandler> messagehandler,
      seal::SEALContext& sealcontext,
      seal::PublicKey const& sealhpk,
      seal::SecretKey const& sealprivatekey,
      std::vector<std::pair<int, int>> providedM)
      : messageHandlerInstance(messagehandler),
        sealContext(sealcontext),
        sealHpk(sealhpk),
        sealPrivateKey(sealprivatekey),
        sealEncryptor(sealcontext, sealhpk),
        sealDecryptor(sealcontext, sealprivatekey),
        sealBatchEncoder(sealcontext),
        M(providedM) {
    sealSlotCount = sealBatchEncoder.slot_count();
    twoPowerAlpha = (int)pow(2, alpha);
    twoPowerBeta = (int)pow(2, beta);
  }
};