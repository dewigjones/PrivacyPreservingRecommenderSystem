#pragma once
#include <cryptopp/elgamal.h>
#include <cryptopp/osrng.h>
#include <seal/seal.h>
#include "Ratings.hpp"
#include <math.h>

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
  seal::SEALContext sealContext;
  seal::PublicKey sealHpk;
  seal::SecretKey sealPrivateKey;
  seal::Encryptor sealEncryptor;
  seal::Decryptor sealDecryptor;
  seal::BatchEncoder sealBatchEncoder;
  size_t sealSlotCount;

  // Algorithmic parameters
  int alpha;
  int beta;
  int twoPowerAlpha, twoPowerBeta;

 public:
  int generateKeys();
  CryptoPP::ElGamalKeys::PublicKey getPublicKeyAHE();
  EncryptedRating convertRatingAHEtoFHE(EncryptedRatingAHE rating);
  std::vector<std::vector<seal::Ciphertext>> sumF(
      std::vector<std::vector<seal::Ciphertext>> f);

  CSP(seal::SEALContext sealcontext,
      seal::PublicKey sealhpk,
      seal::SecretKey sealprivatekey)
      : sealContext(sealcontext),
        sealHpk(sealhpk),
        sealPrivateKey(sealprivatekey),
        sealEncryptor(sealcontext, sealhpk),
        sealDecryptor(sealcontext, sealprivatekey),
        sealBatchEncoder(sealcontext) {
    sealSlotCount = sealBatchEncoder.slot_count();
    twoPowerAlpha = pow(2, alpha);
    twoPowerBeta = pow(2, beta);
  }
};