#include "CSP.hpp"

int CSP::generateKeys() {
  return 2;
}

///@brief getter for ElGamal AHE public key
CryptoPP::ElGamalKeys::PublicKey CSP::getPublicKeyAHE() {
  return ahe_PublicKey;
}

/// @brief Generates the Keys and populates the variables for AHE scheme
/// @return Result status - true if successfull
bool CSP::generateKeysAHE() {
  ahe_Decryptor.AccessKey().GenerateRandomWithKeySize(rng, 2048);
  ahe_PrivateKey = ahe_Decryptor.AccessKey();
  ahe_Encryptor = CryptoPP::ElGamal::Encryptor(ahe_Decryptor);
  ahe_PublicKey = ahe_Encryptor.AccessKey();
  return true;
}

///@brief Take a AHE encryptedRating and convert it to a standard (FHE)
/// Encrypted Rating - Upload Phase
EncryptedRating CSP::convertRatingAHEtoFHE(EncryptedRatingAHE rating) {
  return EncryptedRating();
}

/// @brief Sum f vector produced by RecSys - Step 3 and 4 of GDS
/// @return R''
std::vector<std::vector<seal::Ciphertext>> CSP::sumF(
    const std::vector<std::vector<seal::Ciphertext>> f) {
  // Declare result
  std::vector<std::vector<uint64_t>> rprime;

  // Decrypt f and sum
  std::vector<std::vector<seal::Plaintext>> f_dec;
  std::vector<std::vector<std::vector<uint64_t>>> f_decode;
  for (int i = 0; i < f.size(); i++) {
    for (int j = 0; j < f[i].size(); j++) {
      // Decrypt and decode
      sealDecryptor.decrypt(f[i][j], f_dec[i][j]);
      sealBatchEncoder.decode(f_dec[i][j], f_decode[i][j]);

      // sum f[i][j]
      rprime[i][j] = 0;
      for (int k = 0; k < sealSlotCount; k++) {
        rprime[i][j] += f_decode[i][j][k];
      }

      // Scale 
      rprime[i][j] /= twoPowerAlpha;
    }
  }

  // Encode, encrypt and return rprime
  std::vector<std::vector<std::vector<uint64_t>>> rprimeEncodingVector;
  std::vector<std::vector<seal::Plaintext>> rprimeEncode;
  std::vector<std::vector<seal::Ciphertext>> rprimeEncrypt;
  // Encode
  for (int i = 0; i < rprime.size(); i++) {
    for (int j = 0; j < rprime[i].size(); j++) {
      for (int k = 0; k < sealSlotCount; k++) {
        rprimeEncodingVector[i][j][k] = rprime[i][j];
      }
      sealBatchEncoder.encode(rprimeEncodingVector[i][j], rprimeEncode[i][j]);
      sealEncryptor.encrypt(rprimeEncode[i][j], rprimeEncrypt[i][j]);
    }
  }
  return rprimeEncrypt;
}