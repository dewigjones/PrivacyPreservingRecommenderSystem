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
std::vector<seal::Ciphertext> CSP::sumF(
    const std::vector<seal::Ciphertext> f) {
  // Declare result
  std::vector<uint64_t> rprime;

  // Decrypt f and sum
  std::vector<seal::Plaintext> f_dec;
  std::vector<std::vector<uint64_t>> f_decode;
  for(int i = 0 ; i < CSP::M.size(); i++) {
    // Decrypt and decode
    sealDecryptor.decrypt(f[i], f_dec[i]);
    sealBatchEncoder.decode(f_dec[i], f_decode[i]);

    // sum f[i]
    rprime[i] = 0;
    for (int j = 0; j < sealSlotCount; j++) {
      rprime[i] += f_decode[i][j];
    }

    // Scale 
    rprime[i] /= twoPowerAlpha;
  }

  // Encode, encrypt and return rprime
  std::vector<std::vector<uint64_t>> rprimeEncodingVector;
  std::vector<seal::Plaintext> rprimeEncode;
  std::vector<seal::Ciphertext> rprimeEncrypt;
  // Encode
  for(int i = 0; i < CSP::M.size(); i++) {
    for (int j = 0; j < sealSlotCount; j++) {
      rprimeEncodingVector[i][j] = rprime[i];
    }
    sealBatchEncoder.encode(rprimeEncodingVector[i], rprimeEncode[i]);
    sealEncryptor.encrypt(rprimeEncode[i], rprimeEncrypt[i]);
  }
  return rprimeEncrypt;
}