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
std::vector<seal::Ciphertext> CSP::sumF(const std::vector<seal::Ciphertext> f) {
  // Declare result
  std::vector<uint64_t> rprime;

  // Decrypt f and sum
  std::vector<seal::Plaintext> f_dec;
  std::vector<std::vector<uint64_t>> f_decode;
  for (int i = 0; i < CSP::M.size(); i++) {
    // Decrypt and decode
    sealDecryptor.decrypt(f[i], f_dec[i]);
    sealBatchEncoder.decode(f_dec[i], f_decode[i]);

    // sum f[i]
    rprime[i] = 0;
    for (int j = 0; j < sealSlotCount; j++) {
      rprime[i] += f_decode[i][j];
    }

    // Scale
    rprime[i] = (uint64_t)std::floor(rprime[i] / twoPowerAlpha);
  }

  // Encode, encrypt and return rprime
  std::vector<std::vector<uint64_t>> rprimeEncodingVector;
  std::vector<seal::Plaintext> rprimeEncode;
  std::vector<seal::Ciphertext> rprimeEncrypt;
  // Encode
  for (int i = 0; i < CSP::M.size(); i++) {
    for (int j = 0; j < sealSlotCount; j++) {
      rprimeEncodingVector[i][j] = rprime[i];
    }
    sealBatchEncoder.encode(rprimeEncodingVector[i], rprimeEncode[i]);
    sealEncryptor.encrypt(rprimeEncode[i], rprimeEncrypt[i]);
  }
  return rprimeEncrypt;
}

/// Sum d-dimensional vector of A vector, grouped by user
/// @brief aggu operation in paper
/// @param A - decoded plaintext vector
std::vector<std::vector<uint64_t>> CSP::aggregateUser(
    const std::vector<std::vector<uint64_t>> A) {
  std::vector<std::vector<uint64_t>> result;
  std::vector<uint64_t> curResult = std::vector<uint64_t>(sealSlotCount, 0ULL);
  int prevUser = -1;

  for (int i = 0; i < A.size(); i++) {
    // Get corresponding user at index of M
    int curUser = M.at(i).first;

    // If current user is not the same as the last, push result and move onto
    // the next user
    if (curUser != prevUser) {
      if (prevUser != -1) {
        result.push_back(curResult);
        std::fill(curResult.begin(), curResult.end(), 0);
      }
      prevUser = curUser;
    }

    // Add current entry to the running total for the current user
    for (int j = 0; j < sealSlotCount; j++) {
      curResult[j] += A[i][j];
    }
  }
  return result;
}

/// Sum d-dimensional vector of A vector, grouped by item
/// @brief aggv operation in paper
/// @param A - decoded plaintext vector
std::vector<std::vector<uint64_t>> CSP::aggregateItem(
    const std::vector<std::vector<uint64_t>> A) {
  std::vector<std::vector<uint64_t>> result;
  std::vector<uint64_t> curResult = std::vector<uint64_t>(sealSlotCount, 0ULL);
  int prevItem = -1;

  for (int i = 0; i < A.size(); i++) {
    // Get corresponding user at index of M
    int curItem = M.at(i).first;

    // If current item is not the same as the last, push result and move onto
    // the next item
    if (curItem != prevItem) {
      if (prevItem != -1) {
        result.push_back(curResult);
        std::fill(curResult.begin(), curResult.end(), 0);
      }
      prevItem = curItem;
    }

    // Add current entry to the running total for the current item
    for (int j = 0; j < sealSlotCount; j++) {
      curResult[j] += A[i][j];
    }
  }
  return result;
}

/// Reconstitute A, grouping by User
/// @brief recu in paper
/// @param A - decoded plaintext vector
std::vector<std::vector<uint64_t>> CSP::reconstituteUser(
    std::vector<std::vector<uint64_t>> A) {
  std::vector<std::vector<uint64_t>> result;
  int prevUser = -1;
  int aIndex = -1;

  // Go through M
  for (auto [i, j] : CSP::M) {
    // If new user, increase index
    if (i != prevUser) {
      aIndex++;
    }
    // Push A[i] to the result
    result.push_back(A.at(aIndex));
  }
  return result;
}

/// Reconstitute A, grouping by Item
/// @brief recv in paper
/// @param A - decoded plaintext vector
std::vector<std::vector<uint64_t>> CSP::reconstituteItem(
    std::vector<std::vector<uint64_t>> A) {
  std::vector<std::vector<uint64_t>> result;
  int prevItem = -1;
  int aIndex = -1;

  // Go through M
  for (auto [i, j] : CSP::M) {
    // If new user, increase index
    if (j != prevItem) {
      aIndex++;
    }
    // Push A[i] to the result
    result.push_back(A.at(aIndex));
  }
  return result;
}

std::pair<std::vector<seal::Ciphertext>, std::vector<seal::Ciphertext>>
CSP::calculateNewUandUHat(std::vector<seal::Ciphertext> maskedUPrime) {
  std::vector<seal::Ciphertext> newU;
  std::vector<seal::Ciphertext> newUHat;

  // Decrypt and decode maskedUPrime
  std::vector<seal::Plaintext> maskedUPrimePlaintext;
  std::vector<std::vector<uint64_t>> maskedUPrimeDecoded;
  for (int i = 0; i < maskedUPrime.size(); i++) {
    sealDecryptor.decrypt(maskedUPrime[i], maskedUPrimePlaintext[i]);
    sealBatchEncoder.decode(maskedUPrimePlaintext[i], maskedUPrimeDecoded[i]);
  }

  // Calculate new U
  std::vector<std::vector<uint64_t>> newUDecoded =
      reconstituteUser(aggregateUser(maskedUPrimeDecoded));
  std::vector<seal::Plaintext> newUPlaintext;
  for (int i = 0; i < newUDecoded.size(); i++) {
    sealBatchEncoder.encode(newUDecoded[i], newUPlaintext[i]);
    sealEncryptor.encrypt(newUPlaintext[i], newU[i]);
  }

  // Calculate new UHat
  int prevUser = -1;
  int uIndex = 0;
  // Go through M
  for (auto [i, j] : CSP::M) {
    // If not new user, push zero, otherwise push value of newU
    if (i == prevUser) {
      std::vector<uint64_t> zeroVector(sealSlotCount, 0ULL);
      seal::Plaintext zeroPlain;
      seal::Ciphertext zeroEnc;

      sealBatchEncoder.encode(zeroVector, zeroPlain);
      sealEncryptor.encrypt(zeroPlain, zeroEnc);
      newUHat.push_back(zeroEnc);
    } else {
      newUHat.push_back(newU.at(uIndex));
      prevUser = i;
    }
    uIndex++;
  }
  return std::make_pair(newU, newUHat);
}