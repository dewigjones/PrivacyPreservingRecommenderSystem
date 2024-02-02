#include "CSP.hpp"
#include <seal/plaintext.h>
#include <cstdint>
#include <ostream>
#include <vector>

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
  std::vector<uint64_t> rprime(sealSlotCount);

  // Decrypt f and sum
  std::vector<seal::Plaintext> f_dec(CSP::M.size());
  std::vector<std::vector<uint64_t>> f_decode(CSP::M.size());
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
  std::vector<seal::Ciphertext> rprimeEncrypt(M.size());
  // Encode
  for (int i = 0; i < CSP::M.size(); i++) {
    std::vector<uint64_t> rprimeEncodingVector(sealSlotCount);
    seal::Plaintext rprimeEncode;
    for (int j = 0; j < sealSlotCount; j++) {
      rprimeEncodingVector[j] = rprime[i];
    }
    sealBatchEncoder.encode(rprimeEncodingVector, rprimeEncode);
    sealEncryptor.encrypt(rprimeEncode, rprimeEncrypt[i]);
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
      curResult[j] += A.at(i).at(j);
    }
  }
  result.push_back(curResult);
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
  result.push_back(curResult);
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
      prevUser = i;
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
      prevItem = i;
    }
    // Push A[i] to the result
    result.push_back(A.at(aIndex));
  }
  return result;
}

/// @brief Step 8 - Calculate new U and UHat
/// @return Pair containing new U and UHat in that order
std::pair<std::vector<seal::Ciphertext>, std::vector<seal::Ciphertext>>
CSP::calculateNewUandUHat(std::vector<seal::Ciphertext> maskedUPrime) {
  std::vector<seal::Ciphertext> newU;
  std::vector<seal::Ciphertext> newUHat;

  // Decrypt and decode maskedUPrime
  std::vector<seal::Plaintext> maskedUPrimePlaintext(maskedUPrime.size());
  std::vector<std::vector<uint64_t>> maskedUPrimeDecoded(maskedUPrime.size());
  for (int i = 0; i < maskedUPrime.size(); i++) {
    sealDecryptor.decrypt(maskedUPrime[i], maskedUPrimePlaintext[i]);
    sealBatchEncoder.decode(maskedUPrimePlaintext[i], maskedUPrimeDecoded[i]);
    // Scale
    for (int j = 0; j < sealSlotCount; j++) {
      maskedUPrimeDecoded[i][j] =
          (uint64_t)std::floor(maskedUPrimeDecoded[i][j] / twoPowerAlpha);
    }
  }

  // Calculate new U
  std::vector<std::vector<uint64_t>> newUDecoded =
      reconstituteUser(aggregateUser(maskedUPrimeDecoded));
  std::vector<seal::Plaintext> newUPlaintext(newUDecoded.size());
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

/// @brief Step 8 - Calculate new  and VHat
/// @return Pair containing new V and VHat in that order
std::pair<std::vector<seal::Ciphertext>, std::vector<seal::Ciphertext>>
CSP::calculateNewVandVHat(std::vector<seal::Ciphertext> maskedVPrime) {
  std::vector<seal::Ciphertext> newV;
  std::vector<seal::Ciphertext> newVHat;

  // Decrypt and decode maskedVPrime
  std::vector<seal::Plaintext> maskedVPrimePlaintext;
  std::vector<std::vector<uint64_t>> maskedVPrimeDecoded;
  for (int i = 0; i < maskedVPrime.size(); i++) {
    sealDecryptor.decrypt(maskedVPrime[i], maskedVPrimePlaintext[i]);
    sealBatchEncoder.decode(maskedVPrimePlaintext[i], maskedVPrimeDecoded[i]);
    // Scale
    for (int j = 0; j < sealSlotCount; j++) {
      maskedVPrimeDecoded[i][j] =
          (uint64_t)std::floor(maskedVPrimeDecoded[i][j] / twoPowerAlpha);
    }
  }

  // Calculate new V
  std::vector<std::vector<uint64_t>> newVDecoded =
      reconstituteItem(aggregateItem(maskedVPrimeDecoded));
  std::vector<seal::Plaintext> newVPlaintext;
  for (int i = 0; i < newVDecoded.size(); i++) {
    sealBatchEncoder.encode(newVDecoded[i], newVPlaintext[i]);
    sealEncryptor.encrypt(newVPlaintext[i], newV[i]);
  }

  // Calculate new VHat
  int prevItem = -1;
  int vIndex = 0;
  // Go through M
  for (auto [i, j] : CSP::M) {
    // If not new user, push zero, otherwise push value of newV
    if (j == prevItem) {
      std::vector<uint64_t> zeroVector(sealSlotCount, 0ULL);
      seal::Plaintext zeroPlain;
      seal::Ciphertext zeroEnc;

      sealBatchEncoder.encode(zeroVector, zeroPlain);
      sealEncryptor.encrypt(zeroPlain, zeroEnc);
      newVHat.push_back(zeroEnc);
    } else {
      newVHat.push_back(newV.at(vIndex));
      prevItem = j;
    }
    vIndex++;
  }
  return std::make_pair(newV, newVHat);
}

/// @brief Calculate new U Gradient - Step 9
std::vector<seal::Ciphertext> CSP::calculateNewUGradient(
    std::vector<seal::Ciphertext> maskedUGradientPrime) {
  // Decrypt and decode input
  std::vector<std::vector<uint64_t>> maskedUGradientDecoded;
  for (int i = 0; i < maskedUGradientPrime.size(); i++) {
    seal::Plaintext maskedUGradientDecrypt;
    sealDecryptor.decrypt(maskedUGradientPrime[i], maskedUGradientDecrypt);
    sealBatchEncoder.decode(maskedUGradientDecrypt, maskedUGradientDecoded[i]);
    // Scale
    for (int j = 0; j < sealSlotCount; j++) {
      maskedUGradientDecoded[i][j] =
          (uint64_t)std::floor(maskedUGradientDecoded[i][j] / twoPowerAlpha);
    }
  }

  // Get aggregation
  std::vector<std::vector<uint64_t>> newUGradientDecoded =
      aggregateUser(maskedUGradientDecoded);

  // Re-encode and re-encrypt
  std::vector<seal::Ciphertext> newUGradient;
  for (int i = 0; i < newUGradientDecoded.size(); i++) {
    seal::Plaintext newUGradientPlaintext;
    sealBatchEncoder.encode(newUGradientDecoded[i], newUGradientPlaintext);
    sealEncryptor.encrypt(newUGradientPlaintext, newUGradient[i]);
  }

  return newUGradient;
}

/// @brief Calculate new V Gradient - Step 9
std::vector<seal::Ciphertext> CSP::calculateNewVGradient(
    std::vector<seal::Ciphertext> maskedVGradientPrime) {
  // Decrypt and decode input
  std::vector<std::vector<uint64_t>> maskedVGradientDecoded;
  for (int i = 0; i < maskedVGradientPrime.size(); i++) {
    seal::Plaintext maskedVGradientDecrypt;
    sealDecryptor.decrypt(maskedVGradientPrime[i], maskedVGradientDecrypt);
    sealBatchEncoder.decode(maskedVGradientDecrypt, maskedVGradientDecoded[i]);
    // Scale
    for (int j = 0; j < sealSlotCount; j++) {
      maskedVGradientDecoded[i][j] =
          (uint64_t)std::floor(maskedVGradientDecoded[i][j] / twoPowerAlpha);
    }
  }

  // Get aggregation
  std::vector<std::vector<uint64_t>> newVGradientDecoded =
      aggregateItem(maskedVGradientDecoded);

  // Re-encode and re-encrypt
  std::vector<seal::Ciphertext> newVGradient;
  for (int i = 0; i < newVGradientDecoded.size(); i++) {
    seal::Plaintext newVGradientPlaintext;
    sealBatchEncoder.encode(newVGradientDecoded[i], newVGradientPlaintext);
    sealEncryptor.encrypt(newVGradientPlaintext, newVGradient[i]);
  }

  return newVGradient;
}

/// @brief Calculate the boolean pair for whether the Stopping Criterion is
/// met for the user and the items respectivesly
/// @return pair of bools {User threshold met, Item threshold met}
std::pair<bool, bool> CSP::calculateStoppingVector(
    std::vector<seal::Ciphertext> maskedUGradientSquare,
    std::vector<seal::Ciphertext> maskedVGradientSquare,
    std::vector<uint64_t> Su,
    std::vector<uint64_t> Sv) {
  std::vector<uint64_t> maskedUGradientSquareSum(sealSlotCount, 0ULL),
      maskedVGradientSquareSum(sealSlotCount, 0ULL);
  bool UThresholdMet = false;
  bool VThresholdMet = false;

  // Decrypt and sum maskedUGradientSquared
  for (int i = 0; i < maskedUGradientSquare.size(); i++) {
    seal::Plaintext maskedUGradientSquarePlain;
    std::vector<uint64_t> maskedUGradientSquareDecoded;
    sealDecryptor.decrypt(maskedUGradientSquare[i], maskedUGradientSquarePlain);
    sealBatchEncoder.decode(maskedUGradientSquarePlain,
                            maskedUGradientSquareDecoded);

    for (int j = 0; j < sealSlotCount; j++) {
      maskedUGradientSquareSum[j] += maskedUGradientSquareDecoded[j];
    }
  }
  // Decrypt and sum maskedVGradientSquared
  for (int i = 0; i < maskedVGradientSquare.size(); i++) {
    seal::Plaintext maskedVGradientSquarePlain;
    std::vector<uint64_t> maskedVGradientSquareDecoded;
    sealDecryptor.decrypt(maskedVGradientSquare[i], maskedVGradientSquarePlain);
    sealBatchEncoder.decode(maskedVGradientSquarePlain,
                            maskedVGradientSquareDecoded);

    for (int j = 0; j < sealSlotCount; j++) {
      maskedVGradientSquareSum[j] += maskedVGradientSquareDecoded[j];
    }
  }

  // Set the value of whether the gradient is less than the threshold for both
  // users and items
  for (int i = 0; i < sealSlotCount; i++) {
    if (maskedUGradientSquareSum[i] <= Su[i])
      UThresholdMet = true;
    if (maskedVGradientSquareSum[i] <= Sv[i])
      VThresholdMet = true;
  }

  return {UThresholdMet, VThresholdMet};
}