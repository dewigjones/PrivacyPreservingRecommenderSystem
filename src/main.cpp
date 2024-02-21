#include <seal/ciphertext.h>
#include <seal/context.h>
#include <seal/decryptor.h>
#include <seal/encryptionparams.h>
#include <seal/keygenerator.h>
#include <seal/modulus.h>
#include <seal/plaintext.h>
#include <seal/publickey.h>
#include <seal/secretkey.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include "CSP.hpp"
#include "MessageHandler.hpp"
#include "RecSys.hpp"
#include "seal/seal.h"

int main() {
  // Set up seal
  std::cout << "Initialising seal" << std::endl;
  seal::EncryptionParameters parms(seal::scheme_type::bgv);
  size_t poly_modulus_degree = 16384;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(
      seal::PlainModulus::Batching(poly_modulus_degree, 60));
  seal::SEALContext context(parms);
  seal::KeyGenerator keygen(context);
  seal::SecretKey secret_key = keygen.secret_key();
  seal::PublicKey public_key;
  keygen.create_public_key(public_key);

  seal::Encryptor encryptor(context, public_key);
  seal::BatchEncoder batchEncoder(context);
  seal::Decryptor decryptor(context, secret_key);
  std::shared_ptr<MessageHandler> messageHandlerInstance{};

  // Read test data
  // Declare vectors to hold input
  std::cout << "Reading data" << std::endl;
  std::set<std::tuple<int, int, int>> data;
  std::vector<std::pair<int, int>> curM;
  std::vector<int> ratings;
  int maxLines = 150;
  int skipLines = 50;
  int curLine = 0;
  // Use read file stream
  if (std::ifstream fileReader("../res/u1.base"); fileReader.is_open()) {
    std::string line;

    // Get each line
    while (curLine++ < maxLines && std::getline(fileReader, line)) {
      if (skipLines-- < 0) {
        std::string column;       // Hold current column entry in line
        int columnIndex = 0;      // Count which column of line we're in
        int user, movie, rating;  // Variables for output

        // Create a stringstream for current line so we can use getline to split
        // by delimiter
        std::stringstream ss;
        ss.str(line);

        // Separate line by tab delimiter
        while (std::getline(ss, column, '\t')) {
          // Assign the entries by column to the correct variable, ignoring the
          // timestamp and coverting to int
          if (columnIndex % 4 == 0)
            user = std::stoi(column);
          if (columnIndex % 4 == 1)
            movie = std::stoi(column);
          if (columnIndex % 4 == 2)
            rating = std::stoi(column);
          columnIndex++;
        }

        // Push current line to our vectors
        data.insert(std::make_tuple(user, movie, rating));
      }
    }
    fileReader.close();
  } else {
    std::cout << "Could not open file" << std::endl;
  }

  // Populate M and rating vectors
  for (auto [user, movie, rating] : data) {
    curM.push_back(std::make_pair(user, movie));
    ratings.push_back(rating);
  }

  // Encrypt ratings
  std::cout << "Encrypting ratings" << std::endl;
  std::vector<seal::Ciphertext> encryptedRatings;
  for (int rating : ratings) {
    std::vector<uint64_t> ratingEncodingVector(batchEncoder.slot_count(), 0ULL);
    ratingEncodingVector[0] = static_cast<uint64_t>(rating);

    seal::Plaintext ratingPlain;
    seal::Ciphertext ratingEnc;
    batchEncoder.encode(ratingEncodingVector, ratingPlain);
    encryptor.encrypt(ratingPlain, ratingEnc);

    encryptedRatings.push_back(ratingEnc);
  }

  // Encode random values for U, V, UHat, VHat
  // Need to move this to main and insert it
  std::cout << "Creating embeddings" << std::endl;
  std::vector<seal::Ciphertext> U(curM.size()), V(curM.size()), UHat, VHat;
  int prevUser = -1;
  int prevItem = -1;
  for (int i = 0; i < curM.size(); i++) {
    std::vector<uint64_t> UEncodingVector(batchEncoder.slot_count(), 0ULL),
        VEncodingVector(batchEncoder.slot_count(), 0ULL);
    for (int j = 0; j < batchEncoder.slot_count(); j++) {
      UEncodingVector[j] = 1ULL;
      VEncodingVector[j] = 1ULL;
    }
    seal::Plaintext UPlain, VPlain;
    batchEncoder.encode(UEncodingVector, UPlain);
    batchEncoder.encode(VEncodingVector, VPlain);
    encryptor.encrypt(UPlain, U[i]);
    encryptor.encrypt(VPlain, V[i]);

    // Add entry for UHat
    if (curM.at(i).first == prevUser) {
      std::vector<uint64_t> zeroEncodingVector(batchEncoder.slot_count(), 0ULL);
      seal::Plaintext zeroPlain;
      seal::Ciphertext zeroEnc;

      batchEncoder.encode(zeroEncodingVector, zeroPlain);
      encryptor.encrypt(zeroPlain, zeroEnc);
      UHat.push_back(zeroEnc);
    } else {
      UHat.push_back(U.at(i));
    }

    // Add entry for UHat
    if (curM.at(i).second == prevItem) {
      std::vector<uint64_t> zeroEncodingVector(batchEncoder.slot_count(), 0ULL);
      seal::Plaintext zeroPlain;
      seal::Ciphertext zeroEnc;

      batchEncoder.encode(zeroEncodingVector, zeroPlain);
      encryptor.encrypt(zeroPlain, zeroEnc);
      VHat.push_back(zeroEnc);
    } else {
      VHat.push_back(V.at(i));
    }

    // Re-assign prevUser and prevItem
    std::tie(prevUser, prevItem) = curM.at(i);
  }
  // Inject data into new CSP
  std::cout << "Creating CSP Instance" << std::endl;
  auto CSPInstance = std::make_shared<CSP>(messageHandlerInstance, context,
                                           public_key, secret_key, curM);
  // Inject data into RecSys
  std::cout << "Creating RecSys Instance" << std::endl;
  std::unique_ptr<RecSys> recSysInstance = std::make_unique<RecSys>(
      CSPInstance, messageHandlerInstance, context, curM);
  recSysInstance->setRatings(encryptedRatings);
  recSysInstance->setEmbeddings(U, V, UHat, VHat);

  std::cout << "Running Gradient Descent" << std::endl;
  recSysInstance->gradientDescent();

  std::cout << "Computing results for user 1" << std::endl;
  auto [items, resultsFor1] = recSysInstance->computePredictions(1);

  std::cout << "Decrypted results for user 1:" << std::endl;
  for (int i = 0; i < resultsFor1.size(); i++) {
    seal::Plaintext curRowPlain;
    std::vector<uint64_t> curRow;
    decryptor.decrypt(resultsFor1.at(i), curRowPlain);
    batchEncoder.decode(curRowPlain, curRow);
    std::cout << items.at(i) << ", " << (double)curRow.at(0) / pow(2, 20)
              << std::endl;
  }
  std::cout << "Finished" << std::endl;
  return 0;
}
