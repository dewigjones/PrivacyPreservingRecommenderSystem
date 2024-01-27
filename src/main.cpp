#include <seal/context.h>
#include <seal/encryptionparams.h>
#include <seal/keygenerator.h>
#include <seal/modulus.h>
#include <seal/publickey.h>
#include <seal/secretkey.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>
#include "CSP.hpp"
#include "MessageHandler.hpp"
#include "RecSys.hpp"
#include "seal/seal.h"

int main() {
  // Set up seal
  seal::EncryptionParameters parms(seal::scheme_type::bgv);
  size_t poly_modulus_degree = 16384;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(
      seal::PlainModulus::Batching(poly_modulus_degree, 20));
  seal::SEALContext context(parms);
  seal::KeyGenerator keygen(context);
  seal::SecretKey secret_key = keygen.secret_key();
  seal::PublicKey public_key;
  keygen.create_public_key(public_key);

  seal::Encryptor encryptor(context, public_key);
  seal::BatchEncoder batchEncoder(context);
  std::shared_ptr<MessageHandler> messageHandlerInstance{};
  // messageHandlerInstance->last_write_size =
  //     parms.save(messageHandlerInstance->parms_stream);
  std::cout << "Hello World, public key size is " << public_key.data().size()
            << std::endl;
  auto CSPInstance = std::make_shared<CSP>(messageHandlerInstance, context,
                                           public_key, secret_key);
  std::cout << CSPInstance->generateKeys() << std::endl;

  // Read test data
  // Declare vectors to hold input
  std::vector<std::pair<int, int>> curM;
  std::vector<int> ratings;
  int maxLines = 100;
  int curLine = 0;
  // Use read file stream
  if (std::ifstream fileReader("../res/u1.base"); fileReader.is_open()) {
    std::string line;

    // Get each line
    while (curLine++ < maxLines && std::getline(fileReader, line)) {
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
      curM.push_back(std::make_pair(user, movie));
      ratings.push_back(rating);
    }
    fileReader.close();
  } else {
    std::cout << "Could not open file" << std::endl;
  }

  // Encrypt ratings
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

  // Inject data into RecSys
  std::unique_ptr<RecSys> recSysInstance =
      std::make_unique<RecSys>(CSPInstance, messageHandlerInstance, context);
  recSysInstance->setM(curM);
  recSysInstance->setRatings(encryptedRatings);

  recSysInstance->gradientDescent();

  return 0;
}