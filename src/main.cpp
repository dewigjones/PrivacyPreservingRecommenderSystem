#include <seal/context.h>
#include <seal/encryptionparams.h>
#include <seal/keygenerator.h>
#include <seal/modulus.h>
#include <seal/publickey.h>
#include <seal/secretkey.h>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>
#include "CSP.hpp"
#include "seal/seal.h"

int main() {
  // Set up seal
  seal::EncryptionParameters params(seal::scheme_type::bgv);
  size_t poly_modulus_degree = 16384;
  params.set_poly_modulus_degree(poly_modulus_degree);
  params.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
  params.set_plain_modulus(
      seal::PlainModulus::Batching(poly_modulus_degree, 60));
  seal::SEALContext context(params);

  seal::KeyGenerator keygen(context);
  seal::SecretKey secret_key = keygen.secret_key();
  seal::PublicKey public_key;
  keygen.create_public_key(public_key);

  std::cout << "Hello World, public key size is " << public_key.data().size()
            << std::endl;
  auto CSPInstance = std::make_shared<CSP>(context, public_key, secret_key);
  std::cout << CSPInstance->generateKeys() << std::endl;

  // Read test data
  // Declare vectors to hold input
  std::vector<std::pair<int, int>> curM;
  std::vector<int> ratings;
  int maxLines = 100;
  int curLine = 0;
  // Use read file stream
  std::ifstream fileReader("./res/u1.base");
  if (fileReader.is_open()) {
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
  return 0;
}