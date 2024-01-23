#include <seal/context.h>
#include <seal/encryptionparams.h>
#include <seal/keygenerator.h>
#include <seal/modulus.h>
#include <seal/publickey.h>
#include <seal/secretkey.h>
#include <cstddef>
#include <iostream>
#include <memory>
#include <string>
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

  return 0;
}