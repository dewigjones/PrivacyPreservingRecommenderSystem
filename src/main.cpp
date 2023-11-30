#include <cstddef>
#include <iostream>
#include <seal/context.h>
#include <seal/encryptionparams.h>
#include <seal/keygenerator.h>
#include <seal/modulus.h>
#include <seal/publickey.h>
#include <seal/secretkey.h>
#include <string>
#include "seal/seal.h"

int main(){
    //Set up seal 
    seal::EncryptionParameters params(seal::scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    params.set_plain_modulus(1024);
    seal::SEALContext context(params);

    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);

    std::cout << "Hello World, public key size is " << public_key.data().size() << std::endl;

    return 0;
}