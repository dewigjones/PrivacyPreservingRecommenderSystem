#pragma once
#include <cryptopp/elgamal.h>
class CSP {

int generateKeysFHE();
int generateKeysAHE();
int encryptAHE(int input);
int decryptAHE(int input);

public:

int generateKeys();

};