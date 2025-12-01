#pragma once
#include <eccrypto.h>
#include "Member.h"
extern CryptoPP::AutoSeededRandomPool seed;
//Class that include ciphertext (alpha,beta)
class Ciphertext
{
private:
	CryptoPP::ECP::Point alpha;
	CryptoPP::ECP::Point beta;
public:
	Ciphertext() {};
	Ciphertext(CryptoPP::ECP::Point alpha1, CryptoPP::ECP::Point beta1);
	
	CryptoPP::ECP::Point getalpha() const { return alpha; }
	CryptoPP::ECP::Point getbeta() const { return beta; }
};