#include "Ciphertext.h"
Ciphertext::Ciphertext(CryptoPP::ECP::Point alpha1,
	CryptoPP::ECP::Point beta1)
{
	alpha = alpha1;
	beta = beta1;
}