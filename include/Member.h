#pragma once
#include <eccrypto.h>
#include <Integer.h>
#include <osrng.h>
#include <chrono>
#include "Ciphertext.h"
class Ciphertext;
extern CryptoPP::AutoSeededRandomPool seed;
class Member
{
private:
	CryptoPP::Integer partOfPrivKey;
	CryptoPP::ECP::Point partOfPublKey;
	CryptoPP::ECP::Point aDL;
	CryptoPP::Integer rDL;
	CryptoPP::ECP::Point aDLEQ;
	CryptoPP::ECP::Point bDLEQ;
	CryptoPP::Integer rDLEQ;
	std::chrono::milliseconds time_of_key_generation;
	std::chrono::milliseconds time_of_Betai_generation;
	int role;
public:
	Member(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
		int role1);
	CryptoPP::Integer getPrivK();
	CryptoPP::ECP::Point getPubK();
	CryptoPP::ECP::Point geta();
	CryptoPP::Integer getr();
	CryptoPP::ECP::Point getaDLEQ();
	CryptoPP::ECP::Point getBDLEQ();
	CryptoPP::Integer getrDLEQ();
	int getrole();
	CryptoPP::ECP::Point partbeta(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
		Ciphertext todencr);
	void generateSchnorrProof(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs);
	void generateDLEQProof(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
		CryptoPP::ECP::Point g,
		CryptoPP::ECP::Point g2,
		CryptoPP::ECP::Point w);
	std::chrono::milliseconds getkeytime();
	std::chrono::milliseconds getbetatime();
};