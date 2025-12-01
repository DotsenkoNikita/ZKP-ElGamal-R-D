#pragma once
#include <eccrypto.h>
#include <oids.h>
#include <osrng.h>
#include <integer.h>
#include <iostream>
#include <vector>
#include "Ciphertext.h"
#include "Member.h"
Ciphertext encrypt(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	int m,
	CryptoPP::ECP::Point publickey);
int distributedDecr(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	Ciphertext todecr, 
	std::vector<Member>& commitet,
	std::chrono::milliseconds& time_of_decr);
 std::string PointToByte(CryptoPP::ECP::Point& point);
 int PointSizeBytes(const CryptoPP::ECP::Point& point);
void outputPoint(CryptoPP::ECP::Point temp);
CryptoPP::ECP::Point calculatePublicKey(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	std::vector<Member> comit);
CryptoPP::ECP::Point getrndpoint(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs);
bool proofOfKnowledge(Member member,
	const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	CryptoPP::ECP::Point a,
	CryptoPP::Integer r,
	CryptoPP::ECP::Point v);
bool proofOfEquality(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	CryptoPP::ECP::Point v,
	CryptoPP::ECP::Point aDLEQ,
	CryptoPP::ECP::Point bDLEQ,
	CryptoPP::Integer rDLEQ,
	CryptoPP::ECP::Point g,
	CryptoPP::ECP::Point g2,
	CryptoPP::ECP::Point w);