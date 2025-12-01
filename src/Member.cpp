#include "Member.h"
#include "Ciphertext.h"
#include <eccrypto.h>
#include <Integer.h>
#include <osrng.h>
#include <chrono>
#include "utilits.h"
CryptoPP::AutoSeededRandomPool seed;

//Generates the member's key pair during constructor
//Role 2 uses to simulates a malicious member who doesn't know private key
Member::Member(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs, 
	int role1)
{
	const CryptoPP::ECP& curve = parametrs.GetCurve();
	role = role1;
	CryptoPP::ECP::Point G = parametrs.GetSubgroupGenerator();
	if (role == 2)
	{
		auto start = std::chrono::high_resolution_clock::now();
		partOfPrivKey.Randomize(seed, 1, parametrs.GetGroupOrder());
		partOfPublKey = getrndpoint(parametrs);
		auto end = std::chrono::high_resolution_clock::now();
		time_of_key_generation = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	}
	else 
	{
		auto start = std::chrono::high_resolution_clock::now();
		partOfPrivKey.Randomize(seed, 1, parametrs.GetGroupOrder());
		partOfPublKey = curve.ScalarMultiply(G, partOfPrivKey);
		auto end = std::chrono::high_resolution_clock::now();
		time_of_key_generation = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	}

}

//Getter methods
CryptoPP::Integer Member::getPrivK() { return partOfPrivKey; }
CryptoPP::ECP::Point Member::getPubK() { return partOfPublKey; }
int Member::getrole() { return role; }
CryptoPP::ECP::Point Member::geta() { return aDL; };
CryptoPP::Integer Member::getr() { return rDL; };
std::chrono::milliseconds Member::getkeytime() { return time_of_key_generation; }
std::chrono::milliseconds Member::getbetatime() { return time_of_Betai_generation; }
CryptoPP::ECP::Point Member::getaDLEQ() { return aDLEQ; }
CryptoPP::ECP::Point Member::getBDLEQ() { return bDLEQ; }
CryptoPP::Integer Member::getrDLEQ() { return rDLEQ; }

//Method uses to generate partial decryption(Beta_i)
CryptoPP::ECP::Point Member::partbeta(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	Ciphertext todencr)
{
	auto start = std::chrono::high_resolution_clock::now();
	const CryptoPP::ECP& curve = parametrs.GetCurve();
	CryptoPP::ECP::Point betaI = curve.ScalarMultiply(todencr.getbeta(), partOfPrivKey);
	auto end = std::chrono::high_resolution_clock::now();
	time_of_Betai_generation = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	return betaI;
}

void Member::generateDLEQProof(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	CryptoPP::ECP::Point g, 
	CryptoPP::ECP::Point g2, 
	CryptoPP::ECP::Point w)
{
	const CryptoPP::ECP& curve = parametrs.GetCurve();
	CryptoPP::Integer z;
	z.Randomize(seed, 1, parametrs.GetGroupOrder()-1);
	aDLEQ = curve.ScalarMultiply(g, z);
	bDLEQ = curve.ScalarMultiply(g2, z);
	CryptoPP::ECP::Point v = partOfPublKey;
	CryptoPP::SHA256 hash;
	CryptoPP::SecByteBlock digest(hash.DigestSize());
	std::string toHash;
	toHash += PointToByte(g);
	toHash += PointToByte(g2);
	toHash += PointToByte(v);
	toHash += PointToByte(w);
	toHash += PointToByte(aDLEQ);
	toHash += PointToByte(bDLEQ);
	hash.CalculateDigest(digest, (CryptoPP::byte*)toHash.data(), toHash.size());
	CryptoPP::Integer c(digest, digest.size());
	c = c % parametrs.GetGroupOrder();
	rDLEQ = (z + c * partOfPrivKey) % parametrs.GetGroupOrder();
}

void Member::generateSchnorrProof(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs)
{
	const CryptoPP::ECP& curve = parametrs.GetCurve();
	CryptoPP::Integer z;
	CryptoPP::ECP::Point g = parametrs.GetSubgroupGenerator();
	z.Randomize(seed, 1, parametrs.GetGroupOrder() - 1);
	aDL = curve.ScalarMultiply(g, z);
	CryptoPP::SHA256 hash;
	CryptoPP::SecByteBlock digest(hash.DigestSize());
	std::string toHash;
	toHash += PointToByte(g);
	toHash += PointToByte(partOfPublKey);
	toHash += PointToByte(aDL);
	hash.CalculateDigest(digest, (CryptoPP::byte*)toHash.data(), toHash.size());
	CryptoPP::Integer c(digest, digest.size());
	c = c % parametrs.GetGroupOrder();
	rDL = (z + c * partOfPrivKey) % parametrs.GetGroupOrder();
}