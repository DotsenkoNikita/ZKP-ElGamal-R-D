#include <eccrypto.h>
#include <oids.h>
#include <osrng.h>
#include <integer.h>
#include <iostream>
#include <nbtheory.h>
#include <vector>
#include <chrono>
#include "Ciphertext.h"
#include "Member.h"
#include "utilits.h"
using namespace CryptoPP;
using namespace std;
int main()
{
	//Message to encrypt
	int message = 1234;
	ECP::Point publicKey;
	publicKey.identity = true;

	//------------------------------------------------------------------------------------------
	// Initializing the parameters of the elliptic curve
	//------------------------------------------------------------------------------------------
	OID curveOID = ASN1::secp256k1();
	DL_GroupParameters_EC<ECP> parametrs;
	parametrs.Initialize(curveOID);
	const ECP& curve = parametrs.GetCurve();
	//------------------------------------------------------------------------------------------
	// Request the number of honest/malicious committee members
	//------------------------------------------------------------------------------------------
	cout << "Enter the number of honest committee members: ";
	int honest;
	cin >> honest;
	cout << "malicious? (1 - yep, 0 - nope): ";
	int mal;
	cin >> mal;
	system("cls");
	cout << "============== Protocol parameters ==============" << endl;
	cout << "Total number of honest committee members: " << honest << endl;
	cout << "Total number of malicious committee members: " << mal << endl;
	cout << "Elliptic curve used: secp256k1" <<endl;
	cout << "Message to encrypt: " << message << endl;
	cout << "============== Performance metrics ==============" << endl;
	cout << "----------- Key pair generation time ------------" << endl;
	
	//------------------------------------------------------------------------------------------
	// Fill the committee by generating key pairs
	//------------------------------------------------------------------------------------------
	vector<Member> committee;
	for (int i = 0;i < honest;i++)
	{
		int hon = (mal == 1 && i == honest / 2) ? 2 : 1;
		Member member(parametrs, hon);
		//Prover generates a,r
		member.generateSchnorrProof(parametrs);
		//requesting proof of knowledge of the discrete logarithm
		if (proofOfKnowledge(member, parametrs,
			member.geta(),
			member.getr(),
			member.getPubK()) == 1) 
		{
			publicKey = curve.Add(publicKey, member.getPubK());
			committee.push_back(member);
			cout << "Member " << i+1 << ": " 
				<< member.getkeytime().count() << " ms"<<endl;
		}
		else
		{
			cout << "Comittee member " << i << " Failed verification" << endl;
		}
	}
	//Encrypt message 
	Ciphertext c = encrypt(parametrs, message, publicKey); 
	std::chrono::milliseconds time_of_decr;
	//Decrypt message
	int decrypted = distributedDecr(parametrs, c, committee, time_of_decr);
	//------------------------------------------------------------------------------------------
	//Output metrics
	//------------------------------------------------------------------------------------------

	cout << "\n------- Partial decryption generation time ------" << endl;
	for (int i = 0;i < committee.size();i++)
	{
		cout << "Member " << i + 1 << ": "
			<<committee[i].getbetatime().count() << " ms" << endl;
	}
	cout << "-------------" << endl;
	cout << "Total decryption time : "<<time_of_decr.count() << " ms" << endl;
	cout << "\n----------- Communication cost (bytes) ----------" << endl;
	int roud1 =0;
	int round2 = 010;
	//Key generation
	roud1 += (PointSizeBytes(committee[1].getPubK()));
	roud1 += (PointSizeBytes(committee[1].geta()));
	roud1 += committee[1].getr().ByteCount();
	//decription
	round2 += (PointSizeBytes(committee[1].partbeta(parametrs, c)));
	round2 += (PointSizeBytes(committee[1].getaDLEQ()));
	round2 += (PointSizeBytes(committee[1].getBDLEQ()));
	round2 += committee[1].getrDLEQ().ByteCount();
	cout << "Key pair generation (one member): " << " "
		<< roud1 << " bytes" << endl;
	cout << "Partial decryption generation (one member): " << " "
		<< round2 << " bytes" << endl;
	cout << "-------------" << endl;
	cout << "Total Communication cost (for all members): " << (roud1 + round2) * committee.size()<<" bytes" << endl;

}
	
	