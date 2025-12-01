#include "utilits.h"
#include "Ciphertext.h"

Ciphertext encrypt(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	int m, 
	CryptoPP::ECP::Point publickey)
{
	const CryptoPP::ECP& curve = parametrs.GetCurve();
	CryptoPP::ECP::Point G = parametrs.GetSubgroupGenerator();
	CryptoPP::Integer r;
	CryptoPP::ECP::Point m1 = curve.ScalarMultiply(G, m);
	r.Randomize(seed, 1, parametrs.GetGroupOrder() - 1);
	CryptoPP::ECP::Point alpha = curve.Add(m1, curve.ScalarMultiply(publickey, r));
	CryptoPP::ECP::Point beta = curve.ScalarMultiply(G, r);
	Ciphertext temp(alpha, beta);
	return temp;
}


int distributedDecr(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	Ciphertext todecr, 
	std::vector<Member>& commitet,
	std::chrono::milliseconds& time_of_decr)
{
	auto start = std::chrono::high_resolution_clock::now();

	const CryptoPP::ECP& curve = parametrs.GetCurve();
	CryptoPP::ECP::Point g = parametrs.GetSubgroupGenerator();
	CryptoPP::ECP::Point beta;
	beta.identity = true;
	for (int i = 0;i < commitet.size(); i++)
	{
	CryptoPP::ECP::Point partialBeta = commitet[i].partbeta(parametrs, todecr);
		
		if (commitet[i].getrole() == 1|| commitet[i].getrole() == 2)
		{
		beta = curve.Add(beta, partialBeta);
		}
		else
		{
			partialBeta = getrndpoint(parametrs);
			beta = curve.Add(beta, partialBeta);
		}
		CryptoPP::ECP::Point w = partialBeta;
		commitet[i].generateDLEQProof(parametrs, g, todecr.getbeta(), partialBeta);
		if (proofOfEquality(parametrs, 
			commitet[i].getPubK(),
			commitet[i].getaDLEQ(), 
			commitet[i].getBDLEQ(), 
			commitet[i].getrDLEQ(),
			g,
			todecr.getbeta(), 
			partialBeta) != 1)

		{
			return -1;
		}
	}
	CryptoPP::ECP::Point result = curve.Add(todecr.getalpha(), curve.Inverse(beta));
	auto end = std::chrono::high_resolution_clock::now();
	time_of_decr = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	for (CryptoPP::Integer i = 0; i < 100000; i++)
	{
		if (curve.ScalarMultiply(g, i) == result)
		{
			return i.ConvertToLong();
		}
	}
	return -1;
}

// Converting a point to bytes for further hashing
std::string PointToByte(CryptoPP::ECP::Point& point)
{
	std::string result;
	int coordSize = point.x.ByteCount();
	result.push_back(0x04); 
	CryptoPP::SecByteBlock xBytes(coordSize);
	point.x.Encode(xBytes, xBytes.size());
	result.append((char*)xBytes.data(), xBytes.size());
	CryptoPP::SecByteBlock yBytes(coordSize);
	point.y.Encode(yBytes, yBytes.size());
	result.append((char*)yBytes.data(), yBytes.size());

	return result;
}

//Function returns size of point 
int PointSizeBytes(const CryptoPP::ECP::Point& point)
{
	int xSize = point.x.ByteCount();
	int ySize = point.y.ByteCount();
	return 1 + xSize + ySize;
}

void outputPoint(CryptoPP::ECP::Point temp)
{
	std::cout << "(" << temp.x << "," << temp.y << ")";
}


CryptoPP::ECP::Point calculatePublicKey(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	std::vector<Member> comit)
{
	const CryptoPP::ECP& curve = parametrs.GetCurve();
	CryptoPP::ECP::Point beta;
	beta.identity = true;
	for (int i = 0;i < comit.size();i++)
	{
		beta = curve.Add(beta, comit[i].getPubK());
	}
	return beta;
}

CryptoPP::ECP::Point getrndpoint(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs)
{
	const CryptoPP::ECP& curve = parametrs.GetCurve();
	CryptoPP::Integer n = parametrs.GetGroupOrder();
	CryptoPP::Integer rndK;
	rndK.Randomize(seed, 1, n - 1);
	return curve.ScalarMultiply(parametrs.GetSubgroupGenerator(), rndK);
}

bool proofOfKnowledge(Member member, 
	const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs, 
	CryptoPP::ECP::Point a,
	CryptoPP::Integer r,
	CryptoPP::ECP::Point v)
{
	CryptoPP::ECP::Point publickKey = member.getPubK();
	const CryptoPP::ECP& curve = parametrs.GetCurve();
	CryptoPP::ECP::Point g = parametrs.GetSubgroupGenerator();
	CryptoPP::SHA256 hash;
	CryptoPP::SecByteBlock digest(hash.DigestSize());
	std::string toHash;
	toHash += PointToByte(g);
	toHash += PointToByte(publickKey);
	toHash += PointToByte(a);
	hash.CalculateDigest(digest, (CryptoPP::byte*)toHash.data(), toHash.size());
	CryptoPP::Integer c(digest, digest.size());
	c = c % parametrs.GetGroupOrder();
	return curve.ScalarMultiply(g, r) == curve.Add(a, curve.ScalarMultiply(v, c)) ? true : false;

}

bool proofOfEquality(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& parametrs,
	CryptoPP::ECP::Point v,
	CryptoPP::ECP::Point aDLEQ,
	CryptoPP::ECP::Point bDLEQ,
	CryptoPP::Integer rDLEQ,
	CryptoPP::ECP::Point g,
	CryptoPP::ECP::Point g2,
	CryptoPP::ECP::Point w)
{
	const CryptoPP::ECP& curve = parametrs.GetCurve();
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
	if (curve.ScalarMultiply(g, rDLEQ) == curve.Add(aDLEQ, curve.ScalarMultiply(v, c)) &&
		curve.ScalarMultiply(g2, rDLEQ) == curve.Add(bDLEQ, curve.ScalarMultiply(w, c))) {return 1;}
	else { return 0; }

}