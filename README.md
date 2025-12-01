This repository demonstrates an implementation of a distributed encryption protocol based on the ElGamal scheme,
as described in Efficient Cryptographic Protocol Design Based on [Distributed ElGamal Encryption, Felix Brandt, 2005](https://pub.dss.in.tum.de/brandt-research/millionaire.pdf)


The protocol was implemented as part of a study on the computational and communication complexity of 
an MPC protocol, using different elliptic curves (secp256k1, secp384r1, secp521r1) and committee parameters.

Note: Since Felix Brandt's original protocol works with abstract number groups, this implementation
was adapted to work with elliptic curve point groups. Consequently, some formulas differ slightly from those presented in the paper.
