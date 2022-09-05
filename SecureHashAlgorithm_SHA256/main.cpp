#include <iostream>
#include "SecureHashAlgorithm_SHA256.h"


int main()
{
//	std::string input = "i"; // DE7D1B721A1E0632B7CF04EDF5032C8ECFFA9F9A08492152B926F1A5A7E765D7 // WORKS
//	std::string input = "abc"; // BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD // WORKS
//	std::string input = "abcd"; // 88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589 // WORKS
	//std::string input = "abcdefghijklmnopqrstuvwrxyz"; // 21B9144A8F751450CBEBFC02B7797AD0E688DBF884EAEAF80044EC1FCB2470A1 // WORKS
//	std::string input = "hello world"; // B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9  // WORKS
	std::string input = "hello world Good Morning, adding some more to this to fi"; // 19f8b22aaf4b0dba87ffcfa65d55d3e2a0870b23c6ee9ccc796c91f77554d9e1 // DOESNT WORK

	SHA_256 sha256(input);
	std::cin.get();
	return 0;
}