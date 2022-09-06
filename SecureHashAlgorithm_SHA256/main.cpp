#include <iostream>
#include "SecureHashAlgorithm_SHA256.h"

int main()
{
	std::shared_ptr<SHA_256> sha256 = std::make_shared<SHA_256>();
	std::string hash = sha256->Digest("This is a test string to be converted");
	std::cout << "Hash: " << hash << std::endl;

	std::cin.get();
	return 0;
}