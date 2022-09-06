#include <iostream>
#include "SecureHashAlgorithm_SHA256.h"

int main()
{
	// Initialize the SHA_256 Class
	std::shared_ptr<SHA_256> sha256 = std::make_shared<SHA_256>();

	// Call the Digest function with the string, and store the resulted hash
	std::string hash0 = sha256->Digest("This is a test string to be converted");
	std::string hash1 = sha256->Digest("This is a test string to be converted that a little longer");
	std::string hash2 = sha256->Digest("This is a test string to be converted thats even longer than the previous text string thats been converted");

	// Print the results
	std::cout << "Hash0: " << hash0 << std::endl;
	std::cout << "Hash1: " << hash1 << std::endl;
	std::cout << "Hash2: " << hash2 << std::endl;

	std::cin.get();
	return 0;
}