#include <iostream>
#include "SecureHashAlgorithm_SHA256.h"


void TestValues() {
	// Correct Hash Results
	std::deque<std::string> hashed_answers =
	{
		"88D4266FD4E6338D13B845FCF289579D209C897823B9217DA3E161936F031589",
		"21B9144A8F751450CBEBFC02B7797AD0E688DBF884EAEAF80044EC1FCB2470A1",
		"9E7574E019A7FB33B516772F9D5E854DDFC60004B36FF3FF9562B07326D2573F",
		"50380F922E8F5CD2391F6D2B799882CEB816345C38FE7D0210F5ABD6B15950E5",
		"92DF77F0BA1468AB5148DB0BC090CEDB88B8EE3FA3CA14FC05E44C426D73F78B",
		"B3EFD5D2273A7F9DDBA983CA879F24A0D6CAF596F56A8C8FAB16FA85B6688BEA",
		"19F8B22AAF4B0DBA87FFCFA65D55D3E2A0870B23C6EE9CCC796C91F77554D9E1",
		"6C1E9F830562DC9CBC1F4DC8C47F2813653E6784F99461BF28118E249FA40286",
		"14C8ADA07D94072087CBCC07723F95DB4421E49E0E39E9950B1F3D0BC8980EB6",
		"67038B139D8CE3896C6553FAF6ADE7903B09EC2A87CAA68365939A7BEA76B68D"
	};
	// Input String
	std::deque<std::string> input_values =
	{
		"abcd",
		"abcdefghijklmnopqrstuvwrxyz",
		"hello world Good Morning, This is a longer messagge than before to add bits to the second chunk",
		"hello world Good Morning, adding some more to this to fi asdasdasasasdfkjasdkl;fj;lkjads;lfjkadslkjadslf;kjagoijro;ijfo;iajdfioajdfiojioajsdiofjoiajiodsgjoaidsjgoijfg;oiajfdg;oijsfd;ogijSDOPIJGSDFIOJGSLIUDFHGoijOIJA;OSDFIJGS;OFDIJGS;OIFDJGP;OIAJRFG;OSZIJDFG;OISJAFDG;OIJSDFG;OIJDFGIJAOIJ",
		"This text that im writingggggg currently is exactly 64 bits long",
		"hello world Good Morning, adding some more to this to f",
		"hello world Good Morning, adding some more to this to fi",
		"hello world Good Morning, adding some more to this to finnnnnn",
		"hello world Good Morning, adding some more to this to finnnnnnnn",
		"hello world Good Morning, adding some more to this to finnnnnnn"
	};
	// Results from SHA256 HASH
	std::deque<std::string> _hashedvalues;

	for (int i = 0; i < input_values.size(); i++) {
		std::shared_ptr<SHA_256> sha256 = std::make_shared<SHA_256>();
		_hashedvalues.push_back(sha256->Digest(input_values[i]));
	}

	for (int i = 0; i < _hashedvalues.size(); i++) {
		for (int j = 0; j < hashed_answers.size(); j++) {
			if (_hashedvalues[i] == hashed_answers[j]) {
				std::cout << "Sucessful Hash" << std::endl;
			}
		}
	}
}

int main()
{
	TestValues();
	std::cin.get();
	return 0;
}