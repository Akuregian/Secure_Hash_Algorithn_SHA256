#include <iostream>
#include "SecureHashAlgorithm_SHA256.h"


bool flip(bool val) {
	if (val) { return true; }
	return false;
}

int main()
{
//	std::string input = "abcd"; // 88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589 // WORKS
//	std::string input = "abcdefghijklmnopqrstuvwrxyz"; // 21B9144A8F751450CBEBFC02B7797AD0E688DBF884EAEAF80044EC1FCB2470A1 // WORKS
//	std::string input = "hello world Good Morning, adding some more to this to fi"; // 19f8b22aaf4b0dba87ffcfa65d55d3e2a0870b23c6ee9ccc796c91f77554d9e1 // DOESNT WORK
	//std::string input = "hello world Good Morning, This is a longer messagge than before to add bits to the second chunk"; //9E7574E019A7FB33B516772F9D5E854DDFC60004B36FF3FF9562B07326D2573F // DOESNT WORK

	//std::string input = "ck";
	bool flipit = false;
	std::string input;
	if(flip(flipit)) { input = "abcdefghijklmnopqrstuvwrxyz"; }
	else { input = "hello world Good Morning, adding some more to this to fi asdasdasasasdfkjasdkl;fj;lkjads;lfjkadslkjadslf;kjagoijro;ijfo;iajdfioajdfiojioajsdiofjoiajiodsgjoaidsjgoijfg;oiajfdg;oijsfd;ogijSDOPIJGSDFIOJGSLIUDFHGoijOIJA;OSDFIJGS;OFDIJGS;OIFDJGP;OIAJRFG;OSZIJDFG;OISJAFDG;OIJSDFG;OIJDFGIJAOIJ"; }

	SHA_256 sha256(input);
	std::cin.get();
	return 0;
}