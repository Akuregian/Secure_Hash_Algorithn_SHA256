#include <iostream>
#include "SecureHashAlgorithm_SHA256.h"

int main()
{
	// These Sets if strings work....
//	std::string input = "abcd"; // 88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589 // WORKS
//	std::string input = "abcdefghijklmnopqrstuvwrxyz"; // 21B9144A8F751450CBEBFC02B7797AD0E688DBF884EAEAF80044EC1FCB2470A1 // WORKS
//	std::string input = "hello world Good Morning, This is a longer messagge than before to add bits to the second chunk"; //9E7574E019A7FB33B516772F9D5E854DDFC60004B36FF3FF9562B07326D2573F // DOESNT WORK
//	std::string input = "hello world Good Morning, adding some more to this to fi asdasdasasasdfkjasdkl;fj;lkjads;lfjkadslkjadslf;kjagoijro;ijfo;iajdfioajdfiojioajsdiofjoiajiodsgjoaidsjgoijfg;oiajfdg;oijsfd;ogijSDOPIJGSDFIOJGSLIUDFHGoijOIJA;OSDFIJGS;OFDIJGS;OIFDJGP;OIAJRFG;OSZIJDFG;OISJAFDG;OIJSDFG;OIJDFGIJAOIJ"; 
//	std::string input = "This text that im writingggggg currently is exactly 64 bits long"; // 50380F922E8F5CD2391F6D2B799882CEB816345C38FE7D0210F5ABD6B15950E5// WORKS [64]
//	std::string input = "hello world Good Morning, adding some more to this to f"; // 19f8b22aaf4b0dba87ffcfa65d55d3e2a0870b23c6ee9ccc796c91f77554d9e1 // WORKS [55]
//	std::string input = "hello world Good Morning, adding some more to this to fi"; // 19f8b22aaf4b0dba87ffcfa65d55d3e2a0870b23c6ee9ccc796c91f77554d9e1 //  WORKS [56]


//	std::string input = "hello world Good Morning, adding some more to this to finnnnnn"; // 6C1E9F830562DC9CBC1F4DC8C47F2813653E6784F99461BF28118E249FA40286 // DOESNT WORK [62]
//	std::string input = "hello world Good Morning, adding some more to this to finnnnnnnn"; // 14C8ADA07D94072087CBCC07723F95DB4421E49E0E39E9950B1F3D0BC8980EB6 // DOESNT WORK [64]


	// These Sets if strings dont work.... Anything between 56 - 63 byte inputs dont work
	// At 63 bits we dont get an Exception error, but we get a wong hashed value
	std::string input = "hello world Good Morning, adding some more to this to finnnnnnn"; // 67038B139D8CE3896C6553FAF6ADE7903B09EC2A87CAA68365939A7BEA76B68D // DOESNT WORK [63]

	SHA_256 sha256(input);
	std::cin.get();
	return 0;
}