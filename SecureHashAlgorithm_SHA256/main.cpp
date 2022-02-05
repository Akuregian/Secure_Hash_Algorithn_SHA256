#include <iostream>
#include "SecureHashAlgorithm_SHA256.h"

int main()
{
//	std::string input = "abc";
//  std::string input = "hello world";
	std::string input = "hello world Good Morning this is a shorter test versionp";

//	std::string input = "This is a test to see if the chunks are proerly working. The Sad lamp talked too the cat and walked down the road to white castle and gabbed like two burgers";
//	std::string input = "This is a test to see if the chunks are proerly working, "
//						"The Sad lamp talked too the cat and walked down the roaAd to white castle and gabbed like two burgers "
//						"tarkov is litty as lit can be boy, now go get me some french fries and toast mofoucka ayyyyyyy lit lit lit lit litAS U BEING MY FRIEND I WILL "
//						"WARN ABOUT MY HUMAN BEING IN THE TELESCOPE. BUT WHAT I REALLY NEED TO TALK TO U ABOUT IS THE FLYING SAUSAGE INCIDENT I DON’T THINK I TALKED TO U ABOUT THIS BUT U REALLY"
//						"SHOULD KNOW THAT I AM SECRETLY A FLYING SAUSAGE NOT ONLY AM I A FLYING SAUSAGE BUT I AM THE FLYING SAUSAGE THAT TOOK THE WALKING CHEESEBURGERS PICKLES. I NEED UR HELP TO"
//						"ESCAPE THE POLICE MEN BECAUSE THE ONLY REASON I STOLE HIS PICKLES WAS BECAUSE I WAS GOING THROUGH THIS THING WHERE ALL I WANTED TO DO WAS EAT PICKLES AND MY MOM WOULDN’T"
//						"BUY ANY. I HAD NO MONEY SO I DIDN’T KNOW WHAT ELSE TO DO. I WALKED OVER TO THE CHEESEURGER AND TOOK HIS PICKLES. APPARENTLY THATS AGAINST THE LAW BUT I STILL DID IT."
//						"I ALREADY ATE THE PICKLES SO I CAN’T RETURN THEM. I ASKED BOBBYJO TO PUT ME IN A BOX AND SEND ME TO NORTH CAROLINA SO I AM NOW IN NEW ENGLAND I NEED U TO GO ON A SECRET"
//						"MISSION AND GO BUY ME A PRIVATE JET U SEE I CAN NOT FLY ANYMORE SO I NEED SOMEONE TO SEND ME A PRIVATE JET NOT A AIRPLANE I ALREADY HAVE 2,345 AIRPLANES PLEASE DO NOT SEND"
//						"ME AN AIRPLANE.PLEASE AND THANK YOU I HOPE U CAN COMPLETE MY MISSION. ";
	SHA_256 sha256(input);
	std::cin.get();
	return 0;
}