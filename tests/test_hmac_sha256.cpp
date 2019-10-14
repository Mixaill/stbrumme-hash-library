#include "hmac.h"
#include "sha256.h"
#include <iostream>

int test_1()
{
	auto sha2hmac = HMAC<SHA256>("TEST");
	sha2hmac.Append("TEST");
	return sha2hmac.GetHashString() == "e6413e5ce7c4ef6a24f61b06687d199d8d94c59dc545e705226a2936a06cfcc3" ? 0 : 1;
}

int test_2()
{
	auto sha2hmac = HMAC<SHA256>("TEST");
	sha2hmac.Append("T");
	sha2hmac.Append("E");
	sha2hmac.Append("S");
	sha2hmac.Append("T");
	return sha2hmac.GetHashString() == "e6413e5ce7c4ef6a24f61b06687d199d8d94c59dc545e705226a2936a06cfcc3" ? 0 : 1;
}

int test_3()
{
	auto sha2hmac = HMAC<SHA256>("TEST");
	sha2hmac.Append("TEST");
	if(sha2hmac.GetHashString() != "e6413e5ce7c4ef6a24f61b06687d199d8d94c59dc545e705226a2936a06cfcc3")
	{
		return 1;
	}

	if(sha2hmac.GetHashString() != "e6413e5ce7c4ef6a24f61b06687d199d8d94c59dc545e705226a2936a06cfcc3")
	{
		return 2;
	}

	return 0;
}


int main(int argc, char* argv[])
{
	if(argc<2)
	{
		return -1;
	}

	switch(std::atoi(argv[1]))
	{
	case 1:
		return test_1();
	case 2:
		return test_2();
	case 3:
		return test_3();
	default:
		return -2;
	}
}
