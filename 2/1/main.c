#include <openssl/crypto.h>
#include <stdio.h>

int main()
{
	printf( "%s \n ", SSLeay_version(SSLEAY_VERSION));
}

