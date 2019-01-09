#include <openssl/crypto.h>
#include <stdio.h>

int main()
{
	// 打印openSSL 版本号
	printf( "%s \n ", SSLeay_version(SSLEAY_VERSION));
}

