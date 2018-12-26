#include <stdio.h>
#include <string.h>
#include <openssl/md2.h>
#include <openssl/md4.h> 
#include <openssl/md5.h> 
#include <openssl/sha.h>

int main() 
{
	unsigned char in[]="3dsferyewyrtetegvbzVEgarhaggavxcv"; 
	unsigned char out[20];
	size_t n;
	int i;
	n=strlen((const char*)in);

	//#ifdef OPENSSL_NO_MDC2 
	//printf("默认 openssl 安装配置无 MDC2\n"); 
	//#else
	//MDC2(in,n,out);
	//printf("MDC2 digest result :\n"); 
	//for(i=0;i<16;i++)
	//	printf("%x ",out[i]);
	//#endif

	RIPEMD160(in,n,out); 
	printf("RIPEMD160 digest result :\n");
	for(i=0;i<20;i++) 
		printf("%x ",out[i]);

	//MD2(in,n,out);
	//printf("MD2 digest result :\n"); 
	//for(i=0;i<16;i++)
	//	printf("%x ",out[i]);

	MD4(in,n,out);
	printf("\n\nMD4 digest result :\n"); 
	for(i=0;i<16;i++)
		printf("%x ",out[i]);
	MD5(in,n,out);
	printf("\n\nMD5 digest result :\n"); 
	for(i=0;i<16;i++)
		printf("%x ",out[i]);

	//SHA(in,n,out);
	//printf("\n\nSHA digest result :\n"); 
	//for(i=0;i<20;i++)
	//	printf("%x ",out[i]);
	SHA1(in,n,out);
	printf("\n\nSHA1 digest result :\n"); 
	for(i=0;i<20;i++)
		printf("%x ",out[i]);

	SHA256(in,n,out); 
	printf("\n\nSHA256 digest result :\n"); 
	for(i=0;i<32;i++)
		printf("%x ",out[i]);

	SHA512(in,n,out); printf("\n\nSHA512 digest result :\n"); 
	for(i=0;i<64;i++)
		printf("%x ",out[i]); printf("\n");
	return 0; 
}

