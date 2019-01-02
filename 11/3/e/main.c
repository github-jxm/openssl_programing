#include <openssl/bio.h>
#include <openssl/bn.h>
int main()
{
	BIGNUM *ret1 = NULL, * ret2 = BN_new();
	char   *p = NULL;
	int    len = 0;
	
	// new bio
	BIO *bio_out;
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);


	ret1 = BN_bin2bn("242424ab",8, NULL);  /* 二进制 转 bn*/
	p = BN_bn2hex(ret1);       /* bn 转 16进制字符串*/
	//printf("\n0x%s\n",p);
	BIO_printf(bio_out,"0x%s\n", p);

	/*hex to bn*/
        //BN_dec2bn(&ret2,"254");  /* 10进制字符串 转换 bn*/
        BN_hex2bn(&ret2,"FE");   /* 16进制字符串 转换 bn*/  
	BN_print(bio_out, ret2); // 16进制打印

	BIO_printf(bio_out,"\n");

	BN_free(ret1);
	BN_free(ret2);
	OPENSSL_free(p);  // free
	//getchar();
	return 0;
}
