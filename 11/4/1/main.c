#include <openssl/bn.h>
#include <openssl/bio.h>
#include <string.h>

int main()
{
	BIGNUM *bn;
	BIO   *b;
	char  a[20];
	int   ret;

	bn = BN_new();
	strcpy(a,"32");

        //ret = BN_dec2bn(&bn,a);  /* 10进制字符串 转换 bn*/
	ret = BN_hex2bn(&bn,a); // 16进制字符串 转换 bn

	b = BIO_new(BIO_s_file());
	ret = BIO_set_fp(b,stdout,BIO_NOCLOSE);

	BN_print(b,bn);
	BIO_write(b,"\naaa",4);
	BIO_printf(b,"\nbbb\n");

	BN_free(bn);
	return 0;
}

