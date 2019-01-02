/******************
  示例6:
         平方运算
*****************/

#include <openssl/bn.h>
#include <string.h>
#include <openssl/bio.h>

int main()
{
	BIGNUM *a, *sqr;
	BN_CTX *ctx;
	BIO    *out;
	char c[20];
	int  ret;

	ctx = BN_CTX_new();
	a = BN_new();
	strcpy(c,"100");
	ret = BN_hex2bn(&a,c); // 16进制字符串 转换 bn

	sqr = BN_new();
	out = BIO_new(BIO_s_file());
	ret = BIO_set_fp(out,stdout,BIO_NOCLOSE);

	ret = BN_sqr(sqr,a,ctx);
	if(ret != 1) {
		printf("err.\n");
		return -1;
	}
	BIO_puts(out,"bn : 0x100 sqr = 0x");
	BN_print(out,sqr);
	BIO_puts(out,"\n");

	BN_free(a);
	BN_free(sqr);
	BIO_free(out);
	BN_CTX_free(ctx);
	return 0;
}           
