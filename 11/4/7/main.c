/******************
  示例7 :
         次方运算
*****************/
#include <openssl/bn.h>
#include <string.h>
#include <openssl/bio.h>

int    main()
{
	BIGNUM *a, *exp, *b;
	BN_CTX *ctx;
	BIO   *out;
	char c[20],d[20];
	int ret;

	ctx = BN_CTX_new();
	a = BN_new();
	strcpy(c,"100");
	ret = BN_hex2bn(&a,c); // 16进制字符串 转换 bn

	b = BN_new();
	strcpy(d,"3");
	ret = BN_hex2bn(&b,d);

	exp = BN_new();
	out = BIO_new(BIO_s_file());
	ret = BIO_set_fp(out,stdout,BIO_NOCLOSE);

	ret = BN_exp(exp,a,b,ctx);
	if(ret !=1 ) {
		printf("err.\n");
		return -1;
	}
	BIO_puts(out,"bn : 0x100 exp 0x3 = 0x");
	BN_print(out,exp);
	BIO_puts(out,"\n");
	BN_free(a);
	BN_free(b);
	BN_free(exp);
	BIO_free(out);
	BN_CTX_free(ctx);
	return 0;
}
