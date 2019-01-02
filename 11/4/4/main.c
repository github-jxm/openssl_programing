/******************
   示例4 :
         乘法运算
*****************/

#include <openssl/bn.h>
#include <string.h>
#include <openssl/bio.h>

int    main()
{
	BIGNUM *a, *b, *mul;
	BN_CTX *ctx;
	BIO  *out;
	char c[20],d[20];
	int  ret;

	ctx = BN_CTX_new();

	a = BN_new();
	strcpy(c,"32");
	ret = BN_hex2bn(&a,c);  // 16进制字符串 转换 bn

	b = BN_new();
	strcpy(d,"100");
	ret = BN_hex2bn(&b,d);

	out = BIO_new(BIO_s_file());
	ret = BIO_set_fp(out,stdout,BIO_NOCLOSE);

	mul = BN_new();
	ret = BN_mul(mul,a,b,ctx);
	if(ret != 1) {
		printf("err.\n");
		return -1;
	}
	BIO_puts(out,"bn : 0x32 * 0x100 = 0x");
	BN_print(out,mul);
	BIO_puts(out,"\n");

	BN_free(a);
	BN_free(b);
	BN_free(mul);
	BIO_free(out);
	BN_CTX_free(ctx);
	return 0;
}
