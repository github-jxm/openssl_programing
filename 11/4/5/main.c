/******************
  示例5:
         除法运算
*****************/

#include <openssl/bn.h>
#include <string.h>
#include <openssl/bio.h>

int    main()
{
	BIGNUM *a, *b, *div, *rem;
	BN_CTX *ctx;
	BIO  *out;
	char c[20], d[20];
	int  ret;

	ctx = BN_CTX_new();
	a = BN_new();
	strcpy(c,"100");
	ret = BN_hex2bn(&a,c); // 16进制字符串 转换 bn

	b = BN_new();
	strcpy(d,"17");
	ret = BN_hex2bn(&b,d);

	out = BIO_new(BIO_s_file());
	ret = BIO_set_fp(out,stdout,BIO_NOCLOSE);

	div = BN_new();
	rem = BN_new();
	ret = BN_div(div,rem,a,b,ctx);
	if(ret != 1){
		printf("err.\n");
		return -1;
	}
	BIO_puts(out,"bn : 0x100 / 0x17 = 0x");
	BN_print(out,div);
	BIO_puts(out,"\n");
	BIO_puts(out,"bn : 0x100 % 0x17 = 0x");
	BN_print(out,rem);
	BIO_puts(out,"\n");

	BN_free(a);
	BN_free(b);
	BN_free(div);
	BN_free(rem);
	BIO_free(out);
	BN_CTX_free(ctx);
	return 0;
}
