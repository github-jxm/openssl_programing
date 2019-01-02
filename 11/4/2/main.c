/******************
  示例2:
      加法运算
*****************/

#include <openssl/bn.h>
#include <string.h>
#include <openssl/bio.h>

int main()
{
	BIGNUM *a, *b, *add;
	BIO    *out;
	char c[20], d[20];
	int  ret;

	a = BN_new();
	strcpy(c,"32");
	ret = BN_hex2bn(&a,c);  // 16进制字符串 转换 bn

	b = BN_new();
	strcpy(d,"100");
	ret = BN_hex2bn(&b,d);

	out = BIO_new(BIO_s_file());
	ret = BIO_set_fp(out,stdout,BIO_NOCLOSE);

	add = BN_new();
	ret = BN_add(add,a,b);
	if(ret!=1) {
		printf("err.\n");
		return -1;
	}
	BIO_puts(out,"bn 0x32 + 0x100 = 0x");
	BN_print(out,add);
	BIO_puts(out,"\n");

	BN_free(a);
	BN_free(b);
	BN_free(add);
	BIO_free(out);
	return 0;
}
