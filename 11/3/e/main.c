/************************************************************************
 *      转换
 
        int     BN_bn2bin(const BIGNUM *a, unsigned char *to);
        int     BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
        BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);

        int     BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
        BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);

        char *BN_bn2hex(const BIGNUM *a);
        char *BN_bn2dec(const BIGNUM *a);
        int   BN_hex2bn(BIGNUM **a, const char *str);
        int   BN_dec2bn(BIGNUM **a, const char *str);

        int BN_print(BIO *fp, const BIGNUM *a);
        int BN_print_fp(FILE *fp, const BIGNUM *a);

        int     BN_bn2mpi(const BIGNUM *a, unsigned char *to);
        BIGNUM *BN_mpi2bn(unsigned char *s, int len, BIGNUM *ret);

************************************************************************/

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



	BIO_printf(bio_out,"\n---- BN_bin2bn  ----\n");
       
	ret1 = BN_bin2bn("242424ab",8, NULL);  /* 二进制 转 bn*/
	p = BN_bn2hex(ret1);                  /* bn 转 16进制字符串*/
	//printf("\n0x%s\n",p);
	BIO_printf(bio_out,"0x%s\n", p);
	OPENSSL_free(p);  // free

	BIO_printf(bio_out,"\n---- BN_hex2bn / BN_bn2hex ----\n");
        BIGNUM  * a = BN_new();
        BN_hex2bn(&a, "ABFE123");   // 将十六进制字符串转换为大数
	BN_print(bio_out, a);        // 16进制打印
	p = BN_bn2hex(a);         /* bn 转 16进制字符串*/
	BIO_printf(bio_out,"\n0x%s\n", p);
	OPENSSL_free(p);  // free
	BN_free(a);

	/*hex to bn*/
	BIO_printf(bio_out,"\n---- BN_dec2bn ----\n");
        BN_dec2bn(&ret2,"254");  /* 10进制字符串 转换 bn*/
	BN_print(bio_out, ret2); // 16进制打印
	BIO_printf(bio_out,"\n");

	BN_free(ret1);
	BN_free(ret2);
	//getchar();
	return 0;
}
