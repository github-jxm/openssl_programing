#include <openssl/bio.h>
#include <openssl/bn.h>

int main()
{
	BIGNUM *ret = NULL;
	char bin[50]={'s'}, *buf = NULL;
	int  len;

	ret = BN_bin2bn("242424ab",8, NULL);
	len = BN_bn2bin(ret,bin);

	len = BN_num_bytes(ret);
	buf = (char *) malloc(len + 1);
	len = BN_bn2bin(ret,buf);
	
	// new bio
	BIO *bio_out;
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	// bio printf
	BN_print(bio_out, ret); // 16进制打印
	BIO_printf(bio_out, "\n");
	BIO_printf(bio_out,"%s\n", buf);

	BIO_free(bio_out);
	free (buf);
	BN_free(ret);
	return 0;
}
