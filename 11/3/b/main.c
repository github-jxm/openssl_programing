#include <openssl/bio.h>
#include <openssl/bn.h>

int main()
{
    BIGNUM *ret1,*ret2;
 
    ret1=BN_new();
    ret1=BN_bin2bn("242424ab",8, ret1);
    ret2=BN_bin2bn("242424ab",8, NULL);
	
    // printf
    BIO *bio_out;
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BN_print(bio_out, ret1); // 16进制打印
    BIO_printf(bio_out, "\n");
    BN_print(bio_out, ret2);
    BIO_printf(bio_out, "\n");
    BIO_free(bio_out);

    // free
    BN_free(ret1);
    BN_free(ret2);
    return 0;
}
