#include <openssl/bio.h>
#include <openssl/bn.h>

int main() 
{
	int ret; 
	BIGNUM *a;
	BN_ULONG w;

	a=BN_new(); 
	BN_one(a); 
	w=2685550010; 
	ret=BN_add_word(a,w); 
	if(ret!=1) {
		printf("a+=w err!\n"); 
		BN_free(a);
		return -1;
	} 
	
	BIO *bio_out;
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	//int BN_print(BIO *fp, const BIGNUM *a);
	BIO_printf(bio_out, "-------------------\n");
	BN_print(bio_out, a);
	BIO_printf(bio_out, "\n-------------------\n");
	
	BN_free(a); 
	return 0;
}


