#include <openssl/bio.h>
#include <openssl/bn.h>

int main() 
{
	int ret; 
	BIGNUM *a;
	BN_ULONG w;

	a=BN_new(); 
	//BN_zero(a); 
	//BN_one(a); 
	//BN_set_word(a,16);
	//BN_set_word(a,256);
	w=2685550010; 
	//w=0x2685550010; 
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

        int bits = BN_num_bits(a);
	BIO_printf(bio_out, "bits = %d \n" ,bits);

        bits = BN_num_bytes(a);
	BIO_printf(bio_out, "bytes = %d \n" ,bits);
	
	BN_free(a); 
	return 0;
}


