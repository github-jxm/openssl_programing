#include <openssl/rsa.h> 
int main()
{
	RSA *r;
	int bits = 512, ret; 
	unsigned long e = RSA_3; 

	unsigned char priKeyBuf[1024]={0}, *ptrPriKeyBuf =NULL ;
	ptrPriKeyBuf = priKeyBuf;

	BIGNUM *bne;

	bne = BN_new();
	ret = BN_set_word(bne,e);
	r = RSA_new(); 
	ret = RSA_generate_key_ex(r,bits,bne,NULL); 
	if(ret!=1) {
		printf("RSA_generate_key_ex err!\n"); 
		return -1;
	} 

	// -----
	int len = i2d_RSAPrivateKey(r,&ptrPriKeyBuf);
	printf("\nRSAPrivateKey len = %d \n\n" ,len);

	int i;
	for ( i = 0; i < len; i++ ){
		printf("%02x:",priKeyBuf[i]); 
	}
	printf("\n");

	// -----
	len = i2d_RSAPublicKey(r,NULL);  // get length
	printf("\nRSAPublicKey len = %d \n\n" ,len);

	uint8_t * const buf = (uint8_t *) OPENSSL_malloc(len);
	ptrPriKeyBuf = buf;

	len = i2d_RSAPublicKey(r,&ptrPriKeyBuf);
	for ( i = 0; i < len; i++ ){
		printf("%02x:",buf[i]); 
	}
	printf("\n");
	OPENSSL_free(buf);

	BN_free(bne);

	RSA_print_fp(stdout,r,11);
	RSA_free(r); 
	return 0;
}
