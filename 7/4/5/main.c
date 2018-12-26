#include <string.h> 
#include <openssl/bio.h> 
#include <openssl/evp.h>

int main()
{
	/* 加密 */ 
	BIO *bc=NULL,*b=NULL; 
	const EVP_CIPHER *c=EVP_des_ecb(); 
	int len,i;
	char tmp[1024]={0};

	unsigned char key[8],iv[8];
	for(i=0;i<8;i++) {
		memset(&key[i],i+1,1);
		memset(&iv[i],i+1,1); 
	}
	bc=BIO_new(BIO_f_cipher());
	BIO_set_cipher(bc,c,key,iv,1); 
	b= BIO_new(BIO_s_null());
	b=BIO_push(bc,b); 
	len=BIO_write(b,"openssl",7); 
	len=BIO_read(b,tmp,1024); 
	BIO_free(b);

	/*print */
	for (i =0; i < 8; i++){
		printf("%x ", (uint8_t) tmp[i]);
	}
	printf("\n");

	/* 解密 */
	BIO *bdec=NULL,*bd=NULL;
	const EVP_CIPHER*cd=EVP_des_ecb();
	bdec=BIO_new(BIO_f_cipher()); 
	BIO_set_cipher(bdec,cd,key,iv,0); 
	bd= BIO_new(BIO_s_null()); 
	bd=BIO_push(bdec,bd); 
	len=BIO_write(bdec,tmp,len);

	len=BIO_read(bdec,tmp,1024); 
	BIO_free(bdec);

	/*print */
	tmp[len]='\0';
	printf("len = %d, %s \n", len, tmp);

	return 0;
}
