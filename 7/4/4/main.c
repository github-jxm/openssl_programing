#include <openssl/bio.h> 
#include <openssl/evp.h>

int main()
{

	BIO *bmd=NULL,*b=NULL;
	const  EVP_MD *md=EVP_md5();
	int len, i;  
	char tmp[1024]={0};

	bmd=BIO_new(BIO_f_md()); 
	BIO_set_md(bmd,md);
	b= BIO_new(BIO_s_null()); 
	b=BIO_push(bmd,b); 
	len=BIO_write(b,"openssl",7); 
	len=BIO_gets(b,tmp,1024); 
	

	for ( i=0 ; i < 16; i++)
		printf("0x%02x: ", (uint8_t)tmp[i]);
	BIO_free(b);
	return 0;
}
