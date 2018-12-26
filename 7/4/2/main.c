#include <stdio.h> 
#include <openssl/bio.h>
int main()
{
	BIO *b=NULL; 
	int len=0,outlen=0;

	char *out=NULL;

	b=BIO_new_file("bf.txt","w"); 
	len=BIO_write(b,"openssl",4); 
	len=BIO_printf(b,"%s","zcp"); 
	BIO_free(b); 

	b=BIO_new_file("bf.txt","r"); 
	len=BIO_pending(b);
	len=50;
	out=(char *)OPENSSL_malloc(len); 
	len=1;
	while(len>0) {
		len=BIO_read(b,out+outlen,1);
		outlen+=len; 
	}
	printf("outlen = %d \n" , outlen);

	BIO_free(b); 
	free(out); 
	return 0;
}

