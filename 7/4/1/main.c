#include <stdio.h> 
#include <string.h> 
#include <openssl/bio.h>

int main() 
{
	BIO *b=NULL; 
	int len=0;
	char *out=NULL;

	b=BIO_new(BIO_s_mem()); 
	len=BIO_write(b,"openssl",4);
	//len=BIO_write(b,"openssl",7);
	len=BIO_printf(b,"%s","zcp"); 
	len=BIO_ctrl_pending(b);
	out=(char *)OPENSSL_malloc(len); 
	len=BIO_read(b,out,len); 
	printf(" %zu :  %s \n" ,strlen(out), out);
	//printf(" %d :  %s \n" ,len, out);

	OPENSSL_free(out);
	BIO_free(b);
	return 0; 
}
