//#include <openssl/dso.h>
#include "internal/dso.h"
#include <openssl/bio.h>
#include <stdio.h>

int main()
{
	DSO  *d;
	void (*f1)();
	void (*f2)();
	BIO  *(*BIO_newx)(BIO_METHOD *a);
	BIO  *(*BIO_freex)(BIO_METHOD *a);
	BIO  *test;

	d=DSO_new();
	//d=DSO_load(d,"libeay32",NULL,0);
	d=DSO_load(d,"/usr/local/openssl/lib/libcrypto.so",NULL,0);
	if ( d == NULL ) {
		perror("not fond libcrypto.so");
	       	return 1;
	}
	
	f1 = DSO_bind_func(d,"BIO_new");
	f2 = DSO_bind_func(d,"BIO_free");
	BIO_newx = (BIO *(*)(BIO_METHOD *))f1;
	BIO_freex = (BIO *(*)(BIO_METHOD *))f2;

	test = BIO_newx(BIO_s_file());
	BIO_set_fp(test,stdout,BIO_NOCLOSE);
	BIO_puts(test,"abd\n\n");
	BIO_freex(test);
	DSO_free(d);
	return 0;
}
/*
   本例动态加载libeay32动态库，获取BIO_new和BIO_free的地址并调用。
*/
