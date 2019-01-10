//#include <openssl/dso.h>
#include "crypto/dso/dso_locl.h"
#include "internal/dso.h"
#include <openssl/bio.h>
int    main()
{
	DSO       *d;
	void       (*f)();
	BIO        *(*BIO_newx)(BIO_METHOD *a);
	BIO        *test;
	char       *load_name;
	const char *loaded_name;
	int        flags;

	d = DSO_new();
#if 0
	DSO_set_name_converter
		DSO_ctrl(d,DSO_CTRL_SET_FLAGS,DSO_FLAG_NO_NAME_TRANSLATION,NULL);
	DSO_ctrl(d,DSO_CTRL_SET_FLAGS,DSO_FLAG_NAME_TRANSLATION_EXT_ONLY,NULL);
	DSO_ctrl(d,DSO_CTRL_SET_FLAGS,DSO_FLAG_GLOBAL_SYMBOLS,NULL);
	/* 最好写成libeay32而不是libeay32.dll，
	 * 除非前面调用了DSO_ctrl(d,DSO_CTRL_SET_FLAGS,DSO_FLAG_NO_NAME_TRANSLATION,NULL)
	 * 否则它会加载libeay32.dll.dll
	*/
	load_name = DSO_merge(d,"libeay32","D:\\zcp\\OpenSSL\\openssl-0.9.8b\\out32dll\\Debug");
#endif
	//d = DSO_load(d,"libeay32",NULL,0);
	d = DSO_load(d,"/usr/local/openssl/lib/libcrypto.so",NULL,0);
	if(d == NULL)
	{
		printf("err\n");
		return -1;
	}
	//loaded_name = DSO_get_loaded_filename(d);
	loaded_name = DSO_get_filename(d);
	if(loaded_name != NULL)
	{
		printf("loaded file is %s\n",loaded_name);

	}
	flags = DSO_flags(d);
	printf("current falgs is %d\n",flags);
	DSO_up_ref(d);
	f = (void (*)())DSO_bind_func(d,"BIO_new");
	BIO_newx = (BIO *(*)(BIO_METHOD *))f;
	test = BIO_newx(BIO_s_file());
	BIO_set_fp(test,stdout,BIO_NOCLOSE);
	BIO_puts(test,"abd\n\n");
	BIO_free(test);
	printf("filename : %s\n",d->filename);
	printf("loaded_filename : %s\n",d->loaded_filename);
	//printf("handle in dso number is : %d\n",d->meth_data->num);
	DSO_free(d);
	//DSO_free(d);
	//printf("handle in dso number is : %d\n",d->meth_data->num);
	return 0;
}
/*
本例主要演示了DSO的控制函数。
*/
