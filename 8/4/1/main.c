#include <openssl/conf.h>
int    main()
{
	CONF  *conf;
	long eline,result;
	int  ret;
	char *p;
	BIO *bp;

	conf = NCONF_new(NULL);
#if 0
	bp=BIO_new_file("openssl.cnf","r");
	NCONF_load_bio(conf,bp,&eline);
#else
	ret = NCONF_load(conf,"openssl.cnf",&eline);
	//ret = CONF_modules_load_file
	if(ret != 1)
	{
		printf("err!\n");
		return -1;
	}
#endif
	p = NCONF_get_string(conf,NULL,"certs");
	if(p == NULL){
		printf("no global certs info\n");
	}
	p=NCONF_get_string(conf,"CA_default","certs");
	printf("%s\n",p);
	p=NCONF_get_string(conf,"CA_default","default_days");
	printf("%s\n",p);
	ret=NCONF_get_number_e(conf,"CA_default","default_days",&result);
	printf("%d\n",result);
	ret=NCONF_get_number(conf,"CA_default","default_days",&result);
	printf("%d\n",result);
	NCONF_free(conf);
	return 0;
}
