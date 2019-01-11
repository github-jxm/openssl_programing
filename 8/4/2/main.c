// NCONF_get_section 的用法：

#include <openssl/conf.h>
int main()
{
	CONF     *conf;
	BIO      *bp;
	STACK_OF(CONF_VALUE) *v;
	CONF_VALUE   *one;
	int   i,num;
	long  eline;

	conf = NCONF_new(NULL);
	bp = BIO_new_file("../1/openssl.cnf","r");
	if(bp == NULL) {
		printf("err!\n");
		return -1;
	}

	NCONF_load_bio(conf,bp,&eline);
	v = NCONF_get_section(conf,"CA_default");
	num = sk_CONF_VALUE_num(v);
	printf("section CA_default :\n");
	for(i = 0;i < num;i ++)
	{
		one = sk_CONF_VALUE_value(v,i);
		printf("%s = %s\n",one->name,one->value);
	}
	BIO_free(bp);
	printf("\n");
	return 0;
}
