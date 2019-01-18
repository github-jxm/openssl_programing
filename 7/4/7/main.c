#include <openssl/bio.h>
#include <openssl/asn1.h>
int main()
{
	int ret,len,indent;
	BIO *bp;
	char *pp,buf[5000];
	FILE  *fp;

	bp = BIO_new(BIO_s_file());
	BIO_set_fp(bp,stdout,BIO_NOCLOSE);
	fp = fopen("der.cer","rb");
	len = fread(buf,1,5000,fp);
	fclose(fp);
	pp = buf;
	indent = 5;
	ret = BIO_dump_indent(bp,pp,len,indent);
	BIO_free(bp);
	return 0;
}

