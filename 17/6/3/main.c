#include <string.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>

int main()
{
	int  ret;
	RSA  *r;
	int  i, bits=1024, signlen, datalen, alg, nid;
	unsigned long  e = RSA_3;
	BIGNUM *bne;
	unsigned char data[100],signret[200];

	bne=BN_new();
	ret=BN_set_word(bne,e);
	r=RSA_new();
	ret=RSA_generate_key_ex(r,bits,bne,NULL);
	if(ret!=1) {
		printf("RSA_generate_key_ex err!\n");
		return -1;
	}

	for(i = 0;i < 100;i ++){
		memset(&data[i], i+1, 1);
	}

	printf("please select digest alg: \n");
	printf("1.NID_md5\n");
	printf("2.NID_sha\n");
	printf("3.NID_sha1\n");
	printf("4.NID_md5_sha1\n");
	scanf("%d",&alg);

	if(alg == 1) {
		datalen = 55;
		nid=NID_md5;
	}
	else if(alg == 2) {
		datalen = 55;
		nid=NID_sha;
	}
	else if(alg == 3) {
		datalen = 55;
		nid=NID_sha1;
	}
	else if(alg == 4) {
		datalen = 36;
		nid=NID_md5_sha1;
	}
	ret=RSA_sign(nid,data,datalen,signret,&signlen,r);
	if(ret != 1) {
		printf("RSA_sign err!\n");
		RSA_free(r);
		return -1;
	}
	ret=RSA_verify(nid,data,datalen,signret,signlen,r);
	if(ret!=1) {
		printf("RSA_verify err!\n");
		RSA_free(r);
		return -1;
	}
	RSA_free(r);
	printf("test ok!\n");
	return 0;
}
