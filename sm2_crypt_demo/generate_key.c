#include <string.h>
#include <stdio.h>
#include <openssl/ec.h> 
#include <openssl/ecdsa.h> 
#include <openssl/objects.h> 
#include <openssl/err.h>
#include <openssl/evp.h>  //include NID_sm2

int sm2_generate_key(unsigned char *privKey_str,unsigned char *pubKey_str)
{
	EC_KEY *key1,*key2; 

	EC_POINT *pubkey1,*pubkey2; 
	EC_GROUP *group1; 
	int ret,nid,size,i,sig_len;


	/* 构造 EC_KEY 数据结构 */ 
	key1=EC_KEY_new(); 
	if(key1==NULL) {
		printf("EC_KEY_new err!\n");
		return -1; 
	}

	key2=EC_KEY_new(); 
	if(key2==NULL) {
		printf("EC_KEY_new err!\n");
		return -1;
       	}

	/* 选取一种椭圆曲线 */
	/* 根据选择的椭圆曲线生成密钥参数 group */ 
	group1=EC_GROUP_new_by_curve_name(NID_sm2);
	if(group1==NULL) {
		printf("EC_GROUP_new_by_curve_name err!\n");
		return -1; 
	}

	/* 设置密钥参数 */ 
	ret=EC_KEY_set_group(key1,group1); 
	if(ret!=1) {
		printf("EC_KEY_set_group err.\n");
		return -1; 
	}
	/* 生成密钥 */ 
	ret=EC_KEY_generate_key(key1); 
	if(ret!=1) {
		printf("EC_KEY_generate_key err.\n");
		return -1; 
	}

	/* 检查密钥 */ 
	ret=EC_KEY_check_key(key1); 
	if(ret!=1) {
		printf("check key err.\n");
		return -1; 
	}
	/* 获取密钥大小 */ 
	// size=ECDSA_size(key1); 
	//printf("size %d \n",size); 


	/**************************/
	/*获取private_key*/
        const BIGNUM * private_key = EC_KEY_get0_private_key(key1);
        int pirKey_len = BN_num_bytes(private_key);
        //printf("gen key success:\n prv =   %s ,len = %d\n", 
	//		BN_bn2hex(private_key),pirKey_len);

	strncpy(privKey_str,BN_bn2hex(private_key),pirKey_len*2);
        privKey_str[pirKey_len*2] = '\0';

	// get publick key 
        unsigned char pubKey[256];
        int pubKeyLen = 0;
        unsigned char * ptrPubKey=pubKey;
        pubKeyLen = i2o_ECPublicKey(key1,&ptrPubKey);


	// init BIO
        BIO *bio_out;
        bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	// publick key => BIGNUM
        BIGNUM *ret1 = BN_new() ;
        ret1 = BN_bin2bn(pubKey,pubKeyLen, ret1);
	//BN_print(bio_out,ret1);

        // conver to hex_str
        unsigned char *str_hex = NULL;
        str_hex = BN_bn2hex(ret1);
        //BIO_printf(bio_out," pub = %s ,len = %d \n",str_hex,pubKeyLen );
        //BIO_printf(bio_out,"---------------------------------------------- %d \n",pubKeyLen*2);

	strncpy(pubKey_str,str_hex, pubKeyLen*2);
        pubKey_str[ pubKeyLen*2] = '\0';

        OPENSSL_free(str_hex);
	EC_KEY_free(key1); 
	return 0;
}

#ifdef TEST_MAIN
int main()
{
   
        unsigned char privKey_str[1024];
	unsigned char pubKey_str[1024];
	sm2_generate_key(privKey_str,pubKey_str);
	printf(" privKey_str =   %s \n pubKey_str  = %s \n",privKey_str,pubKey_str);
}
#endif
