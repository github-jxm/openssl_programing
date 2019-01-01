#include <string.h>
#include <stdio.h>
#include <openssl/ec.h> 
#include <openssl/ecdsa.h> 
#include <openssl/objects.h> 
#include <openssl/err.h>

int main()
{
	EC_KEY *key1,*key2; 

	EC_POINT *pubkey1,*pubkey2; 
	EC_GROUP *group1,*group2; 
	int ret,nid,size,i,sig_len;

	unsigned char *signature,digest[20]; 
	BIO *berr; 
	EC_builtin_curve *curves;
	int crv_len; 
	//char shareKey1[128*2],shareKey2[128*2];
	uint8_t shareKey1[256],shareKey2[256];
	int len1,len2;

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

	/* 获取实现的椭圆曲线个数 */
	crv_len = EC_get_builtin_curves(NULL, 0);
	curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len); 
	/* 获取椭圆曲线列表 */
	EC_get_builtin_curves(curves, crv_len);
	/*
	nid=curves[0].nid;会有错误，原因是密钥太短
	*/
	/* 选取一种椭圆曲线 */
	//nid=curves[25].nid;
	nid=curves[81].nid; // SM2
	/* 根据选择的椭圆曲线生成密钥参数 group */ 
	group1=EC_GROUP_new_by_curve_name(nid);
	if(group1==NULL) {
		printf("EC_GROUP_new_by_curve_name err!\n");
		return -1; 
	}

	group2=EC_GROUP_new_by_curve_name(nid); 
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
	ret=EC_KEY_set_group(key2,group2); 
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
	ret=EC_KEY_generate_key(key2); 
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
	size=ECDSA_size(key1); 
	printf("size %d \n",size); 

	for(i=0;i<20;i++){
		memset(&digest[i],i+1,1);
	}

	signature=malloc(size);

	/*加载各自错误信息*/
	ERR_load_crypto_strings();

	berr=BIO_new(BIO_s_file());
	BIO_set_fp(berr,stdout,BIO_NOCLOSE);

	/*签名 验签*/
	/* 签名数据，本例未做摘要，可将 digest 中的数据看作是 sha1 摘要结果 */ 
	ret=ECDSA_sign(0,digest,20,signature,&sig_len,key1);
	if(ret!=1) {
		ERR_print_errors(berr); printf("sign err!\n"); return -1;
	}
	/* 验证签名 */ 
	ret=ECDSA_verify(0,digest,20,signature,sig_len,key1); 

	if(ret!=1) {
		ERR_print_errors(berr); printf("ECDSA_verify err!\n"); return -1;
	}

	/** DH 会话密钥**/
	/* 获取对方公钥，不能直接引用 */
	pubkey2 = EC_KEY_get0_public_key(key2);
	/* 生成一方的共享密钥 */
	len1=ECDH_compute_key(shareKey1, 256, pubkey2, key1, NULL);
	
	/* printf */
	for ( i = 0; i<len1; i ++){
		printf("%02x:",shareKey1[i]);
	}
	printf("\n");
	

	pubkey1 = EC_KEY_get0_public_key(key1);
	/* 生成另一方共享密钥 */
	len2=ECDH_compute_key(shareKey2, 256, pubkey1, key2, NULL); 
	if(len1!=len2) {
		printf("err\n"); 
	}
	else {
		ret=memcmp(shareKey1,shareKey2,len1); 
		if(ret==0)
			printf("生成共享密钥成功\n"); 
		else
			printf("生成共享密钥失败\n");
	}

	printf("test ok!\n"); 
	BIO_free(berr); 
	EC_KEY_free(key1); 
	EC_KEY_free(key2); 
	free(signature); 
	free(curves);
	return 0;
}
