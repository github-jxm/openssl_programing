#include <string.h>
#include <openssl/evp.h>
int main()
{
	EVP_ENCODE_CTX  *ectx = NULL,*dctx = NULL;
	ectx = EVP_ENCODE_CTX_new();
	dctx = EVP_ENCODE_CTX_new();

	unsigned char in[500],out[800],d[500];
	int           inl,outl,i,total,ret,total2;

	EVP_EncodeInit(ectx);
	for(i = 0;i < 500;i ++){
		memset(&in[i],i,1);
	}
	inl = 500;
	total = 0;
	EVP_EncodeUpdate(ectx,out,&outl,in,inl);
	total += outl;
	EVP_EncodeFinal(ectx,out+total,&outl);
	total += outl;
	printf("%s\n",out);

	EVP_DecodeInit(dctx);
	outl = 500;
	total2 = 0;
	ret=EVP_DecodeUpdate(dctx,d,&outl,out,total);
	if(ret < 0) {
		printf("EVP_DecodeUpdate err!\n");
		return -1;
	}
	total2 += outl;
	ret=EVP_DecodeFinal(dctx,d,&outl);
	total2 += outl;

	EVP_ENCODE_CTX_free(ectx);
	EVP_ENCODE_CTX_free(dctx);
	return 0;
}
/*
 *
       本例中先编码再解码。
       编码调用次序为EVP_EncodeInit、EVP_EncodeUpdate(可以多次)和EVP_EncodeFinal。
       解码调用次序为EVP_DecodeInit、EVP_DecodeUpdate(可以多次)和EVP_DecodeFinal。
       注意：采用上述函数BASE64编码的结果不在一行，解码所处理的数据也不在一行。
       用上述函数进行BASE64编码时，输出都是格式化输出。
       特别需要注意的是，BASE64解码时如果某一行字符格式超过80个，会出错。
       如果要BASE64编码的结果不是格式化的，可以直接调用函数：EVP_EncodeBlock。
       同样对于非格式化数据的BASE64解码可以调用EVP_DecodeBlock函数，
       不过用户需要自己去除后面填充的0。
*/
