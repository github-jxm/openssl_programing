#include <openssl/ec.h> 

/*
  https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_new.html
  typedef struct {
          int nid;
          const char *comment;
          } EC_builtin_curve
*/

int main() 
{
	EC_builtin_curve *curves = NULL; 
	size_t crv_len = 0, n = 0;
	int nid,ret;
	EC_GROUP *group = NULL;

	/*
	size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems)
	说明: 获取内置的椭圆曲线。
	      当输入参数 r 为 NULL 或者 nitems 为 0 时，返回内置椭圆曲线的个数，
	      否则将各个椭圆曲线信息存放在 r 中。
	*/
	crv_len = EC_get_builtin_curves(NULL, 0);
	curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * crv_len); 

	/* 获取椭圆曲线列表 */
	EC_get_builtin_curves(curves, crv_len);
	for (n=0;n<crv_len;n++) {
		nid = curves[n].nid; 
		group=NULL;
		printf("[%zd] nid = %d comment=%s \n", 
				n , curves[n].nid,curves[n].comment);
		group = EC_GROUP_new_by_curve_name(nid);
		ret=EC_GROUP_check(group,NULL); /*检查椭圆曲线，成功返回 1*/ 
	}
	OPENSSL_free(curves);


	return 0;
}
