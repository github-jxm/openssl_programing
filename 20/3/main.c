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

	crv_len = EC_get_builtin_curves(NULL, 0);
	curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * crv_len); 
	EC_get_builtin_curves(curves, crv_len);

	for (n=0;n<crv_len;n++) {
		nid = curves[n].nid; 
		group=NULL;
		//printf("nid = %d comment=%s \n", curves[n].nid,curves[n].comment);
		group = EC_GROUP_new_by_curve_name(nid);
		ret=EC_GROUP_check(group,NULL); 
	}
	OPENSSL_free(curves);


	return 0;
}
