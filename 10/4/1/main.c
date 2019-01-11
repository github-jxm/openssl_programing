/* txtdb.dat的内容
   赵春平	28    湖北	无
   zcp	28	荆门	无
*/
#include <openssl/bio.h>
#include <openssl/txt_db.h>
#include <openssl/lhash.h>

/* 名字过滤 */
static  int name_filter(char **in)
{
	if(strlen(in[0])<2)
		return 0;
	return 1;
}

static unsigned long index_name_hash(const char **a)
{
	const char *n;

	n=a[0];
	while (*n == '0') n++;
	return(lh_strhash(n));
}

static int index_name_cmp(const char **a, const char **b)
{
	const char *aa,*bb;

	for (aa = a[0]; *aa == '0'; aa++);
	for (bb = b[0]; *bb == '0'; bb++);
	return(strcmp(aa,bb));
}

int    main()
{
	TXT_DB *db = NULL,*out = NULL;
	BIO    *in;
	int    num,ret;
	char   **added = NULL,**rrow = 0,**row = NULL;

	in = BIO_new_file("txtdb.dat","r");
	num = 1024;
	db = TXT_DB_read(in,4);
	added = (char **)OPENSSL_malloc(sizeof(char *)*(3+1));
	added[0] = (char *)OPENSSL_malloc(10);
#if 1
	strcpy(added[0],"skp");
#else
	strcpy(added[0],"a");     /* 不能插入名字对应的哈希表 */
#endif

	added[1] = (char *)OPENSSL_malloc(10);
	strcpy(added[1],"22");

	added[2] = (char *)OPENSSL_malloc(10);
	strcpy(added[2],"chairman");

	added[3] = NULL;

	ret = TXT_DB_insert(db,added);
	if(ret != 1) {
		printf("err!\n");
		return -1;
	}
	ret = TXT_DB_create_index(db,0, name_filter,index_name_hash,index_name_cmp);
	if(ret != 1) {
		printf("err\n");
		return 0;
	}
	row = (char **)malloc(2*sizeof(char *));
	row[0] = (char *)malloc(10);
	strcpy(row[0],"skp");
	row[1] = NULL;
	rrow = TXT_DB_get_by_index(db,0,row);
	if(rrow != NULL){
		printf("%s      %s   %s\n",rrow[0],rrow[1],rrow[2]);
	}
	out = BIO_new_file("txtdb2.dat","w");
	ret = TXT_DB_write(out,db);
	TXT_DB_free(db);
	BIO_free(in);
	BIO_free(out);
	return 0;
}

       /*
	* 本示例只对第一列做了哈希。
	* 需要注意的是，added数组及其元素申请空间时尽量采用OPENSSL_malloc而不是malloc，
	* 且其申请的空间由TXT_DB_free(调用OPENSSL_free)释放           
	*/
