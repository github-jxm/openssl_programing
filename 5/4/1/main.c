#include <string.h>
#include <openssl/crypto.h>
int    main()
{    
	char *p;
	int  i;
	p=OPENSSL_malloc(4);
	//p=OPENSSL_remalloc(p,40);
	p=OPENSSL_realloc(p,32);
	for(i=0;i<32;i++)
		memset(&p[i],i,1);
	/* realloc时将以前的内存区清除(置乱) */
	//p=OPENSSL_realloc_clean(p,32,77);
	//p=OPENSSL_remalloc(p,40);
	//OPENSSL_malloc_locked(3);
	OPENSSL_free(p);
	return 0;
}

/*
      上述示例使用了基本的openssl内存分配和释放函数。
	OPENSSL_malloc:        分配内存空间。
	OPENSSL_remalloc:      重新分配内存空间。
	OPENSSL_realloc_clean：重新分配内存空间，将老的数据进行拷贝，置乱老的数据空间并释放。
	OPENSSL_malloc_locked: 与锁有关。
	OPENSSL_free:          释放空间。
*/
