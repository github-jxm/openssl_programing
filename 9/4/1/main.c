#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

int    main()
{
	char          buf[20],*p;
	unsigned char out[20],filename[50];
	int           ret,len;
	BIO           *print;

	//RAND_screen();
	strcpy(buf,"我的随机数");
	RAND_add(buf,20,strlen(buf));
	strcpy(buf,"23424d");
	RAND_seed(buf,20);
	while(1) {
		ret = RAND_status();
		if(ret==1) {
			printf("seeded enough!\n");
			break;
		}
		else {
			printf("not enough sedded!\n");
			RAND_poll();
		}
	}
	p = RAND_file_name(filename,50);
	if(p == NULL) {
		printf("can not get rand file\n");
		return -1;
	}
	ret = RAND_write_file(p);
	len = RAND_load_file(p,1024);
	ret = RAND_bytes(out, 20);
	if(ret != 1) {
		printf("err.\n");
		return -1;
	}
	print = BIO_new(BIO_s_file());
	BIO_set_fp(print,stdout,BIO_NOCLOSE);
	BIO_write(print,out,20);
	BIO_write(print,"\n",2);
	BIO_free(print);
	RAND_cleanup();
	return 0;
}           
