#include "random.h"
static int my_rand(char *rand,int len) 
{
	memset(rand,0x02,len);
	return 0; 
}

int main()
{
	char random[10];

	printf("%ld\n",sizeof(random));
	printf ("-----------------\n");
	for (int  i =0; i < sizeof(random); i++){
		printf ("%d - ",random[i]);
	}
	printf ("-----------------\n");
	

	int ret; 
	set_callback(my_rand); 
	ret=genrate_random(random,5); 
	//printf("%d\n",ret);
	
	printf("%ld\n",sizeof(random));

	printf ("-----------------\n");
	for (int  i =0; i < sizeof(random); i++){
		printf ("%d - ",random[i]);
	}
	printf ("-----------------\n");
	return 0;
}

